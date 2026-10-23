// DoIP over TLS on real sockets: platform::DoipTlsServer + DiagGateway against
// an OpenSSL client on loopback. Certificates are generated per test run.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/diag/doip_client.hpp"
#include "ccg/doip/doip_message.hpp"
#include "doip_ecu.hpp"
#include "doip_tcp_connector.hpp"
#include "doip_tls_server.hpp"
#include "test_framework.hpp"
#include "vehicle_diag_routing.hpp"
#include "vehicle_key_master.hpp"

using namespace ccg;
using Bytes = std::vector<std::uint8_t>;
namespace pt = doip::payload;
namespace dg = config::dg;

namespace {

// --- test PKI ------------------------------------------------------------------

struct Credential {
    EVP_PKEY* key = nullptr;
    X509* cert = nullptr;
    std::string certFile;
    std::string keyFile;
};

std::string tempFile(const std::string& name) {
    return "/tmp/ccg_tls_" + std::to_string(::getpid()) + "_" + name + ".pem";
}

void addExtension(X509* cert, X509* issuer, int nid, const char* value) {
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
}

// ECDSA P-256 certificate, signed by `issuer` (self-signed CA if null).
Credential makeCredential(const std::string& name, const char* cn, const Credential* issuer, bool ca, long serial) {
    Credential c;
    c.key = EVP_EC_gen("P-256");
    c.cert = X509_new();
    X509_set_version(c.cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(c.cert), serial);
    X509_gmtime_adj(X509_getm_notBefore(c.cert), -3600);
    X509_gmtime_adj(X509_getm_notAfter(c.cert), 86400);
    X509_set_pubkey(c.cert, c.key);
    X509_NAME* subject = X509_get_subject_name(c.cert);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    X509_set_issuer_name(c.cert, issuer ? X509_get_subject_name(issuer->cert) : subject);
    X509* signer = issuer ? issuer->cert : c.cert;
    addExtension(c.cert, signer, NID_basic_constraints, ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    addExtension(c.cert, signer, NID_key_usage, ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
    if (!ca) addExtension(c.cert, signer, NID_ext_key_usage, "serverAuth,clientAuth");
    X509_sign(c.cert, issuer ? issuer->key : c.key, EVP_sha256());

    c.certFile = tempFile(name + "_cert");
    c.keyFile = tempFile(name + "_key");
    FILE* f = std::fopen(c.certFile.c_str(), "w");
    PEM_write_X509(f, c.cert);
    std::fclose(f);
    f = std::fopen(c.keyFile.c_str(), "w");
    PEM_write_PrivateKey(f, c.key, nullptr, nullptr, 0, nullptr, nullptr);
    std::fclose(f);
    return c;
}

// CRL of `ca` revoking the given serial numbers; `expired`: nextUpdate in the past.
std::string makeCrl(const std::string& name, const Credential& ca, const std::vector<long>& revoked,
                    bool expired = false) {
    X509_CRL* crl = X509_CRL_new();
    X509_CRL_set_version(crl, 1);  // v2
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca.cert));
    ASN1_TIME* last = X509_gmtime_adj(nullptr, expired ? -2 * 86400 : -3600);
    ASN1_TIME* next = X509_gmtime_adj(nullptr, expired ? -86400 : 7 * 86400);
    X509_CRL_set1_lastUpdate(crl, last);
    X509_CRL_set1_nextUpdate(crl, next);
    for (const long serial : revoked) {
        X509_REVOKED* r = X509_REVOKED_new();
        ASN1_INTEGER* sn = ASN1_INTEGER_new();
        ASN1_INTEGER_set(sn, serial);
        X509_REVOKED_set_serialNumber(r, sn);
        X509_REVOKED_set_revocationDate(r, last);
        X509_CRL_add0_revoked(crl, r);
        ASN1_INTEGER_free(sn);
    }
    X509_CRL_sort(crl);
    X509_CRL_sign(crl, ca.key, EVP_sha256());
    const std::string path = tempFile(name);
    FILE* f = std::fopen(path.c_str(), "w");
    PEM_write_X509_CRL(f, crl);
    std::fclose(f);
    ASN1_TIME_free(last);
    ASN1_TIME_free(next);
    X509_CRL_free(crl);
    return path;
}

struct Pki {
    Credential ca = makeCredential("ca", "CCG Tester CA", nullptr, true, 1);
    Credential gateway = makeCredential("gw", "ccg-gateway", &ca, false, 2);
    Credential tester = makeCredential("tester", "backend-keyserver", &ca, false, 3);
    Credential rogueCa = makeCredential("rogue_ca", "Rogue CA", nullptr, true, 4);
    Credential rogue = makeCredential("rogue", "rogue-tester", &rogueCa, false, 5);
    Credential adas = makeCredential("adas", "adas-dc", &ca, false, 6);
    Credential rogueAdas = makeCredential("rogue_adas", "adas-dc", &rogueCa, false, 7);

    ~Pki() {
        for (auto* c : {&ca, &gateway, &tester, &rogueCa, &rogue, &adas, &rogueAdas}) {
            std::remove(c->certFile.c_str());
            std::remove(c->keyFile.c_str());
            X509_free(c->cert);
            EVP_PKEY_free(c->key);
        }
    }
};

// --- gateway with TLS server ----------------------------------------------------

struct TlsTransport final : diag::IDiagTransport {
    platform::DoipTlsServer* tls = nullptr;
    void sendTcp(diag::ConnectionId c, const Bytes& d) override { tls->send(c, d); }
    void closeTcp(diag::ConnectionId c) override { tls->close(c); }
    void sendUdp(const diag::UdpPeer&, const Bytes&) override {}
    void broadcastUdp(const Bytes&) override {}
    bool transmitCan(std::size_t, const can::CanFrame&) override { return true; }
};

struct Bench {
    TlsTransport transport;
    platform::DoipTlsServer server;
    diag::DiagGateway gw;

    Bench(std::uint16_t port, const platform::TlsServerConfig& cfg)
        : server(port, 2, cfg), gw(config::makeVehicleDiagRouting(), transport) {
        transport.tls = &server;
        gw.start(diag::Clock::now());
    }
    void step() {
        auto fds = server.pollFds();
        ::poll(fds.data(), fds.size(), 2);
        const auto now = diag::Clock::now();
        server.process(fds, gw, now);
        gw.mainFunction(now);
    }
};

// --- OpenSSL client (the tester) ------------------------------------------------

struct Client {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    int fd = -1;
    doip::StreamReassembler stream{4096};
    std::vector<doip::StreamReassembler::Item> messages;

    Client(std::uint16_t port, const Pki& pki, const Credential* identity) {
        ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_load_verify_locations(ctx, pki.ca.certFile.c_str(), nullptr);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);  // the tester checks the gateway too
        if (identity) {
            SSL_CTX_use_certificate_file(ctx, identity->certFile.c_str(), SSL_FILETYPE_PEM);
            SSL_CTX_use_PrivateKey_file(ctx, identity->keyFile.c_str(), SSL_FILETYPE_PEM);
        }
        fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set1_host(ssl, "ccg-gateway");
        SSL_set_connect_state(ssl);
    }
    ~Client() {
        SSL_free(ssl);
        ::close(fd);
        SSL_CTX_free(ctx);
    }

    // true: done, false: failed, nullopt: in progress
    std::optional<bool> handshakeStep() {
        const int r = SSL_do_handshake(ssl);
        if (r == 1) return true;
        const int e = SSL_get_error(ssl, r);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return std::nullopt;
        ERR_clear_error();
        return false;
    }
    void send(std::uint16_t type, const Bytes& payload) {
        const auto b = doip::encode(doip::kVersion2012, type, payload);
        SSL_write(ssl, b.data(), static_cast<int>(b.size()));
    }
    // Reads what arrived; false once the gateway closed the connection.
    bool poll() {
        std::uint8_t buf[2048];
        for (;;) {
            const int n = SSL_read(ssl, buf, sizeof buf);
            if (n > 0) {
                stream.feed(buf, static_cast<std::size_t>(n));
                while (auto m = stream.next()) messages.push_back(std::move(*m));
                continue;
            }
            const int e = SSL_get_error(ssl, n);
            ERR_clear_error();
            return e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE;
        }
    }
    std::optional<Bytes> last(std::uint16_t type) const {
        for (auto it = messages.rbegin(); it != messages.rend(); ++it) {
            if (it->header.type == type) return it->payload;
        }
        return std::nullopt;
    }
};

const Bytes kCentralSecurity = {0x0E, 0x80, diag::kActivationCentralSecurity, 0, 0, 0, 0};
const Bytes kDefaultActivation = {0x0E, 0x80, diag::kActivationDefault, 0, 0, 0, 0};

// Drives server and client until the client's handshake finishes.
std::optional<bool> handshake(Bench& bench, Client& client) {
    for (int i = 0; i < 500; ++i) {
        bench.step();
        const auto r = client.handshakeStep();
        if (r) {
            for (int j = 0; j < 20; ++j) bench.step();  // let the server see the end of the handshake
            return r;
        }
    }
    return std::nullopt;
}

// Sends and waits for a message of `type` (or the connection's end).
std::optional<Bytes> exchange(Bench& bench, Client& client, std::uint16_t type, const Bytes& payload,
                              std::uint16_t answer) {
    client.messages.clear();
    client.send(type, payload);
    for (int i = 0; i < 500; ++i) {
        bench.step();
        const bool open = client.poll();
        if (auto m = client.last(answer)) return m;
        if (!open) return std::nullopt;
    }
    return std::nullopt;
}

// The server refuses the client. With TLS 1.3 the client may finish its side of
// the handshake first and only sees the server's alert when it reads.
bool refused(Bench& bench, Client& client) {
    const auto r = handshake(bench, client);
    if (r == std::optional<bool>(false)) return true;
    if (!r) return false;
    return !exchange(bench, client, pt::kRoutingActivationRequest, kDefaultActivation, pt::kRoutingActivationResponse);
}

platform::TlsServerConfig serverConfig(const Pki& pki, bool requireClientCert) {
    platform::TlsServerConfig c;
    c.certificateFile = pki.gateway.certFile;
    c.privateKeyFile = pki.gateway.keyFile;
    c.caFile = pki.ca.certFile;
    c.requireClientCertificate = requireClientCert;
    return c;
}

}  // namespace

TEST_CASE("doip tls linux: mutual TLS, central security activation and UDS") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    Bench bench(31496, serverConfig(pki, false));
    Client client(31496, pki, &pki.tester);
    REQUIRE(handshake(bench, client) == std::optional<bool>(true));
    CHECK_EQ(bench.gw.statistics().tlsConnections, 1u);
    CHECK_EQ(bench.gw.statistics().authenticatedConnections, 1u);

    const auto ra = exchange(bench, client, pt::kRoutingActivationRequest, kCentralSecurity, pt::kRoutingActivationResponse);
    REQUIRE(ra.has_value());
    CHECK_EQ(ra->at(4), 0x10);
    const auto rsp = exchange(bench, client, pt::kDiagnosticMessage,
                              doip::diagnosticMessagePayload(dg::kTester, dg::kGateway, {0x22, 0xF1, 0x90}),
                              pt::kDiagnosticMessage);
    REQUIRE(rsp.has_value());
    CHECK_EQ(rsp->at(4), 0x62);
    CHECK_EQ(rsp->size(), 4u + 3u + 17u);  // SA TA | 62 F1 90 | VIN
}

TEST_CASE("doip tls linux: TLS without client certificate is anonymous") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    Bench bench(31497, serverConfig(pki, false));
    {
        Client client(31497, pki, nullptr);
        REQUIRE(handshake(bench, client) == std::optional<bool>(true));
        const auto ra = exchange(bench, client, pt::kRoutingActivationRequest, kCentralSecurity,
                                 pt::kRoutingActivationResponse);
        REQUIRE(ra.has_value());
        CHECK_EQ(ra->at(4), 0x04);  // missing authentication
    }
    Client client(31497, pki, nullptr);
    REQUIRE(handshake(bench, client) == std::optional<bool>(true));
    const auto ra = exchange(bench, client, pt::kRoutingActivationRequest, kDefaultActivation,
                             pt::kRoutingActivationResponse);
    REQUIRE(ra.has_value());
    CHECK_EQ(ra->at(4), 0x10);
    CHECK_EQ(bench.gw.statistics().authenticatedConnections, 0u);
}

TEST_CASE("doip tls linux: untrusted or missing client certificates fail the handshake") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    {
        Bench bench(31498, serverConfig(pki, false));
        Client client(31498, pki, &pki.rogue);  // certificate from another CA
        CHECK(refused(bench, client));
        CHECK_EQ(bench.server.handshakeFailures(), 1u);
        CHECK_EQ(bench.gw.statistics().tcpConnectionsAccepted, 0u);  // the gateway never saw it
    }
    {
        Bench bench(31499, serverConfig(pki, true));
        Client client(31499, pki, nullptr);  // certificate required
        CHECK(refused(bench, client));
        CHECK_EQ(bench.server.handshakeFailures(), 1u);
        CHECK_EQ(bench.gw.statistics().tcpConnectionsAccepted, 0u);
    }
}

TEST_CASE("doip tls linux: plain DoIP on the TLS port is dropped") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    Bench bench(31500, serverConfig(pki, false));
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(31500);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    REQUIRE(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) == 0);
    const auto ra = doip::encode(doip::kVersion2012, pt::kRoutingActivationRequest, kDefaultActivation);
    ::send(fd, ra.data(), ra.size(), MSG_NOSIGNAL);
    for (int i = 0; i < 50; ++i) bench.step();
    CHECK_EQ(bench.server.handshakeFailures(), 1u);
    CHECK_EQ(bench.server.connections(), 0u);
    CHECK_EQ(bench.gw.statistics().tcpConnectionsAccepted, 0u);
    ::close(fd);
}

TEST_CASE("doip tls linux: bad server credentials are reported at start-up") {
    Pki pki;
    auto cfg = serverConfig(pki, false);
    cfg.privateKeyFile = pki.tester.keyFile;  // does not match the certificate
    bool threw = false;
    try {
        platform::DoipTlsServer server(31501, 2, cfg);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
}

// --------------------------------------------------------------- gateway -> ADAS over TLS

namespace {

// ADAS DoIP entity behind a real TLS server; the gateway's DoIP client with
// the real TLS connector.
struct AdasOverTls {
    TlsTransport transport;
    platform::DoipTlsServer server;
    sim::DoipEcu adas;
    platform::DoipTcpConnector connector;
    diag::DoipClient client;
    std::vector<std::pair<diag::ClientResult, Bytes>> results;

    static diag::DoipClientConfig clientConfig(std::uint16_t port, const std::string& serverName) {
        auto c = config::makeVehicleDoipClient();
        c.ecus[0].endpoint = "127.0.0.1:" + std::to_string(port);
        c.ecus[0].serverName = serverName;
        return c;
    }
    AdasOverTls(std::uint16_t port, const platform::TlsServerConfig& serverCfg, const std::string& serverName = "adas-dc")
        : server(port, 2, serverCfg),
          adas(config::makeAdasDoipEntity(), config::makeEcuKeySlots(dg::kAdas), transport),
          client(clientConfig(port, serverName), connector) {
        transport.tls = &server;
        connector.attach(client);
        adas.entity().start(diag::Clock::now());
    }
    // Runs a request to ADAS; nullopt if nothing came back.
    std::optional<std::pair<diag::ClientResult, Bytes>> request(const Bytes& uds) {
        results.clear();
        client.request(dg::kAdas, uds, diag::Clock::now(),
                       [this](diag::ClientResult r, Bytes d) { results.emplace_back(r, std::move(d)); });
        for (int i = 0; i < 1000 && results.empty(); ++i) {
            auto fds = server.pollFds();
            const std::size_t clientBase = fds.size();
            const auto clientFds = connector.pollFds();
            fds.insert(fds.end(), clientFds.begin(), clientFds.end());
            ::poll(fds.data(), fds.size(), 2);
            const auto now = diag::Clock::now();
            server.process(std::vector<pollfd>(fds.begin(), fds.begin() + static_cast<std::ptrdiff_t>(clientBase)),
                           adas.entity(), now);
            connector.process(std::vector<pollfd>(fds.begin() + static_cast<std::ptrdiff_t>(clientBase), fds.end()), now);
            client.mainFunction(now);
            adas.entity().mainFunction(now);
        }
        if (results.empty()) return std::nullopt;
        return results.front();
    }
};

platform::TlsServerConfig adasServer(const Credential& identity, const Pki& pki) {
    platform::TlsServerConfig c;
    c.certificateFile = identity.certFile;
    c.privateKeyFile = identity.keyFile;
    c.caFile = pki.ca.certFile;  // vehicle CA: verifies the gateway
    c.requireClientCertificate = true;
    return c;
}

platform::TlsClientConfig gatewayClient(const Pki& pki, bool withCertificate = true) {
    platform::TlsClientConfig c;
    if (withCertificate) {
        c.certificateFile = pki.gateway.certFile;
        c.privateKeyFile = pki.gateway.keyFile;
    }
    c.caFile = pki.ca.certFile;
    return c;
}

}  // namespace

TEST_CASE("doip tls linux: gateway to ADAS over mutual TLS") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    AdasOverTls v(31510, adasServer(pki.adas, pki));
    v.connector.enableTls(gatewayClient(pki));
    const auto r = v.request({0x22, 0xF2, 0xA1});
    REQUIRE(r.has_value());
    CHECK(r->first == diag::ClientResult::Ok);
    CHECK_EQ(r->second.size(), 3u + 15u);
    CHECK(v.client.routingActive(dg::kAdas));
    // ADAS saw a TLS connection authenticated with the gateway's certificate.
    CHECK_EQ(v.adas.entity().statistics().tlsConnections, 1u);
    CHECK_EQ(v.adas.entity().statistics().authenticatedConnections, 1u);
    // The connection is kept.
    CHECK(v.request({0x3E, 0x00})->first == diag::ClientResult::Ok);
    CHECK_EQ(v.client.statistics().connects, 1u);
}

TEST_CASE("doip tls linux: the gateway refuses an ADAS with a wrong name or foreign certificate") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    {
        AdasOverTls v(31511, adasServer(pki.adas, pki), "ivi-head-unit");  // expects another ECU
        v.connector.enableTls(gatewayClient(pki));
        const auto r = v.request({0x3E, 0x00});
        REQUIRE(r.has_value());
        CHECK(r->first == diag::ClientResult::TransportError);
        CHECK_EQ(v.connector.tlsHandshakeFailures(), 1u);
        CHECK_EQ(v.adas.entity().statistics().tcpConnectionsAccepted, 0u);
    }
    {
        AdasOverTls v(31512, adasServer(pki.rogueAdas, pki));  // right name, wrong CA
        v.connector.enableTls(gatewayClient(pki));
        const auto r = v.request({0x3E, 0x00});
        REQUIRE(r.has_value());
        CHECK(r->first == diag::ClientResult::TransportError);
        CHECK_EQ(v.connector.tlsHandshakeFailures(), 1u);
        CHECK_EQ(v.adas.entity().statistics().tcpConnectionsAccepted, 0u);
    }
}

TEST_CASE("doip tls linux: ADAS refuses a gateway without vehicle certificate; no plain fallback") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    {
        AdasOverTls v(31513, adasServer(pki.adas, pki));
        v.connector.enableTls(gatewayClient(pki, false));
        const auto r = v.request({0x3E, 0x00});
        REQUIRE(r.has_value());
        CHECK(r->first != diag::ClientResult::Ok);
        CHECK_EQ(v.server.handshakeFailures(), 1u);
        CHECK_EQ(v.adas.entity().statistics().tcpConnectionsAccepted, 0u);
    }
    {
        AdasOverTls v(31514, adasServer(pki.adas, pki));  // TLS route, connector without TLS
        const auto r = v.request({0x3E, 0x00});
        REQUIRE(r.has_value());
        CHECK(r->first == diag::ClientResult::TransportError);
        CHECK_EQ(v.server.connections(), 0u);  // never even opened a TCP connection
    }
    bool threw = false;
    try {
        platform::DoipTcpConnector c;
        auto cfg = gatewayClient(pki);
        cfg.privateKeyFile = pki.tester.keyFile;  // does not match the certificate
        c.enableTls(cfg);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
}

// --------------------------------------------------------------- revocation (CRLs)

namespace {

struct TempFiles {
    std::vector<std::string> paths;
    std::string add(std::string p) {
        paths.push_back(p);
        return p;
    }
    ~TempFiles() {
        for (const auto& p : paths) std::remove(p.c_str());
    }
};

platform::TlsServerConfig withCrl(platform::TlsServerConfig c, const std::string& crl, bool require = true,
                                  bool acceptExpired = true) {
    c.crl = platform::CrlPolicy{crl, require, acceptExpired};
    return c;
}

// Connects a tester; true if TLS came up and routing activation succeeded.
bool testerGetsIn(Bench& bench, std::uint16_t port, const Pki& pki, const Credential& identity) {
    Client client(port, pki, &identity);
    const auto hs = handshake(bench, client);
    if (hs != std::optional<bool>(true)) return false;
    const auto ra = exchange(bench, client, pt::kRoutingActivationRequest, kDefaultActivation,
                             pt::kRoutingActivationResponse);
    return ra && ra->at(4) == 0x10;
}

}  // namespace

TEST_CASE("doip tls linux: a revoked tester certificate is refused, others are not") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    const auto crl = files.add(makeCrl("crl_tester", pki.ca, {3}));  // serial 3: backend-keyserver
    Bench bench(31520, withCrl(serverConfig(pki, false), crl));
    CHECK(!testerGetsIn(bench, 31520, pki, pki.tester));
    CHECK_EQ(bench.server.revocation().revokedRejected, 1u);
    CHECK_EQ(bench.gw.statistics().tcpConnectionsAccepted, 0u);
    CHECK(testerGetsIn(bench, 31520, pki, pki.gateway));  // serial 2, not revoked
    CHECK_EQ(bench.gw.statistics().authenticatedConnections, 1u);
}

TEST_CASE("doip tls linux: CRL policy for missing and outdated CRLs") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    const auto foreign = files.add(makeCrl("crl_foreign", pki.rogueCa, {}));  // no CRL of our CA
    const auto expired = files.add(makeCrl("crl_expired", pki.ca, {}, true));
    {
        Bench bench(31521, withCrl(serverConfig(pki, false), foreign));
        CHECK(!testerGetsIn(bench, 31521, pki, pki.tester));
        CHECK(bench.server.revocation().missingCrlRejected >= 1u);
    }
    {
        Bench bench(31522, withCrl(serverConfig(pki, false), foreign, false));  // --crl-optional
        CHECK(testerGetsIn(bench, 31522, pki, pki.tester));
        CHECK(bench.server.revocation().missingCrlAccepted >= 1u);
    }
    {
        Bench bench(31523, withCrl(serverConfig(pki, false), expired));  // offline vehicle: outdated CRL used
        CHECK(testerGetsIn(bench, 31523, pki, pki.tester));
        CHECK(bench.server.revocation().expiredCrlAccepted >= 1u);
    }
    {
        Bench bench(31524, withCrl(serverConfig(pki, false), expired, true, false));  // --crl-reject-expired
        CHECK(!testerGetsIn(bench, 31524, pki, pki.tester));
        CHECK(bench.server.revocation().expiredCrlRejected >= 1u);
    }
    bool threw = false;
    try {
        Bench bench(31525, withCrl(serverConfig(pki, false), "/nonexistent/crl.pem"));
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
}

TEST_CASE("doip tls linux: a CRL update closes the session of a revoked tester") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    const auto crl = files.add(makeCrl("crl_update", pki.ca, {}));
    Bench bench(31526, withCrl(serverConfig(pki, false), crl));
    Client client(31526, pki, &pki.tester);
    REQUIRE(handshake(bench, client) == std::optional<bool>(true));
    const auto ra = exchange(bench, client, pt::kRoutingActivationRequest, kCentralSecurity,
                             pt::kRoutingActivationResponse);
    REQUIRE(ra.has_value());
    REQUIRE(ra->at(4) == 0x10);
    CHECK_EQ(bench.gw.openConnections(), 1u);

    // The backend revokes the tester's certificate and distributes a new CRL.
    makeCrl("crl_update", pki.ca, {3});
    CHECK(bench.server.reloadCrl(bench.gw, diag::Clock::now()));
    CHECK_EQ(bench.server.revocation().sessionsClosed, 1u);
    CHECK_EQ(bench.server.connections(), 0u);
    CHECK_EQ(bench.gw.openConnections(), 0u);
    bool open = true;
    for (int i = 0; i < 50 && open; ++i) {
        bench.step();
        open = client.poll();
    }
    CHECK(!open);  // the tester sees its connection end
    CHECK(!testerGetsIn(bench, 31526, pki, pki.tester));  // and cannot come back

    // A broken CRL file is not taken; the previous CRLs stay in force.
    {
        FILE* f = std::fopen(crl.c_str(), "w");
        std::fputs("-----BEGIN X509 CRL-----\nnot a crl\n-----END X509 CRL-----\n", f);
        std::fclose(f);
    }
    CHECK(!bench.server.reloadCrl(bench.gw, diag::Clock::now()));
    CHECK(!testerGetsIn(bench, 31526, pki, pki.tester));
    CHECK(testerGetsIn(bench, 31526, pki, pki.gateway));
}

TEST_CASE("doip tls linux: a revoked ADAS certificate is refused; a CRL update ends the connection") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    {
        const auto crl = files.add(makeCrl("crl_vehicle_revoked", pki.ca, {6}));  // serial 6: adas-dc
        AdasOverTls v(31527, adasServer(pki.adas, pki));
        auto cfg = gatewayClient(pki);
        cfg.crl = platform::CrlPolicy{crl, true, true};
        v.connector.enableTls(cfg);
        const auto r = v.request({0x3E, 0x00});
        REQUIRE(r.has_value());
        CHECK(r->first == diag::ClientResult::TransportError);
        REQUIRE(v.connector.revocation() != nullptr);
        CHECK_EQ(v.connector.revocation()->revokedRejected, 1u);
        CHECK_EQ(v.adas.entity().statistics().tcpConnectionsAccepted, 0u);
    }
    {
        const auto crl = files.add(makeCrl("crl_vehicle", pki.ca, {}));
        AdasOverTls v(31528, adasServer(pki.adas, pki));
        auto cfg = gatewayClient(pki);
        cfg.crl = platform::CrlPolicy{crl, true, true};
        v.connector.enableTls(cfg);
        CHECK(v.request({0x3E, 0x00})->first == diag::ClientResult::Ok);
        CHECK(v.client.routingActive(dg::kAdas));

        makeCrl("crl_vehicle", pki.ca, {6});  // ADAS certificate revoked
        CHECK(v.connector.reloadCrl(diag::Clock::now()));
        CHECK_EQ(v.connector.revocation()->sessionsClosed, 1u);
        CHECK(!v.client.routingActive(dg::kAdas));
        CHECK(v.request({0x3E, 0x00})->first == diag::ClientResult::TransportError);  // no reconnect possible
    }
}
