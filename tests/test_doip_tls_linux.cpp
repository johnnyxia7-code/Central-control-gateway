// DoIP over TLS on real sockets: platform::DoipTlsServer + DiagGateway against
// an OpenSSL client on loopback. Certificates are generated per test run.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
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
Credential makeCredential(const std::string& name, const char* cn, const Credential* issuer, bool ca, long serial,
                          bool mustStaple = false) {
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
    if (mustStaple) addExtension(c.cert, signer, NID_tlsfeature, "status_request");  // RFC 7633
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

// CRL entry: serial number and CRLReason (-1: none).
struct CrlEntry {
    long serial = 0;
    int reason = -1;
};

struct CrlSpec {
    std::vector<CrlEntry> entries;
    bool expired = false;                 // nextUpdate in the past
    long number = -1;                     // CRL number; -1: none
    long deltaBase = -1;                  // delta CRL: BaseCRLNumber (critical Delta CRL Indicator)
    const Credential* signer = nullptr;   // another key than the issuer's: forged CRL
};

// CRL issued in the name of `ca` (complete or delta).
std::string writeCrl(const std::string& name, const Credential& ca, const CrlSpec& spec) {
    X509_CRL* crl = X509_CRL_new();
    X509_CRL_set_version(crl, 1);  // v2
    X509_CRL_set_issuer_name(crl, X509_get_subject_name(ca.cert));
    ASN1_TIME* last = X509_gmtime_adj(nullptr, spec.expired ? -2 * 86400 : -3600);
    ASN1_TIME* next = X509_gmtime_adj(nullptr, spec.expired ? -86400 : 7 * 86400);
    X509_CRL_set1_lastUpdate(crl, last);
    X509_CRL_set1_nextUpdate(crl, next);
    for (const auto& entry : spec.entries) {
        X509_REVOKED* r = X509_REVOKED_new();
        ASN1_INTEGER* sn = ASN1_INTEGER_new();
        ASN1_INTEGER_set(sn, entry.serial);
        X509_REVOKED_set_serialNumber(r, sn);
        X509_REVOKED_set_revocationDate(r, last);
        if (entry.reason >= 0) {
            ASN1_ENUMERATED* reason = ASN1_ENUMERATED_new();
            ASN1_ENUMERATED_set(reason, entry.reason);
            X509_REVOKED_add1_ext_i2d(r, NID_crl_reason, reason, 0, 0);
            ASN1_ENUMERATED_free(reason);
        }
        X509_CRL_add0_revoked(crl, r);
        ASN1_INTEGER_free(sn);
    }
    auto addNumber = [&](int nid, long value, int critical) {
        ASN1_INTEGER* n = ASN1_INTEGER_new();
        ASN1_INTEGER_set(n, value);
        X509_CRL_add1_ext_i2d(crl, nid, n, critical, 0);
        ASN1_INTEGER_free(n);
    };
    if (spec.number >= 0) addNumber(NID_crl_number, spec.number, 0);
    if (spec.deltaBase >= 0) addNumber(NID_delta_crl, spec.deltaBase, 1);
    X509_CRL_sort(crl);
    X509_CRL_sign(crl, (spec.signer ? spec.signer : &ca)->key, EVP_sha256());
    const std::string path = tempFile(name);
    FILE* f = std::fopen(path.c_str(), "w");
    PEM_write_X509_CRL(f, crl);
    std::fclose(f);
    ASN1_TIME_free(last);
    ASN1_TIME_free(next);
    X509_CRL_free(crl);
    return path;
}

// CRL of `ca` revoking the given serial numbers; `expired`: nextUpdate in the past.
std::string makeCrl(const std::string& name, const Credential& ca, const std::vector<long>& revoked,
                    bool expired = false) {
    CrlSpec spec;
    for (const long serial : revoked) spec.entries.push_back({serial, -1});
    spec.expired = expired;
    return writeCrl(name, ca, spec);
}

// OCSP response signed by `signer` about `cert` (issued by `issuer`).
enum class OcspTime { Current, Expired, NotYetValid };
std::string makeOcsp(const std::string& name, const Credential& cert, const Credential& issuer,
                     const Credential& signer, int status, OcspTime time = OcspTime::Current) {
    OCSP_CERTID* id = OCSP_cert_to_id(nullptr, cert.cert, issuer.cert);
    OCSP_BASICRESP* basic = OCSP_BASICRESP_new();
    const long from = time == OcspTime::Expired ? -2 * 86400 : time == OcspTime::NotYetValid ? 86400 : -60;
    const long to = time == OcspTime::Expired ? -86400 : 7 * 86400;
    ASN1_TIME* thisUpdate = X509_gmtime_adj(nullptr, from);
    ASN1_TIME* nextUpdate = X509_gmtime_adj(nullptr, to);
    ASN1_TIME* revokedAt = X509_gmtime_adj(nullptr, -3600);
    OCSP_basic_add1_status(basic, id, status, OCSP_REVOKED_STATUS_KEYCOMPROMISE,
                           status == V_OCSP_CERTSTATUS_REVOKED ? revokedAt : nullptr, thisUpdate, nextUpdate);
    OCSP_basic_sign(basic, signer.cert, signer.key, EVP_sha256(), nullptr, 0);
    OCSP_RESPONSE* resp = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
    unsigned char* der = nullptr;
    const int len = i2d_OCSP_RESPONSE(resp, &der);
    const std::string path = tempFile(name);
    FILE* f = std::fopen(path.c_str(), "wb");
    std::fwrite(der, 1, static_cast<std::size_t>(len), f);
    std::fclose(f);
    OPENSSL_free(der);
    OCSP_RESPONSE_free(resp);
    OCSP_BASICRESP_free(basic);
    OCSP_CERTID_free(id);
    ASN1_TIME_free(thisUpdate);
    ASN1_TIME_free(nextUpdate);
    ASN1_TIME_free(revokedAt);
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
    Credential adasMustStaple = makeCredential("adas_ms", "adas-dc", &ca, false, 8, true);
    Credential gatewayMustStaple = makeCredential("gw_ms", "ccg-gateway", &ca, false, 9, true);

    ~Pki() {
        for (auto* c : {&ca, &gateway, &tester, &rogueCa, &rogue, &adas, &rogueAdas, &adasMustStaple, &gatewayMustStaple}) {
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
    c.crl = platform::CrlPolicy{crl, require, acceptExpired, ""};
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
        cfg.crl = platform::CrlPolicy{crl, true, true, ""};
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
        cfg.crl = platform::CrlPolicy{crl, true, true, ""};
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

// --------------------------------------------------------------- delta CRLs

namespace {

constexpr int kKeyCompromise = 1;
constexpr int kCertificateHold = 6;
constexpr int kRemoveFromCrl = 8;

platform::TlsServerConfig withDelta(platform::TlsServerConfig c, const std::string& crl, const std::string& delta,
                                    bool acceptExpired = true) {
    c.crl = platform::CrlPolicy{crl, true, acceptExpired, delta};
    return c;
}

CrlSpec delta(long number, long base, std::vector<CrlEntry> entries = {}) {
    CrlSpec spec;
    spec.number = number;
    spec.deltaBase = base;
    spec.entries = std::move(entries);
    return spec;
}

CrlSpec complete(long number, std::vector<CrlEntry> entries = {}) {
    CrlSpec spec;
    spec.number = number;
    spec.entries = std::move(entries);
    return spec;
}

bool serverStarts(std::uint16_t port, const platform::TlsServerConfig& cfg) {
    try {
        Bench bench(port, cfg);
    } catch (const std::runtime_error&) {
        return false;
    }
    return true;
}

}  // namespace

TEST_CASE("doip tls linux: a delta CRL revokes a tester on top of its base CRL") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    const auto base = files.add(writeCrl("dcrl_base", pki.ca, complete(10)));
    const auto d = files.add(writeCrl("dcrl_delta", pki.ca, delta(11, 10, {{3, kKeyCompromise}})));
    Bench bench(31540, withDelta(serverConfig(pki, false), base, d));
    CHECK_EQ(bench.server.revocation().deltaCrls, 1u);
    CHECK(!testerGetsIn(bench, 31540, pki, pki.tester));  // revoked by the delta only
    CHECK_EQ(bench.server.revocation().revokedByDelta, 1u);
    CHECK_EQ(bench.server.revocation().revokedRejected, 1u);
    CHECK(testerGetsIn(bench, 31540, pki, pki.gateway));  // not in the delta
    CHECK_EQ(bench.gw.statistics().tcpConnectionsAccepted, 1u);
}

TEST_CASE("doip tls linux: delta CRL updates lift a hold and end a revoked session") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    // The base CRL puts the tester on hold (certificateHold).
    const auto base = files.add(writeCrl("dcrl_hold_base", pki.ca, complete(10, {{3, kCertificateHold}})));
    const auto d = files.add(writeCrl("dcrl_hold_delta", pki.ca, delta(11, 10)));
    Bench bench(31541, withDelta(serverConfig(pki, false), base, d));
    CHECK(!testerGetsIn(bench, 31541, pki, pki.tester));

    // Delta 12: hold lifted (removeFromCRL).
    writeCrl("dcrl_hold_delta", pki.ca, delta(12, 10, {{3, kRemoveFromCrl}}));
    CHECK(bench.server.reloadCrl(bench.gw, diag::Clock::now()));
    CHECK(testerGetsIn(bench, 31541, pki, pki.tester));
    CHECK(bench.server.revocation().unrevokedByDelta >= 1u);

    Client client(31541, pki, &pki.tester);
    REQUIRE(handshake(bench, client) == std::optional<bool>(true));
    const auto ra = exchange(bench, client, pt::kRoutingActivationRequest, kCentralSecurity,
                             pt::kRoutingActivationResponse);
    REQUIRE(ra.has_value());
    REQUIRE(ra->at(4) == 0x10);

    // Delta 13: the key was compromised after all - the running session ends.
    writeCrl("dcrl_hold_delta", pki.ca, delta(13, 10, {{3, kKeyCompromise}}));
    CHECK(bench.server.reloadCrl(bench.gw, diag::Clock::now()));
    CHECK_EQ(bench.server.revocation().sessionsClosed, 1u);
    CHECK_EQ(bench.gw.openConnections(), 0u);
    bool open = true;
    for (int i = 0; i < 50 && open; ++i) {
        bench.step();
        open = client.poll();
    }
    CHECK(!open);
    CHECK(!testerGetsIn(bench, 31541, pki, pki.tester));
    CHECK(testerGetsIn(bench, 31541, pki, pki.gateway));
}

TEST_CASE("doip tls linux: obsolete, mismatched, forged and misplaced delta CRLs") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    // The complete CRL 12 already contains delta 11: the delta is ignored.
    {
        const auto base = files.add(writeCrl("dcrl_new_base", pki.ca, complete(12)));
        const auto d = files.add(writeCrl("dcrl_old_delta", pki.ca, delta(11, 10, {{3, kKeyCompromise}})));
        Bench bench(31542, withDelta(serverConfig(pki, false), base, d));
        CHECK_EQ(bench.server.revocation().deltasObsolete, 1u);
        CHECK_EQ(bench.server.revocation().deltaCrls, 0u);
        CHECK(testerGetsIn(bench, 31542, pki, pki.tester));
    }
    const auto base10 = files.add(writeCrl("dcrl_base10", pki.ca, complete(10)));
    // Delta for a complete CRL the gateway does not have yet: its changes could not be applied.
    const auto ahead = files.add(writeCrl("dcrl_ahead", pki.ca, delta(14, 13)));
    CHECK(!serverStarts(31543, withDelta(serverConfig(pki, false), base10, ahead)));
    // Delta in the CA's name, signed by another key.
    auto forgedSpec = delta(11, 10, {{2, kKeyCompromise}});
    forgedSpec.signer = &pki.rogueCa;
    const auto forged = files.add(writeCrl("dcrl_forged", pki.ca, forgedSpec));
    CHECK(!serverStarts(31543, withDelta(serverConfig(pki, false), base10, forged)));
    // A complete CRL in the delta file, a delta in the complete CRL file.
    CHECK(!serverStarts(31543, withDelta(serverConfig(pki, false), base10, base10)));
    const auto good = files.add(writeCrl("dcrl_good", pki.ca, delta(11, 10, {{3, kKeyCompromise}})));
    CHECK(!serverStarts(31543, withDelta(serverConfig(pki, false), good, good)));
    // A delta without a numbered complete CRL, or without any complete CRL.
    const auto unnumbered = files.add(makeCrl("dcrl_unnumbered", pki.ca, {}));
    const auto fromZero = files.add(writeCrl("dcrl_from_zero", pki.ca, delta(1, 0, {{3, kKeyCompromise}})));
    CHECK(!serverStarts(31543, withDelta(serverConfig(pki, false), unnumbered, good)));
    CHECK(!serverStarts(31543, withDelta(serverConfig(pki, false), unnumbered, fromZero)));
    CHECK(!serverStarts(31543, withDelta(serverConfig(pki, false), "", good)));

    // At run time an inapplicable delta is refused and the deltas in force stay.
    Bench bench(31544, withDelta(serverConfig(pki, false), base10, good));
    CHECK(!testerGetsIn(bench, 31544, pki, pki.tester));
    writeCrl("dcrl_good", pki.ca, delta(12, 11));  // needs complete CRL 11
    CHECK(!bench.server.reloadCrl(bench.gw, diag::Clock::now()));
    CHECK_EQ(bench.server.revocation().deltaCrls, 1u);
    CHECK(!testerGetsIn(bench, 31544, pki, pki.tester));
    // The backend installs complete CRL 11 (with the tester) next to it.
    writeCrl("dcrl_base10", pki.ca, complete(11, {{3, kKeyCompromise}}));
    CHECK(bench.server.reloadCrl(bench.gw, diag::Clock::now()));
    CHECK(!testerGetsIn(bench, 31544, pki, pki.tester));
    CHECK(testerGetsIn(bench, 31544, pki, pki.gateway));
}

TEST_CASE("doip tls linux: an outdated delta CRL follows the expired-CRL policy") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    const auto base = files.add(writeCrl("dcrl_exp_base", pki.ca, complete(10)));
    auto spec = delta(11, 10, {{3, kKeyCompromise}});
    spec.expired = true;
    const auto d = files.add(writeCrl("dcrl_exp_delta", pki.ca, spec));
    {
        Bench bench(31545, withDelta(serverConfig(pki, false), base, d));  // offline vehicle
        CHECK(!testerGetsIn(bench, 31545, pki, pki.tester));  // its revocations stay in force
        CHECK(testerGetsIn(bench, 31545, pki, pki.gateway));
        CHECK(bench.server.revocation().expiredCrlAccepted >= 1u);
    }
    {
        Bench bench(31546, withDelta(serverConfig(pki, false), base, d, false));  // --crl-reject-expired
        CHECK(!testerGetsIn(bench, 31546, pki, pki.gateway));
        CHECK(bench.server.revocation().expiredCrlRejected >= 1u);
    }
}

TEST_CASE("doip tls linux: a delta CRL ends the connection to a revoked ADAS") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    const auto base = files.add(writeCrl("dcrl_vehicle_base", pki.ca, complete(20)));
    const auto d = files.add(writeCrl("dcrl_vehicle_delta", pki.ca, delta(21, 20)));
    AdasOverTls v(31547, adasServer(pki.adas, pki));
    auto cfg = gatewayClient(pki);
    cfg.crl = platform::CrlPolicy{base, true, true, d};
    v.connector.enableTls(cfg);
    CHECK(v.request({0x3E, 0x00})->first == diag::ClientResult::Ok);

    writeCrl("dcrl_vehicle_delta", pki.ca, delta(22, 20, {{6, kKeyCompromise}}));  // ADAS revoked
    CHECK(v.connector.reloadCrl(diag::Clock::now()));
    REQUIRE(v.connector.revocation() != nullptr);
    CHECK_EQ(v.connector.revocation()->sessionsClosed, 1u);
    CHECK(v.connector.revocation()->revokedByDelta >= 1u);
    CHECK(!v.client.routingActive(dg::kAdas));
    CHECK(v.request({0x3E, 0x00})->first == diag::ClientResult::TransportError);

    // A forged delta "un-revoking" ADAS is refused.
    auto forged = delta(23, 20, {{6, kRemoveFromCrl}});
    forged.signer = &pki.rogueCa;
    writeCrl("dcrl_vehicle_delta", pki.ca, forged);
    CHECK(!v.connector.reloadCrl(diag::Clock::now()));
    CHECK(v.request({0x3E, 0x00})->first == diag::ClientResult::TransportError);
}

// --------------------------------------------------------------- OCSP stapling

namespace {

// Tester that asks for the staple; returns the OCSP status of the gateway's
// certificate it received (nullopt: no staple).
std::optional<int> testerSeesStaple(Bench& bench, std::uint16_t port, const Pki& pki, bool ask = true,
                                    const Credential* about = nullptr) {
    Client client(port, pki, &pki.tester);
    if (ask) SSL_set_tlsext_status_type(client.ssl, TLSEXT_STATUSTYPE_ocsp);
    if (handshake(bench, client) != std::optional<bool>(true)) return std::nullopt;
    const unsigned char* p = nullptr;
    const long len = SSL_get_tlsext_status_ocsp_resp(client.ssl, &p);
    if (!p || len <= 0) return std::nullopt;
    OCSP_RESPONSE* resp = d2i_OCSP_RESPONSE(nullptr, &p, len);
    OCSP_BASICRESP* basic = resp ? OCSP_response_get1_basic(resp) : nullptr;
    OCSP_CERTID* id = OCSP_cert_to_id(nullptr, (about ? *about : pki.gateway).cert, pki.ca.cert);
    int status = -1;
    int reason = 0;
    ASN1_GENERALIZEDTIME *rev = nullptr, *thisUpd = nullptr, *nextUpd = nullptr;
    if (basic) OCSP_resp_find_status(basic, id, &status, &reason, &rev, &thisUpd, &nextUpd);
    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(resp);
    return status;
}

platform::TlsServerConfig withOcsp(platform::TlsServerConfig c, const std::string& file) {
    c.ocspResponseFile = file;
    return c;
}

}  // namespace

TEST_CASE("doip tls linux: the gateway staples its OCSP response for testers") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    const auto good = files.add(makeOcsp("ocsp_gw_good", pki.gateway, pki.ca, pki.ca, V_OCSP_CERTSTATUS_GOOD));
    Bench bench(31530, withOcsp(serverConfig(pki, false), good));
    CHECK(testerSeesStaple(bench, 31530, pki) == std::optional<int>(V_OCSP_CERTSTATUS_GOOD));
    CHECK_EQ(bench.server.ocsp().stapled, 1u);
    CHECK(!testerSeesStaple(bench, 31530, pki, false).has_value());  // not asked, not sent
    CHECK_EQ(bench.server.ocsp().stapled, 1u);

    auto tls12 = withOcsp(serverConfig(pki, false), good);  // CertificateStatus message instead of extension
    tls12.maxProtocolVersion = TLS1_2_VERSION;
    Bench bench12(31529, tls12);
    CHECK(testerSeesStaple(bench12, 31529, pki) == std::optional<int>(V_OCSP_CERTSTATUS_GOOD));
}

TEST_CASE("doip tls linux: an outdated OCSP response is withheld; a reload takes the new one") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    const auto file = files.add(
        makeOcsp("ocsp_gw", pki.gateway, pki.ca, pki.ca, V_OCSP_CERTSTATUS_GOOD, OcspTime::Expired));
    Bench bench(31531, withOcsp(serverConfig(pki, false), file));
    CHECK(!testerSeesStaple(bench, 31531, pki).has_value());
    CHECK_EQ(bench.server.ocsp().notStapledExpired, 1u);

    makeOcsp("ocsp_gw", pki.gateway, pki.ca, pki.ca, V_OCSP_CERTSTATUS_GOOD);  // backend fetched a fresh one
    CHECK(bench.server.reloadOcsp());
    CHECK(testerSeesStaple(bench, 31531, pki) == std::optional<int>(V_OCSP_CERTSTATUS_GOOD));

    {
        FILE* f = std::fopen(file.c_str(), "wb");
        std::fputs("garbage", f);
        std::fclose(f);
    }
    CHECK(!bench.server.reloadOcsp());  // the previous response stays
    CHECK(testerSeesStaple(bench, 31531, pki) == std::optional<int>(V_OCSP_CERTSTATUS_GOOD));

    bool threw = false;
    try {
        Bench broken(31532, withOcsp(serverConfig(pki, false), file));
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
}

TEST_CASE("doip tls linux: the gateway checks the ADAS OCSP staple") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    const auto good = files.add(makeOcsp("ocsp_adas_good", pki.adas, pki.ca, pki.ca, V_OCSP_CERTSTATUS_GOOD));
    const auto revoked = files.add(makeOcsp("ocsp_adas_revoked", pki.adas, pki.ca, pki.ca, V_OCSP_CERTSTATUS_REVOKED));
    const auto forged = files.add(makeOcsp("ocsp_adas_forged", pki.adas, pki.ca, pki.rogueCa, V_OCSP_CERTSTATUS_GOOD));
    const auto otherCert = files.add(makeOcsp("ocsp_other", pki.gateway, pki.ca, pki.ca, V_OCSP_CERTSTATUS_GOOD));
    const auto notYet = files.add(
        makeOcsp("ocsp_adas_future", pki.adas, pki.ca, pki.ca, V_OCSP_CERTSTATUS_GOOD, OcspTime::NotYetValid));

    struct Case {
        std::string staple;  // empty: ADAS staples nothing
        bool require;
        diag::ClientResult expected;
        std::uint64_t platform::OcspStatistics::*counter;
    };
    using S = platform::OcspStatistics;
    const std::vector<Case> cases = {
        {good, true, diag::ClientResult::Ok, &S::verified},
        {revoked, false, diag::ClientResult::TransportError, &S::revoked},  // revoked fails even if optional
        {"", true, diag::ClientResult::TransportError, &S::missing},
        {"", false, diag::ClientResult::Ok, &S::missing},                  // optional: CRLs remain the check
        {forged, true, diag::ClientResult::TransportError, &S::invalid},   // not signed by the vehicle CA
        {forged, false, diag::ClientResult::Ok, &S::invalid},
        {otherCert, true, diag::ClientResult::TransportError, &S::invalid},// about another certificate
        {notYet, true, diag::ClientResult::TransportError, &S::invalid},   // outside its validity
    };
    std::uint16_t port = 31533;
    for (const int version : {0, TLS1_2_VERSION}) {  // TLS 1.3 (extension) and TLS 1.2 (CertificateStatus)
      for (const auto& c : cases) {
        auto server = adasServer(pki.adas, pki);
        server.ocspResponseFile = c.staple;
        server.maxProtocolVersion = version;
        server.ocspCheckResponse = c.staple != otherCert;  // emulate an ECU stapling a wrong response
        AdasOverTls v(port++, server);
        auto cfg = gatewayClient(pki);
        cfg.ocsp = platform::OcspPolicy{true, c.require};
        v.connector.enableTls(cfg);
        const auto r = v.request({0x3E, 0x00});
        REQUIRE(r.has_value());
        CHECK(r->first == c.expected);
        REQUIRE(v.connector.ocsp() != nullptr);
        CHECK_EQ((*v.connector.ocsp()).*(c.counter), 1u);
        CHECK_EQ(v.adas.entity().statistics().tcpConnectionsAccepted, c.expected == diag::ClientResult::Ok ? 1u : 0u);
        if (c.expected == diag::ClientResult::Ok) {
            CHECK(v.server.protocol(0x10000) == (version == TLS1_2_VERSION ? "TLSv1.2" : "TLSv1.3"));
        }
      }
    }
}

// --------------------------------------------------------------- must-staple (RFC 7633)

TEST_CASE("doip tls linux: must-staple ADAS certificate needs a good staple whatever the policy") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    CHECK(platform::hasMustStaple(pki.adasMustStaple.cert));
    CHECK(!platform::hasMustStaple(pki.adas.cert));
    const auto good = files.add(makeOcsp("ocsp_ms_good", pki.adasMustStaple, pki.ca, pki.ca, V_OCSP_CERTSTATUS_GOOD));
    const auto forged =
        files.add(makeOcsp("ocsp_ms_forged", pki.adasMustStaple, pki.ca, pki.rogueCa, V_OCSP_CERTSTATUS_GOOD));
    struct Case {
        std::string staple;
        diag::ClientResult expected;
    };
    const std::vector<Case> cases = {
        {"", diag::ClientResult::TransportError},      // no staple although the certificate demands one
        {forged, diag::ClientResult::TransportError},  // unverifiable staple
        {good, diag::ClientResult::Ok},
    };
    std::uint16_t port = 31560;
    for (const int version : {0, TLS1_2_VERSION}) {
        for (const auto& c : cases) {
            auto server = adasServer(pki.adasMustStaple, pki);
            server.ocspResponseFile = c.staple;
            server.maxProtocolVersion = version;
            server.ocspCheckResponse = !c.staple.empty();  // emulate an ECU that ignores its must-staple
            AdasOverTls v(port++, server);
            auto cfg = gatewayClient(pki);
            cfg.ocsp = platform::OcspPolicy{true, false};  // optional by policy ...
            v.connector.enableTls(cfg);
            const auto r = v.request({0x3E, 0x00});
            REQUIRE(r.has_value());
            CHECK(r->first == c.expected);  // ... but required by the certificate
            CHECK_EQ(v.connector.ocsp()->mustStapleEnforced, 1u);
        }
    }
}

TEST_CASE("doip tls linux: a must-staple gateway certificate needs its OCSP response") {
    std::signal(SIGPIPE, SIG_IGN);
    Pki pki;
    TempFiles files;
    auto config = [&](const std::string& ocsp) {
        platform::TlsServerConfig c;
        c.certificateFile = pki.gatewayMustStaple.certFile;
        c.privateKeyFile = pki.gatewayMustStaple.keyFile;
        c.caFile = pki.ca.certFile;
        c.ocspResponseFile = ocsp;
        return c;
    };
    auto starts = [&](std::uint16_t port, const std::string& ocsp) {
        try {
            Bench bench(port, config(ocsp));
            return true;
        } catch (const std::runtime_error&) {
            return false;
        }
    };
    const auto other = files.add(makeOcsp("ocsp_gw_other", pki.gateway, pki.ca, pki.ca, V_OCSP_CERTSTATUS_GOOD));
    CHECK(!starts(31570, ""));     // must-staple without a response to staple
    CHECK(!starts(31571, other));  // response about another certificate

    const auto file = files.add(makeOcsp("ocsp_gw_ms", pki.gatewayMustStaple, pki.ca, pki.ca,
                                         V_OCSP_CERTSTATUS_GOOD, OcspTime::Expired));
    Bench bench(31572, config(file));
    CHECK(!testerSeesStaple(bench, 31572, pki, true, &pki.gatewayMustStaple).has_value());
    CHECK_EQ(bench.server.ocsp().mustStapleUnserved, 1u);  // the tester will refuse such a gateway

    makeOcsp("ocsp_gw_ms", pki.gatewayMustStaple, pki.ca, pki.ca, V_OCSP_CERTSTATUS_GOOD);
    CHECK(bench.server.reloadOcsp());
    CHECK(testerSeesStaple(bench, 31572, pki, true, &pki.gatewayMustStaple) ==
          std::optional<int>(V_OCSP_CERTSTATUS_GOOD));

    // A reload with a response about another certificate is not taken.
    makeOcsp("ocsp_gw_ms", pki.gateway, pki.ca, pki.ca, V_OCSP_CERTSTATUS_GOOD);
    CHECK(!bench.server.reloadOcsp());
    CHECK(testerSeesStaple(bench, 31572, pki, true, &pki.gatewayMustStaple) ==
          std::optional<int>(V_OCSP_CERTSTATUS_GOOD));
}
