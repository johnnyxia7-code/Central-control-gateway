#include "doip_tcp_connector.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <stdexcept>

#ifdef CCG_HAVE_TLS
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

namespace ccg::platform {

namespace {

bool parseEndpoint(const std::string& endpoint, sockaddr_in& addr) {
    const auto colon = endpoint.rfind(':');
    if (colon == std::string::npos) return false;
    addr = sockaddr_in{};
    addr.sin_family = AF_INET;
    try {
        const unsigned long port = std::stoul(endpoint.substr(colon + 1));
        if (port == 0 || port > 0xFFFF) return false;
        addr.sin_port = htons(static_cast<std::uint16_t>(port));
    } catch (const std::exception&) {
        return false;
    }
    return ::inet_pton(AF_INET, endpoint.substr(0, colon).c_str(), &addr.sin_addr) == 1;
}

#ifdef CCG_HAVE_TLS
std::string sslError(const std::string& what) {
    char buf[256];
    const unsigned long e = ERR_get_error();
    ERR_error_string_n(e, buf, sizeof buf);
    ERR_clear_error();
    return what + ": " + (e ? buf : "unknown error");
}
#endif

}  // namespace

DoipTcpConnector::~DoipTcpConnector() {
    while (!sockets_.empty()) close(sockets_.begin()->first);
#ifdef CCG_HAVE_TLS
    SSL_CTX_free(ctx_);
#endif
}

void DoipTcpConnector::enableTls(const TlsClientConfig& config) {
#ifdef CCG_HAVE_TLS
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) throw std::runtime_error(sslError("TLS client context"));
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
                                 "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384");
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    // The ECU must prove its identity: certificate from the vehicle CA (not
    // revoked), name checked per route.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    auto checker = std::make_unique<RevocationChecker>(config.crl);
    auto ocsp = std::make_unique<OcspVerifier>(config.ocsp);
    ocsp->attach(ctx);
    try {
        SSL_CTX_set_cert_store(ctx, checker->build(config.caFile));
    } catch (...) {
        SSL_CTX_free(ctx);
        throw;
    }
    if (!config.certificateFile.empty()) {
        if (SSL_CTX_use_certificate_chain_file(ctx, config.certificateFile.c_str()) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, config.privateKeyFile.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1) {
            SSL_CTX_free(ctx);
            throw std::runtime_error(sslError("vehicle certificate " + config.certificateFile));
        }
    }
    SSL_CTX_free(ctx_);
    ctx_ = ctx;
    revocation_ = std::move(checker);
    ocsp_ = std::move(ocsp);
    caFile_ = config.caFile;
#else
    (void)config;
    throw std::runtime_error("built without OpenSSL: no DoIP over TLS");
#endif
}

void DoipTcpConnector::connect(diag::ConnectionId id, const diag::DoipTarget& target) {
    close(id);
    sockaddr_in addr{};
    if (!parseEndpoint(target.endpoint, addr) || (target.tls && !ctx_)) {
        failed_.push_back(id);  // also: TLS route without TLS credentials - never fall back to plain
        return;
    }
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        failed_.push_back(id);
        return;
    }
    const int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0 && errno != EINPROGRESS) {
        ::close(fd);
        failed_.push_back(id);
        return;
    }
    Socket s;
    s.fd = fd;
#ifdef CCG_HAVE_TLS
    if (target.tls) {
        s.ssl = SSL_new(ctx_);
        SSL_set_fd(s.ssl, fd);
        SSL_set_tlsext_host_name(s.ssl, target.serverName.c_str());  // SNI
        SSL_set_hostflags(s.ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        SSL_set1_host(s.ssl, target.serverName.c_str());              // certificate name check
        ocsp_->prepare(s.ssl);                                          // ask for the OCSP staple
        SSL_set_connect_state(s.ssl);
    }
#endif
    sockets_[id] = s;  // completion is seen as POLLOUT
}

void DoipTcpConnector::send(diag::ConnectionId id, const std::vector<std::uint8_t>& data) {
    const auto it = sockets_.find(id);
    if (it == sockets_.end() || !it->second.established) return;
    Socket& s = it->second;
    std::size_t done = 0;
    while (done < data.size()) {
        short waitFor = POLLOUT;
#ifdef CCG_HAVE_TLS
        if (s.ssl) {
            const int n = SSL_write(s.ssl, data.data() + done, static_cast<int>(data.size() - done));
            if (n > 0) {
                done += static_cast<std::size_t>(n);
                continue;
            }
            const int e = SSL_get_error(s.ssl, n);
            ERR_clear_error();
            if (e != SSL_ERROR_WANT_WRITE && e != SSL_ERROR_WANT_READ) break;
            waitFor = e == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
        } else
#endif
        {
            const ssize_t n = ::send(s.fd, data.data() + done, data.size() - done, MSG_NOSIGNAL);
            if (n > 0) {
                done += static_cast<std::size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) break;
        }
        pollfd p{s.fd, waitFor, 0};
        if (::poll(&p, 1, 100) <= 0) break;  // DoIP messages are small; a stuck socket is dead
    }
    if (done < data.size()) fail(id);
}

void DoipTcpConnector::close(diag::ConnectionId id) {
    const auto it = sockets_.find(id);
    if (it == sockets_.end()) return;
#ifdef CCG_HAVE_TLS
    if (it->second.ssl) {
        if (it->second.established) SSL_shutdown(it->second.ssl);  // best effort close_notify
        SSL_free(it->second.ssl);
        X509_free(it->second.peer);
    }
#endif
    ::close(it->second.fd);
    sockets_.erase(it);
}

bool DoipTcpConnector::reloadCrl(diag::TimePoint now) {
#ifdef CCG_HAVE_TLS
    if (!ctx_ || !revocation_ || !revocation_->enabled()) return false;
    X509_STORE* store = nullptr;
    try {
        store = revocation_->build(caFile_);
    } catch (const std::exception&) {
        return false;  // keep the CRLs in use
    }
    SSL_CTX_set_cert_store(ctx_, store);
    std::vector<diag::ConnectionId> revoked;
    for (const auto& [id, s] : sockets_) {
        if (s.established && s.ssl && s.peer && !revocation_->stillValid(store, s.ssl, s.peer, false)) {
            revoked.push_back(id);
        }
    }
    for (const auto id : revoked) {
        ++revocation_->statistics().sessionsClosed;
        close(id);
        if (client_) client_->onClosed(id, now);
    }
    return true;
#else
    (void)now;
    return false;
#endif
}

bool DoipTcpConnector::fetchCrls(diag::TimePoint now) {
#ifdef CCG_HAVE_TLS
    return revocation_ && revocation_->fetch(now) && reloadCrl(now);
#else
    (void)now;
    return false;
#endif
}

void DoipTcpConnector::fail(diag::ConnectionId id) {
    close(id);
    failed_.push_back(id);
}

std::vector<pollfd> DoipTcpConnector::pollFds() const {
    std::vector<pollfd> fds;
    for (const auto& [id, s] : sockets_) {
        const bool out = !s.tcpConnected || (!s.established && s.wantWrite);
        fds.push_back({s.fd, static_cast<short>(out ? POLLOUT : POLLIN), 0});
    }
    return fds;
}

void DoipTcpConnector::handshake(diag::ConnectionId id, Socket& s, diag::TimePoint now) {
#ifdef CCG_HAVE_TLS
    const int r = SSL_do_handshake(s.ssl);
    if (r != 1) {
        const int e = SSL_get_error(s.ssl, r);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            s.wantWrite = e == SSL_ERROR_WANT_WRITE;
            return;
        }
        ERR_clear_error();
        ++tlsFailures_;  // untrusted certificate, wrong name, our certificate refused ...
        fail(id);
        return;
    }
    s.established = true;
    s.wantWrite = false;
    s.peer = SSL_get1_peer_certificate(s.ssl);
    if (client_) client_->onConnected(id, now);
#else
    (void)s;
    (void)now;
    fail(id);
#endif
}

void DoipTcpConnector::read(diag::ConnectionId id, Socket& s, diag::TimePoint now) {
    std::uint8_t buffer[4096];
    (void)s;
    for (;;) {
        const auto it = sockets_.find(id);
        if (it == sockets_.end()) return;  // closed by the client while handling data
        ssize_t n;
        bool again = false;
#ifdef CCG_HAVE_TLS
        if (it->second.ssl) {
            const int r = SSL_read(it->second.ssl, buffer, sizeof buffer);
            n = r;
            if (r <= 0) {
                const int e = SSL_get_error(it->second.ssl, r);
                again = e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE;
                ERR_clear_error();
            }
        } else
#endif
        {
            n = ::recv(it->second.fd, buffer, sizeof buffer, 0);
            if (n < 0 && errno == EINTR) continue;
            again = n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
        }
        if (n > 0) {
            if (client_) client_->onData(id, buffer, static_cast<std::size_t>(n), now);
            continue;
        }
        if (!again) fail(id);  // closed by the entity, close_notify or error
        return;
    }
}

void DoipTcpConnector::process(const std::vector<pollfd>& fds, diag::TimePoint now) {
    for (const auto& p : fds) {
        if (p.revents == 0) continue;
        diag::ConnectionId id = 0;
        for (const auto& [i, s] : sockets_) {
            if (s.fd == p.fd) id = i;
        }
        if (id == 0) continue;  // closed meanwhile
        auto& s = sockets_[id];
        if (!s.tcpConnected) {
            int error = 0;
            socklen_t len = sizeof error;
            ::getsockopt(s.fd, SOL_SOCKET, SO_ERROR, &error, &len);
            if (error != 0) {
                fail(id);
                continue;
            }
            s.tcpConnected = true;
            if (s.ssl) {
                handshake(id, s, now);
            } else {
                s.established = true;
                if (client_) client_->onConnected(id, now);
            }
            continue;
        }
        if (!s.established) {
            handshake(id, s, now);
            continue;
        }
        read(id, s, now);
    }
    while (!failed_.empty()) {
        const auto id = failed_.front();
        failed_.pop_front();
        if (client_) client_->onClosed(id, now);
    }
}

}  // namespace ccg::platform
