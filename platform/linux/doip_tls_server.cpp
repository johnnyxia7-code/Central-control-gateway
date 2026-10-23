#include "doip_tls_server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace ccg::platform {

namespace {

// TLS 1.2: forward secrecy and AEAD only. TLS 1.3 suites are the OpenSSL defaults.
constexpr const char* kTls12Ciphers =
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384";

std::string sslError(const std::string& what) {
    char buf[256];
    const unsigned long e = ERR_get_error();
    ERR_error_string_n(e, buf, sizeof buf);
    ERR_clear_error();
    return what + ": " + (e ? buf : "unknown error");
}

std::string commonName(X509* cert) {
    char cn[256] = {};
    if (X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, sizeof cn) < 0) return {};
    return cn;
}

}  // namespace

DoipTlsServer::DoipTlsServer(std::uint16_t port, std::size_t maxConnections, const TlsServerConfig& config,
                             diag::ConnectionId firstId)
    : maxConnections_(maxConnections), firstId_(firstId), nextId_(firstId), handshakeTimeout_(config.handshakeTimeout) {
    ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ctx_) throw std::runtime_error(sslError("TLS context"));
    try {
        SSL_CTX_set_min_proto_version(ctx_, TLS1_2_VERSION);
        if (SSL_CTX_set_cipher_list(ctx_, kTls12Ciphers) != 1) throw std::runtime_error(sslError("TLS ciphers"));
        SSL_CTX_set_options(ctx_, SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);
        SSL_CTX_set_mode(ctx_, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        if (SSL_CTX_use_certificate_chain_file(ctx_, config.certificateFile.c_str()) != 1) {
            throw std::runtime_error(sslError("TLS certificate " + config.certificateFile));
        }
        if (SSL_CTX_use_PrivateKey_file(ctx_, config.privateKeyFile.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx_) != 1) {
            throw std::runtime_error(sslError("TLS private key " + config.privateKeyFile));
        }
        if (!config.caFile.empty()) {
            if (SSL_CTX_load_verify_locations(ctx_, config.caFile.c_str(), nullptr) != 1) {
                throw std::runtime_error(sslError("TLS tester CA " + config.caFile));
            }
            SSL_CTX_set_client_CA_list(ctx_, SSL_load_client_CA_file(config.caFile.c_str()));
            // A presented certificate must verify; without one the tester is
            // only unauthenticated (unless certificates are required).
            SSL_CTX_set_verify(ctx_,
                               SSL_VERIFY_PEER | (config.requireClientCertificate ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0),
                               nullptr);
        } else if (config.requireClientCertificate) {
            throw std::runtime_error("TLS: client certificates required but no tester CA given");
        }

        listenFd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (listenFd_ < 0) throw std::runtime_error("TLS socket: " + std::string(strerror(errno)));
        const int one = 1;
        ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0 || ::listen(listenFd_, 8) != 0) {
            throw std::runtime_error("TLS listen on port " + std::to_string(port) + ": " + strerror(errno));
        }
    } catch (...) {
        if (listenFd_ >= 0) ::close(listenFd_);
        SSL_CTX_free(ctx_);
        throw;
    }
}

DoipTlsServer::~DoipTlsServer() {
    while (!sockets_.empty()) destroy(sockets_.begin()->first);
    if (listenFd_ >= 0) ::close(listenFd_);
    SSL_CTX_free(ctx_);
}

std::vector<pollfd> DoipTlsServer::pollFds() const {
    std::vector<pollfd> fds = {{listenFd_, POLLIN, 0}};
    for (const auto& [id, s] : sockets_) {
        fds.push_back({s.fd, static_cast<short>(s.wantWrite ? POLLOUT : POLLIN), 0});
    }
    return fds;
}

void DoipTlsServer::process(const std::vector<pollfd>& fds, diag::DiagGateway& gateway, diag::TimePoint now) {
    for (const auto& p : fds) {
        if (p.fd == listenFd_) {
            if (p.revents & POLLIN) accept(now);
            continue;
        }
        if (!p.revents) continue;
        for (auto& [id, s] : sockets_) {
            if (s.fd != p.fd) continue;
            const auto cid = id;
            if (s.established) {
                read(cid, s, gateway, now);
            } else {
                handshake(cid, s, gateway, now);
            }
            break;
        }
    }
    // Handshakes that do not finish in time (also: a plain DoIP client on the TLS port).
    std::vector<diag::ConnectionId> late;
    for (const auto& [id, s] : sockets_) {
        if (!s.established && now >= s.deadline) late.push_back(id);
    }
    for (const auto id : late) {
        ++handshakeFailures_;
        destroy(id);
    }
}

void DoipTlsServer::accept(diag::TimePoint now) {
    for (;;) {
        const int fd = ::accept4(listenFd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) return;
        if (sockets_.size() >= maxConnections_ + 1) {  // like the plain server: max + 1 for the 0x01 answer
            ::close(fd);
            continue;
        }
        const int one = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        SSL* ssl = SSL_new(ctx_);
        if (!ssl || SSL_set_fd(ssl, fd) != 1) {
            if (ssl) SSL_free(ssl);
            ::close(fd);
            continue;
        }
        SSL_set_accept_state(ssl);
        sockets_[nextId_++] = Socket{fd, ssl, false, false, now + handshakeTimeout_};
    }
}

void DoipTlsServer::handshake(diag::ConnectionId id, Socket& s, diag::DiagGateway& gateway, diag::TimePoint now) {
    const int r = SSL_do_handshake(s.ssl);
    if (r != 1) {
        const int e = SSL_get_error(s.ssl, r);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            s.wantWrite = e == SSL_ERROR_WANT_WRITE;
            return;
        }
        ERR_clear_error();
        ++handshakeFailures_;
        destroy(id);  // bad or untrusted certificate, protocol error, plain TCP client ...
        return;
    }
    s.established = true;
    s.wantWrite = false;
    diag::ConnectionSecurity security;
    security.tls = true;
    if (X509* peer = SSL_get1_peer_certificate(s.ssl)) {
        security.clientAuthenticated = SSL_get_verify_result(s.ssl) == X509_V_OK;
        security.peer = commonName(peer);
        X509_free(peer);
    }
    gateway.onTcpConnected(id, now, security);
    read(id, s, gateway, now);  // data may have arrived with the last handshake flight
}

void DoipTlsServer::read(diag::ConnectionId id, Socket& s, diag::DiagGateway& gateway, diag::TimePoint now) {
    std::uint8_t buffer[4096];
    for (;;) {
        const int n = SSL_read(s.ssl, buffer, sizeof buffer);
        if (n > 0) {
            gateway.onTcpData(id, buffer, static_cast<std::size_t>(n), now);
            if (!sockets_.count(id)) return;  // closed by the gateway meanwhile
            continue;
        }
        const int e = SSL_get_error(s.ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return;
        ERR_clear_error();
        destroy(id);  // close_notify, reset or protocol error
        gateway.onTcpClosed(id, now);
        return;
    }
}

bool DoipTlsServer::send(diag::ConnectionId id, const std::vector<std::uint8_t>& data) {
    const auto it = sockets_.find(id);
    if (it == sockets_.end() || !it->second.established) return false;
    std::size_t done = 0;
    while (done < data.size()) {
        const int n = SSL_write(it->second.ssl, data.data() + done, static_cast<int>(data.size() - done));
        if (n > 0) {
            done += static_cast<std::size_t>(n);
            continue;
        }
        const int e = SSL_get_error(it->second.ssl, n);
        if (e != SSL_ERROR_WANT_WRITE && e != SSL_ERROR_WANT_READ) break;
        pollfd p{it->second.fd, static_cast<short>(e == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN), 0};
        if (::poll(&p, 1, 100) <= 0) break;  // DoIP messages are small; a stuck tester is dead
    }
    ERR_clear_error();
    return done == data.size();  // a failed send shows up as a closed socket on the next read
}

void DoipTlsServer::close(diag::ConnectionId id) { destroy(id); }

void DoipTlsServer::destroy(diag::ConnectionId id) {
    const auto it = sockets_.find(id);
    if (it == sockets_.end()) return;
    if (it->second.established) SSL_shutdown(it->second.ssl);  // best effort close_notify
    SSL_free(it->second.ssl);
    ::close(it->second.fd);
    sockets_.erase(it);
}

}  // namespace ccg::platform
