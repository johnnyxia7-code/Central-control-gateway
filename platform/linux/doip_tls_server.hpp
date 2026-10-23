#pragma once

#include <poll.h>

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

// DoIP over TLS (ISO 13400-2:2019, TCP port 3496) for testers, with OpenSSL.
//
//  - TLS 1.2 (ECDHE with AES-GCM) or TLS 1.3, server certificate + key (PEM)
//  - optional mutual TLS: client certificates verified against the tester CA;
//    a verified certificate makes the connection "authenticated" for the
//    gateway (central security activation, key management routines)
//  - non-blocking handshakes and I/O for the process's poll() loop; the
//    gateway sees a connection only once its handshake has completed
//
// Connection IDs start at `firstId` so they never collide with the plain
// TCP server's IDs.
namespace ccg::platform {

struct TlsServerConfig {
    std::string certificateFile;  // server certificate chain (PEM)
    std::string privateKeyFile;   // its private key (PEM)
    std::string caFile;           // tester CA (PEM); empty = no client certificates
    bool requireClientCertificate = false;  // handshake fails without a valid client certificate
    std::chrono::milliseconds handshakeTimeout{2000};
};

class DoipTlsServer {
public:
    // Throws std::runtime_error (bad certificate/key, port in use, ...).
    DoipTlsServer(std::uint16_t port, std::size_t maxConnections, const TlsServerConfig& config,
                  diag::ConnectionId firstId = 0x10000);
    ~DoipTlsServer();
    DoipTlsServer(const DoipTlsServer&) = delete;
    DoipTlsServer& operator=(const DoipTlsServer&) = delete;

    bool owns(diag::ConnectionId id) const { return id >= firstId_; }

    // poll() set: the listening socket plus every TLS socket.
    std::vector<pollfd> pollFds() const;
    // Accepts, drives handshakes and reads; reports to the gateway
    // (onTcpConnected with the connection security, onTcpData, onTcpClosed).
    void process(const std::vector<pollfd>& fds, diag::DiagGateway& gateway, diag::TimePoint now);

    // For the gateway's transport.
    bool send(diag::ConnectionId id, const std::vector<std::uint8_t>& data);
    void close(diag::ConnectionId id);

    std::size_t connections() const { return sockets_.size(); }
    std::uint64_t handshakeFailures() const { return handshakeFailures_; }

private:
    struct Socket {
        int fd = -1;
        SSL* ssl = nullptr;
        bool established = false;
        bool wantWrite = false;  // handshake waits for POLLOUT
        diag::TimePoint deadline{};
    };

    void accept(diag::TimePoint now);
    void handshake(diag::ConnectionId id, Socket& s, diag::DiagGateway& gateway, diag::TimePoint now);
    void read(diag::ConnectionId id, Socket& s, diag::DiagGateway& gateway, diag::TimePoint now);
    void destroy(diag::ConnectionId id);

    SSL_CTX* ctx_ = nullptr;
    int listenFd_ = -1;
    std::size_t maxConnections_;
    diag::ConnectionId firstId_;
    diag::ConnectionId nextId_;
    std::chrono::milliseconds handshakeTimeout_;
    std::map<diag::ConnectionId, Socket> sockets_;
    std::uint64_t handshakeFailures_ = 0;
};

}  // namespace ccg::platform
