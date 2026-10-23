#pragma once

#include <poll.h>

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "tls_ocsp.hpp"
#include "tls_revocation.hpp"

typedef struct ssl_ctx_st SSL_CTX;

// DoIP over TLS (ISO 13400-2:2019, TCP port 3496) for testers, with OpenSSL.
//
//  - TLS 1.2 (ECDHE with AES-GCM) or TLS 1.3, server certificate + key (PEM)
//  - optional mutual TLS: client certificates verified against the tester CA;
//    a verified certificate makes the connection "authenticated" for the
//    gateway (central security activation, key management routines)
//  - non-blocking handshakes and I/O for the process's poll() loop; the
//    gateway sees a connection only once its handshake has completed
//  - revocation: client certificates are checked against the tester CRLs
//    (CrlPolicy); reloadCrl() takes a new CRL file and closes sessions whose
//    certificate has been revoked meanwhile
//  - OCSP stapling: the server's own OCSP response (DER file from the
//    backend) is stapled when the client asks for it; reloadOcsp() takes a
//    new response
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
    CrlPolicy crl;  // revocation of client certificates (needs caFile)
    std::string ocspResponseFile;  // OCSP response for our certificate (DER); empty = no stapling
    int maxProtocolVersion = 0;    // e.g. TLS1_2_VERSION for interoperability tests; 0 = newest
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
    // Negotiated protocol of an established connection ("TLSv1.3", ...), empty if unknown.
    std::string protocol(diag::ConnectionId id) const;
    std::uint64_t handshakeFailures() const { return handshakeFailures_; }

    // Loads the CRL file again (e.g. after the backend replaced it) and closes
    // established sessions whose client certificate is now revoked (reported
    // with onTcpClosed). False: the file is unusable, the old CRLs stay.
    bool reloadCrl(diag::DiagGateway& gateway, diag::TimePoint now);
    const RevocationStatistics& revocation() const { return revocation_.statistics(); }

    // Loads a new OCSP response for stapling. False: unusable, the old one stays.
    bool reloadOcsp() { return stapler_.load(); }
    const OcspStatistics& ocsp() const { return stapler_.statistics(); }

private:
    struct Socket {
        int fd = -1;
        SSL* ssl = nullptr;
        X509* peer = nullptr;  // verified client certificate, for re-checks
        bool established = false;
        bool wantWrite = false;  // handshake waits for POLLOUT
        diag::TimePoint deadline{};
    };

    void accept(diag::TimePoint now);
    void handshake(diag::ConnectionId id, Socket& s, diag::DiagGateway& gateway, diag::TimePoint now);
    void read(diag::ConnectionId id, Socket& s, diag::DiagGateway& gateway, diag::TimePoint now);
    void destroy(diag::ConnectionId id);

    RevocationChecker revocation_;
    OcspStapler stapler_;
    std::string caFile_;
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
