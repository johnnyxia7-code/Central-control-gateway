#pragma once

#include <poll.h>

#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ccg/diag/doip_client.hpp"
#include "tls_ocsp.hpp"
#include "tls_revocation.hpp"

typedef struct ssl_ctx_st SSL_CTX;

// TCP connections of the gateway's DoIP client to DoIP entities on the
// vehicle Ethernet (non-blocking connect, for a poll() loop).
//
//   connector.attach(client);
//   loop: fds = connector.pollFds(); poll(...); connector.process(fds, now);
//
// TLS targets (DoIP over TLS, ISO 13400-2:2019) need enableTls(): the
// connector then runs the TLS handshake after the TCP connect, verifies the
// entity's certificate against the vehicle CA and its name against the
// route's server name, and presents the gateway's vehicle certificate. The
// client is told "connected" only once TLS is up. With a CRL policy the ECU
// certificates are checked for revocation; reloadCrl() takes a new CRL file
// and closes connections to ECUs whose certificate has been revoked;
// fetchCrls() does the same with CRLs from the distribution points. The ECU
// is asked for an OCSP staple, which is verified (OcspPolicy).
namespace ccg::platform {

struct TlsClientConfig {
    std::string certificateFile;  // gateway's vehicle certificate (PEM)
    std::string privateKeyFile;
    std::string caFile;           // vehicle CA that signs the ECU certificates
    CrlPolicy crl;                // revocation of ECU certificates
    OcspPolicy ocsp;              // OCSP stapling by the ECUs
};

class DoipTcpConnector final : public diag::IDoipConnector {
public:
    DoipTcpConnector() = default;
    ~DoipTcpConnector();
    DoipTcpConnector(const DoipTcpConnector&) = delete;
    DoipTcpConnector& operator=(const DoipTcpConnector&) = delete;

    void attach(diag::DoipClient& client) { client_ = &client; }

    // Throws std::runtime_error (no OpenSSL in this build, bad files). Call
    // before the first connection.
    void enableTls(const TlsClientConfig& config);
    bool tlsEnabled() const { return ctx_ != nullptr; }

    // Loads the CRL file again and closes established TLS connections whose
    // ECU certificate is now revoked (reported with onClosed). False: the
    // file is unusable (old CRLs stay) or no CRL is configured.
    bool reloadCrl(diag::TimePoint now);
    const RevocationStatistics* revocation() const { return revocation_ ? &revocation_->statistics() : nullptr; }
    // CRL distribution points (CrlPolicy::fetch), called regularly from the
    // poll loop; true when a newer CRL was taken and applied as by reloadCrl().
    bool fetchCrls(diag::TimePoint now);
    const CrlFetchStatistics* crlFetch() const { return revocation_ ? revocation_->fetchStatistics() : nullptr; }
    std::vector<std::string> crlDistributionPoints() const {
        return revocation_ ? revocation_->distributionPoints() : std::vector<std::string>{};
    }
    bool crlFetchBusy() const { return revocation_ && revocation_->fetchBusy(); }
    const OcspStatistics* ocsp() const { return ocsp_ ? &ocsp_->statistics() : nullptr; }

    // diag::IDoipConnector; endpoint "a.b.c.d:port"
    void connect(diag::ConnectionId id, const diag::DoipTarget& target) override;
    void send(diag::ConnectionId id, const std::vector<std::uint8_t>& data) override;
    void close(diag::ConnectionId id) override;

    // Sockets to watch (connecting / handshaking / reading).
    std::vector<pollfd> pollFds() const;
    // Handles the poll results and reports connection events and data to the client.
    void process(const std::vector<pollfd>& fds, diag::TimePoint now);

    std::uint64_t tlsHandshakeFailures() const { return tlsFailures_; }

private:
    struct Socket {
        int fd = -1;
        bool tcpConnected = false;
        bool established = false;  // plain: TCP up; TLS: handshake done
        SSL* ssl = nullptr;
        X509* peer = nullptr;  // ECU certificate, for re-checks
        bool wantWrite = false;
    };
    void fail(diag::ConnectionId id);  // closes and reports onClosed at the end of process()
    void handshake(diag::ConnectionId id, Socket& s, diag::TimePoint now);
    void read(diag::ConnectionId id, Socket& s, diag::TimePoint now);

    diag::DoipClient* client_ = nullptr;
    std::unique_ptr<RevocationChecker> revocation_;
    std::unique_ptr<OcspVerifier> ocsp_;
    std::string caFile_;
    SSL_CTX* ctx_ = nullptr;
    std::map<diag::ConnectionId, Socket> sockets_;
    std::deque<diag::ConnectionId> failed_;
    std::uint64_t tlsFailures_ = 0;
};

}  // namespace ccg::platform
