#pragma once

#include <cstdint>
#include <string>

typedef struct x509_store_st X509_STORE;
typedef struct x509_st X509;
typedef struct ssl_st SSL;

// Certificate revocation for the DoIP TLS connections (testers and vehicle
// Ethernet ECUs), with certificate revocation lists (CRLs, RFC 5280).
//
// Vehicles are often offline, so OCSP is not used: the backend distributes
// CRLs with the PKI and the gateway reloads them when the file changes.
//
//  - every certificate of the peer's chain is checked against the CRL of its
//    issuer (signature, issuer and validity of the CRL checked by OpenSSL)
//  - no CRL for an issuer: rejected (`requireCrl`), or accepted and counted
//  - CRL past its nextUpdate: accepted and counted (`acceptExpiredCrl`, so an
//    offline vehicle does not lock out its workshop), or rejected
//  - a revoked certificate always fails the verification
namespace ccg::platform {

struct CrlPolicy {
    std::string crlFile;           // PEM, one or more CRLs; empty = no revocation checking
    bool requireCrl = true;        // every issuer in the chain must have a CRL
    bool acceptExpiredCrl = true;  // keep using an outdated CRL (reported in the statistics)
};

struct RevocationStatistics {
    std::uint64_t revokedRejected = 0;      // handshakes refused: certificate revoked
    std::uint64_t missingCrlRejected = 0;   // handshakes refused: no CRL for an issuer
    std::uint64_t missingCrlAccepted = 0;   // accepted without CRL (requireCrl = false)
    std::uint64_t expiredCrlAccepted = 0;   // accepted with an outdated CRL
    std::uint64_t expiredCrlRejected = 0;
    std::uint64_t sessionsClosed = 0;       // established sessions closed after a CRL update
    std::uint64_t crlReloads = 0;
};

// Trust store of one TLS context: trust anchors + CRLs + policy. The store
// handed out by build() refers to this object, which must outlive it.
class RevocationChecker {
public:
    explicit RevocationChecker(CrlPolicy policy) : policy_(std::move(policy)) {}

    bool enabled() const { return !policy_.crlFile.empty(); }
    const CrlPolicy& policy() const { return policy_; }

    // New X509_STORE with the CAs of `caFile` and, if enabled, the CRLs of the
    // policy. Throws std::runtime_error (unreadable CA or CRL file, CRL file
    // without any CRL).
    X509_STORE* build(const std::string& caFile);

    // Verifies an established peer again against `store` (after a CRL update).
    // `ssl` provides the chain the peer sent. False if it is no longer valid.
    bool stillValid(X509_STORE* store, SSL* ssl, X509* peer, bool serverSide);

    RevocationStatistics& statistics() { return stats_; }
    const RevocationStatistics& statistics() const { return stats_; }

private:
    CrlPolicy policy_;
    RevocationStatistics stats_;
};

}  // namespace ccg::platform
