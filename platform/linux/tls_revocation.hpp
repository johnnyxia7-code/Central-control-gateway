#pragma once

#include <cstdint>
#include <ctime>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "crl_fetcher.hpp"

typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct x509_st X509;
typedef struct ssl_st SSL;

// Certificate revocation for the DoIP TLS connections (testers and vehicle
// Ethernet ECUs), with certificate revocation lists (CRLs, RFC 5280).
//
// Vehicles are often offline, so OCSP is not queried: the backend distributes
// CRLs with the PKI and the gateway reloads them when the files change.
//
//  - every certificate of the peer's chain is checked against the CRL of its
//    issuer (signature, issuer and validity of the CRL checked by OpenSSL)
//  - no CRL for an issuer: rejected (`requireCrl`), or accepted and counted
//  - CRL past its nextUpdate: accepted and counted (`acceptExpiredCrl`, so an
//    offline vehicle does not lock out its workshop), or rejected
//  - a revoked certificate always fails the verification
//
// Delta CRLs (RFC 5280 5.2.4) carry the changes since a base CRL, so the
// backend can push small, frequent updates. They are applied by the gateway
// itself (OpenSSL applies deltas only when announced by a Freshest CRL
// extension, and silently drops expired ones):
//  - each delta is checked at load: critical Delta CRL Indicator, CRL number,
//    signature by its issuer (a CA of the trust file), and a loaded base CRL
//    of that issuer with CRL number >= the delta's BaseCRLNumber
//  - a delta not newer than the loaded base is obsolete and ignored
//  - a delta for a base the gateway does not have makes the load fail (its
//    changes could not be applied) - install the matching base CRL
//  - serials listed in a delta are revoked; reason removeFromCRL lifts a
//    certificateHold of the base
//  - an expired delta follows `acceptExpiredCrl`: its revocations stay in
//    force when accepted, the verification fails when not
//
// CRL distribution points (CrlFetchPolicy, crl_fetcher.hpp): when the vehicle
// is online the gateway also downloads the CRLs named in the certificates:
//  - URLs (CRL Distribution Points and Freshest CRL) are taken from the CAs of
//    the trust file, from fetched complete CRLs, and from peer certificates
//    whose signatures verify up to a trust anchor - a forged certificate
//    cannot make the gateway send requests
//  - a downloaded CRL must be signed by its issuer, a CA of the trust file,
//    and not be issued in the future; it is taken only if newer than the CRL
//    in force for that issuer (CRL number, else thisUpdate) - an old copy
//    from a stale mirror or an attacker never replaces a newer one
//  - a fetched delta must fit the complete CRL in force (else it waits)
//  - taken CRLs are kept in a cache file and used next to the configured
//    files, the newest complete CRL per issuer winning; so the gateway can
//    start without any CRL file and stays protected across restarts offline
namespace ccg::platform {

struct CrlPolicy {
    std::string crlFile;           // PEM, one or more complete CRLs; empty = no revocation checking
    bool requireCrl = true;        // every issuer in the chain must have a CRL
    bool acceptExpiredCrl = true;  // keep using an outdated CRL (reported in the statistics)
    std::string deltaCrlFile;      // PEM, delta CRLs for the CRLs above; empty = none
    CrlFetchPolicy fetch;          // distribution point fetching; off without cache file
};

struct RevocationStatistics {
    std::uint64_t revokedRejected = 0;      // handshakes refused: certificate revoked
    std::uint64_t missingCrlRejected = 0;   // handshakes refused: no CRL for an issuer
    std::uint64_t missingCrlAccepted = 0;   // accepted without CRL (requireCrl = false)
    std::uint64_t expiredCrlAccepted = 0;   // accepted with an outdated CRL (complete or delta)
    std::uint64_t expiredCrlRejected = 0;
    std::uint64_t sessionsClosed = 0;       // established sessions closed after a CRL update
    std::uint64_t crlReloads = 0;
    std::uint64_t deltaCrls = 0;            // deltas in force after the last load
    std::uint64_t deltasObsolete = 0;       // deltas ignored at the last load (base is newer)
    std::uint64_t revokedByDelta = 0;       // verifications failed because of a delta entry
    std::uint64_t unrevokedByDelta = 0;     // certificateHold lifted by removeFromCRL
};

// Trust store of one TLS context: trust anchors + CRLs + policy. The store
// handed out by build() refers to this object, which must outlive it.
class RevocationChecker {
public:
    explicit RevocationChecker(CrlPolicy policy) : policy_(std::move(policy)) {}

    bool enabled() const { return !policy_.crlFile.empty() || fetching(); }
    bool fetching() const { return !policy_.fetch.cacheFile.empty(); }
    const CrlPolicy& policy() const { return policy_; }

    // New X509_STORE with the CAs of `caFile` and, if enabled, the CRLs and
    // delta CRLs of the policy. Throws std::runtime_error (unreadable files,
    // CRL file without any CRL, invalid or inapplicable delta); the deltas in
    // force are only replaced when the whole load succeeds.
    X509_STORE* build(const std::string& caFile);

    // Verifies an established peer again against `store` (after a CRL update).
    // `ssl` provides the chain the peer sent. False if it is no longer valid.
    bool stillValid(X509_STORE* store, SSL* ssl, X509* peer, bool serverSide);

    RevocationStatistics& statistics() { return stats_; }
    const RevocationStatistics& statistics() const { return stats_; }

    // Distribution point fetching, from the poll loop: starts due downloads
    // and checks the CRLs that arrived. True if a CRL was taken - the owner
    // then builds a new store (reloadCrl) so that it applies.
    bool fetch(std::chrono::steady_clock::time_point now);
    const CrlFetchStatistics* fetchStatistics() const { return fetcher_ ? &fetcher_->statistics() : nullptr; }
    std::vector<std::string> distributionPoints() const { return fetcher_ ? fetcher_->urls() : std::vector<std::string>{}; }
    bool fetchBusy() const { return fetcher_ && fetcher_->busy(); }

    // Verify callback: learns the distribution points of the certificate
    // being checked if its chain verifies up to a trust anchor.
    void noteCertificate(X509_STORE_CTX* ctx);

    // Applied delta of one issuer (DER subject of the issuer as key).
    struct Delta {
        std::uint64_t crlNumber = 0;
        std::time_t nextUpdate = 0;
        std::map<std::string, bool> entries;  // serial (hex) -> true: revoked, false: removeFromCRL
    };
    // Effect of the deltas on one certificate; used by the verify callback.
    enum class DeltaVerdict { None, Revoked, Unrevoked, Expired };
    DeltaVerdict deltaVerdict(X509* cert) const;

private:
    // Fetched CRL kept in the cache (DER); key: issuer + 'C' (complete) / 'D' (delta).
    struct CachedCrl {
        std::string der;
        long long number = -1;  // CRL number; -1: none
        std::time_t issued = 0; // thisUpdate
    };
    // Newest CRLs of one issuer in the store built last.
    struct InForce {
        long long complete = -1;
        std::time_t completeIssued = 0;
        long long delta = -1;
    };
    std::optional<std::time_t> install(const std::vector<std::uint8_t>& body);
    bool saveCache() const;

    CrlPolicy policy_;
    RevocationStatistics stats_;
    std::map<std::string, Delta> deltas_;
    std::string caFile_;
    std::set<std::string> anchors_;  // DER of the trust file's certificates
    std::map<std::string, InForce> inForce_;
    std::map<std::string, CachedCrl> cache_;
    bool cacheLoaded_ = false;
    bool changed_ = false;
    std::unique_ptr<CrlFetcher> fetcher_;
};

}  // namespace ccg::platform
