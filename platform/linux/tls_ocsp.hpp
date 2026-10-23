#pragma once

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct x509_st X509;

// OCSP stapling (RFC 6066 status_request, RFC 6960) for the DoIP TLS
// connections, complementing the CRLs (tls_revocation.hpp).
//
//  - Server side (OcspStapler): the gateway - or an ECU - staples a signed
//    OCSP response about its own certificate into the handshake. The vehicle
//    is often offline, so the response is fetched by the backend / OTA client
//    and given as a DER file; it is reloaded when it changes and never stapled
//    once past its nextUpdate.
//  - Client side (OcspVerifier): the gateway asks the ECU for a staple and
//    checks it: signature (CA or delegated OCSP signer) against the trust
//    store, response for exactly the peer's certificate, thisUpdate/nextUpdate
//    (5 min clock tolerance) and the status. "revoked" always fails the
//    handshake; a missing or unusable staple fails it only if required.
//  - Must-staple (RFC 7633 TLS Feature extension with status_request): a
//    peer certificate carrying it gets a valid staple required whatever the
//    policy says; a server whose own certificate carries it needs a response
//    to staple (no response file: start-up error; outdated: counted).
namespace ccg::platform {

struct OcspStatistics {
    std::uint64_t stapled = 0;          // server: responses sent
    std::uint64_t notStapledExpired = 0;// server: response outdated, not sent
    std::uint64_t reloads = 0;
    std::uint64_t verified = 0;         // client: staple checked, status good
    std::uint64_t revoked = 0;          // client: status revoked -> handshake failed
    std::uint64_t missing = 0;          // client: no staple
    std::uint64_t invalid = 0;          // client: bad signature, wrong certificate, outdated, unknown
    std::uint64_t rejected = 0;         // client: handshakes failed because of the staple
    std::uint64_t mustStapleEnforced = 0;   // client: staple required by the peer's certificate
    std::uint64_t mustStapleUnserved = 0;   // server: own certificate is must-staple, nothing valid to send
};

// True if the certificate carries the TLS Feature extension with status_request (must-staple).
bool hasMustStaple(X509* cert);

class OcspStapler {
public:
    // `checkResponse` = false only emulates a misconfigured peer in tests.
    explicit OcspStapler(std::string responseFile, bool checkResponse = true)
        : file_(std::move(responseFile)), checkResponse_(checkResponse) {}
    bool enabled() const { return !file_.empty(); }

    // Installs the status callback on a server context whose certificate is
    // loaded; notes whether that certificate is must-staple.
    void attach(SSL_CTX* ctx);
    bool mustStaple() const { return mustStaple_; }

    // Reads the DER response: "successful", basic response with a
    // SingleResponse for our certificate (serial + issuer name hash). False:
    // unusable file or a response about another certificate; the previous
    // response stays.
    bool load();

    std::time_t nextUpdate() const { return nextUpdate_; }
    const OcspStatistics& statistics() const { return stats_; }

    static int callback(SSL* ssl, void* arg);

private:
    std::string file_;
    bool checkResponse_;
    X509* certificate_ = nullptr;  // owned by the SSL_CTX
    bool mustStaple_ = false;
    std::vector<unsigned char> response_;
    std::time_t nextUpdate_ = 0;  // 0: no nextUpdate in the response
    OcspStatistics stats_;
};

struct OcspPolicy {
    bool request = true;   // ask the peer for a staple
    bool require = false;  // fail the handshake without a good staple
};

class OcspVerifier {
public:
    explicit OcspVerifier(OcspPolicy policy) : policy_(policy) {}
    const OcspPolicy& policy() const { return policy_; }

    // Installs the status callback on a client context.
    void attach(SSL_CTX* ctx);
    // Per connection: asks for the staple (status_request).
    void prepare(SSL* ssl) const;

    const OcspStatistics& statistics() const { return stats_; }

    static int callback(SSL* ssl, void* arg);

private:
    int check(SSL* ssl);

    OcspPolicy policy_;
    OcspStatistics stats_;
};

}  // namespace ccg::platform
