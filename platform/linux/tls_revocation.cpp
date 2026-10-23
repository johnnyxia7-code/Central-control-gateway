#include "tls_revocation.hpp"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <memory>
#include <stdexcept>

namespace ccg::platform {

namespace {

int storeIndex() {
    static const int index = X509_STORE_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return index;
}

// Applies the CRL policy to the verification result of each certificate.
int revocationVerifyCallback(int ok, X509_STORE_CTX* ctx) {
    auto* checker =
        static_cast<RevocationChecker*>(X509_STORE_get_ex_data(X509_STORE_CTX_get0_store(ctx), storeIndex()));
    if (ok || !checker) return ok;
    auto& s = checker->statistics();
    const auto& policy = checker->policy();
    switch (X509_STORE_CTX_get_error(ctx)) {
        case X509_V_ERR_CRL_HAS_EXPIRED:
            if (policy.acceptExpiredCrl) {
                ++s.expiredCrlAccepted;
                return 1;
            }
            ++s.expiredCrlRejected;
            return 0;
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            if (!policy.requireCrl) {
                ++s.missingCrlAccepted;
                return 1;
            }
            ++s.missingCrlRejected;
            return 0;
        case X509_V_ERR_CERT_REVOKED:
            ++s.revokedRejected;
            return 0;
        default:
            return 0;
    }
}

}  // namespace

X509_STORE* RevocationChecker::build(const std::string& caFile) {
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(X509_STORE_new(), X509_STORE_free);
    if (!store || X509_STORE_load_file(store.get(), caFile.c_str()) != 1) {
        ERR_clear_error();
        throw std::runtime_error("TLS: cannot load CA file " + caFile);
    }
    if (enabled()) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_file(policy_.crlFile.c_str(), "r"), BIO_free);
        if (!bio) {
            ERR_clear_error();
            throw std::runtime_error("TLS: cannot open CRL file " + policy_.crlFile);
        }
        std::size_t count = 0;
        while (X509_CRL* crl = PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr)) {
            X509_STORE_add_crl(store.get(), crl);
            X509_CRL_free(crl);
            ++count;
        }
        ERR_clear_error();  // end of file
        if (count == 0) throw std::runtime_error("TLS: no CRL in " + policy_.crlFile);
        X509_STORE_set_flags(store.get(), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
        X509_STORE_set_verify_cb(store.get(), revocationVerifyCallback);
        X509_STORE_set_ex_data(store.get(), storeIndex(), this);
        ++stats_.crlReloads;
    }
    return store.release();
}

bool RevocationChecker::stillValid(X509_STORE* store, SSL* ssl, X509* peer, bool serverSide) {
    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    // Server side: the chain excludes the client's leaf; client side: it starts with it.
    STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
    if (!ctx || X509_STORE_CTX_init(ctx.get(), store, peer, chain) != 1) return false;
    X509_STORE_CTX_set_purpose(ctx.get(), serverSide ? X509_PURPOSE_SSL_CLIENT : X509_PURPOSE_SSL_SERVER);
    const bool ok = X509_verify_cert(ctx.get()) == 1;
    ERR_clear_error();
    return ok;
}

}  // namespace ccg::platform
