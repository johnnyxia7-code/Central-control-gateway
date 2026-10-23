#include "tls_revocation.hpp"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <memory>
#include <stdexcept>
#include <vector>

namespace ccg::platform {

namespace {

constexpr long kRemoveFromCrl = 8;  // CRLReason removeFromCRL

int storeIndex() {
    static const int index = X509_STORE_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return index;
}

using CrlPtr = std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)>;
using CertPtr = std::unique_ptr<X509, decltype(&X509_free)>;

std::vector<CrlPtr> readCrls(const std::string& file) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_file(file.c_str(), "r"), BIO_free);
    if (!bio) {
        ERR_clear_error();
        throw std::runtime_error("TLS: cannot open CRL file " + file);
    }
    std::vector<CrlPtr> crls;
    while (X509_CRL* crl = PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr)) {
        crls.emplace_back(crl, X509_CRL_free);
    }
    ERR_clear_error();  // end of file
    if (crls.empty()) throw std::runtime_error("TLS: no CRL in " + file);
    return crls;
}

std::vector<CertPtr> readCertificates(const std::string& file) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_file(file.c_str(), "r"), BIO_free);
    std::vector<CertPtr> certs;
    if (!bio) return certs;
    while (X509* c = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)) certs.emplace_back(c, X509_free);
    ERR_clear_error();
    return certs;
}

std::string nameKey(const X509_NAME* name) {
    unsigned char* der = nullptr;
    const int len = i2d_X509_NAME(name, &der);
    std::string key = len > 0 ? std::string(reinterpret_cast<char*>(der), static_cast<std::size_t>(len)) : "";
    OPENSSL_free(der);
    return key;
}

std::string serialKey(const ASN1_INTEGER* serial) {
    BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
    char* hex = bn ? BN_bn2hex(bn) : nullptr;
    std::string key = hex ? hex : "";
    OPENSSL_free(hex);
    BN_free(bn);
    return key;
}

// Integer extension (CRL number, delta CRL indicator); -1 if absent.
long long integerExtension(X509_CRL* crl, int nid, int* critical) {
    ASN1_INTEGER* value = static_cast<ASN1_INTEGER*>(X509_CRL_get_ext_d2i(crl, nid, critical, nullptr));
    if (!value) return -1;
    const long long n = static_cast<long long>(ASN1_INTEGER_get(value));
    ASN1_INTEGER_free(value);
    return n;
}

std::time_t toTime(const ASN1_TIME* t) {
    struct tm tm {};
    if (!t || ASN1_TIME_to_tm(t, &tm) != 1) return 0;
    return timegm(&tm);
}

// Applies the CRL policy to the verification result of each certificate, and
// the delta CRLs to every certificate that passed the complete CRL check.
int revocationVerifyCallback(int ok, X509_STORE_CTX* ctx) {
    auto* checker =
        static_cast<RevocationChecker*>(X509_STORE_get_ex_data(X509_STORE_CTX_get0_store(ctx), storeIndex()));
    if (!checker) return ok;
    auto& s = checker->statistics();
    const auto& policy = checker->policy();
    const auto verdict = checker->deltaVerdict(X509_STORE_CTX_get_current_cert(ctx));
    if (ok) {
        switch (verdict) {
            case RevocationChecker::DeltaVerdict::Revoked:
                ++s.revokedByDelta;
                ++s.revokedRejected;
                X509_STORE_CTX_set_error(ctx, X509_V_ERR_CERT_REVOKED);
                return 0;
            case RevocationChecker::DeltaVerdict::Expired:
                if (policy.acceptExpiredCrl) {
                    ++s.expiredCrlAccepted;
                    return 1;
                }
                ++s.expiredCrlRejected;
                X509_STORE_CTX_set_error(ctx, X509_V_ERR_CRL_HAS_EXPIRED);
                return 0;
            default:
                return 1;
        }
    }
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
            if (verdict == RevocationChecker::DeltaVerdict::Unrevoked) {
                ++s.unrevokedByDelta;  // hold lifted by a newer delta
                X509_STORE_CTX_set_error(ctx, X509_V_OK);
                return 1;
            }
            ++s.revokedRejected;
            return 0;
        default:
            return 0;
    }
}

}  // namespace

RevocationChecker::DeltaVerdict RevocationChecker::deltaVerdict(X509* cert) const {
    if (!cert || deltas_.empty()) return DeltaVerdict::None;
    const auto it = deltas_.find(nameKey(X509_get_issuer_name(cert)));
    if (it == deltas_.end()) return DeltaVerdict::None;
    const auto entry = it->second.entries.find(serialKey(X509_get0_serialNumber(cert)));
    if (entry != it->second.entries.end()) return entry->second ? DeltaVerdict::Revoked : DeltaVerdict::Unrevoked;
    if (it->second.nextUpdate != 0 && std::time(nullptr) > it->second.nextUpdate) return DeltaVerdict::Expired;
    return DeltaVerdict::None;
}

X509_STORE* RevocationChecker::build(const std::string& caFile) {
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(X509_STORE_new(), X509_STORE_free);
    if (!store || X509_STORE_load_file(store.get(), caFile.c_str()) != 1) {
        ERR_clear_error();
        throw std::runtime_error("TLS: cannot load CA file " + caFile);
    }
    if (!enabled()) {
        if (!policy_.deltaCrlFile.empty()) throw std::runtime_error("TLS: delta CRLs need the complete CRLs");
        return store.release();
    }

    // Complete CRLs: into the store; their numbers per issuer for the deltas.
    std::map<std::string, long long> baseNumbers;
    for (auto& crl : readCrls(policy_.crlFile)) {
        if (integerExtension(crl.get(), NID_delta_crl, nullptr) >= 0) {
            throw std::runtime_error("TLS: " + policy_.crlFile + " holds a delta CRL - use the delta CRL file");
        }
        const long long number = integerExtension(crl.get(), NID_crl_number, nullptr);
        const auto [known, added] = baseNumbers.emplace(nameKey(X509_CRL_get_issuer(crl.get())), number);
        if (!added) known->second = std::max(known->second, number);  // -1: unnumbered
        X509_STORE_add_crl(store.get(), crl.get());
    }

    // Delta CRLs: checked here, applied by the verify callback.
    std::map<std::string, Delta> deltas;
    std::uint64_t obsolete = 0;
    if (!policy_.deltaCrlFile.empty()) {
        const auto cas = readCertificates(caFile);
        for (auto& crl : readCrls(policy_.deltaCrlFile)) {
            int critical = 0;
            const long long base = integerExtension(crl.get(), NID_delta_crl, &critical);
            const long long number = integerExtension(crl.get(), NID_crl_number, nullptr);
            if (base < 0 || critical != 1 || number < 0) {
                throw std::runtime_error("TLS: " + policy_.deltaCrlFile +
                                         " holds a CRL without critical Delta CRL Indicator and CRL number");
            }
            const X509_NAME* issuerName = X509_CRL_get_issuer(crl.get());
            bool signedByCa = false;
            for (const auto& ca : cas) {
                if (X509_NAME_cmp(X509_get_subject_name(ca.get()), issuerName) == 0 &&
                    X509_CRL_verify(crl.get(), X509_get0_pubkey(ca.get())) == 1) {
                    signedByCa = true;
                }
            }
            ERR_clear_error();
            if (!signedByCa) throw std::runtime_error("TLS: delta CRL not signed by a CA of " + caFile);
            const std::string issuer = nameKey(issuerName);
            const auto b = baseNumbers.find(issuer);
            if (b == baseNumbers.end() || b->second < 0) {
                throw std::runtime_error("TLS: delta CRL without a numbered complete CRL of its issuer");
            }
            if (number <= b->second) {
                ++obsolete;  // the complete CRL already contains these changes
                continue;
            }
            if (base > b->second) {
                throw std::runtime_error("TLS: delta CRL for base CRL " + std::to_string(base) + ", loaded is " +
                                         std::to_string(b->second) + " - install the matching complete CRL");
            }
            auto& d = deltas[issuer];
            if (number <= static_cast<long long>(d.crlNumber)) continue;  // an older delta of the same issuer
            d = Delta{};
            d.crlNumber = static_cast<std::uint64_t>(number);
            d.nextUpdate = toTime(X509_CRL_get0_nextUpdate(crl.get()));
            STACK_OF(X509_REVOKED)* revoked = X509_CRL_get_REVOKED(crl.get());
            for (int i = 0; revoked && i < sk_X509_REVOKED_num(revoked); ++i) {
                X509_REVOKED* r = sk_X509_REVOKED_value(revoked, i);
                long reason = -1;
                if (auto* e = static_cast<ASN1_ENUMERATED*>(X509_REVOKED_get_ext_d2i(r, NID_crl_reason, nullptr, nullptr))) {
                    reason = ASN1_ENUMERATED_get(e);
                    ASN1_ENUMERATED_free(e);
                }
                d.entries[serialKey(X509_REVOKED_get0_serialNumber(r))] = reason != kRemoveFromCrl;
            }
        }
    }

    X509_STORE_set_flags(store.get(), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    X509_STORE_set_verify_cb(store.get(), revocationVerifyCallback);
    X509_STORE_set_ex_data(store.get(), storeIndex(), this);
    deltas_ = std::move(deltas);  // only after the whole load succeeded
    stats_.deltaCrls = deltas_.size();
    stats_.deltasObsolete = obsolete;
    ++stats_.crlReloads;
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
