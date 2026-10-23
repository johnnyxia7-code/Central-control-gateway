#include "tls_ocsp.hpp"

#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cstdio>
#include <cstring>
#include <memory>

namespace ccg::platform {

namespace {

constexpr long kClockTolerance = 300;  // seconds

using ResponsePtr = std::unique_ptr<OCSP_RESPONSE, decltype(&OCSP_RESPONSE_free)>;
using BasicPtr = std::unique_ptr<OCSP_BASICRESP, decltype(&OCSP_BASICRESP_free)>;

std::time_t toTime(const ASN1_GENERALIZEDTIME* t) {
    struct tm tm {};
    if (!t || ASN1_TIME_to_tm(t, &tm) != 1) return 0;
    return timegm(&tm);
}

// Issuer of `leaf` from the peer's chain, else from the trust store.
X509* findIssuer(SSL* ssl, X509* leaf) {
    STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
    for (int i = 0; chain && i < sk_X509_num(chain); ++i) {
        X509* c = sk_X509_value(chain, i);
        if (c != leaf && X509_check_issued(c, leaf) == X509_V_OK) {
            X509_up_ref(c);
            return c;
        }
    }
    X509_STORE* store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl));
    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> ctx(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    X509* issuer = nullptr;
    if (ctx && X509_STORE_CTX_init(ctx.get(), store, leaf, nullptr) == 1) {
        if (X509_STORE_CTX_get1_issuer(&issuer, ctx.get(), leaf) != 1) issuer = nullptr;
    }
    return issuer;
}

}  // namespace

// --- server: staple our own status ---------------------------------------------

bool OcspStapler::load() {
    if (!enabled()) return false;
    std::FILE* f = std::fopen(file_.c_str(), "rb");
    if (!f) return false;
    std::vector<unsigned char> der;
    unsigned char buf[4096];
    for (std::size_t n; (n = std::fread(buf, 1, sizeof buf, f)) > 0;) der.insert(der.end(), buf, buf + n);
    std::fclose(f);

    const unsigned char* p = der.data();
    ResponsePtr resp(d2i_OCSP_RESPONSE(nullptr, &p, static_cast<long>(der.size())), OCSP_RESPONSE_free);
    if (!resp || OCSP_response_status(resp.get()) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        ERR_clear_error();
        return false;
    }
    BasicPtr basic(OCSP_response_get1_basic(resp.get()), OCSP_BASICRESP_free);
    if (!basic || OCSP_resp_count(basic.get()) < 1) {
        ERR_clear_error();
        return false;
    }
    ASN1_GENERALIZEDTIME* thisUpdate = nullptr;
    ASN1_GENERALIZEDTIME* nextUpdate = nullptr;
    OCSP_single_get0_status(OCSP_resp_get0(basic.get(), 0), nullptr, nullptr, &thisUpdate, &nextUpdate);
    response_ = std::move(der);
    nextUpdate_ = toTime(nextUpdate);
    ++stats_.reloads;
    return true;
}

void OcspStapler::attach(SSL_CTX* ctx) {
    SSL_CTX_set_tlsext_status_cb(ctx, &OcspStapler::callback);
    SSL_CTX_set_tlsext_status_arg(ctx, this);
}

int OcspStapler::callback(SSL* ssl, void* arg) {
    auto* self = static_cast<OcspStapler*>(arg);
    if (!self || self->response_.empty()) return SSL_TLSEXT_ERR_NOACK;
    if (self->nextUpdate_ != 0 && std::time(nullptr) > self->nextUpdate_) {
        ++self->stats_.notStapledExpired;  // an outdated staple would only fail the client
        return SSL_TLSEXT_ERR_NOACK;
    }
    auto* copy = static_cast<unsigned char*>(OPENSSL_malloc(self->response_.size()));
    if (!copy) return SSL_TLSEXT_ERR_NOACK;
    std::memcpy(copy, self->response_.data(), self->response_.size());
    SSL_set_tlsext_status_ocsp_resp(ssl, copy, static_cast<long>(self->response_.size()));  // takes ownership
    ++self->stats_.stapled;
    return SSL_TLSEXT_ERR_OK;
}

// --- client: check the peer's staple ----------------------------------------------

void OcspVerifier::attach(SSL_CTX* ctx) {
    SSL_CTX_set_tlsext_status_cb(ctx, &OcspVerifier::callback);
    SSL_CTX_set_tlsext_status_arg(ctx, this);
}

void OcspVerifier::prepare(SSL* ssl) const {
    if (policy_.request || policy_.require) SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
}

int OcspVerifier::callback(SSL* ssl, void* arg) {
    auto* self = static_cast<OcspVerifier*>(arg);
    if (!self) return 1;
    const int r = self->check(ssl);
    ERR_clear_error();
    if (r == 0) ++self->stats_.rejected;
    return r;
}

// 1: accept, 0: fail the handshake.
int OcspVerifier::check(SSL* ssl) {
    const bool require = policy_.require;
    const unsigned char* p = nullptr;
    const long len = SSL_get_tlsext_status_ocsp_resp(ssl, &p);
    if (!p || len <= 0) {
        ++stats_.missing;
        return require ? 0 : 1;
    }
    auto invalid = [&] {
        ++stats_.invalid;
        return require ? 0 : 1;
    };
    ResponsePtr resp(d2i_OCSP_RESPONSE(nullptr, &p, len), OCSP_RESPONSE_free);
    if (!resp || OCSP_response_status(resp.get()) != OCSP_RESPONSE_STATUS_SUCCESSFUL) return invalid();
    BasicPtr basic(OCSP_response_get1_basic(resp.get()), OCSP_BASICRESP_free);
    if (!basic) return invalid();

    // Signed by the CA or by an OCSP signer it authorised, chained to our trust anchors.
    X509_STORE* store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl));
    if (OCSP_basic_verify(basic.get(), SSL_get_peer_cert_chain(ssl), store, 0) <= 0) return invalid();

    X509* leaf = SSL_get0_peer_certificate(ssl);
    if (!leaf) return invalid();
    std::unique_ptr<X509, decltype(&X509_free)> issuer(findIssuer(ssl, leaf), X509_free);
    if (!issuer) return invalid();
    std::unique_ptr<OCSP_CERTID, decltype(&OCSP_CERTID_free)> id(OCSP_cert_to_id(nullptr, leaf, issuer.get()),
                                                                OCSP_CERTID_free);
    int status = 0;
    int reason = 0;
    ASN1_GENERALIZEDTIME* revokedAt = nullptr;
    ASN1_GENERALIZEDTIME* thisUpdate = nullptr;
    ASN1_GENERALIZEDTIME* nextUpdate = nullptr;
    if (!id || OCSP_resp_find_status(basic.get(), id.get(), &status, &reason, &revokedAt, &thisUpdate, &nextUpdate) != 1) {
        return invalid();  // a response about another certificate
    }
    if (status == V_OCSP_CERTSTATUS_REVOKED) {
        ++stats_.revoked;
        return 0;  // revoked is never acceptable
    }
    if (OCSP_check_validity(thisUpdate, nextUpdate, kClockTolerance, -1) != 1) return invalid();
    if (status != V_OCSP_CERTSTATUS_GOOD) return invalid();  // unknown to the responder
    ++stats_.verified;
    return 1;
}

}  // namespace ccg::platform
