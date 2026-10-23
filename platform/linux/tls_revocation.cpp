#include "tls_revocation.hpp"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <vector>

namespace ccg::platform {

namespace {

constexpr long kRemoveFromCrl = 8;      // CRLReason removeFromCRL
constexpr std::time_t kClockTolerance = 300;  // a fetched CRL may be this much "from the future"

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

bool isDelta(X509_CRL* crl) { return integerExtension(crl, NID_delta_crl, nullptr) >= 0; }

// Signed by its issuer, a CA of the trust file.
bool signedByCa(X509_CRL* crl, const std::vector<CertPtr>& cas) {
    bool ok = false;
    for (const auto& ca : cas) {
        if (X509_NAME_cmp(X509_get_subject_name(ca.get()), X509_CRL_get_issuer(crl)) == 0 &&
            X509_CRL_verify(crl, X509_get0_pubkey(ca.get())) == 1) {
            ok = true;
        }
    }
    ERR_clear_error();
    return ok;
}

// True if (number, issued) is newer than (number0, issued0): by CRL number
// when both have one, else by thisUpdate.
bool newer(long long number, std::time_t issued, long long number0, std::time_t issued0) {
    if (number >= 0 && number0 >= 0) return number > number0;
    return issued > issued0;
}

std::string toDer(X509_CRL* crl) {
    unsigned char* der = nullptr;
    const int len = i2d_X509_CRL(crl, &der);
    std::string s = len > 0 ? std::string(reinterpret_cast<char*>(der), static_cast<std::size_t>(len)) : "";
    OPENSSL_free(der);
    return s;
}

CrlPtr fromDer(const std::string& der) {
    const auto* p = reinterpret_cast<const unsigned char*>(der.data());
    return CrlPtr(d2i_X509_CRL(nullptr, &p, static_cast<long>(der.size())), X509_CRL_free);
}

// A downloaded CRL: DER (RFC 5280 4.2.1.13), or PEM from lenient servers.
CrlPtr parseCrl(const std::vector<std::uint8_t>& body) {
    const unsigned char* p = body.data();
    X509_CRL* crl = d2i_X509_CRL(nullptr, &p, static_cast<long>(body.size()));
    if (!crl) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(body.data(), static_cast<int>(body.size())),
                                                      BIO_free);
        if (bio) crl = PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr);
    }
    ERR_clear_error();
    return CrlPtr(crl, X509_CRL_free);
}

// URIs of CRL Distribution Points / Freshest CRL extensions.
void addUris(CRL_DIST_POINTS* points, std::vector<std::string>& urls) {
    for (int i = 0; points && i < sk_DIST_POINT_num(points); ++i) {
        const DIST_POINT* dp = sk_DIST_POINT_value(points, i);
        if (!dp->distpoint || dp->distpoint->type != 0) continue;  // full names only
        const GENERAL_NAMES* names = dp->distpoint->name.fullname;
        for (int j = 0; j < sk_GENERAL_NAME_num(names); ++j) {
            const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, j);
            if (name->type != GEN_URI) continue;
            const ASN1_IA5STRING* uri = name->d.uniformResourceIdentifier;
            urls.emplace_back(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)),
                              static_cast<std::size_t>(ASN1_STRING_length(uri)));
        }
    }
    CRL_DIST_POINTS_free(points);
}

std::vector<std::string> distributionPointUrls(X509* cert) {
    std::vector<std::string> urls;
    addUris(static_cast<CRL_DIST_POINTS*>(X509_get_ext_d2i(cert, NID_crl_distribution_points, nullptr, nullptr)),
            urls);
    addUris(static_cast<CRL_DIST_POINTS*>(X509_get_ext_d2i(cert, NID_freshest_crl, nullptr, nullptr)), urls);
    return urls;
}

std::vector<std::string> freshestUrls(X509_CRL* crl) {
    std::vector<std::string> urls;
    addUris(static_cast<CRL_DIST_POINTS*>(X509_CRL_get_ext_d2i(crl, NID_freshest_crl, nullptr, nullptr)), urls);
    return urls;
}

std::string certDer(X509* cert) {
    unsigned char* der = nullptr;
    const int len = i2d_X509(cert, &der);
    std::string s = len > 0 ? std::string(reinterpret_cast<char*>(der), static_cast<std::size_t>(len)) : "";
    OPENSSL_free(der);
    return s;
}

// Applies the CRL policy to the verification result of each certificate, and
// the delta CRLs to every certificate that passed the complete CRL check.
int revocationVerifyCallback(int ok, X509_STORE_CTX* ctx) {
    auto* checker =
        static_cast<RevocationChecker*>(X509_STORE_get_ex_data(X509_STORE_CTX_get0_store(ctx), storeIndex()));
    if (!checker) return ok;
    checker->noteCertificate(ctx);
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
    const auto cas = readCertificates(caFile);

    // Fetched CRLs: from the cache file once, then kept in memory.
    if (fetching() && !cacheLoaded_) {
        cacheLoaded_ = true;
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_file(policy_.fetch.cacheFile.c_str(), "r"), BIO_free);
        while (X509_CRL* raw = bio ? PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr) : nullptr) {
            CrlPtr crl(raw, X509_CRL_free);
            if (!signedByCa(crl.get(), cas)) continue;  // not ours to trust
            CachedCrl entry{toDer(crl.get()), integerExtension(crl.get(), NID_crl_number, nullptr),
                            toTime(X509_CRL_get0_lastUpdate(crl.get()))};
            const std::string key = nameKey(X509_CRL_get_issuer(crl.get())) + (isDelta(crl.get()) ? "D" : "C");
            const auto it = cache_.find(key);
            if (it == cache_.end() || newer(entry.number, entry.issued, it->second.number, it->second.issued)) {
                cache_[key] = std::move(entry);
            }
        }
        ERR_clear_error();
    }

    // Complete CRLs: the newest per issuer, from the CRL file and the fetched ones.
    struct Newest {
        CrlPtr crl{nullptr, X509_CRL_free};
        long long number = -1;
        std::time_t issued = 0;
    };
    std::map<std::string, Newest> complete;
    auto offer = [&](CrlPtr crl) {
        const long long number = integerExtension(crl.get(), NID_crl_number, nullptr);
        const std::time_t issued = toTime(X509_CRL_get0_lastUpdate(crl.get()));
        auto& n = complete[nameKey(X509_CRL_get_issuer(crl.get()))];
        if (!n.crl || newer(number, issued, n.number, n.issued)) n = Newest{std::move(crl), number, issued};
    };
    if (!policy_.crlFile.empty()) {
        for (auto& crl : readCrls(policy_.crlFile)) {
            if (isDelta(crl.get())) {
                throw std::runtime_error("TLS: " + policy_.crlFile + " holds a delta CRL - use the delta CRL file");
            }
            offer(std::move(crl));
        }
    }
    std::vector<CrlPtr> fetchedDeltas;
    for (const auto& entry : cache_) {
        CrlPtr crl = fromDer(entry.second.der);
        if (!crl) continue;
        if (isDelta(crl.get())) {
            fetchedDeltas.push_back(std::move(crl));
        } else {
            offer(std::move(crl));
        }
    }
    std::map<std::string, InForce> inForce;
    for (auto& [issuer, n] : complete) {
        X509_STORE_add_crl(store.get(), n.crl.get());
        inForce[issuer].complete = n.number;
        inForce[issuer].completeIssued = n.issued;
    }

    // Delta CRLs: checked here, applied by the verify callback. The delta file
    // must be right (else the load fails); fetched deltas that no longer fit
    // are skipped.
    std::map<std::string, Delta> deltas;
    std::uint64_t obsolete = 0;
    auto considerDelta = [&](X509_CRL* crl, bool strict) {
        auto refuse = [&](const std::string& why) {
            if (strict) throw std::runtime_error("TLS: " + why);
        };
        int critical = 0;
        const long long base = integerExtension(crl, NID_delta_crl, &critical);
        const long long number = integerExtension(crl, NID_crl_number, nullptr);
        if (base < 0 || critical != 1 || number < 0) {
            return refuse(policy_.deltaCrlFile + " holds a CRL without critical Delta CRL Indicator and CRL number");
        }
        if (!signedByCa(crl, cas)) return refuse("delta CRL not signed by a CA of " + caFile);
        const std::string issuer = nameKey(X509_CRL_get_issuer(crl));
        const auto b = inForce.find(issuer);
        if (b == inForce.end() || b->second.complete < 0) {
            return refuse("delta CRL without a numbered complete CRL of its issuer");
        }
        if (number <= b->second.complete) {
            ++obsolete;  // the complete CRL already contains these changes
            return;
        }
        if (base > b->second.complete) {
            return refuse("delta CRL for base CRL " + std::to_string(base) + ", loaded is " +
                          std::to_string(b->second.complete) + " - install the matching complete CRL");
        }
        auto& d = deltas[issuer];
        if (number <= static_cast<long long>(d.crlNumber)) return;  // an older delta of the same issuer
        d = Delta{};
        d.crlNumber = static_cast<std::uint64_t>(number);
        d.nextUpdate = toTime(X509_CRL_get0_nextUpdate(crl));
        STACK_OF(X509_REVOKED)* revoked = X509_CRL_get_REVOKED(crl);
        for (int i = 0; revoked && i < sk_X509_REVOKED_num(revoked); ++i) {
            X509_REVOKED* r = sk_X509_REVOKED_value(revoked, i);
            long reason = -1;
            if (auto* e = static_cast<ASN1_ENUMERATED*>(X509_REVOKED_get_ext_d2i(r, NID_crl_reason, nullptr, nullptr))) {
                reason = ASN1_ENUMERATED_get(e);
                ASN1_ENUMERATED_free(e);
            }
            d.entries[serialKey(X509_REVOKED_get0_serialNumber(r))] = reason != kRemoveFromCrl;
        }
        b->second.delta = number;
    };
    if (!policy_.deltaCrlFile.empty()) {
        for (auto& crl : readCrls(policy_.deltaCrlFile)) considerDelta(crl.get(), true);
    }
    for (auto& crl : fetchedDeltas) considerDelta(crl.get(), false);

    X509_STORE_set_flags(store.get(), X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    X509_STORE_set_verify_cb(store.get(), revocationVerifyCallback);
    X509_STORE_set_ex_data(store.get(), storeIndex(), this);
    // Only after the whole load succeeded:
    deltas_ = std::move(deltas);
    inForce_ = std::move(inForce);
    caFile_ = caFile;
    anchors_.clear();
    for (const auto& ca : cas) anchors_.insert(certDer(ca.get()));
    stats_.deltaCrls = deltas_.size();
    stats_.deltasObsolete = obsolete;
    ++stats_.crlReloads;

    // Distribution points named by the trust file and the fetched complete CRLs.
    if (fetching()) {
        if (!fetcher_) fetcher_ = std::make_unique<CrlFetcher>(policy_.fetch);
        const auto now = CrlFetcher::Clock::now();
        for (const auto& ca : cas) {
            for (const auto& url : distributionPointUrls(ca.get())) fetcher_->learn(url, now);
        }
        for (const auto& [issuer, n] : complete) {
            for (const auto& url : freshestUrls(n.crl.get())) fetcher_->learn(url, now);
        }
    }
    return store.release();
}

void RevocationChecker::noteCertificate(X509_STORE_CTX* ctx) {
    if (!fetcher_) return;
    X509* cert = X509_STORE_CTX_get_current_cert(ctx);
    if (!cert) return;
    std::vector<std::string> fresh;
    for (auto& url : distributionPointUrls(cert)) {
        if (!fetcher_->known(url)) fresh.push_back(std::move(url));
    }
    if (fresh.empty()) return;
    // Only from a certificate whose chain verifies up to a trust anchor. The
    // revocation check runs before OpenSSL checks the signatures, so this is
    // done here: a forged certificate must not make the gateway send requests.
    STACK_OF(X509)* chain = X509_STORE_CTX_get0_chain(ctx);
    const int n = chain ? sk_X509_num(chain) : 0;
    int i = 0;
    while (i < n && sk_X509_value(chain, i) != cert) ++i;
    if (i == n || anchors_.count(certDer(sk_X509_value(chain, n - 1))) == 0) return;
    for (int j = i; j + 1 < n; ++j) {
        if (X509_verify(sk_X509_value(chain, j), X509_get0_pubkey(sk_X509_value(chain, j + 1))) != 1) {
            ERR_clear_error();
            return;
        }
    }
    const auto now = CrlFetcher::Clock::now();
    for (const auto& url : fresh) fetcher_->learn(url, now);
}

bool RevocationChecker::fetch(std::chrono::steady_clock::time_point now) {
    if (!fetcher_) return false;
    changed_ = false;
    fetcher_->process(now, [this](const std::string&, const std::vector<std::uint8_t>& body) { return install(body); });
    return changed_;
}

std::optional<std::time_t> RevocationChecker::install(const std::vector<std::uint8_t>& body) {
    auto& st = fetcher_->statistics();
    CrlPtr crl = parseCrl(body);
    if (!crl || !signedByCa(crl.get(), readCertificates(caFile_))) {
        ++st.rejected;  // not a CRL, forged, or of an issuer we do not trust
        return std::nullopt;
    }
    const std::time_t issued = toTime(X509_CRL_get0_lastUpdate(crl.get()));
    if (issued == 0 || issued > std::time(nullptr) + kClockTolerance) {
        ++st.rejected;
        return std::nullopt;
    }
    const std::time_t nextUpdate = toTime(X509_CRL_get0_nextUpdate(crl.get()));
    const std::string issuer = nameKey(X509_CRL_get_issuer(crl.get()));
    int critical = 0;
    const long long base = integerExtension(crl.get(), NID_delta_crl, &critical);
    const long long number = integerExtension(crl.get(), NID_crl_number, nullptr);
    const bool delta = base >= 0;

    InForce current;
    if (const auto it = inForce_.find(issuer); it != inForce_.end()) current = it->second;
    if (const auto it = cache_.find(issuer + "C");
        it != cache_.end() && newer(it->second.number, it->second.issued, current.complete, current.completeIssued)) {
        current.complete = it->second.number;
        current.completeIssued = it->second.issued;
    }
    if (const auto it = cache_.find(issuer + "D"); it != cache_.end()) {
        current.delta = std::max(current.delta, it->second.number);
    }
    if (delta) {
        if (critical != 1 || number < 0) {
            ++st.rejected;
            return std::nullopt;
        }
        if (current.complete < 0 || base > current.complete) {
            ++st.deltasAhead;  // its complete CRL comes first
            return std::nullopt;
        }
        if (number <= current.delta || number <= current.complete) {
            ++st.stale;
            return nextUpdate;
        }
    } else if (!newer(number, issued, current.complete, current.completeIssued)) {
        ++st.stale;  // unchanged, or older than the CRL in force
        return nextUpdate;
    }

    cache_[issuer + (delta ? "D" : "C")] = CachedCrl{toDer(crl.get()), number, issued};
    if (!delta) {
        const auto d = cache_.find(issuer + "D");
        if (d != cache_.end() && number >= 0 && d->second.number <= number) cache_.erase(d);  // contained now
        const auto now = CrlFetcher::Clock::now();
        for (const auto& url : freshestUrls(crl.get())) fetcher_->learn(url, now);
    }
    if (!saveCache()) ++st.cacheWriteFailures;  // still used until the restart
    ++st.installed;
    changed_ = true;
    return nextUpdate;
}

bool RevocationChecker::saveCache() const {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio) return false;
    for (const auto& entry : cache_) {
        CrlPtr crl = fromDer(entry.second.der);
        if (crl) PEM_write_bio_X509_CRL(bio.get(), crl.get());
    }
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio.get(), &data);
    // Written next to the file and renamed: a crash leaves the old or the new cache.
    const std::string& path = policy_.fetch.cacheFile;
    const std::string tmp = path + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) return false;
    long done = 0;
    while (done < size) {
        const ssize_t n = ::write(fd, data + done, static_cast<std::size_t>(size - done));
        if (n <= 0) break;
        done += n;
    }
    const bool ok = done == size && ::fsync(fd) == 0;
    ::close(fd);
    if (!ok || std::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return false;
    }
    return true;
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
