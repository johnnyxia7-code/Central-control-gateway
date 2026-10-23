#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// CRL distribution point fetching (RFC 5280 4.2.1.13 / 5.2.6) for the DoIP
// TLS connections: when the vehicle is online, the gateway downloads the CRLs
// named in the certificates it checks, instead of waiting for the backend to
// push them.
//
//  - HTTP only (RFC 5280: CRLs are signed, so no TLS is needed to fetch them,
//    and TLS would make revocation depend on revocation); HTTP/1.0 GET, no
//    redirects, size and time limits
//  - downloads run on one worker thread (name resolution blocks), the results
//    are handed to the owner on the poll-loop thread
//  - each URL is fetched again at the CRL's nextUpdate, bounded by
//    `minInterval` and `refresh`; failures back off exponentially from `retry`
//
// What a downloaded CRL must satisfy before it is used is decided by the
// owner (RevocationChecker).
namespace ccg::platform {

struct HttpResponse {
    bool ok = false;  // status 200 and complete body
    int status = 0;   // 0: no HTTP response
    std::vector<std::uint8_t> body;
    std::string error;
};

// Blocking HTTP GET; called on the fetch worker only.
class IHttpClient {
public:
    virtual ~IHttpClient() = default;
    virtual HttpResponse get(const std::string& url, std::chrono::milliseconds timeout, std::size_t maxBytes) = 0;
};

// http://host[:port][/path]; nullopt for other schemes, user info, or
// characters that do not belong in a request line.
struct HttpUrl {
    std::string host;
    std::string port = "80";
    std::string path = "/";
};
std::optional<HttpUrl> parseHttpUrl(const std::string& url);

// HTTP/1.0 over TCP (IPv4/IPv6), Connection: close.
class HttpClient final : public IHttpClient {
public:
    HttpResponse get(const std::string& url, std::chrono::milliseconds timeout, std::size_t maxBytes) override;
};

struct CrlFetchPolicy {
    std::string cacheFile;  // fetched CRLs (PEM), kept across restarts; empty = no fetching
    std::chrono::milliseconds refresh = std::chrono::hours(6);       // longest time between two fetches of a URL
    std::chrono::milliseconds minInterval = std::chrono::minutes(5); // shortest (also when nextUpdate is past)
    std::chrono::milliseconds retry = std::chrono::seconds(30);      // first retry after a failure, doubling
    std::chrono::milliseconds timeout = std::chrono::seconds(10);    // per download
    std::size_t maxBytes = 4u << 20;                                 // per CRL
    std::size_t maxUrls = 32;
};

struct CrlFetchStatistics {
    std::uint64_t urls = 0;               // distribution points known
    std::uint64_t unsupportedUrls = 0;    // not http:// (ldap, https, ...) - never fetched
    std::uint64_t droppedUrls = 0;        // over maxUrls
    std::uint64_t fetches = 0;            // downloads finished (successful or not)
    std::uint64_t failures = 0;           // no connection, HTTP error, redirect, too large, timeout
    std::uint64_t rejected = 0;           // not a CRL, bad signature, unknown issuer, issued in the future
    std::uint64_t stale = 0;              // not newer than the CRL in force (unchanged or rolled back)
    std::uint64_t installed = 0;          // newer CRLs taken
    std::uint64_t deltasAhead = 0;        // delta for a complete CRL the gateway does not have (yet)
    std::uint64_t cacheWriteFailures = 0;
};

class CrlFetcher {
public:
    using Clock = std::chrono::steady_clock;
    // Verdict on a downloaded body: nullopt = unusable (retried with back-off),
    // otherwise the CRL's nextUpdate (0: none) for the next fetch.
    using Consumer =
        std::function<std::optional<std::time_t>(const std::string& url, const std::vector<std::uint8_t>& body)>;

    explicit CrlFetcher(CrlFetchPolicy policy, std::unique_ptr<IHttpClient> http = nullptr);
    ~CrlFetcher();
    CrlFetcher(const CrlFetcher&) = delete;
    CrlFetcher& operator=(const CrlFetcher&) = delete;

    const CrlFetchPolicy& policy() const { return policy_; }

    // A distribution point; fetched at the next process(). False if it is
    // already known, unsupported or over the limit.
    bool learn(const std::string& url, Clock::time_point now);
    bool known(const std::string& url) const { return sources_.count(url) != 0 || ignored_.count(url) != 0; }
    std::vector<std::string> urls() const;

    // Poll-loop thread: hands finished downloads to `consume`, then queues
    // the URLs that are due.
    void process(Clock::time_point now, const Consumer& consume);
    bool busy() const;  // downloads queued or running

    CrlFetchStatistics& statistics() { return stats_; }
    const CrlFetchStatistics& statistics() const { return stats_; }

private:
    struct Source {
        Clock::time_point due;
        std::chrono::milliseconds backoff{0};
        bool queued = false;
    };
    void schedule(Source& s, Clock::time_point now, std::optional<std::time_t> nextUpdate);
    void work();

    CrlFetchPolicy policy_;
    std::unique_ptr<IHttpClient> http_;
    std::map<std::string, Source> sources_;  // poll-loop thread only
    std::set<std::string> ignored_;          // unsupported or over the limit
    CrlFetchStatistics stats_;

    mutable std::mutex mutex_;  // guards the queues below
    std::condition_variable wake_;
    std::deque<std::string> jobs_;
    std::deque<std::pair<std::string, HttpResponse>> done_;
    std::size_t running_ = 0;
    bool stop_ = false;
    std::thread worker_;  // started with the first download
};

}  // namespace ccg::platform
