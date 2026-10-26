// CRL distribution point fetching without TLS: URL parsing, the HTTP client
// against a loopback server, and the fetch schedule.
#include <ctime>
#include <map>
#include <mutex>
#include <string>
#include <thread>

#include "crl_fetcher.hpp"
#include "http_test_server.hpp"
#include "test_framework.hpp"

using namespace ccg;
using namespace std::chrono_literals;
using platform::CrlFetcher;

TEST_CASE("crl fetcher: HTTP URLs of distribution points") {
    auto u = platform::parseHttpUrl("http://pki.oem.example/crl/vehicle-ca.crl");
    REQUIRE(u.has_value());
    CHECK(u->host == "pki.oem.example");
    CHECK(u->port == "80");
    CHECK(u->path == "/crl/vehicle-ca.crl");
    u = platform::parseHttpUrl("HTTP://10.0.0.1:8080");
    REQUIRE(u.has_value());
    CHECK(u->port == "8080");
    CHECK(u->path == "/");
    u = platform::parseHttpUrl("http://[fd00::1]:8080/ca.crl?v=2#top");
    REQUIRE(u.has_value());
    CHECK(u->host == "fd00::1");
    CHECK(u->path == "/ca.crl?v=2");
    // Not fetched: other schemes, user info, bad ports, anything that could
    // change the request line.
    for (const char* bad : {"https://pki.oem.example/ca.crl", "ldap://ldap.oem.example/cn=CA?certificateRevocationList",
                            "file:///etc/ca.crl", "http://user@pki.oem.example/ca.crl", "http://:80/ca.crl",
                            "http://pki.oem.example:0/ca.crl", "http://pki.oem.example:70000/x",
                            "http://pki.oem.example:8o/x", "http://pki.oem.example/a b",
                            "http://pki.oem.example/a\r\nX-Injected: 1", "http://[fd00::1/x"}) {
        CHECK(!platform::parseHttpUrl(bad).has_value());
    }
}

TEST_CASE("crl fetcher: HTTP client against a loopback server") {
    test::HttpTestServer server(31600);
    platform::HttpClient http;
    const std::string base = "http://127.0.0.1:31600";
    {
        test::HttpTestServer::Response r;
        r.body = std::string("\x30\x82\x01\x00", 4) + std::string(256, 'x');  // binary body
        server.set("/ca.crl", r);
        const auto got = http.get(base + "/ca.crl", 1000ms, 4096);
        CHECK(got.ok);
        CHECK_EQ(got.body.size(), 260u);
        const auto req = server.lastRequest();
        CHECK(req.rfind("GET /ca.crl HTTP/1.0\r\n", 0) == 0);
        CHECK(req.find("Host: 127.0.0.1:31600\r\n") != std::string::npos);
    }
    {
        test::HttpTestServer::Response r;
        r.body = "body until close";
        r.contentLength = false;
        server.set("/close.crl", r);
        const auto got = http.get(base + "/close.crl", 1000ms, 4096);
        CHECK(got.ok);
        CHECK_EQ(got.body.size(), 16u);
    }
    {
        const auto got = http.get(base + "/missing.crl", 1000ms, 4096);
        CHECK(!got.ok);
        CHECK_EQ(got.status, 404);
    }
    {
        test::HttpTestServer::Response r;
        r.status = 302;
        r.headers = "Location: http://elsewhere.example/ca.crl\r\n";
        server.set("/moved.crl", r);
        const auto got = http.get(base + "/moved.crl", 1000ms, 4096);
        CHECK(!got.ok);
        CHECK(got.error.find("redirect") != std::string::npos);
    }
    {
        test::HttpTestServer::Response r;
        r.body = std::string(5000, 'x');
        server.set("/big.crl", r);
        CHECK(!http.get(base + "/big.crl", 1000ms, 4096).ok);
        r.body = "short";
        r.lengthDelta = 10;
        server.set("/cut.crl", r);
        const auto cut = http.get(base + "/cut.crl", 1000ms, 4096);
        CHECK(!cut.ok);
        CHECK(cut.error == "truncated response");
    }
    {
        test::HttpTestServer::Response r;
        r.body = "late";
        r.delayMs = 500;
        server.set("/slow.crl", r);
        const auto got = http.get(base + "/slow.crl", 100ms, 4096);
        CHECK(!got.ok);
        CHECK(got.error == "timeout");
    }
    CHECK(!http.get("http://127.0.0.1:31609/ca.crl", 500ms, 4096).ok);  // nobody listening
    CHECK(!http.get("https://127.0.0.1:31600/ca.crl", 500ms, 4096).ok);
}

namespace {

// Answers from a table on the worker thread and counts the downloads.
struct FakeHttp final : platform::IHttpClient {
    std::mutex mutex;
    std::map<std::string, bool> ok;  // URL -> answers 200
    std::map<std::string, int> calls;
    platform::HttpResponse get(const std::string& url, std::chrono::milliseconds, std::size_t) override {
        std::lock_guard<std::mutex> lock(mutex);
        ++calls[url];
        platform::HttpResponse r;
        r.ok = ok[url];
        r.status = r.ok ? 200 : 503;
        if (r.ok) r.body = {1, 2, 3};
        return r;
    }
    int count(const std::string& url) {
        std::lock_guard<std::mutex> lock(mutex);
        return calls[url];
    }
};

// Runs process() at `now` until the downloads it started are handled.
void settle(CrlFetcher& f, CrlFetcher::Clock::time_point now, const CrlFetcher::Consumer& consume) {
    for (int i = 0; i < 1000; ++i) {
        f.process(now, consume);
        if (!f.busy()) return;
        std::this_thread::sleep_for(1ms);
    }
}

}  // namespace

TEST_CASE("crl fetcher: refetch at nextUpdate, back-off on failures, URL limits") {
    auto* http = new FakeHttp;
    platform::CrlFetchPolicy policy;
    policy.cacheFile = "unused";
    policy.maxUrls = 2;
    CrlFetcher f(policy, std::unique_ptr<platform::IHttpClient>(http));
    const std::string good = "http://pki.example/ca.crl";
    const std::string down = "http://pki.example/down.crl";
    http->ok[good] = true;
    const auto t0 = CrlFetcher::Clock::now();
    std::time_t nextUpdate = std::time(nullptr) + 3600;
    int consumed = 0;
    const auto consume = [&](const std::string&, const std::vector<std::uint8_t>& body) -> std::optional<std::time_t> {
        ++consumed;
        CHECK_EQ(body.size(), 3u);
        return nextUpdate;
    };

    CHECK(f.learn(good, t0));
    CHECK(!f.learn(good, t0));  // known
    CHECK(f.learn(down, t0));
    CHECK(!f.learn("http://pki.example/third.crl", t0));  // over maxUrls
    CHECK(!f.learn("ldap://pki.example/cn=CA", t0));
    CHECK(!f.learn("ldap://pki.example/cn=CA", t0));      // counted once
    CHECK_EQ(f.statistics().urls, 2u);
    CHECK_EQ(f.statistics().droppedUrls, 1u);
    CHECK_EQ(f.statistics().unsupportedUrls, 1u);

    settle(f, t0, consume);
    CHECK_EQ(http->count(good), 1);
    CHECK_EQ(http->count(down), 1);
    CHECK_EQ(consumed, 1);
    CHECK_EQ(f.statistics().failures, 1u);

    // The failed one retries after 30 s, then 60 s, 120 s ...
    settle(f, t0 + 29s, consume);
    CHECK_EQ(http->count(down), 1);
    settle(f, t0 + 30s, consume);
    CHECK_EQ(http->count(down), 2);
    settle(f, t0 + 89s, consume);
    CHECK_EQ(http->count(down), 2);
    settle(f, t0 + 90s, consume);
    CHECK_EQ(http->count(down), 3);
    // Back online: next fetch per its nextUpdate again.
    http->ok[down] = true;
    settle(f, t0 + 210s, consume);
    CHECK_EQ(http->count(down), 4);
    CHECK_EQ(consumed, 2);

    // The good URL comes back at its nextUpdate (1 h), not before.
    settle(f, t0 + 3590s, consume);
    CHECK_EQ(http->count(good), 1);
    settle(f, t0 + 3601s, consume);
    CHECK_EQ(http->count(good), 2);
    // A CRL already past its nextUpdate (backend late): not before minInterval (5 min).
    nextUpdate = std::time(nullptr) - 60;
    settle(f, t0 + 7300s, consume);  // both due
    const int before = http->count(good);
    settle(f, t0 + 7300s + 299s, consume);
    CHECK_EQ(http->count(good), before);
    settle(f, t0 + 7300s + 300s, consume);
    CHECK_EQ(http->count(good), before + 1);
    // A body the owner refuses is retried like a failed download.
    const auto refuse = [&](const std::string&, const std::vector<std::uint8_t>&) -> std::optional<std::time_t> {
        return std::nullopt;
    };
    const auto t1 = t0 + 7300s + 300s;
    settle(f, t1 + 300s, refuse);
    const int refused = http->count(good);
    settle(f, t1 + 329s, consume);
    CHECK_EQ(http->count(good), refused);
    settle(f, t1 + 330s, consume);
    CHECK_EQ(http->count(good), refused + 1);
    CHECK_EQ(f.urls().size(), 2u);
}
