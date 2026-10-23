#include "crl_fetcher.hpp"

#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>

namespace ccg::platform {

namespace {

using SteadyClock = std::chrono::steady_clock;

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Waits for `events` on `fd` until `deadline`; false on timeout.
bool waitFor(int fd, short events, SteadyClock::time_point deadline) {
    for (;;) {
        const auto now = SteadyClock::now();
        if (now >= deadline) return false;
        const auto left = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
        pollfd p{fd, events, 0};
        const int n = ::poll(&p, 1, static_cast<int>(std::min<long long>(left, 1000)));
        if (n > 0) return true;
        if (n < 0 && errno != EINTR) return false;
    }
}

int connectTo(const HttpUrl& url, SteadyClock::time_point deadline, std::string& error) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* list = nullptr;
    if (const int e = ::getaddrinfo(url.host.c_str(), url.port.c_str(), &hints, &list); e != 0) {
        error = std::string("name resolution: ") + ::gai_strerror(e);
        return -1;
    }
    int fd = -1;
    for (const addrinfo* ai = list; ai && fd < 0; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) continue;
        bool connected = ::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0;
        if (!connected && errno == EINPROGRESS && waitFor(fd, POLLOUT, deadline)) {
            int soError = 0;
            socklen_t len = sizeof soError;
            connected = ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len) == 0 && soError == 0;
        }
        if (!connected) {
            ::close(fd);
            fd = -1;
        }
    }
    ::freeaddrinfo(list);
    if (fd < 0) error = SteadyClock::now() >= deadline ? "timeout" : "connection failed";
    return fd;
}

}  // namespace

std::optional<HttpUrl> parseHttpUrl(const std::string& url) {
    if (url.size() < 8 || url.size() > 512) return std::nullopt;
    for (const char c : url) {
        if (c <= 0x20 || c >= 0x7F) return std::nullopt;  // nothing that could end the request line
    }
    if (lower(url.substr(0, 7)) != "http://") return std::nullopt;
    const std::string rest = url.substr(7);
    const auto end = rest.find_first_of("/?#");
    const std::string authority = rest.substr(0, end);
    HttpUrl u;
    if (end != std::string::npos) {
        u.path = rest.substr(end);
        u.path.erase(std::min(u.path.find('#'), u.path.size()));  // fragments stay with the client
        if (u.path.empty() || u.path[0] != '/') u.path.insert(0, "/");
    }
    if (authority.empty() || authority.find('@') != std::string::npos) return std::nullopt;
    std::string port;
    if (authority[0] == '[') {  // IPv6 literal
        const auto close = authority.find(']');
        if (close == std::string::npos) return std::nullopt;
        u.host = authority.substr(1, close - 1);
        const std::string after = authority.substr(close + 1);
        if (!after.empty()) {
            if (after[0] != ':') return std::nullopt;
            port = after.substr(1);
        }
    } else {
        const auto colon = authority.rfind(':');
        u.host = authority.substr(0, colon);
        if (colon != std::string::npos) port = authority.substr(colon + 1);
    }
    if (u.host.empty()) return std::nullopt;
    if (!port.empty()) {
        if (port.size() > 5 || !std::all_of(port.begin(), port.end(), [](char c) { return c >= '0' && c <= '9'; })) {
            return std::nullopt;
        }
        const unsigned long n = std::stoul(port);
        if (n == 0 || n > 0xFFFF) return std::nullopt;
        u.port = port;
    }
    return u;
}

HttpResponse HttpClient::get(const std::string& url, std::chrono::milliseconds timeout, std::size_t maxBytes) {
    HttpResponse r;
    const auto u = parseHttpUrl(url);
    if (!u) {
        r.error = "unsupported URL";
        return r;
    }
    const auto deadline = SteadyClock::now() + timeout;
    const int fd = connectTo(*u, deadline, r.error);
    if (fd < 0) return r;

    std::string host = u->host.find(':') != std::string::npos ? "[" + u->host + "]" : u->host;
    if (u->port != "80") host += ":" + u->port;
    const std::string request = "GET " + u->path + " HTTP/1.0\r\nHost: " + host +
                                "\r\nAccept: application/pkix-crl, application/x-pkcs7-crl, */*\r\n"
                                "User-Agent: ccg-diag-gateway\r\nConnection: close\r\n\r\n";
    std::size_t sent = 0;
    while (sent < request.size()) {
        const ssize_t n = ::send(fd, request.data() + sent, request.size() - sent, MSG_NOSIGNAL);
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) && waitFor(fd, POLLOUT, deadline)) {
            continue;
        } else {
            r.error = SteadyClock::now() >= deadline ? "timeout" : "send failed";
            ::close(fd);
            return r;
        }
    }

    std::string data;
    const std::size_t limit = maxBytes + 16384;  // body + headers
    char buffer[8192];
    for (;;) {
        const ssize_t n = ::recv(fd, buffer, sizeof buffer, 0);
        if (n > 0) {
            data.append(buffer, static_cast<std::size_t>(n));
            if (data.size() > limit) {
                r.error = "response too large";
                break;
            }
            continue;
        }
        if (n == 0) break;  // HTTP/1.0: the server closes after the body
        if (errno == EINTR) continue;
        if ((errno == EAGAIN || errno == EWOULDBLOCK) && waitFor(fd, POLLIN, deadline)) continue;
        r.error = SteadyClock::now() >= deadline ? "timeout" : "receive failed";
        break;
    }
    ::close(fd);
    if (!r.error.empty()) return r;

    const auto headerEnd = data.find("\r\n\r\n");
    if (data.compare(0, 7, "HTTP/1.") != 0 || headerEnd == std::string::npos || data.size() < 12) {
        r.error = "malformed response";
        return r;
    }
    r.status = std::atoi(data.substr(9, 3).c_str());
    std::optional<std::size_t> contentLength;
    std::size_t line = data.find("\r\n") + 2;
    while (line < headerEnd) {
        const auto eol = data.find("\r\n", line);
        const std::string header = data.substr(line, eol - line);
        const auto colon = header.find(':');
        if (colon != std::string::npos && lower(header.substr(0, colon)) == "content-length") {
            contentLength = static_cast<std::size_t>(std::strtoull(header.c_str() + colon + 1, nullptr, 10));
        }
        line = eol + 2;
    }
    if (r.status != 200) {
        r.error = "HTTP " + std::to_string(r.status) +
                  (r.status >= 300 && r.status < 400 ? " (redirects are not followed)" : "");
        return r;
    }
    const std::size_t bodySize = data.size() - headerEnd - 4;
    if (bodySize > maxBytes) {
        r.error = "response too large";
        return r;
    }
    if (contentLength && *contentLength != bodySize) {
        r.error = "truncated response";
        return r;
    }
    r.body.assign(data.begin() + static_cast<std::ptrdiff_t>(headerEnd + 4), data.end());
    r.ok = true;
    return r;
}

// --- fetcher ------------------------------------------------------------------------

CrlFetcher::CrlFetcher(CrlFetchPolicy policy, std::unique_ptr<IHttpClient> http)
    : policy_(std::move(policy)), http_(http ? std::move(http) : std::make_unique<HttpClient>()) {}

CrlFetcher::~CrlFetcher() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_ = true;
    }
    wake_.notify_all();
    if (worker_.joinable()) worker_.join();  // at most one download timeout
}

bool CrlFetcher::learn(const std::string& url, Clock::time_point now) {
    if (sources_.count(url) != 0 || ignored_.count(url) != 0) return false;
    const bool supported = parseHttpUrl(url).has_value();
    if (!supported || sources_.size() >= policy_.maxUrls) {
        ++(supported ? stats_.droppedUrls : stats_.unsupportedUrls);
        if (ignored_.size() < 256) ignored_.insert(url);  // counted once
        return false;
    }
    sources_[url].due = now;
    stats_.urls = sources_.size();
    return true;
}

std::vector<std::string> CrlFetcher::urls() const {
    std::vector<std::string> list;
    for (const auto& entry : sources_) list.push_back(entry.first);
    return list;
}

bool CrlFetcher::busy() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !jobs_.empty() || running_ != 0 || !done_.empty();
}

void CrlFetcher::schedule(Source& s, Clock::time_point now, std::optional<std::time_t> nextUpdate) {
    if (!nextUpdate) {
        s.backoff = s.backoff.count() == 0 ? policy_.retry : std::min(s.backoff * 2, policy_.refresh);
        s.due = now + s.backoff;
        return;
    }
    s.backoff = std::chrono::milliseconds(0);
    std::chrono::milliseconds delay = policy_.refresh;
    if (*nextUpdate != 0) {
        const std::time_t left = std::max<std::time_t>(*nextUpdate - std::time(nullptr), 0);
        delay = std::min(delay, std::chrono::milliseconds(std::chrono::seconds(left)));
    }
    s.due = now + std::max(delay, policy_.minInterval);
}

void CrlFetcher::process(Clock::time_point now, const Consumer& consume) {
    std::deque<std::pair<std::string, HttpResponse>> finished;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        finished.swap(done_);
    }
    for (auto& [url, response] : finished) {
        const auto it = sources_.find(url);
        if (it == sources_.end()) continue;
        it->second.queued = false;
        ++stats_.fetches;
        std::optional<std::time_t> verdict;
        if (response.ok) {
            verdict = consume(url, response.body);
        } else {
            ++stats_.failures;
        }
        schedule(it->second, now, verdict);
    }

    bool queued = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [url, s] : sources_) {
            if (s.queued || s.due > now) continue;
            jobs_.push_back(url);
            s.queued = true;
            queued = true;
        }
        if (queued && !worker_.joinable()) worker_ = std::thread(&CrlFetcher::work, this);
    }
    if (queued) wake_.notify_one();
}

void CrlFetcher::work() {
    std::unique_lock<std::mutex> lock(mutex_);
    for (;;) {
        wake_.wait(lock, [this] { return stop_ || !jobs_.empty(); });
        if (stop_) return;
        std::string url = std::move(jobs_.front());
        jobs_.pop_front();
        ++running_;
        lock.unlock();
        HttpResponse response = http_->get(url, policy_.timeout, policy_.maxBytes);
        lock.lock();
        --running_;
        done_.emplace_back(std::move(url), std::move(response));
    }
}

}  // namespace ccg::platform
