#pragma once
// Minimal HTTP server on loopback for the CRL fetching tests: a thread answers
// each connection with the response configured for the request's path (404
// otherwise) and closes it.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ccg::test {

class HttpTestServer {
public:
    struct Response {
        int status = 200;
        std::string body;
        std::string headers;       // extra header lines, each ending in \r\n
        bool contentLength = true; // false: the end of the body is the end of the connection
        long lengthDelta = 0;      // announce more than sent (truncated response)
        int delayMs = 0;           // before answering
    };

    explicit HttpTestServer(std::uint16_t port) {
        fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        const int one = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr);
        ::listen(fd_, 8);
        thread_ = std::thread([this] { run(); });
    }
    ~HttpTestServer() {
        stop_ = true;
        thread_.join();
        ::close(fd_);
    }
    HttpTestServer(const HttpTestServer&) = delete;
    HttpTestServer& operator=(const HttpTestServer&) = delete;

    void set(const std::string& path, Response response) {
        std::lock_guard<std::mutex> lock(mutex_);
        responses_[path] = std::move(response);
    }
    void set(const std::string& path, const std::vector<std::uint8_t>& body) {
        Response r;
        r.body.assign(body.begin(), body.end());
        set(path, r);
    }
    std::size_t hits(const std::string& path) const {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = hits_.find(path);
        return it == hits_.end() ? 0 : it->second;
    }
    std::size_t requests() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::size_t n = 0;
        for (const auto& h : hits_) n += h.second;
        return n;
    }
    std::string lastRequest() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return last_;
    }

private:
    void run() {
        while (!stop_) {
            pollfd p{fd_, POLLIN, 0};
            if (::poll(&p, 1, 20) <= 0) continue;
            const int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) continue;
            serve(c);
            ::close(c);
        }
    }
    void serve(int c) {
        std::string request;
        char buf[1024];
        while (request.find("\r\n\r\n") == std::string::npos && request.size() < 8192) {
            pollfd p{c, POLLIN, 0};
            if (::poll(&p, 1, 1000) <= 0) return;
            const ssize_t n = ::recv(c, buf, sizeof buf, 0);
            if (n <= 0) return;
            request.append(buf, static_cast<std::size_t>(n));
        }
        const auto sp1 = request.find(' ');
        const auto sp2 = request.find(' ', sp1 + 1);
        const std::string path = request.substr(sp1 + 1, sp2 - sp1 - 1);
        Response r;
        r.status = 404;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++hits_[path];
            last_ = request;
            const auto it = responses_.find(path);
            if (it != responses_.end()) r = it->second;
        }
        if (r.delayMs > 0) std::this_thread::sleep_for(std::chrono::milliseconds(r.delayMs));
        std::string out = "HTTP/1.0 " + std::to_string(r.status) + " X\r\nContent-Type: application/pkix-crl\r\n";
        if (r.contentLength) {
            out += "Content-Length: " + std::to_string(static_cast<long>(r.body.size()) + r.lengthDelta) + "\r\n";
        }
        out += r.headers + "\r\n" + r.body;
        std::size_t done = 0;
        while (done < out.size()) {
            const ssize_t n = ::send(c, out.data() + done, out.size() - done, MSG_NOSIGNAL);
            if (n <= 0) return;
            done += static_cast<std::size_t>(n);
        }
    }

    int fd_ = -1;
    std::atomic<bool> stop_{false};
    std::thread thread_;
    mutable std::mutex mutex_;
    std::map<std::string, Response> responses_;
    std::map<std::string, std::size_t> hits_;
    std::string last_;
};

}  // namespace ccg::test
