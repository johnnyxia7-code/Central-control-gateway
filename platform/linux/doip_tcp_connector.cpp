#include "doip_tcp_connector.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>

namespace ccg::platform {

namespace {

bool parseEndpoint(const std::string& endpoint, sockaddr_in& addr) {
    const auto colon = endpoint.rfind(':');
    if (colon == std::string::npos) return false;
    addr = sockaddr_in{};
    addr.sin_family = AF_INET;
    try {
        const unsigned long port = std::stoul(endpoint.substr(colon + 1));
        if (port == 0 || port > 0xFFFF) return false;
        addr.sin_port = htons(static_cast<std::uint16_t>(port));
    } catch (const std::exception&) {
        return false;
    }
    return ::inet_pton(AF_INET, endpoint.substr(0, colon).c_str(), &addr.sin_addr) == 1;
}

}  // namespace

DoipTcpConnector::~DoipTcpConnector() {
    for (auto& [id, s] : sockets_) ::close(s.fd);
}

void DoipTcpConnector::connect(diag::ConnectionId id, const std::string& endpoint) {
    close(id);
    sockaddr_in addr{};
    if (!parseEndpoint(endpoint, addr)) {
        failed_.push_back(id);
        return;
    }
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        failed_.push_back(id);
        return;
    }
    const int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0 && errno != EINPROGRESS) {
        ::close(fd);
        failed_.push_back(id);
        return;
    }
    sockets_[id] = Socket{fd, false};  // completion is seen as POLLOUT
}

void DoipTcpConnector::send(diag::ConnectionId id, const std::vector<std::uint8_t>& data) {
    const auto it = sockets_.find(id);
    if (it == sockets_.end() || !it->second.connected) return;
    std::size_t done = 0;
    while (done < data.size()) {
        const ssize_t n = ::send(it->second.fd, data.data() + done, data.size() - done, MSG_NOSIGNAL);
        if (n > 0) {
            done += static_cast<std::size_t>(n);
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pollfd p{it->second.fd, POLLOUT, 0};
            if (::poll(&p, 1, 100) <= 0) break;  // DoIP messages are small; a stuck socket is dead
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    if (done < data.size()) fail(id);
}

void DoipTcpConnector::close(diag::ConnectionId id) {
    const auto it = sockets_.find(id);
    if (it == sockets_.end()) return;
    ::close(it->second.fd);
    sockets_.erase(it);
}

void DoipTcpConnector::fail(diag::ConnectionId id) {
    close(id);
    failed_.push_back(id);
}

std::vector<pollfd> DoipTcpConnector::pollFds() const {
    std::vector<pollfd> fds;
    for (const auto& [id, s] : sockets_) {
        fds.push_back({s.fd, static_cast<short>(s.connected ? POLLIN : POLLOUT), 0});
    }
    return fds;
}

void DoipTcpConnector::process(const std::vector<pollfd>& fds, diag::TimePoint now) {
    for (const auto& p : fds) {
        if (p.revents == 0) continue;
        diag::ConnectionId id = 0;
        for (const auto& [i, s] : sockets_) {
            if (s.fd == p.fd) id = i;
        }
        if (id == 0) continue;  // closed meanwhile
        auto& s = sockets_[id];
        if (!s.connected) {
            int error = 0;
            socklen_t len = sizeof error;
            ::getsockopt(s.fd, SOL_SOCKET, SO_ERROR, &error, &len);
            if (error != 0) {
                fail(id);
                continue;
            }
            s.connected = true;
            if (client_) client_->onConnected(id, now);
            continue;
        }
        std::uint8_t buffer[4096];
        for (;;) {
            const auto it = sockets_.find(id);
            if (it == sockets_.end()) break;  // closed by the client while handling data
            const ssize_t n = ::recv(it->second.fd, buffer, sizeof buffer, 0);
            if (n > 0) {
                if (client_) client_->onData(id, buffer, static_cast<std::size_t>(n), now);
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n < 0 && errno == EINTR) continue;
            fail(id);  // closed by the entity or error
            break;
        }
    }
    while (!failed_.empty()) {
        const auto id = failed_.front();
        failed_.pop_front();
        if (client_) client_->onClosed(id, now);
    }
}

}  // namespace ccg::platform
