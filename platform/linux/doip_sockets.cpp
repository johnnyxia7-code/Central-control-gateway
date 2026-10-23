#include "doip_sockets.hpp"

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <stdexcept>
#include <system_error>

namespace ccg::platform {

namespace {

[[noreturn]] void throwErrno(const char* what) {
    throw std::system_error(errno, std::generic_category(), what);
}

}  // namespace

// ---------------------------------------------------------------------------
// TCP
// ---------------------------------------------------------------------------

DoipTcpServer::DoipTcpServer(std::uint16_t port, std::size_t maxConnections)
    : maxConnections_(maxConnections) {
    listenFd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listenFd_ < 0) throwErrno("socket(TCP)");
    const int on = 1;
    ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0 ||
        ::listen(listenFd_, 8) < 0) {
        const int err = errno;
        ::close(listenFd_);
        throw std::system_error(err, std::generic_category(), "bind/listen(TCP 13400)");
    }
}

DoipTcpServer::~DoipTcpServer() {
    for (const auto& [id, fd] : connections_) ::close(fd);
    if (listenFd_ >= 0) ::close(listenFd_);
}

std::vector<diag::ConnectionId> DoipTcpServer::acceptPending() {
    std::vector<diag::ConnectionId> accepted;
    for (;;) {
        const int fd = ::accept4(listenFd_, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) break;
        if (connections_.size() >= maxConnections_ + 1) {
            ::close(fd);  // no socket left at all
            continue;
        }
        const int on = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof on);
        const diag::ConnectionId id = nextId_++;
        connections_[id] = fd;
        accepted.push_back(id);
    }
    return accepted;
}

std::vector<DoipTcpServer::Socket> DoipTcpServer::sockets() const {
    std::vector<Socket> out;
    for (const auto& [id, fd] : connections_) out.push_back({fd, id});
    return out;
}

DoipTcpServer::ReadResult DoipTcpServer::read(diag::ConnectionId id,
                                              std::vector<std::uint8_t>& data) {
    const auto it = connections_.find(id);
    if (it == connections_.end()) return ReadResult::Nothing;
    data.resize(16384);
    const auto n = ::recv(it->second, data.data(), data.size(), 0);
    if (n > 0) {
        data.resize(static_cast<std::size_t>(n));
        return ReadResult::Data;
    }
    data.clear();
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        return ReadResult::Nothing;
    }
    ::close(it->second);
    connections_.erase(it);
    return ReadResult::Closed;
}

bool DoipTcpServer::send(diag::ConnectionId id, const std::vector<std::uint8_t>& data) {
    const auto it = connections_.find(id);
    if (it == connections_.end()) return false;
    std::size_t offset = 0;
    while (offset < data.size()) {
        const auto n = ::send(it->second, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
        if (n > 0) {
            offset += static_cast<std::size_t>(n);
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pollfd p{it->second, POLLOUT, 0};
            if (::poll(&p, 1, 100) > 0) continue;  // short wait for a slow tester
        }
        return false;
    }
    return true;
}

void DoipTcpServer::close(diag::ConnectionId id) {
    const auto it = connections_.find(id);
    if (it == connections_.end()) return;
    ::close(it->second);
    connections_.erase(it);
}

// ---------------------------------------------------------------------------
// UDP
// ---------------------------------------------------------------------------

DoipUdpSocket::DoipUdpSocket(std::uint16_t port, const std::string& broadcastAddress) {
    fd_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd_ < 0) throwErrno("socket(UDP)");
    const int on = 1;
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    ::setsockopt(fd_, SOL_SOCKET, SO_BROADCAST, &on, sizeof on);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        const int err = errno;
        ::close(fd_);
        throw std::system_error(err, std::generic_category(), "bind(UDP 13400)");
    }
    broadcast_.sin_family = AF_INET;
    broadcast_.sin_port = htons(port);
    if (::inet_pton(AF_INET, broadcastAddress.c_str(), &broadcast_.sin_addr) != 1) {
        ::close(fd_);
        throw std::invalid_argument("invalid broadcast address: " + broadcastAddress);
    }
}

DoipUdpSocket::~DoipUdpSocket() {
    if (fd_ >= 0) ::close(fd_);
}

diag::UdpPeer DoipUdpSocket::toPeer(const sockaddr_in& addr) {
    return {(static_cast<std::uint64_t>(ntohl(addr.sin_addr.s_addr)) << 16) | ntohs(addr.sin_port)};
}

sockaddr_in DoipUdpSocket::toAddress(const diag::UdpPeer& peer) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(static_cast<std::uint32_t>(peer.token >> 16));
    addr.sin_port = htons(static_cast<std::uint16_t>(peer.token & 0xFFFFU));
    return addr;
}

bool DoipUdpSocket::receive(std::vector<std::uint8_t>& data, diag::UdpPeer& peer) {
    data.resize(4096);
    sockaddr_in from{};
    socklen_t len = sizeof from;
    const auto n = ::recvfrom(fd_, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&from), &len);
    if (n < 0) {
        data.clear();
        return false;
    }
    data.resize(static_cast<std::size_t>(n));
    peer = toPeer(from);
    return true;
}

void DoipUdpSocket::sendTo(const diag::UdpPeer& peer, const std::vector<std::uint8_t>& data) {
    const auto addr = toAddress(peer);
    ::sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<const sockaddr*>(&addr), sizeof addr);
}

void DoipUdpSocket::broadcast(const std::vector<std::uint8_t>& data) {
    ::sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<const sockaddr*>(&broadcast_),
             sizeof broadcast_);
}

}  // namespace ccg::platform
