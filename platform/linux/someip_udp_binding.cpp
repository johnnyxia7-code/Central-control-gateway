#include "someip_udp_binding.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <iostream>
#include <stdexcept>
#include <system_error>

namespace ccg::platform {

namespace {

[[noreturn]] void throwErrno(const char* what) {
    throw std::system_error(errno, std::generic_category(), what);
}

}  // namespace

SomeIpUdpBinding::SomeIpUdpBinding(std::uint16_t localPort, std::uint16_t instanceId)
    : instanceId_(instanceId) {
    fd_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd_ < 0) {
        throwErrno("socket(AF_INET)");
    }
    const int on = 1;
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(localPort);
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        ::close(fd_);
        throwErrno("bind(UDP)");
    }
}

SomeIpUdpBinding::~SomeIpUdpBinding() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

s2s::Peer SomeIpUdpBinding::toPeer(const sockaddr_in& addr) {
    return s2s::Peer{(static_cast<std::uint64_t>(ntohl(addr.sin_addr.s_addr)) << 16) |
                     ntohs(addr.sin_port)};
}

sockaddr_in SomeIpUdpBinding::toAddress(const s2s::Peer& peer) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(static_cast<std::uint32_t>(peer.token >> 16));
    addr.sin_port = htons(static_cast<std::uint16_t>(peer.token & 0xFFFFU));
    return addr;
}

void SomeIpUdpBinding::addStaticSubscriber(std::uint16_t serviceId, std::uint16_t instanceId,
                                           std::uint16_t eventgroupId, const std::string& ipv4,
                                           std::uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, ipv4.c_str(), &addr.sin_addr) != 1) {
        throw std::invalid_argument("invalid IPv4 address: " + ipv4);
    }
    auto& list = subscribers_[{serviceId, instanceId, eventgroupId}];
    for (const auto& existing : list) {
        if (existing.sin_addr.s_addr == addr.sin_addr.s_addr && existing.sin_port == addr.sin_port) {
            return;
        }
    }
    list.push_back(addr);
}

std::vector<SomeIpUdpBinding::Received> SomeIpUdpBinding::receive() {
    std::vector<Received> out;
    std::array<std::uint8_t, 65536> buffer{};
    sockaddr_in from{};
    socklen_t fromLen = sizeof from;
    const ssize_t n = ::recvfrom(fd_, buffer.data(), buffer.size(), 0,
                                 reinterpret_cast<sockaddr*>(&from), &fromLen);
    if (n <= 0) {
        return out;
    }
    std::size_t offset = 0;
    const auto total = static_cast<std::size_t>(n);
    while (offset < total) {
        std::size_t consumed = 0;
        auto msg = someip::parse(buffer.data() + offset, total - offset, &consumed);
        if (!msg) {
            break;  // malformed remainder of the datagram is discarded
        }
        out.push_back({std::move(*msg), s2s::RequestContext{instanceId_, toPeer(from)}});
        offset += consumed;
    }
    return out;
}

void SomeIpUdpBinding::offerService(const s2s::ServiceInstance& service) {
    std::cout << "[someip] offer " << service.name << " 0x" << std::hex << service.serviceId
              << "/0x" << service.instanceId << std::dec << " v" << int{service.majorVersion}
              << "." << service.minorVersion << " (static SD)\n";
}

void SomeIpUdpBinding::notify(std::uint16_t serviceId, std::uint16_t instanceId,
                              std::uint16_t eventgroupId, const someip::Message& message) {
    const auto it = subscribers_.find({serviceId, instanceId, eventgroupId});
    if (it == subscribers_.end()) {
        return;
    }
    for (const auto& addr : it->second) {
        send(addr, message);
    }
}

void SomeIpUdpBinding::sendTo(const s2s::Peer& peer, const someip::Message& message) {
    send(toAddress(peer), message);
}

void SomeIpUdpBinding::send(const sockaddr_in& to, const someip::Message& message) {
    const auto bytes = someip::serialize(message);
    ::sendto(fd_, bytes.data(), bytes.size(), 0, reinterpret_cast<const sockaddr*>(&to),
             sizeof to);
}

}  // namespace ccg::platform
