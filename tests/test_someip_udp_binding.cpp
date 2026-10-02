#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <vector>

#include "someip_udp_binding.hpp"
#include "test_framework.hpp"

using namespace ccg;

namespace {

struct UdpSocket {
    int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in addr{};
    UdpSocket() {
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr);
        socklen_t len = sizeof addr;
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len);
    }
    ~UdpSocket() { ::close(fd); }
    std::uint16_t port() const { return ntohs(addr.sin_port); }
    std::vector<std::uint8_t> receive() const {
        pollfd p{fd, POLLIN, 0};
        if (::poll(&p, 1, 1000) <= 0) return {};
        std::vector<std::uint8_t> buf(2048);
        const auto n = ::recv(fd, buf.data(), buf.size(), 0);
        buf.resize(n > 0 ? static_cast<std::size_t>(n) : 0);
        return buf;
    }
};

std::vector<platform::SomeIpUdpBinding::Received> receiveBlocking(
    platform::SomeIpUdpBinding& binding) {
    pollfd p{binding.fd(), POLLIN, 0};
    if (::poll(&p, 1, 1000) <= 0) return {};
    return binding.receive();
}

}  // namespace

TEST_CASE("udp binding: packed requests, unicast reply and static subscribers") {
    constexpr std::uint16_t kPort = 30999;
    platform::SomeIpUdpBinding binding(kPort, 0x0001);
    UdpSocket client;
    UdpSocket subscriber;
    binding.addStaticSubscriber(0x6002, 0x0001, 0x0001, "127.0.0.1", subscriber.port());
    binding.addStaticSubscriber(0x6002, 0x0001, 0x0001, "127.0.0.1", subscriber.port());  // dup

    // Two SOME/IP messages packed into one UDP datagram.
    std::vector<std::uint8_t> datagram;
    for (std::uint16_t i = 0; i < 2; ++i) {
        someip::Message m;
        m.header.serviceId = 0x6002;
        m.header.methodId = i == 0 ? 0x0010 : 0x0001;
        m.header.sessionId = static_cast<std::uint16_t>(i + 1);
        m.payload.assign(1 - i, 0x01);
        for (const auto byte : someip::serialize(m)) datagram.push_back(byte);
    }

    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(kPort);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::sendto(client.fd, datagram.data(), datagram.size(), 0, reinterpret_cast<sockaddr*>(&to),
             sizeof to);

    const auto received = receiveBlocking(binding);
    REQUIRE(received.size() == 2);
    CHECK_EQ(received[0].message.header.methodId, 0x0010);
    CHECK_EQ(received[1].message.header.methodId, 0x0001);
    CHECK_EQ(received[0].context.instanceId, 0x0001);
    const auto peerAddr = platform::SomeIpUdpBinding::toAddress(received[0].context.peer);
    CHECK_EQ(ntohs(peerAddr.sin_port), client.port());

    someip::Message resp = received[0].message;
    resp.header.messageType = someip::MessageType::Response;
    binding.sendTo(received[0].context.peer, resp);
    const auto reply = client.receive();
    const auto parsed = someip::parse(reply.data(), reply.size());
    REQUIRE(parsed.has_value());
    CHECK(parsed->header.messageType == someip::MessageType::Response);
    CHECK_EQ(parsed->header.sessionId, 1);

    someip::Message event;
    event.header.serviceId = 0x6002;
    event.header.methodId = 0x8001;
    event.header.messageType = someip::MessageType::Notification;
    binding.notify(0x6002, 0x0001, 0x0001, event);
    binding.notify(0x6002, 0x0001, 0x0002, event);  // no subscriber
    const auto notification = subscriber.receive();
    REQUIRE(!notification.empty());
    CHECK_EQ(someip::parse(notification.data(), notification.size())->header.methodId, 0x8001);

    pollfd p{subscriber.fd, POLLIN, 0};
    CHECK_EQ(::poll(&p, 1, 100), 0);  // duplicate subscriber registered only once
}
