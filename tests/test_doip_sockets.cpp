#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <vector>

#include "ccg/doip/doip_message.hpp"
#include "doip_sockets.hpp"
#include "test_framework.hpp"

using namespace ccg;

namespace {

bool readable(int fd, int timeoutMs = 1000) {
    pollfd p{fd, POLLIN, 0};
    return ::poll(&p, 1, timeoutMs) > 0;
}

int connectTcp(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr);
    return fd;
}

}  // namespace

TEST_CASE("doip sockets: TCP server accepts max + 1 testers and carries data both ways") {
    constexpr std::uint16_t kPort = 31400;
    platform::DoipTcpServer server(kPort, 1);
    const int a = connectTcp(kPort);
    const int b = connectTcp(kPort);
    const int c = connectTcp(kPort);  // beyond max + 1: closed by the server
    REQUIRE(readable(server.listenFd()));
    ::usleep(20000);
    const auto ids = server.acceptPending();
    REQUIRE(ids.size() == 2);
    CHECK_EQ(server.sockets().size(), 2U);

    const auto msg = doip::encode(doip::kVersion2012, doip::payload::kAliveCheckResponse, {0x0E, 0x80});
    ::send(a, msg.data(), msg.size(), 0);
    REQUIRE(readable(server.sockets()[0].fd));
    std::vector<std::uint8_t> data;
    CHECK(server.read(ids[0], data) == platform::DoipTcpServer::ReadResult::Data);
    CHECK(data == msg);

    CHECK(server.send(ids[1], msg));
    REQUIRE(readable(b));
    std::vector<std::uint8_t> back(64);
    CHECK_EQ(::recv(b, back.data(), back.size(), 0), static_cast<ssize_t>(msg.size()));

    REQUIRE(readable(c));
    CHECK_EQ(::recv(c, back.data(), back.size(), 0), 0);  // refused connection is closed

    ::close(a);
    REQUIRE(readable(server.sockets()[0].fd));
    CHECK(server.read(ids[0], data) == platform::DoipTcpServer::ReadResult::Closed);
    CHECK_EQ(server.sockets().size(), 1U);
    server.close(ids[1]);
    CHECK(server.sockets().empty());
    ::close(b);
    ::close(c);
}

TEST_CASE("doip sockets: UDP request and unicast answer") {
    constexpr std::uint16_t kPort = 31401;
    platform::DoipUdpSocket gw(kPort, "127.255.255.255");
    const int tester = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(kPort);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const auto vir = doip::encode(doip::kVersionDefault, doip::payload::kVehicleIdRequest, {});
    ::sendto(tester, vir.data(), vir.size(), 0, reinterpret_cast<sockaddr*>(&to), sizeof to);

    REQUIRE(readable(gw.fd()));
    std::vector<std::uint8_t> data;
    diag::UdpPeer peer;
    REQUIRE(gw.receive(data, peer));
    CHECK(data == vir);

    gw.sendTo(peer, {0x01, 0x02});
    REQUIRE(readable(tester));
    std::uint8_t buf[8];
    CHECK_EQ(::recv(tester, buf, sizeof buf, 0), 2);
    ::close(tester);
}
