#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <vector>

#include "ccg/diag/doip_client.hpp"
#include "ccg/doip/doip_message.hpp"
#include "doip_ecu.hpp"
#include "doip_sockets.hpp"
#include "doip_tcp_connector.hpp"
#include "test_framework.hpp"
#include "vehicle_diag_routing.hpp"
#include "vehicle_key_master.hpp"

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

namespace {

// Server side of the simulated ADAS entity on a real TCP socket.
struct TcpPort final : diag::IDiagTransport {
    platform::DoipTcpServer* server = nullptr;
    void sendTcp(diag::ConnectionId c, const std::vector<std::uint8_t>& d) override { server->send(c, d); }
    void closeTcp(diag::ConnectionId c) override { server->close(c); }
    void sendUdp(const diag::UdpPeer&, const std::vector<std::uint8_t>&) override {}
    void broadcastUdp(const std::vector<std::uint8_t>&) override {}
    bool transmitCan(std::size_t, const can::CanFrame&) override { return false; }
};

}  // namespace

TEST_CASE("doip sockets: gateway DoIP client reaches a DoIP entity over TCP") {
    constexpr std::uint16_t kPort = 31402;
    platform::DoipTcpServer server(kPort, 2);
    TcpPort port;
    port.server = &server;
    auto entityCfg = config::makeAdasDoipEntity();
    entityCfg.entity.requireTls = false;  // plain DoIP here; TLS: test_doip_tls_linux.cpp
    sim::DoipEcu adas(entityCfg, config::makeEcuKeySlots(config::dg::kAdas), port);
    auto clientCfg = config::makeVehicleDoipClient();
    clientCfg.ecus[0].endpoint = "127.0.0.1:" + std::to_string(kPort);
    clientCfg.ecus[0].tls = false;
    platform::DoipTcpConnector connector;
    diag::DoipClient client(clientCfg, connector);
    connector.attach(client);
    auto now = diag::Clock::now();
    adas.entity().start(now);

    std::vector<std::pair<diag::ClientResult, std::vector<std::uint8_t>>> results;
    client.request(config::dg::kAdas, {0x22, 0xF2, 0xA1}, now,
                   [&](diag::ClientResult r, std::vector<std::uint8_t> d) { results.emplace_back(r, std::move(d)); });
    std::vector<std::uint8_t> buffer;
    for (int i = 0; i < 400 && results.empty(); ++i) {
        auto fds = connector.pollFds();
        fds.push_back({server.listenFd(), POLLIN, 0});
        const auto sockets = server.sockets();
        for (const auto& s : sockets) fds.push_back({s.fd, POLLIN, 0});
        ::poll(fds.data(), fds.size(), 5);
        now = diag::Clock::now();
        connector.process(fds, now);
        for (const auto id : server.acceptPending()) adas.entity().onTcpConnected(id, now);
        for (const auto& s : sockets) {
            while (server.read(s.id, buffer) == platform::DoipTcpServer::ReadResult::Data) {
                adas.entity().onTcpData(s.id, buffer.data(), buffer.size(), now);
            }
        }
        client.mainFunction(now);
        adas.entity().mainFunction(now);
    }
    REQUIRE(results.size() == 1u);
    CHECK(results[0].first == diag::ClientResult::Ok);
    REQUIRE(results[0].second.size() == 3u + 15u);
    CHECK(std::equal(adas.keys().config().uid.begin(), adas.keys().config().uid.end(), results[0].second.begin() + 3));
    CHECK(client.routingActive(config::dg::kAdas));

    // Nobody listening: the connection attempt fails and is reported.
    clientCfg.ecus[0].endpoint = "127.0.0.1:31403";
    platform::DoipTcpConnector refused;
    diag::DoipClient lonely(clientCfg, refused);
    refused.attach(lonely);
    results.clear();
    lonely.request(config::dg::kAdas, {0x3E, 0x00}, now,
                   [&](diag::ClientResult r, std::vector<std::uint8_t> d) { results.emplace_back(r, std::move(d)); });
    for (int i = 0; i < 100 && results.empty(); ++i) {
        auto fds = refused.pollFds();
        ::poll(fds.data(), fds.size(), 5);
        refused.process(fds, diag::Clock::now());
    }
    REQUIRE(results.size() == 1u);
    CHECK(results[0].first == diag::ClientResult::TransportError);
}
