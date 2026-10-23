#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <vector>

#include "test_framework.hpp"
#include "udp_socket.hpp"

using namespace ccg;

namespace {

bool waitReadable(int fd) {
    pollfd p{fd, POLLIN, 0};
    return ::poll(&p, 1, 1000) > 0;
}

}  // namespace

TEST_CASE("udp socket: point-to-point datagrams, foreign senders dropped") {
    constexpr std::uint16_t kPortA = 30911;
    constexpr std::uint16_t kPortB = 30912;
    platform::UdpSocket a(kPortA, "127.0.0.1", kPortB);
    platform::UdpSocket b(kPortB, "127.0.0.1", kPortA);

    const std::vector<std::uint8_t> payload = {0x00, 0x00, 0x00, 0xB0, 0x00, 0x00, 0x00, 0x01, 0x42};
    CHECK(a.send(payload));
    REQUIRE(waitReadable(b.fd()));
    std::vector<std::uint8_t> received;
    REQUIRE(b.receive(received));
    CHECK(received == payload);
    CHECK(!b.receive(received));  // nothing more pending

    // A datagram from an unexpected sender is discarded.
    const int stranger = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(kPortB);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const std::uint8_t junk[] = {1, 2, 3};
    ::sendto(stranger, junk, sizeof junk, 0, reinterpret_cast<sockaddr*>(&to), sizeof to);
    ::close(stranger);
    REQUIRE(waitReadable(b.fd()));
    CHECK(!b.receive(received));
}
