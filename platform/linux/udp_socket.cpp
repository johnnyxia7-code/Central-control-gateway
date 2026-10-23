#include "udp_socket.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <stdexcept>
#include <system_error>

namespace ccg::platform {

UdpSocket::UdpSocket(std::uint16_t localPort, const std::string& remoteIp,
                     std::uint16_t remotePort) {
    remote_.sin_family = AF_INET;
    remote_.sin_port = htons(remotePort);
    if (::inet_pton(AF_INET, remoteIp.c_str(), &remote_.sin_addr) != 1) {
        throw std::invalid_argument("invalid IPv4 address: " + remoteIp);
    }
    fd_ = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "socket(AF_INET)");
    }
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(localPort);
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&local), sizeof local) < 0) {
        const int err = errno;
        ::close(fd_);
        throw std::system_error(err, std::generic_category(), "bind(UDP)");
    }
}

UdpSocket::~UdpSocket() {
    if (fd_ >= 0) {
        ::close(fd_);
    }
}

bool UdpSocket::send(const std::vector<std::uint8_t>& datagram) {
    const auto n = ::sendto(fd_, datagram.data(), datagram.size(), 0,
                            reinterpret_cast<const sockaddr*>(&remote_), sizeof remote_);
    return n == static_cast<ssize_t>(datagram.size());
}

bool UdpSocket::receive(std::vector<std::uint8_t>& datagram) {
    for (;;) {
        datagram.resize(65536);
        sockaddr_in from{};
        socklen_t fromLen = sizeof from;
        const auto n = ::recvfrom(fd_, datagram.data(), datagram.size(), 0,
                                  reinterpret_cast<sockaddr*>(&from), &fromLen);
        if (n < 0) {
            datagram.clear();
            return false;
        }
        if (from.sin_addr.s_addr != remote_.sin_addr.s_addr || from.sin_port != remote_.sin_port) {
            continue;  // not our peer
        }
        datagram.resize(static_cast<std::size_t>(n));
        return true;
    }
}

}  // namespace ccg::platform
