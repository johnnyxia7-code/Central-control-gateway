#pragma once

#include <netinet/in.h>

#include <cstdint>
#include <string>
#include <vector>

namespace ccg::platform {

// Point-to-point UDP socket connection of one Ethernet gateway channel
// (AUTOSAR SoAd socket connection with a fixed remote address).
class UdpSocket {
public:
    UdpSocket(std::uint16_t localPort, const std::string& remoteIp, std::uint16_t remotePort);
    ~UdpSocket();
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    bool send(const std::vector<std::uint8_t>& datagram);

    // Non-blocking; returns false when no datagram is pending. Datagrams from
    // other senders than the configured remote are dropped.
    bool receive(std::vector<std::uint8_t>& datagram);

    int fd() const { return fd_; }

private:
    int fd_ = -1;
    sockaddr_in remote_{};
};

}  // namespace ccg::platform
