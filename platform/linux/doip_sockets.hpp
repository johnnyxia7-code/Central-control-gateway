#pragma once

#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"

namespace ccg::platform {

// DoIP TCP data socket listener (port 13400). Accepts maxConnections + 1
// sockets so that a surplus tester still gets a routing activation answer;
// further connections are closed right away.
class DoipTcpServer {
public:
    DoipTcpServer(std::uint16_t port, std::size_t maxConnections);
    ~DoipTcpServer();
    DoipTcpServer(const DoipTcpServer&) = delete;
    DoipTcpServer& operator=(const DoipTcpServer&) = delete;

    int listenFd() const { return listenFd_; }
    std::vector<diag::ConnectionId> acceptPending();

    struct Socket {
        int fd;
        diag::ConnectionId id;
    };
    std::vector<Socket> sockets() const;

    enum class ReadResult { Data, Nothing, Closed };
    ReadResult read(diag::ConnectionId id, std::vector<std::uint8_t>& data);
    bool send(diag::ConnectionId id, const std::vector<std::uint8_t>& data);
    void close(diag::ConnectionId id);

private:
    int listenFd_ = -1;
    std::size_t maxConnections_;
    diag::ConnectionId nextId_ = 1;
    std::map<diag::ConnectionId, int> connections_;
};

// DoIP UDP socket: vehicle identification requests and announcements.
class DoipUdpSocket {
public:
    DoipUdpSocket(std::uint16_t port, const std::string& broadcastAddress);
    ~DoipUdpSocket();
    DoipUdpSocket(const DoipUdpSocket&) = delete;
    DoipUdpSocket& operator=(const DoipUdpSocket&) = delete;

    int fd() const { return fd_; }
    bool receive(std::vector<std::uint8_t>& data, diag::UdpPeer& peer);
    void sendTo(const diag::UdpPeer& peer, const std::vector<std::uint8_t>& data);
    void broadcast(const std::vector<std::uint8_t>& data);

    static diag::UdpPeer toPeer(const sockaddr_in& addr);
    static sockaddr_in toAddress(const diag::UdpPeer& peer);

private:
    int fd_ = -1;
    sockaddr_in broadcast_{};
};

}  // namespace ccg::platform
