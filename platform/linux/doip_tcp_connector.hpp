#pragma once

#include <poll.h>

#include <deque>
#include <map>
#include <string>
#include <vector>

#include "ccg/diag/doip_client.hpp"

// TCP connections of the gateway's DoIP client to DoIP entities on the
// vehicle Ethernet (non-blocking connect, for a poll() loop).
//
//   connector.attach(client);
//   loop: fds = connector.pollFds(); poll(...); connector.process(fds, now);
namespace ccg::platform {

class DoipTcpConnector final : public diag::IDoipConnector {
public:
    DoipTcpConnector() = default;
    ~DoipTcpConnector();
    DoipTcpConnector(const DoipTcpConnector&) = delete;
    DoipTcpConnector& operator=(const DoipTcpConnector&) = delete;

    void attach(diag::DoipClient& client) { client_ = &client; }

    // diag::IDoipConnector; endpoint "a.b.c.d:port"
    void connect(diag::ConnectionId id, const std::string& endpoint) override;
    void send(diag::ConnectionId id, const std::vector<std::uint8_t>& data) override;
    void close(diag::ConnectionId id) override;

    // Sockets to watch (POLLOUT while connecting, POLLIN when connected).
    std::vector<pollfd> pollFds() const;
    // Handles the poll results and reports connection events and data to the client.
    void process(const std::vector<pollfd>& fds, diag::TimePoint now);

private:
    struct Socket {
        int fd = -1;
        bool connected = false;
    };
    void fail(diag::ConnectionId id);  // closes and reports onClosed at the next process()

    diag::DoipClient* client_ = nullptr;
    std::map<diag::ConnectionId, Socket> sockets_;
    std::deque<diag::ConnectionId> failed_;
};

}  // namespace ccg::platform
