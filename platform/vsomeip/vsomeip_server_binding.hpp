#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <vsomeip/vsomeip.hpp>

#include "ccg/s2s/s2s_config.hpp"
#include "ccg/s2s/transport.hpp"

namespace ccg::platform {

// HPC side: s2s::ISomeIpBinding on top of a vsomeip application, replacing the
// static-SD UDP binding so that clients (e.g. the Android IVI) find the S2S
// services through SOME/IP-SD.
//
// vsomeip delivers requests and subscriptions on its own threads, while the
// S2SGateway is single threaded. Inbound traffic is therefore queued and
// signalled through an eventfd; the gateway executor drains it with receive().
class VsomeipServerBinding final : public s2s::ISomeIpBinding {
public:
    struct Inbound {
        enum class Kind : std::uint8_t { Request, Subscribe };
        Kind kind = Kind::Request;
        someip::Message message;       // Request
        std::uint16_t serviceId = 0;   // Subscribe
        std::uint16_t eventgroupId = 0;
        s2s::RequestContext context;   // instance + peer (request or subscriber)
    };

    explicit VsomeipServerBinding(std::string applicationName);
    ~VsomeipServerBinding() override;
    VsomeipServerBinding(const VsomeipServerBinding&) = delete;
    VsomeipServerBinding& operator=(const VsomeipServerBinding&) = delete;

    // Creates the application and registers events, handlers and subscription
    // handlers of every service in the matrix. Call before S2SGateway::start().
    bool init(const s2s::GatewayConfig& config);
    void start();
    void stop();

    // Readable when receive() has something to deliver.
    int fd() const { return eventFd_; }
    std::vector<Inbound> receive();

    void offerService(const s2s::ServiceInstance& service) override;
    void notify(std::uint16_t serviceId, std::uint16_t instanceId, std::uint16_t eventgroupId,
                const someip::Message& message) override;
    void sendTo(const s2s::Peer& peer, const someip::Message& message) override;

    std::uint64_t droppedResponses() const;

private:
    void enqueue(Inbound inbound);

    std::string name_;
    std::shared_ptr<vsomeip::application> app_;
    std::thread thread_;
    int eventFd_ = -1;

    mutable std::mutex mutex_;
    std::vector<Inbound> inbox_;
    // Requests waiting for their response, keyed by the Peer token handed to the gateway.
    std::map<std::uint64_t, std::shared_ptr<vsomeip::message>> pendingRequests_;
    std::uint64_t nextToken_ = 1;
    std::uint64_t droppedResponses_ = 0;
};

}  // namespace ccg::platform
