#pragma once

#include <netinet/in.h>

#include <cstdint>
#include <map>
#include <string>
#include <tuple>
#include <vector>

#include "ccg/s2s/transport.hpp"

namespace ccg::platform {

// Minimal SOME/IP over UDP binding for bench / HIL use.
//
// Service discovery is replaced by static configuration ("static SD"): the
// subscribers of every eventgroup are configured up front. In a vehicle this
// class is replaced by the production SOME/IP stack (vsomeip, ara::com, ...)
// behind the same s2s::ISomeIpBinding interface.
class SomeIpUdpBinding final : public s2s::ISomeIpBinding {
public:
    struct Received {
        someip::Message message;
        s2s::RequestContext context;
    };

    SomeIpUdpBinding(std::uint16_t localPort, std::uint16_t instanceId);
    ~SomeIpUdpBinding() override;
    SomeIpUdpBinding(const SomeIpUdpBinding&) = delete;
    SomeIpUdpBinding& operator=(const SomeIpUdpBinding&) = delete;

    void addStaticSubscriber(std::uint16_t serviceId, std::uint16_t instanceId,
                             std::uint16_t eventgroupId, const std::string& ipv4,
                             std::uint16_t port);

    // Drains one datagram (which may carry several SOME/IP messages).
    std::vector<Received> receive();

    void offerService(const s2s::ServiceInstance& service) override;
    void notify(std::uint16_t serviceId, std::uint16_t instanceId, std::uint16_t eventgroupId,
                const someip::Message& message) override;
    void sendTo(const s2s::Peer& peer, const someip::Message& message) override;

    int fd() const { return fd_; }

    static s2s::Peer toPeer(const sockaddr_in& addr);
    static sockaddr_in toAddress(const s2s::Peer& peer);

private:
    void send(const sockaddr_in& to, const someip::Message& message);

    int fd_ = -1;
    std::uint16_t instanceId_;
    std::map<std::tuple<std::uint16_t, std::uint16_t, std::uint16_t>, std::vector<sockaddr_in>>
        subscribers_;
};

}  // namespace ccg::platform
