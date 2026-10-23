#pragma once

#include <cstdint>

#include "ccg/can/can_frame.hpp"
#include "ccg/s2s/s2s_config.hpp"
#include "ccg/someip/someip_message.hpp"

namespace ccg::s2s {

// Opaque address of a SOME/IP communication partner, owned by the binding
// (e.g. IPv4 address + UDP port of the requester or subscriber).
struct Peer {
    std::uint64_t token = 0;
};

struct RequestContext {
    std::uint16_t instanceId = 0;  // instance the request was received on
    Peer peer;                     // where responses go
};

// Lower layer towards the CAN controller (SocketCAN, CanIf, ...).
class ICanTransmitter {
public:
    virtual ~ICanTransmitter() = default;
    virtual bool transmit(const can::CanFrame& frame) = 0;
};

// Lower layer towards the SOME/IP stack (vsomeip, ara::com binding, raw UDP, ...).
// The binding owns service discovery and the subscriber lists.
class ISomeIpBinding {
public:
    virtual ~ISomeIpBinding() = default;
    virtual void offerService(const ServiceInstance& service) = 0;
    // Event / field notification to all subscribers of the eventgroup.
    virtual void notify(std::uint16_t serviceId, std::uint16_t instanceId,
                        std::uint16_t eventgroupId, const someip::Message& message) = 0;
    // Unicast: method responses and initial field events.
    virtual void sendTo(const Peer& peer, const someip::Message& message) = 0;
};

}  // namespace ccg::s2s
