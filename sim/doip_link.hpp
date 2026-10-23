#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/diag/doip_client.hpp"

// In-memory vehicle Ethernet for tests and simulation: TCP connections from
// the gateway's DoIP client to simulated DoIP entities. Events are queued and
// delivered by pump(), like frames on a real network.
namespace ccg::sim {

class DoipLink final : public diag::IDoipConnector {
public:
    // Transport for the simulated entity listening at `endpoint`; pass it to
    // the entity's constructor, then bind() the entity.
    diag::IDiagTransport& port(const std::string& endpoint);
    void bind(const std::string& endpoint, diag::DiagGateway& entity);
    void attach(diag::DoipClient& client) { client_ = &client; }

    void setReachable(const std::string& endpoint, bool reachable) { entities_[endpoint].reachable = reachable; }
    void setMuted(const std::string& endpoint, bool muted) { entities_[endpoint].muted = muted; }

    // diag::IDoipConnector
    void connect(diag::ConnectionId id, const std::string& endpoint) override;
    void send(diag::ConnectionId id, const std::vector<std::uint8_t>& data) override;
    void close(diag::ConnectionId id) override;

    void pump(diag::TimePoint now);

    // Traffic of entity connections that are not the gateway's (opened by a test).
    std::map<diag::ConnectionId, std::vector<std::vector<std::uint8_t>>>& foreign(const std::string& endpoint) {
        return entities_[endpoint].foreign;
    }
    std::uint64_t bytesToEntities() const { return bytesToEntities_; }

private:
    struct Port final : diag::IDiagTransport {
        DoipLink* link = nullptr;
        std::string endpoint;
        void sendTcp(diag::ConnectionId c, const std::vector<std::uint8_t>& d) override;
        void closeTcp(diag::ConnectionId c) override;
        void sendUdp(const diag::UdpPeer&, const std::vector<std::uint8_t>&) override {}
        void broadcastUdp(const std::vector<std::uint8_t>&) override {}
        bool transmitCan(std::size_t, const can::CanFrame&) override { return false; }
    };
    struct Entity {
        std::unique_ptr<Port> port;
        diag::DiagGateway* gateway = nullptr;
        bool reachable = true;
        bool muted = false;
        std::map<diag::ConnectionId, diag::ConnectionId> clientOf;  // entity connection -> client id
        std::map<diag::ConnectionId, std::vector<std::vector<std::uint8_t>>> foreign;
    };
    struct Event {
        enum class Kind : std::uint8_t { Connect, ToEntity, ToClient, CloseByClient, CloseByEntity } kind;
        diag::ConnectionId client = 0;
        std::string endpoint;
        std::vector<std::uint8_t> data;
    };

    diag::DoipClient* client_ = nullptr;
    std::map<std::string, Entity> entities_;
    std::map<diag::ConnectionId, std::pair<std::string, diag::ConnectionId>> routes_;  // client id -> entity conn
    std::deque<Event> events_;
    diag::ConnectionId nextEntityConnection_ = 100;
    std::uint64_t bytesToEntities_ = 0;
};

}  // namespace ccg::sim
