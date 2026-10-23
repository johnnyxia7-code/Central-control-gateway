#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/doip/doip_message.hpp"

// DoIP client of the gateway (ISO 13400-2) for ECUs on the vehicle Ethernet
// that are DoIP entities themselves (e.g. the ADAS domain controller).
//
//   TCP connect -> routing activation (SA) -> diagnostic message -> diagnostic
//   ACK -> diagnostic message(s) (response, NRC 0x78 ...)
//
// Two users:
//  - gateway functions (key master) through IDiagClient::request(), with the
//    gateway's own source address 0x0F00 (in-vehicle test equipment);
//  - DoIP-to-DoIP routing of external testers through route(), with the
//    tester's source address passed through, so the ECU sees who asks.
//
// One TCP connection per (ECU, source address), opened on demand and kept;
// alive check requests of the entity are answered.
namespace ccg::diag {

struct DoipEcuRoute {
    std::string name;
    std::uint16_t logicalAddress = 0;  // DoIP entity address (target address)
    std::string endpoint;              // "ip:port", resolved by the connector
};

struct DoipClientConfig {
    std::uint16_t sourceAddress = 0x0F00;  // ISO 13400-2: internal test equipment 0x0F00..0x0F7F
    std::uint8_t protocolVersion = doip::kVersion2012;
    std::uint8_t activationType = 0x00;  // default
    std::size_t maxMessageSize = 4095;   // UDS bytes per response
    std::vector<DoipEcuRoute> ecus;
    Milliseconds connectTimeout{2000};
    Milliseconds ctrlTimeout{2000};  // A_DoIP_Ctrl: routing activation response, diagnostic ACK
    Milliseconds p2{1000};           // after the diagnostic ACK (internal requests)
    Milliseconds p2Star{5500};       // after NRC 0x78 (internal requests)
};

std::vector<std::string> validateDoipClientConfig(const DoipClientConfig& config);

// TCP towards the DoIP entities. Connection IDs are chosen by the client.
class IDoipConnector {
public:
    virtual ~IDoipConnector() = default;
    // Completion is reported with DoipClient::onConnected or onClosed.
    virtual void connect(ConnectionId id, const std::string& endpoint) = 0;
    virtual void send(ConnectionId id, const std::vector<std::uint8_t>& data) = 0;
    virtual void close(ConnectionId id) = 0;
};

struct DoipClientStatistics {
    std::uint64_t connects = 0;
    std::uint64_t connectFailures = 0;
    std::uint64_t activations = 0;
    std::uint64_t activationFailures = 0;
    std::uint64_t requests = 0;          // internal
    std::uint64_t responses = 0;         // internal
    std::uint64_t routedRequests = 0;    // tester requests forwarded
    std::uint64_t routedResponses = 0;   // entity messages forwarded to testers
    std::uint64_t nacks = 0;
    std::uint64_t timeouts = 0;
    std::uint64_t aliveChecksAnswered = 0;
};

class DoipClient final : public IDiagClient {
public:
    DoipClient(DoipClientConfig config, IDoipConnector& connector);  // throws DiagConfigError

    // --- IDiagClient (gateway functions)
    void request(std::uint16_t target, std::vector<std::uint8_t> uds, TimePoint now, Callback callback) override;
    bool reaches(std::uint16_t target) const override;

    // --- DoIP-to-DoIP routing of a tester's diagnostic message
    struct RouteHandlers {
        // Once: nullopt = the entity acknowledged; otherwise the NACK code for the tester.
        std::function<void(std::optional<doip::DiagNack> nack)> delivered;
        // Every diagnostic message of the entity for this tester (responses, NRC 0x78, ...).
        std::function<void(std::vector<std::uint8_t> uds)> response;
    };
    // `ecu` selects the route; `targetOnWire` is the target address sent (the
    // ECU's address, or the functional address).
    void route(std::uint16_t source, std::uint16_t ecu, std::uint16_t targetOnWire, std::vector<std::uint8_t> uds,
               TimePoint now, RouteHandlers handlers);
    // The tester left: its connections to the entities are closed.
    void closeSource(std::uint16_t source);

    // --- connector events
    void onConnected(ConnectionId id, TimePoint now);
    void onData(ConnectionId id, const std::uint8_t* data, std::size_t length, TimePoint now);
    void onClosed(ConnectionId id, TimePoint now);  // also: connection attempt failed
    void mainFunction(TimePoint now);

    bool routingActive(std::uint16_t target) const { return routingActive(target, config_.sourceAddress); }
    bool routingActive(std::uint16_t target, std::uint16_t source) const;
    std::size_t openConnections() const;
    const DoipClientConfig& config() const { return config_; }
    const DoipClientStatistics& statistics() const { return stats_; }

private:
    enum class State : std::uint8_t { Closed, Connecting, Activating, Active };

    struct Pending {  // internal request
        std::vector<std::uint8_t> uds;
        Callback callback;
        bool sent = false;
        bool acked = false;
    };

    struct Routed {  // tester request, until the entity's ACK
        std::uint16_t targetOnWire = 0;
        std::vector<std::uint8_t> uds;
        RouteHandlers handlers;
        bool sent = false;
    };

    struct Connection {
        Connection(std::size_t r, std::uint16_t s, std::size_t maxPayload) : route(r), source(s), stream(maxPayload) {}
        std::size_t route;
        std::uint16_t source;
        State state = State::Closed;
        doip::StreamReassembler stream;
        TimePoint deadline{};
        std::optional<Pending> pending;
        std::optional<Routed> routed;
        std::function<void(std::vector<std::uint8_t>)> sink;  // tester receiving the entity's messages
    };

    std::optional<std::size_t> routeOf(std::uint16_t target) const;
    ConnectionId connectionFor(std::size_t route, std::uint16_t source);
    const Connection* find(std::size_t route, std::uint16_t source) const;
    void open(ConnectionId id, TimePoint now);
    void flush(ConnectionId id, TimePoint now);  // sends what waits for an active connection
    void handle(ConnectionId id, const doip::StreamReassembler::Item& item, TimePoint now);
    void send(ConnectionId id, std::uint16_t type, const std::vector<std::uint8_t>& payload);
    void drop(ConnectionId id, ClientResult result);  // closes the connection, fails what is open
    void complete(ConnectionId id, ClientResult result, std::vector<std::uint8_t> response);
    void deliver(ConnectionId id, std::optional<doip::DiagNack> nack);

    DoipClientConfig config_;
    IDoipConnector& connector_;
    std::map<ConnectionId, Connection> connections_;
    ConnectionId nextId_ = 1;
    DoipClientStatistics stats_;
};

}  // namespace ccg::diag
