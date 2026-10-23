#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/doip/doip_message.hpp"

// DoIP client of the gateway (ISO 13400-2) for ECUs on the vehicle Ethernet
// that are DoIP entities themselves (e.g. the ADAS domain controller).
//
//   TCP connect -> routing activation (SA = in-vehicle test equipment 0x0F00)
//   -> diagnostic message -> diagnostic ACK -> diagnostic message (response)
//
// The connection is opened on the first request and kept; alive check
// requests of the entity are answered. Implements IDiagClient, so gateway
// functions (key master) use CAN and Ethernet ECUs alike.
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
    Milliseconds p2{1000};           // after the diagnostic ACK
    Milliseconds p2Star{5500};       // after NRC 0x78
};

std::vector<std::string> validateDoipClientConfig(const DoipClientConfig& config);

// TCP towards the DoIP entities (one connection per ECU route, id = route index + 1).
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
    std::uint64_t requests = 0;
    std::uint64_t responses = 0;
    std::uint64_t nacks = 0;
    std::uint64_t timeouts = 0;
    std::uint64_t aliveChecksAnswered = 0;
};

class DoipClient final : public IDiagClient {
public:
    DoipClient(DoipClientConfig config, IDoipConnector& connector);  // throws DiagConfigError

    void request(std::uint16_t target, std::vector<std::uint8_t> uds, TimePoint now, Callback callback) override;
    bool reaches(std::uint16_t target) const override;

    // Connector events.
    void onConnected(ConnectionId id, TimePoint now);
    void onData(ConnectionId id, const std::uint8_t* data, std::size_t length, TimePoint now);
    void onClosed(ConnectionId id, TimePoint now);  // also: connection attempt failed
    void mainFunction(TimePoint now);

    bool routingActive(std::uint16_t target) const;
    const DoipClientConfig& config() const { return config_; }
    const DoipClientStatistics& statistics() const { return stats_; }

private:
    enum class State : std::uint8_t { Closed, Connecting, Activating, Active };

    struct Pending {
        std::vector<std::uint8_t> uds;
        Callback callback;
        bool sent = false;
        bool acked = false;
    };

    struct Connection {
        explicit Connection(std::size_t maxPayload) : stream(maxPayload) {}
        State state = State::Closed;
        doip::StreamReassembler stream;
        TimePoint deadline{};
        std::optional<Pending> pending;
    };

    std::optional<std::size_t> routeOf(std::uint16_t target) const;
    void handle(std::size_t index, const doip::StreamReassembler::Item& item, TimePoint now);
    void sendPending(std::size_t index, TimePoint now);
    void send(std::size_t index, std::uint16_t type, const std::vector<std::uint8_t>& payload);
    void drop(std::size_t index, ClientResult result);  // closes the connection, fails the request
    void complete(std::size_t index, ClientResult result, std::vector<std::uint8_t> response);

    DoipClientConfig config_;
    IDoipConnector& connector_;
    std::vector<Connection> connections_;
    DoipClientStatistics stats_;
};

}  // namespace ccg::diag
