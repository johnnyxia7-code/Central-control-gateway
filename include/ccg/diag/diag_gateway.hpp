#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "ccg/can/can_frame.hpp"
#include "ccg/diag/diag_config.hpp"
#include "ccg/doip/doip_message.hpp"
#include "ccg/isotp/isotp_channel.hpp"

namespace ccg::diag {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using ConnectionId = std::uint32_t;

// Opaque UDP address (IPv4 + port) owned by the binding.
struct UdpPeer {
    std::uint64_t token = 0;
};

class IDiagTransport {
public:
    virtual ~IDiagTransport() = default;
    virtual void sendTcp(ConnectionId connection, const std::vector<std::uint8_t>& data) = 0;
    virtual void closeTcp(ConnectionId connection) = 0;
    virtual void sendUdp(const UdpPeer& peer, const std::vector<std::uint8_t>& data) = 0;
    virtual void broadcastUdp(const std::vector<std::uint8_t>& data) = 0;
    virtual bool transmitCan(std::size_t channel, const can::CanFrame& frame) = 0;
};

struct DiagStatistics {
    std::uint64_t tcpConnectionsAccepted = 0;
    std::uint64_t tcpConnectionsClosed = 0;
    std::uint64_t routingActivationsAccepted = 0;
    std::uint64_t routingActivationsRejected = 0;
    std::uint64_t aliveChecksSent = 0;
    std::uint64_t headerNacks = 0;
    std::uint64_t vehicleIdResponses = 0;
    std::uint64_t announcements = 0;
    std::uint64_t diagRequests = 0;
    std::uint64_t diagAcks = 0;
    std::uint64_t diagNacks = 0;
    std::uint64_t functionalRequests = 0;
    std::uint64_t localRequests = 0;
    std::uint64_t ecuResponses = 0;
    std::uint64_t responsesDropped = 0;
    std::uint64_t isotpTxErrors = 0;
    std::uint64_t isotpRxErrors = 0;
    std::uint64_t tlsConnections = 0;
    std::uint64_t authenticatedConnections = 0;  // TLS with verified client certificate
    std::uint64_t ethernetRequests = 0;   // routed to DoIP entities on the vehicle Ethernet
    std::uint64_t ethernetResponses = 0;
};

// Security of a tester's TCP_DATA connection (ISO 13400-2:2019).
struct ConnectionSecurity {
    bool tls = false;                  // TLS socket (port 3496)
    bool clientAuthenticated = false;  // client certificate verified against the tester CA
    std::string peer;                  // subject CN of the client certificate
};

// Activation types (ISO 13400-2)
inline constexpr std::uint8_t kActivationDefault = 0x00;
inline constexpr std::uint8_t kActivationWwhObd = 0x01;
inline constexpr std::uint8_t kActivationCentralSecurity = 0xE0;

// Request to the gateway's own UDS server, as seen by a local service handler.
struct LocalRequestContext {
    std::uint8_t session = 0x01;  // active diagnostic session of the gateway
    bool functional = false;      // functional (0xE400) or physical request
    TimePoint now{};
    bool tls = false;             // request arrived on a TLS socket
    bool authenticated = false;   // ... from a tester with a verified client certificate
};

// Additional UDS services of the gateway's own diagnostic server (e.g. key
// management). Handlers are asked before the built-in services.
class ILocalServiceHandler {
public:
    virtual ~ILocalServiceHandler() = default;
    // nullopt: not handled here. Otherwise the response: positive, negative
    // (7F SID NRC) or empty for "no response" (suppressPosRspMsgIndicationBit).
    virtual std::optional<std::vector<std::uint8_t>> handle(const std::vector<std::uint8_t>& request,
                                                            const LocalRequestContext& context) = 0;
};

// Gateway-internal diagnostic client (e.g. the key master): UDS requests from
// the gateway itself to an ECU, over the same ISO-TP channel as the testers.
enum class ClientResult : std::uint8_t {
    Ok,              // final response received (positive or negative)
    Busy,            // a tester or another internal request is using the ECU
    UnknownTarget,
    TransportError,  // ISO-TP transmission failed (e.g. no flow control)
    Timeout,         // no final response within P2 / P2* (after NRC 0x78)
};

const char* toString(ClientResult result);

class IDiagClient {
public:
    using Callback = std::function<void(ClientResult result, std::vector<std::uint8_t> response)>;
    virtual ~IDiagClient() = default;
    // Physical request to the ECU with `target` logical address. The callback
    // runs exactly once, possibly before request() returns; it must not send
    // the next request itself (do that from the client's own main function).
    virtual void request(std::uint16_t target, std::vector<std::uint8_t> uds, TimePoint now,
                         Callback callback) = 0;
    // True if this client has a route to `target`.
    virtual bool reaches(std::uint16_t target) const = 0;
};

// Sends each request through the first client that reaches the target (CAN
// ECUs via the diagnostic gateway, Ethernet ECUs via the DoIP client).
class DiagClientRouter final : public IDiagClient {
public:
    void add(IDiagClient& client) { clients_.push_back(&client); }
    void request(std::uint16_t target, std::vector<std::uint8_t> uds, TimePoint now, Callback callback) override {
        for (auto* c : clients_) {
            if (c->reaches(target)) return c->request(target, std::move(uds), now, std::move(callback));
        }
        callback(ClientResult::UnknownTarget, {});
    }
    bool reaches(std::uint16_t target) const override {
        for (const auto* c : clients_) {
            if (c->reaches(target)) return true;
        }
        return false;
    }

private:
    std::vector<IDiagClient*> clients_;
};

class DoipClient;

class DiagConfigError : public std::runtime_error {
public:
    explicit DiagConfigError(std::vector<std::string> errors);
    const std::vector<std::string>& errors() const { return errors_; }

private:
    std::vector<std::string> errors_;
};

// DoIP edge node / gateway: DoIP (TCP + UDP) towards the tester, UDS over
// ISO-TP on the CAN channels towards the ECUs.
//
// Single threaded: all entry points are called from one executor, every 1 ms
// for mainFunction().
class DiagGateway final : public IDiagClient {
public:
    DiagGateway(DiagRoutingConfig config, IDiagTransport& transport);

    // Starts the vehicle announcements.
    void start(TimePoint now);

    // `security`: what the TLS layer established (plain TCP by default).
    void onTcpConnected(ConnectionId connection, TimePoint now, const ConnectionSecurity& security = {});
    void onTcpData(ConnectionId connection, const std::uint8_t* data, std::size_t length,
                   TimePoint now);
    void onTcpClosed(ConnectionId connection, TimePoint now);  // closed by the peer
    void onUdpDatagram(const UdpPeer& peer, const std::uint8_t* data, std::size_t length,
                       TimePoint now);
    void onCanFrame(std::size_t channel, const can::CanFrame& frame, TimePoint now);
    void mainFunction(TimePoint now);

    // The handler must outlive the gateway.
    void addLocalService(ILocalServiceHandler& handler) { localHandlers_.push_back(&handler); }

    // DoIP-to-DoIP routing: tester requests to the client's Ethernet ECUs (and
    // functional requests) are forwarded through it with the tester's source
    // address. The client must outlive the gateway's use of it.
    void setEthernetRouting(DoipClient& client) { ethernet_ = &client; }

    // IDiagClient. While an internal request is open, tester requests to that
    // ECU are refused (diagnostic NACK) and its responses go to the callback.
    void request(std::uint16_t target, std::vector<std::uint8_t> uds, TimePoint now,
                 Callback callback) override;
    bool reaches(std::uint16_t target) const override { return ecuByAddress_.count(target) > 0; }

    std::optional<std::size_t> channelIndex(const std::string& name) const;
    bool isRoutingActive(ConnectionId connection) const;
    std::size_t openConnections() const { return connections_.size(); }
    const DiagStatistics& statistics() const { return stats_; }
    const DiagRoutingConfig& config() const { return config_; }

private:
    struct Requester {
        ConnectionId connection = 0;
        std::uint16_t tester = 0;
    };

    struct Connection {
        explicit Connection(std::size_t maxPayload) : stream(maxPayload) {}
        doip::StreamReassembler stream;
        TimePoint connectedAt{};
        TimePoint lastActivity{};
        bool registered = false;
        std::uint16_t tester = 0;
        std::uint8_t version = doip::kVersion2012;
        ConnectionSecurity security;
    };

    struct PendingActivation {
        ConnectionId connection = 0;
        std::uint16_t tester = 0;
        bool sourceInUse = false;            // else: all sockets in use
        std::set<ConnectionId> waiting;      // alive check sent, no answer yet
        bool anyGone = false;                // a probed connection is dead
        TimePoint deadline{};
    };

    struct InternalRequest {
        Callback callback;
        TimePoint deadline{};
    };

    struct Ecu {
        std::size_t channel = 0;
        std::unique_ptr<isotp::Channel> tp;
        std::optional<InternalRequest> internal;  // gateway-internal client request
        std::optional<Requester> awaitingAck;    // physical request in ISO-TP transmission
        std::optional<Requester> responseOwner;  // tester that gets the ECU responses
    };

    void handleTcpMessage(ConnectionId id, const doip::StreamReassembler::Item& item, TimePoint now);
    void handleRoutingActivation(ConnectionId id, const std::vector<std::uint8_t>& payload,
                                 TimePoint now);
    void handleAliveCheckResponse(ConnectionId id);
    void handleDiagnosticMessage(ConnectionId id, const std::vector<std::uint8_t>& payload,
                                 TimePoint now);
    void handleFunctionalRequest(const Requester& req, const std::vector<std::uint8_t>& data,
                                 TimePoint now);
    void routeToEthernet(const Requester& req, std::uint16_t ecu, std::uint16_t targetOnWire,
                         std::vector<std::uint8_t> data, bool functional, TimePoint now);
    bool testerConnected(const Requester& req) const;
    std::optional<std::vector<std::uint8_t>> localService(const std::vector<std::uint8_t>& request,
                                                          bool functional, TimePoint now,
                                                          const ConnectionSecurity& security);

    void evaluatePendingActivation();
    void finishActivation(bool accept, doip::ActivationCode rejectCode);
    void sendAliveCheck(ConnectionId id);
    void closeConnection(ConnectionId id, bool notifyTransport);

    void onEcuTxDone(std::size_t ecu, isotp::Result result);
    void finishInternal(std::size_t ecu, ClientResult result, std::vector<std::uint8_t> response);
    void onEcuResponse(std::size_t ecu, std::vector<std::uint8_t>&& data);

    void sendTcp(ConnectionId id, std::uint16_t type, const std::vector<std::uint8_t>& payload);
    void sendHeaderNack(ConnectionId id, doip::HeaderNack code);
    void sendDiagAck(const Requester& req, std::uint16_t source);
    void sendDiagNack(const Requester& req, std::uint16_t source, doip::DiagNack code);
    void sendDiagMessage(const Requester& req, std::uint16_t source,
                         const std::vector<std::uint8_t>& data);
    void sendUdp(const UdpPeer& peer, std::uint8_t version, std::uint16_t type,
                 const std::vector<std::uint8_t>& payload);
    bool isTester(std::uint16_t address) const;
    doip::EntityIdentity identity() const;

    DiagRoutingConfig config_;
    IDiagTransport& transport_;
    DiagStatistics stats_;
    std::size_t maxTcpPayload_ = 0;

    std::map<ConnectionId, Connection> connections_;
    std::optional<PendingActivation> pending_;
    std::vector<Ecu> ecus_;
    std::unordered_map<std::uint64_t, std::size_t> ecuByRxId_;
    std::unordered_map<std::uint16_t, std::size_t> ecuByAddress_;
    std::unordered_map<std::string, std::size_t> channelByName_;

    std::uint8_t announcementsLeft_ = 0;
    TimePoint nextAnnouncement_{};
    std::vector<ILocalServiceHandler*> localHandlers_;
    DoipClient* ethernet_ = nullptr;
    TimePoint now_{};  // latest time seen, for callbacks without a time argument
    std::uint8_t localSession_ = 0x01;
    TimePoint localSessionActivity_{};
};

}  // namespace ccg::diag
