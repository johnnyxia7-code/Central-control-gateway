#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
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
};

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
class DiagGateway {
public:
    DiagGateway(DiagRoutingConfig config, IDiagTransport& transport);

    // Starts the vehicle announcements.
    void start(TimePoint now);

    void onTcpConnected(ConnectionId connection, TimePoint now);
    void onTcpData(ConnectionId connection, const std::uint8_t* data, std::size_t length,
                   TimePoint now);
    void onTcpClosed(ConnectionId connection, TimePoint now);  // closed by the peer
    void onUdpDatagram(const UdpPeer& peer, const std::uint8_t* data, std::size_t length,
                       TimePoint now);
    void onCanFrame(std::size_t channel, const can::CanFrame& frame, TimePoint now);
    void mainFunction(TimePoint now);

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
    };

    struct PendingActivation {
        ConnectionId connection = 0;
        std::uint16_t tester = 0;
        bool sourceInUse = false;            // else: all sockets in use
        std::set<ConnectionId> waiting;      // alive check sent, no answer yet
        bool anyGone = false;                // a probed connection is dead
        TimePoint deadline{};
    };

    struct Ecu {
        std::size_t channel = 0;
        std::unique_ptr<isotp::Channel> tp;
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
    std::optional<std::vector<std::uint8_t>> localService(const std::vector<std::uint8_t>& request,
                                                          bool functional, TimePoint now);

    void evaluatePendingActivation();
    void finishActivation(bool accept, doip::ActivationCode rejectCode);
    void sendAliveCheck(ConnectionId id);
    void closeConnection(ConnectionId id, bool notifyTransport);

    void onEcuTxDone(std::size_t ecu, isotp::Result result);
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
    std::uint8_t localSession_ = 0x01;
    TimePoint localSessionActivity_{};
};

}  // namespace ccg::diag
