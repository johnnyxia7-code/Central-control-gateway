#pragma once
#include "ccg/security/event_recorder.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "ccg/can/can_frame.hpp"
#include "ccg/e2e/can_e2e.hpp"
#include "ccg/ethgw/routing_config.hpp"
#include "ccg/secoc/fv_sync.hpp"
#include "ccg/secoc/secoc.hpp"

namespace ccg::ethgw {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

// Lower layer: one CAN controller per CAN channel, one UDP socket connection
// per Ethernet channel. Channels are addressed by their index in RoutingConfig.
class IGatewayTransmitter {
public:
    virtual ~IGatewayTransmitter() = default;
    virtual bool transmitCan(std::size_t channel, const can::CanFrame& frame) = 0;
    virtual bool transmitEthernet(std::size_t channel, const std::vector<std::uint8_t>& datagram) = 0;
};

struct GatewayStatistics {
    // reception
    std::uint64_t canFramesReceived = 0;
    std::uint64_t datagramsReceived = 0;
    std::uint64_t pdusReceived = 0;          // routed PDUs taken in (CAN frames + contained PDUs)
    std::uint64_t unroutedPdus = 0;          // no route for this identifier
    std::uint64_t lengthErrors = 0;
    std::uint64_t malformedDatagrams = 0;
    std::uint64_t e2eErrors = 0;
    std::uint64_t e2eRepeated = 0;
    std::uint64_t rxTimeouts = 0;
    // routing
    std::uint64_t pdusForwarded = 0;         // message routing
    std::uint64_t signalsRouted = 0;         // signal routing
    std::uint64_t assembledPdusSent = 0;     // frame assembly
    // transmission
    std::uint64_t canFramesSent = 0;
    std::uint64_t canTxFailures = 0;
    std::uint64_t datagramsSent = 0;
    std::uint64_t ethTxFailures = 0;
    std::chrono::milliseconds maxDatagramCollectionDelay{0};
    // SecOC
    std::uint64_t secocVerified = 0;
    std::uint64_t secocMacFailures = 0;
    std::uint64_t secocFreshnessFailures = 0;
    std::uint64_t secocProtected = 0;
    std::uint64_t secocTxFailures = 0;   // crypto error or exhausted freshness counter
    // Freshness value master
    std::uint64_t fvSyncMessagesSent = 0;  // one per sync PDU
};

// Failed SecOC verification, reported to the intrusion detection (IdsM).
struct SecurityEvent {
    std::string pdu;
    std::size_t channel = 0;
    secoc::VerifyResult result = secoc::VerifyResult::Ok;
    std::chrono::steady_clock::time_point time{};
};

class RoutingConfigError : public std::runtime_error {
public:
    explicit RoutingConfigError(std::vector<std::string> errors);
    const std::vector<std::string>& errors() const { return errors_; }

private:
    std::vector<std::string> errors_;
};

// Central Ethernet gateway: message routing, signal routing, frame decomposition
// and frame assembly between CAN, CAN FD and Ethernet channels.
//
// Single threaded: all entry points are called from one executor.
class EthernetGateway {
public:
    // Throws RoutingConfigError if validateRoutingConfig() reports problems or a
    // secured PDU's key is not available in `crypto`.
    EthernetGateway(RoutingConfig config, IGatewayTransmitter& transmitter,
                    secoc::ICryptoService* crypto = nullptr);

    void setSecurityRecorder(security::EventRecorder& recorder) { securityRecorder_ = &recorder; }
    void start(TimePoint now);

    void onCanFrame(std::size_t channel, const can::CanFrame& frame, TimePoint now);
    void onEthernetDatagram(std::size_t channel, const std::uint8_t* data, std::size_t length,
                            TimePoint now);

    // Deadline monitoring, cyclic/delayed assembled PDUs, datagram collection timeouts.
    void mainFunction(TimePoint now);

    std::optional<std::size_t> channelIndex(const std::string& name) const;
    const GatewayStatistics& statistics() const { return stats_; }
    const std::deque<SecurityEvent>& securityEvents() const { return securityEvents_; }
    // SecOC freshness counters, to be persisted (NvM) and restored before start().
    // With an FV master the snapshot must be stored whenever
    // freshness().takePersistRequest() reports a new trip counter.
    secoc::FreshnessManager& freshness() { return freshness_; }
    // False if the FV master is configured but its trip counter is exhausted.
    bool freshnessMasterActive() const { return fvMaster_ && fvMaster_->active(); }
    const RoutingConfig& config() const { return config_; }

    // Current raw value of a signal in a PDU assembled by the gateway.
    std::optional<std::uint64_t> assembledSignalRaw(const std::string& pdu,
                                                    const std::string& signal) const;

private:
    security::EventRecorder* securityRecorder_ = nullptr;
    struct PduState {
        std::size_t channel = 0;
        std::vector<std::uint8_t> buffer;  // assembled content (targets)

        // reception
        std::vector<std::size_t> pduRoutes;
        std::vector<std::size_t> signalRoutes;
        std::unique_ptr<e2e::CanE2EReceiver> e2eRx;
        std::uint32_t consecutiveE2EErrors = 0;
        bool sourceFaulty = false;  // E2E failure debounced
        bool received = false;
        bool timedOut = false;
        TimePoint lastRx{};

        // transmission of assembled PDUs
        bool assembled = false;
        std::unique_ptr<e2e::CanE2ESender> e2eTx;
        bool changedSinceTx = false;
        bool pending = false;
        bool transmitted = false;
        TimePoint lastTx{};
        TimePoint nextCyclic{};
    };

    struct RouteRuntime {
        std::size_t sourcePdu = 0;
        std::size_t sourceSignal = 0;
        std::size_t targetPdu = 0;
        std::size_t targetSignal = 0;
    };

    struct Container {
        std::vector<std::uint8_t> datagram;
        std::size_t pduCount = 0;
        TimePoint firstEnqueued{};
        TimePoint deadline{};
    };

    void buildRuntime();
    void processPdu(std::size_t pdu, const std::uint8_t* data, std::size_t length, TimePoint now);
    void routeSignals(std::size_t pdu, const std::uint8_t* data, TimePoint now);
    void substituteSignals(std::size_t pdu, TimePoint now);
    void onE2EError(std::size_t pdu, TimePoint now);
    bool writeTargetSignal(std::size_t route, std::uint64_t raw);
    void evaluateAssembled(std::size_t pdu, bool triggered, TimePoint now);
    bool minDelayActive(std::size_t pdu, TimePoint now) const;
    void transmitAssembled(std::size_t pdu, TimePoint now);
    void forwardPdu(std::size_t target, const std::uint8_t* data, std::size_t length,
                    TimePoint now);
    bool sendPdu(std::size_t pdu, const std::uint8_t* authentic, std::size_t length, TimePoint now);
    void sendOnChannel(std::size_t pdu, const std::uint8_t* data, std::size_t length,
                       TimePoint now);
    void reportSecurityEvent(std::size_t pdu, secoc::VerifyResult result, TimePoint now);
    void flushContainer(std::size_t channel, TimePoint now);

    RoutingConfig config_;
    IGatewayTransmitter& tx_;
    GatewayStatistics stats_;
    secoc::FreshnessManager freshness_;
    std::unique_ptr<secoc::SecOcProcessor> secoc_;
    std::unique_ptr<secoc::FreshnessSyncMaster> fvMaster_;
    std::vector<std::size_t> syncPdus_;
    std::deque<SecurityEvent> securityEvents_;
    bool started_ = false;
    TimePoint startTime_{};

    std::vector<PduState> pdus_;
    std::vector<std::vector<std::size_t>> pduRouteTargets_;  // per PDU route
    std::vector<RouteRuntime> routes_;
    std::vector<Container> containers_;  // indexed by channel
    std::unordered_map<std::uint64_t, std::size_t> rxIndex_;  // (channel, id, ext) -> PDU
    std::unordered_map<std::string, std::size_t> pduByName_;
    std::unordered_map<std::string, std::size_t> channelByName_;
};

}  // namespace ccg::ethgw
