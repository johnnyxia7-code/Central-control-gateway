#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "ccg/can/can_frame.hpp"
#include "ccg/e2e/can_e2e.hpp"
#include "ccg/s2s/s2s_config.hpp"
#include "ccg/s2s/transport.hpp"
#include "ccg/someip/someip_message.hpp"

namespace ccg::s2s {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

// Quality of a signal as published on the service side (one uint8 per element
// when EventMapping::appendStatus is set).
enum class SignalStatus : std::uint8_t {
    Valid = 0,
    Invalid = 1,       // SNA pattern received or physical value out of range
    Timeout = 2,       // Rx deadline missed
    E2EError = 3,      // E2E check failed maxConsecutiveErrors times in a row
    NotAvailable = 4,  // nothing received yet since start-up
};

const char* toString(SignalStatus status);

struct Statistics {
    std::uint64_t canRxAccepted = 0;
    std::uint64_t canRxUnknownId = 0;
    std::uint64_t canRxLengthError = 0;
    std::uint64_t e2eCrcErrors = 0;
    std::uint64_t e2eSequenceErrors = 0;
    std::uint64_t e2eRepeated = 0;
    std::uint64_t rxTimeouts = 0;
    std::uint64_t notificationsSent = 0;
    std::uint64_t requestsReceived = 0;
    std::uint64_t requestsDropped = 0;
    std::uint64_t responsesSent = 0;
    std::uint64_t errorResponsesSent = 0;
    std::uint64_t canTxFrames = 0;
    std::uint64_t canTxFailures = 0;
};

struct SignalSnapshot {
    std::uint64_t raw = 0;
    double physical = 0.0;
    SignalStatus status = SignalStatus::NotAvailable;
};

class ConfigError : public std::runtime_error {
public:
    explicit ConfigError(std::vector<std::string> errors);
    const std::vector<std::string>& errors() const { return errors_; }

private:
    std::vector<std::string> errors_;
};

// Signal-to-Service gateway function of the HPC.
//
// Single threaded by design: all entry points must be called from the same
// executor (typically the gateway's 5 ms task plus its Rx event handlers).
class S2SGateway {
public:
    // Throws ConfigError if validateConfig() reports problems.
    S2SGateway(GatewayConfig config, ICanTransmitter& can, ISomeIpBinding& someip);

    // Offers the service instances and starts deadline monitoring / cyclic timers.
    void start(TimePoint now);

    // CAN -> SOME/IP: decode, E2E check, update signal states, trigger on-change events.
    void onCanFrame(const can::CanFrame& frame, TimePoint now);

    // SOME/IP -> CAN: method calls and field getters.
    void onSomeIpRequest(const someip::Message& request, const RequestContext& ctx,
                         TimePoint now);

    // A client subscribed an eventgroup: send initial values of its fields.
    void onSubscribe(std::uint16_t serviceId, std::uint16_t instanceId,
                     std::uint16_t eventgroupId, const Peer& subscriber, TimePoint now);

    // Periodic processing (deadline monitoring, cyclic/debounced events, CAN Tx scheduling).
    // Call at least as often as the smallest configured time base (5 ms recommended).
    void mainFunction(TimePoint now);

    const Statistics& statistics() const { return stats_; }
    const GatewayConfig& config() const { return config_; }

    std::optional<SignalSnapshot> rxSignal(const std::string& message,
                                           const std::string& signal) const;
    std::optional<std::uint64_t> txSignalRaw(const std::string& message,
                                             const std::string& signal) const;

private:
    struct SignalState {
        std::uint64_t raw = 0;
        std::uint64_t lastValidRaw = 0;
        bool invalid = false;
    };

    struct RxState {
        std::vector<SignalState> signals;
        std::unique_ptr<e2e::CanE2EReceiver> e2e;
        std::uint32_t consecutiveE2EErrors = 0;
        bool e2eFailed = false;
        bool received = false;
        bool timedOut = false;
        TimePoint lastRx{};
        std::vector<std::size_t> dependentEvents;
    };

    struct ElementSource {
        std::size_t rx;
        std::size_t signal;
    };

    struct EventState {
        std::size_t service = 0;
        std::vector<ElementSource> sources;
        std::vector<std::uint8_t> lastPayload;
        bool sent = false;
        bool pending = false;
        TimePoint lastSent{};
        TimePoint nextCyclic{};
        std::uint16_t sessionId = 0;
    };

    struct TxState {
        can::CanFrame frame;
        std::unique_ptr<e2e::CanE2ESender> e2e;
        TimePoint nextCyclic{};
        TimePoint lastTransmit{};
        bool transmitted = false;
        std::uint8_t repetitionsLeft = 0;
        TimePoint nextRepetition{};
        std::vector<std::size_t> pendingPulseReset;
    };

    struct ArgumentTarget {
        std::size_t tx;
        std::size_t signal;
    };

    struct MethodState {
        std::size_t service = 0;
        std::vector<ArgumentTarget> targets;
    };

    enum class HandlerKind : std::uint8_t { Method, Getter };
    struct Handler {
        HandlerKind kind;
        std::size_t index;
    };

    void buildRuntime();
    SignalStatus statusOf(const RxState& rx, const SignalState& sig) const;
    std::vector<std::uint8_t> buildEventPayload(std::size_t event) const;
    void evaluateOnChange(std::size_t event, TimePoint now);
    void sendEvent(std::size_t event, std::vector<std::uint8_t> payload, TimePoint now);
    void onE2EError(std::size_t rx, TimePoint now);
    void handleMethod(std::size_t method, const someip::Message& request,
                      const RequestContext& ctx, TimePoint now);
    void triggerTransmission(std::size_t tx, TimePoint now);
    bool minDelayActive(std::size_t tx, TimePoint now) const;
    void transmit(std::size_t tx, TimePoint now);
    void resetPulses(std::size_t tx);
    void respond(const someip::Message& request, const Peer& peer, someip::MessageType type,
                 someip::ReturnCode code, std::vector<std::uint8_t> payload);

    GatewayConfig config_;
    ICanTransmitter& can_;
    ISomeIpBinding& someip_;
    Statistics stats_;
    bool started_ = false;
    TimePoint startTime_{};

    std::vector<RxState> rx_;
    std::vector<EventState> events_;
    std::vector<TxState> tx_;
    std::vector<MethodState> methods_;

    std::unordered_map<std::uint64_t, std::size_t> rxByCanId_;
    std::unordered_map<std::uint32_t, std::size_t> serviceByKey_;
    std::unordered_map<std::uint64_t, Handler> handlers_;
};

}  // namespace ccg::s2s
