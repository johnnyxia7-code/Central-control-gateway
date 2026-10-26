#include "ccg/s2s/s2s_gateway.hpp"

#include <algorithm>
#include <cmath>
#include <sstream>

#include "ccg/can/signal_codec.hpp"

namespace ccg::s2s {

namespace {

std::uint64_t canKey(std::uint32_t id, bool extended) {
    return (static_cast<std::uint64_t>(extended) << 32) | id;
}

std::uint32_t serviceKey(std::uint16_t service, std::uint16_t instance) {
    return (static_cast<std::uint32_t>(service) << 16) | instance;
}

std::uint64_t handlerKey(std::uint16_t service, std::uint16_t instance, std::uint16_t id) {
    return (static_cast<std::uint64_t>(service) << 32) |
           (static_cast<std::uint64_t>(instance) << 16) | id;
}

std::string joinErrors(const std::vector<std::string>& errors) {
    std::ostringstream os;
    os << "invalid S2S configuration (" << errors.size() << " error(s))";
    for (const auto& e : errors) {
        os << "\n  - " << e;
    }
    return os.str();
}

template <typename Message>
std::optional<std::pair<std::size_t, std::size_t>> locate(const std::vector<Message>& messages,
                                                          const std::string& message,
                                                          const std::string& signal) {
    for (std::size_t m = 0; m < messages.size(); ++m) {
        if (messages[m].name != message) continue;
        const auto& sigs = messages[m].signals;
        for (std::size_t s = 0; s < sigs.size(); ++s) {
            if (sigs[s].name == signal) return std::make_pair(m, s);
        }
    }
    return std::nullopt;
}

bool isOutOfRange(const can::SignalSpec& spec, double physical) {
    // Half an LSB of tolerance so that values produced by float32 rounding still pass.
    const double tolerance = std::abs(spec.factor) / 2.0;
    return std::isnan(physical) || physical < spec.min - tolerance ||
           physical > spec.max + tolerance;
}

}  // namespace

const char* toString(SignalStatus status) {
    switch (status) {
        case SignalStatus::Valid: return "VALID";
        case SignalStatus::Invalid: return "INVALID";
        case SignalStatus::Timeout: return "TIMEOUT";
        case SignalStatus::E2EError: return "E2E_ERROR";
        case SignalStatus::NotAvailable: return "NOT_AVAILABLE";
    }
    return "UNKNOWN";
}

ConfigError::ConfigError(std::vector<std::string> errors)
    : std::runtime_error(joinErrors(errors)), errors_(std::move(errors)) {}

S2SGateway::S2SGateway(GatewayConfig config, ICanTransmitter& can, ISomeIpBinding& someip)
    : config_(std::move(config)), can_(can), someip_(someip) {
    auto errors = validateConfig(config_);
    if (!errors.empty()) {
        throw ConfigError(std::move(errors));
    }
    buildRuntime();
}

void S2SGateway::buildRuntime() {
    rx_.resize(config_.rxMessages.size());
    for (std::size_t i = 0; i < config_.rxMessages.size(); ++i) {
        const auto& cfg = config_.rxMessages[i];
        auto& rx = rx_[i];
        for (const auto& spec : cfg.signals) {
            SignalState s;
            s.raw = spec.initRaw;
            s.lastValidRaw = spec.initRaw;
            rx.signals.push_back(s);
        }
        if (cfg.e2e) {
            rx.e2e = std::make_unique<e2e::CanE2EReceiver>(*cfg.e2e);
        }
        rxByCanId_[canKey(cfg.canId, cfg.extended)] = i;
    }

    tx_.resize(config_.txMessages.size());
    for (std::size_t i = 0; i < config_.txMessages.size(); ++i) {
        const auto& cfg = config_.txMessages[i];
        auto& tx = tx_[i];
        tx.frame.id = cfg.canId;
        tx.frame.extended = cfg.extended;
        tx.frame.fd = cfg.fd;
        tx.frame.length = cfg.length;
        for (const auto& spec : cfg.signals) {
            can::insertRaw(tx.frame.data.data(), spec, spec.initRaw);
        }
        if (cfg.e2e) {
            tx.e2e = std::make_unique<e2e::CanE2ESender>(*cfg.e2e);
        }
    }

    for (std::size_t i = 0; i < config_.services.size(); ++i) {
        const auto& svc = config_.services[i];
        serviceByKey_[serviceKey(svc.serviceId, svc.instanceId)] = i;
    }

    events_.resize(config_.events.size());
    for (std::size_t e = 0; e < config_.events.size(); ++e) {
        const auto& cfg = config_.events[e];
        auto& ev = events_[e];
        ev.service = serviceByKey_.at(serviceKey(cfg.serviceId, cfg.instanceId));
        for (const auto& el : cfg.elements) {
            const auto loc = locate(config_.rxMessages, el.source.message, el.source.signal);
            ev.sources.push_back({loc->first, loc->second});
            auto& deps = rx_[loc->first].dependentEvents;
            if (std::find(deps.begin(), deps.end(), e) == deps.end()) {
                deps.push_back(e);
            }
        }
        if (cfg.getterMethodId) {
            handlers_[handlerKey(cfg.serviceId, cfg.instanceId, *cfg.getterMethodId)] = {
                HandlerKind::Getter, e};
        }
    }

    methods_.resize(config_.methods.size());
    for (std::size_t m = 0; m < config_.methods.size(); ++m) {
        const auto& cfg = config_.methods[m];
        auto& method = methods_[m];
        method.service = serviceByKey_.at(serviceKey(cfg.serviceId, cfg.instanceId));
        for (const auto& arg : cfg.arguments) {
            const auto loc = locate(config_.txMessages, arg.target.message, arg.target.signal);
            method.targets.push_back({loc->first, loc->second});
        }
        handlers_[handlerKey(cfg.serviceId, cfg.instanceId, cfg.methodId)] = {
            HandlerKind::Method, m};
    }
}

void S2SGateway::start(TimePoint now) {
    started_ = true;
    startTime_ = now;
    for (const auto& svc : config_.services) {
        someip_.offerService(svc);
    }
    for (std::size_t e = 0; e < events_.size(); ++e) {
        events_[e].nextCyclic = now + config_.events[e].cycleTime;
    }
    for (auto& tx : tx_) {
        tx.nextCyclic = now;  // start of transmission: first cyclic frame right away
    }
}

// ---------------------------------------------------------------------------
// CAN -> SOME/IP
// ---------------------------------------------------------------------------

void S2SGateway::onCanFrame(const can::CanFrame& frame, TimePoint now) {
    if (!started_) {
        return;
    }
    const auto it = rxByCanId_.find(canKey(frame.id, frame.extended));
    if (it == rxByCanId_.end()) {
        ++stats_.canRxUnknownId;  // not part of the S2S matrix (routed elsewhere)
        return;
    }
    const std::size_t index = it->second;
    const auto& cfg = config_.rxMessages[index];
    auto& rx = rx_[index];

    if (frame.length < cfg.length) {
        ++stats_.canRxLengthError;
        return;
    }

    if (rx.e2e) {
        switch (rx.e2e->check(frame.data.data(), cfg.length)) {
            case e2e::CheckStatus::Ok:
            case e2e::CheckStatus::OkSomeLost:
                break;
            case e2e::CheckStatus::Repeated:
                ++stats_.e2eRepeated;
                return;
            case e2e::CheckStatus::WrongSequence:
                ++stats_.e2eSequenceErrors;
                onE2EError(index, now);
                return;
            case e2e::CheckStatus::CrcError:
                ++stats_.e2eCrcErrors;
                onE2EError(index, now);
                return;
        }
    }

    ++stats_.canRxAccepted;
    rx.consecutiveE2EErrors = 0;
    rx.e2eFailed = false;
    rx.timedOut = false;
    rx.received = true;
    rx.lastRx = now;

    for (std::size_t s = 0; s < cfg.signals.size(); ++s) {
        const auto& spec = cfg.signals[s];
        auto& sig = rx.signals[s];
        sig.raw = can::extractRaw(frame.data.data(), spec);
        sig.invalid = (spec.invalidRaw && sig.raw == *spec.invalidRaw) ||
                      isOutOfRange(spec, can::rawToPhysical(spec, sig.raw));
        if (!sig.invalid) {
            sig.lastValidRaw = sig.raw;
        }
    }

    for (const std::size_t e : rx.dependentEvents) {
        evaluateOnChange(e, now);
    }
}

void S2SGateway::onE2EError(std::size_t index, TimePoint now) {
    auto& rx = rx_[index];
    ++rx.consecutiveE2EErrors;
    if (!rx.e2eFailed &&
        rx.consecutiveE2EErrors >= config_.rxMessages[index].e2e->maxConsecutiveErrors) {
        rx.e2eFailed = true;
        for (const std::size_t e : rx.dependentEvents) {
            evaluateOnChange(e, now);
        }
    }
}

SignalStatus S2SGateway::statusOf(const RxState& rx, const SignalState& sig) const {
    if (rx.e2eFailed) return SignalStatus::E2EError;
    if (rx.timedOut) return SignalStatus::Timeout;
    if (!rx.received) return SignalStatus::NotAvailable;
    if (sig.invalid) return SignalStatus::Invalid;
    return SignalStatus::Valid;
}

std::vector<std::uint8_t> S2SGateway::buildEventPayload(std::size_t event) const {
    const auto& cfg = config_.events[event];
    const auto& ev = events_[event];
    someip::PayloadWriter writer;

    for (std::size_t i = 0; i < cfg.elements.size(); ++i) {
        const auto& el = cfg.elements[i];
        const auto& src = ev.sources[i];
        const auto& rx = rx_[src.rx];
        const auto& sig = rx.signals[src.signal];
        const auto& spec = config_.rxMessages[src.rx].signals[src.signal];
        const SignalStatus status = statusOf(rx, sig);

        double value = 0.0;
        if (status != SignalStatus::Valid && el.substitution.kind == SubstitutionKind::Constant) {
            value = el.substitution.constant;
        } else {
            std::uint64_t raw = sig.raw;
            if (status != SignalStatus::Valid) {
                raw = el.substitution.kind == SubstitutionKind::HoldLastValid ? sig.lastValidRaw
                                                                               : spec.initRaw;
            }
            value = el.representation == Representation::Physical ? can::rawToPhysical(spec, raw)
                                                                  : can::rawToNumber(spec, raw);
        }

        writeValue(writer, el.type, value);
        if (cfg.appendStatus) {
            writer.writeU8(static_cast<std::uint8_t>(status));
        }
    }
    return writer.take();
}

void S2SGateway::evaluateOnChange(std::size_t event, TimePoint now) {
    const auto& cfg = config_.events[event];
    auto& ev = events_[event];
    if (cfg.updateMode == UpdateMode::Cyclic) {
        return;
    }
    auto payload = buildEventPayload(event);
    if (ev.sent && payload == ev.lastPayload) {
        ev.pending = false;
        return;
    }
    if (ev.sent && now - ev.lastSent < cfg.minInterval) {
        ev.pending = true;  // debounced, mainFunction() sends the latest value later
        return;
    }
    sendEvent(event, std::move(payload), now);
}

void S2SGateway::sendEvent(std::size_t event, std::vector<std::uint8_t> payload, TimePoint now) {
    const auto& cfg = config_.events[event];
    auto& ev = events_[event];

    someip::Message msg;
    msg.header.serviceId = cfg.serviceId;
    msg.header.methodId = cfg.eventId;
    msg.header.clientId = 0x0000;
    msg.header.sessionId = someip::nextSessionId(ev.sessionId);
    msg.header.interfaceVersion = config_.services[ev.service].majorVersion;
    msg.header.messageType = someip::MessageType::Notification;
    msg.header.returnCode = someip::ReturnCode::Ok;
    msg.payload = payload;

    someip_.notify(cfg.serviceId, cfg.instanceId, cfg.eventgroupId, msg);
    ++stats_.notificationsSent;

    ev.lastPayload = std::move(payload);
    ev.sent = true;
    ev.pending = false;
    ev.lastSent = now;
}

void S2SGateway::onSubscribe(std::uint16_t serviceId, std::uint16_t instanceId,
                             std::uint16_t eventgroupId, const Peer& subscriber, TimePoint) {
    for (std::size_t e = 0; e < config_.events.size(); ++e) {
        const auto& cfg = config_.events[e];
        if (!cfg.isField || cfg.serviceId != serviceId || cfg.instanceId != instanceId ||
            cfg.eventgroupId != eventgroupId) {
            continue;
        }
        someip::Message msg;
        msg.header.serviceId = cfg.serviceId;
        msg.header.methodId = cfg.eventId;
        msg.header.sessionId = someip::nextSessionId(events_[e].sessionId);
        msg.header.interfaceVersion = config_.services[events_[e].service].majorVersion;
        msg.header.messageType = someip::MessageType::Notification;
        msg.payload = buildEventPayload(e);
        someip_.sendTo(subscriber, msg);
        ++stats_.notificationsSent;
    }
}

// ---------------------------------------------------------------------------
// SOME/IP -> CAN
// ---------------------------------------------------------------------------

void S2SGateway::onSomeIpRequest(const someip::Message& request, const RequestContext& ctx,
                                 TimePoint now) {
    using someip::MessageType;
    using someip::ReturnCode;

    ++stats_.requestsReceived;
    const auto& h = request.header;
    if (!started_ ||
        (h.messageType != MessageType::Request && h.messageType != MessageType::RequestNoReturn)) {
        ++stats_.requestsDropped;
        return;
    }
    const bool expectsResponse = h.messageType == MessageType::Request;
    auto reject = [&](ReturnCode code) {
        if (expectsResponse) {
            respond(request, ctx.peer, MessageType::Error, code, {});
        } else {
            ++stats_.requestsDropped;  // REQUEST_NO_RETURN never gets an error message
        }
    };

    if (h.protocolVersion != someip::kProtocolVersion) {
        return reject(ReturnCode::WrongProtocolVersion);
    }
    const auto svc = serviceByKey_.find(serviceKey(h.serviceId, ctx.instanceId));
    if (svc == serviceByKey_.end()) {
        return reject(ReturnCode::UnknownService);
    }
    if (h.interfaceVersion != config_.services[svc->second].majorVersion) {
        return reject(ReturnCode::WrongInterfaceVersion);
    }
    const auto handler = handlers_.find(handlerKey(h.serviceId, ctx.instanceId, h.methodId));
    if (handler == handlers_.end()) {
        return reject(ReturnCode::UnknownMethod);
    }

    if (handler->second.kind == HandlerKind::Getter) {
        if (!expectsResponse) {
            return reject(ReturnCode::WrongMessageType);
        }
        respond(request, ctx.peer, MessageType::Response, ReturnCode::Ok,
                buildEventPayload(handler->second.index));
        return;
    }

    const auto& method = config_.methods[handler->second.index];
    if (method.fireAndForget == expectsResponse) {
        return reject(ReturnCode::WrongMessageType);
    }
    handleMethod(handler->second.index, request, ctx, now);
}

void S2SGateway::handleMethod(std::size_t index, const someip::Message& request,
                              const RequestContext& ctx, TimePoint now) {
    using someip::MessageType;
    using someip::ReturnCode;

    const auto& cfg = config_.methods[index];
    const auto& method = methods_[index];
    const bool expectsResponse = !cfg.fireAndForget;
    auto reject = [&](ReturnCode code) {
        if (expectsResponse) {
            respond(request, ctx.peer, MessageType::Error, code, {});
        } else {
            ++stats_.requestsDropped;
        }
    };

    // 1. Deserialize all arguments (trailing bytes are tolerated for minor-version
    //    compatibility, missing bytes are not).
    someip::PayloadReader reader(request.payload);
    std::vector<std::uint64_t> raws;
    raws.reserve(cfg.arguments.size());
    for (std::size_t a = 0; a < cfg.arguments.size(); ++a) {
        const auto& arg = cfg.arguments[a];
        const auto value = readValue(reader, arg.type);
        if (!value) {
            return reject(ReturnCode::MalformedMessage);
        }
        // 2. Convert and range check against the CAN signal definition.
        const auto& target = method.targets[a];
        const auto& spec = config_.txMessages[target.tx].signals[target.signal];
        std::uint64_t raw = 0;
        if (arg.representation == Representation::Physical) {
            if (isOutOfRange(spec, *value)) {
                return reject(ReturnCode::NotOk);
            }
            raw = can::physicalToRaw(spec, *value);
        } else {
            const auto converted = can::numberToRaw(spec, *value);
            if (!converted || isOutOfRange(spec, can::rawToPhysical(spec, *converted))) {
                return reject(ReturnCode::NotOk);
            }
            raw = *converted;
        }
        if (spec.invalidRaw && raw == *spec.invalidRaw) {
            return reject(ReturnCode::NotOk);
        }
        raws.push_back(raw);
    }

    // 3. All arguments valid: write the signals (all-or-nothing) and trigger transmission.
    std::vector<std::size_t> touched;
    for (std::size_t a = 0; a < cfg.arguments.size(); ++a) {
        const auto& target = method.targets[a];
        auto& tx = tx_[target.tx];
        const auto& spec = config_.txMessages[target.tx].signals[target.signal];
        can::insertRaw(tx.frame.data.data(), spec, raws[a]);
        if (cfg.arguments[a].pulse &&
            std::find(tx.pendingPulseReset.begin(), tx.pendingPulseReset.end(), target.signal) ==
                tx.pendingPulseReset.end()) {
            tx.pendingPulseReset.push_back(target.signal);
        }
        if (std::find(touched.begin(), touched.end(), target.tx) == touched.end()) {
            touched.push_back(target.tx);
        }
    }
    for (const std::size_t t : touched) {
        triggerTransmission(t, now);
    }

    if (expectsResponse) {
        respond(request, ctx.peer, MessageType::Response, ReturnCode::Ok, {});
    }
}

void S2SGateway::respond(const someip::Message& request, const Peer& peer,
                         someip::MessageType type, someip::ReturnCode code,
                         std::vector<std::uint8_t> payload) {
    someip::Message msg;
    msg.header = request.header;
    msg.header.protocolVersion = someip::kProtocolVersion;
    msg.header.messageType = type;
    msg.header.returnCode = code;
    msg.payload = std::move(payload);
    someip_.sendTo(peer, msg);
    if (type == someip::MessageType::Error) {
        ++stats_.errorResponsesSent;
    } else {
        ++stats_.responsesSent;
    }
}

void S2SGateway::triggerTransmission(std::size_t index, TimePoint now) {
    const auto& cfg = config_.txMessages[index];
    auto& tx = tx_[index];
    if (cfg.eventRepetitions == 0) {
        return;  // value is picked up by the next cyclic frame
    }
    if (minDelayActive(index, now)) {
        // MDT not yet elapsed: the whole burst starts as soon as it is.
        tx.repetitionsLeft = cfg.eventRepetitions;
        tx.nextRepetition = tx.lastTransmit + cfg.minDelay;
        return;
    }
    transmit(index, now);
    tx.repetitionsLeft = static_cast<std::uint8_t>(cfg.eventRepetitions - 1);
    tx.nextRepetition = now + cfg.repetitionInterval;
    if (tx.repetitionsLeft == 0) {
        resetPulses(index);
    }
}

bool S2SGateway::minDelayActive(std::size_t index, TimePoint now) const {
    const auto& tx = tx_[index];
    return tx.transmitted && now - tx.lastTransmit < config_.txMessages[index].minDelay;
}

void S2SGateway::transmit(std::size_t index, TimePoint now) {
    auto& tx = tx_[index];
    tx.transmitted = true;
    tx.lastTransmit = now;
    if (tx.e2e) {
        tx.e2e->protect(tx.frame.data.data(), tx.frame.length);
    }
    if (can_.transmit(tx.frame)) {
        ++stats_.canTxFrames;
    } else {
        ++stats_.canTxFailures;
    }
}

void S2SGateway::resetPulses(std::size_t index) {
    auto& tx = tx_[index];
    const auto& cfg = config_.txMessages[index];
    for (const std::size_t s : tx.pendingPulseReset) {
        can::insertRaw(tx.frame.data.data(), cfg.signals[s], cfg.signals[s].initRaw);
    }
    tx.pendingPulseReset.clear();
}

// ---------------------------------------------------------------------------
// Periodic processing
// ---------------------------------------------------------------------------

void S2SGateway::mainFunction(TimePoint now) {
    if (!started_) {
        return;
    }

    // Reception deadline monitoring (starts at start-up for never received messages).
    for (std::size_t i = 0; i < rx_.size(); ++i) {
        const auto& cfg = config_.rxMessages[i];
        auto& rx = rx_[i];
        if (cfg.timeout.count() <= 0 || rx.timedOut) {
            continue;
        }
        const TimePoint reference = rx.received ? rx.lastRx : startTime_;
        if (now - reference >= cfg.timeout) {
            rx.timedOut = true;
            ++stats_.rxTimeouts;
            if (rx.e2e) {
                rx.e2e->reset();  // resynchronise on the first frame after recovery
            }
            for (const std::size_t e : rx.dependentEvents) {
                evaluateOnChange(e, now);
            }
        }
    }

    // Debounced and cyclic notifications.
    for (std::size_t e = 0; e < events_.size(); ++e) {
        const auto& cfg = config_.events[e];
        auto& ev = events_[e];
        if (ev.pending && now - ev.lastSent >= cfg.minInterval) {
            evaluateOnChange(e, now);
        }
        if (cfg.updateMode != UpdateMode::OnChange && now >= ev.nextCyclic) {
            sendEvent(e, buildEventPayload(e), now);
            ev.nextCyclic += cfg.cycleTime;
            if (ev.nextCyclic <= now) {
                ev.nextCyclic = now + cfg.cycleTime;  // overrun: do not burst to catch up
            }
        }
    }

    // CAN Tx scheduling: fast repetitions first, then the cyclic timer, both
    // subject to the minimum delay time between two frames of the same PDU.
    for (std::size_t t = 0; t < tx_.size(); ++t) {
        const auto& cfg = config_.txMessages[t];
        auto& tx = tx_[t];
        if (tx.repetitionsLeft > 0 && now >= tx.nextRepetition && !minDelayActive(t, now)) {
            transmit(t, now);
            --tx.repetitionsLeft;
            tx.nextRepetition += cfg.repetitionInterval;
            if (tx.repetitionsLeft == 0) {
                resetPulses(t);
            }
        }
        // A cyclic frame blocked by the MDT stays due and goes out on a later call.
        if (cfg.cycleTime.count() > 0 && now >= tx.nextCyclic && !minDelayActive(t, now)) {
            transmit(t, now);
            tx.nextCyclic += cfg.cycleTime;
            if (tx.nextCyclic <= now) {
                tx.nextCyclic = now + cfg.cycleTime;
            }
            if (tx.repetitionsLeft == 0) {
                resetPulses(t);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

std::optional<SignalSnapshot> S2SGateway::rxSignal(const std::string& message,
                                                   const std::string& signal) const {
    const auto loc = locate(config_.rxMessages, message, signal);
    if (!loc) {
        return std::nullopt;
    }
    const auto& rx = rx_[loc->first];
    const auto& sig = rx.signals[loc->second];
    const auto& spec = config_.rxMessages[loc->first].signals[loc->second];
    return SignalSnapshot{sig.raw, can::rawToPhysical(spec, sig.raw), statusOf(rx, sig)};
}

std::optional<std::uint64_t> S2SGateway::txSignalRaw(const std::string& message,
                                                     const std::string& signal) const {
    const auto loc = locate(config_.txMessages, message, signal);
    if (!loc) {
        return std::nullopt;
    }
    return can::extractRaw(tx_[loc->first].frame.data.data(),
                           config_.txMessages[loc->first].signals[loc->second]);
}

}  // namespace ccg::s2s
