#include "ccg/ethgw/ethernet_gateway.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

#include "ccg/can/signal_codec.hpp"
#include "ccg/ethgw/pdu_header_codec.hpp"

namespace ccg::ethgw {

namespace {

std::uint64_t rxKey(std::size_t channel, std::uint32_t id, bool extended) {
    return (static_cast<std::uint64_t>(channel) << 33) | (static_cast<std::uint64_t>(extended) << 32) |
           id;
}

std::string joinErrors(const std::vector<std::string>& errors) {
    std::ostringstream os;
    os << "invalid routing configuration (" << errors.size() << " error(s))";
    for (const auto& e : errors) {
        os << "\n  - " << e;
    }
    return os.str();
}

std::size_t signalIndex(const PduDefinition& pdu, const std::string& name) {
    for (std::size_t i = 0; i < pdu.signals.size(); ++i) {
        if (pdu.signals[i].name == name) return i;
    }
    return pdu.signals.size();  // unreachable after validation
}

bool isCyclic(TxMode mode) { return mode == TxMode::Cyclic || mode == TxMode::CyclicAndOnChange; }

}  // namespace

RoutingConfigError::RoutingConfigError(std::vector<std::string> errors)
    : std::runtime_error(joinErrors(errors)), errors_(std::move(errors)) {}

EthernetGateway::EthernetGateway(RoutingConfig config, IGatewayTransmitter& transmitter,
                                 secoc::ICryptoService* crypto)
    : config_(std::move(config)), tx_(transmitter) {
    auto errors = validateRoutingConfig(config_);
    for (const auto& pdu : config_.pdus) {
        if (pdu.secoc && (crypto == nullptr || !crypto->hasKey(pdu.secoc->keyId))) {
            errors.push_back("PDU '" + pdu.name + "': SecOC key '" + pdu.secoc->keyId +
                             "' not available in the crypto service");
        }
    }
    if (config_.freshnessSync) {
        const auto& keyId = config_.freshnessSync->message.keyId;
        if (crypto == nullptr || !crypto->hasKey(keyId)) {
            errors.push_back("freshness sync: key '" + keyId + "' not available in the crypto service");
        }
    }
    if (!errors.empty()) {
        throw RoutingConfigError(std::move(errors));
    }
    if (crypto != nullptr) {
        secoc_ = std::make_unique<secoc::SecOcProcessor>(*crypto, freshness_);
    }
    if (config_.freshnessSync) {
        freshness_.setLayout(config_.freshnessSync->layout);
        fvMaster_ = std::make_unique<secoc::FreshnessSyncMaster>(config_.freshnessSync->message,
                                                                 *crypto, freshness_);
    }
    buildRuntime();
}

void EthernetGateway::buildRuntime() {
    for (std::size_t c = 0; c < config_.channels.size(); ++c) {
        channelByName_[config_.channels[c].name] = c;
    }
    containers_.resize(config_.channels.size());

    pdus_.resize(config_.pdus.size());
    for (std::size_t p = 0; p < config_.pdus.size(); ++p) {
        const auto& cfg = config_.pdus[p];
        auto& st = pdus_[p];
        pduByName_[cfg.name] = p;
        st.channel = channelByName_.at(cfg.channel);
        st.buffer.assign(authenticLength(cfg), cfg.padding);  // authentic part only
        for (const auto& spec : cfg.signals) {
            can::insertRaw(st.buffer.data(), spec, spec.initRaw);
        }
    }

    pduRouteTargets_.resize(config_.pduRoutes.size());
    for (std::size_t r = 0; r < config_.pduRoutes.size(); ++r) {
        const auto& route = config_.pduRoutes[r];
        const std::size_t src = pduByName_.at(route.source);
        pdus_[src].pduRoutes.push_back(r);
        const auto& cfg = config_.pdus[src];
        rxIndex_[rxKey(pdus_[src].channel, cfg.id, cfg.extended)] = src;
        for (const auto& target : route.targets) {
            pduRouteTargets_[r].push_back(pduByName_.at(target));
        }
    }

    routes_.resize(config_.signalRoutes.size());
    for (std::size_t r = 0; r < config_.signalRoutes.size(); ++r) {
        const auto& route = config_.signalRoutes[r];
        auto& rt = routes_[r];
        rt.sourcePdu = pduByName_.at(route.source.pdu);
        rt.targetPdu = pduByName_.at(route.target.pdu);
        rt.sourceSignal = signalIndex(config_.pdus[rt.sourcePdu], route.source.signal);
        rt.targetSignal = signalIndex(config_.pdus[rt.targetPdu], route.target.signal);
        pdus_[rt.sourcePdu].signalRoutes.push_back(r);
        pdus_[rt.targetPdu].assembled = true;
        const auto& cfg = config_.pdus[rt.sourcePdu];
        rxIndex_[rxKey(pdus_[rt.sourcePdu].channel, cfg.id, cfg.extended)] = rt.sourcePdu;
    }

    if (config_.freshnessSync) {
        for (const auto& name : config_.freshnessSync->syncPdus) {
            syncPdus_.push_back(pduByName_.at(name));
        }
    }

    for (std::size_t p = 0; p < pdus_.size(); ++p) {
        const auto& cfg = config_.pdus[p];
        auto& st = pdus_[p];
        if (cfg.e2e && !st.signalRoutes.empty()) {
            st.e2eRx = std::make_unique<e2e::CanE2EReceiver>(*cfg.e2e);
        }
        if (cfg.e2e && st.assembled) {
            st.e2eTx = std::make_unique<e2e::CanE2ESender>(*cfg.e2e);
        }
    }
}

void EthernetGateway::start(TimePoint now) {
    started_ = true;
    startTime_ = now;
    if (fvMaster_) {
        fvMaster_->start(now);  // new trip counter; inactive if exhausted
    }
    for (std::size_t p = 0; p < pdus_.size(); ++p) {
        if (pdus_[p].assembled && isCyclic(config_.pdus[p].txMode)) {
            pdus_[p].nextCyclic = now + config_.pdus[p].cycleTime;
        }
    }
}

std::optional<std::size_t> EthernetGateway::channelIndex(const std::string& name) const {
    const auto it = channelByName_.find(name);
    if (it == channelByName_.end()) return std::nullopt;
    return it->second;
}

// ---------------------------------------------------------------------------
// Reception and frame decomposition
// ---------------------------------------------------------------------------

void EthernetGateway::onCanFrame(std::size_t channel, const can::CanFrame& frame, TimePoint now) {
    if (!started_ || channel >= config_.channels.size() ||
        config_.channels[channel].type == BusType::Ethernet) {
        return;
    }
    ++stats_.canFramesReceived;
    const auto it = rxIndex_.find(rxKey(channel, frame.id, frame.extended));
    if (it == rxIndex_.end()) {
        ++stats_.unroutedPdus;
        return;
    }
    processPdu(it->second, frame.data.data(), frame.length, now);
}

void EthernetGateway::onEthernetDatagram(std::size_t channel, const std::uint8_t* data,
                                         std::size_t length, TimePoint now) {
    if (!started_ || channel >= config_.channels.size() ||
        config_.channels[channel].type != BusType::Ethernet) {
        return;
    }
    ++stats_.datagramsReceived;
    const auto decoded = decodeDatagram(data, length);
    if (!decoded.complete) {
        if (securityRecorder_) securityRecorder_->report(security::EventId::MalformedDatagram,
            static_cast<std::uint32_t>(channel), now);
        ++stats_.malformedDatagrams;  // PDUs before the defect are still routed
    }
    for (const auto& pdu : decoded.pdus) {
        const auto it = rxIndex_.find(rxKey(channel, pdu.headerId, false));
        if (it == rxIndex_.end()) {
            ++stats_.unroutedPdus;
            continue;
        }
        processPdu(it->second, pdu.data, pdu.length, now);
    }
}

void EthernetGateway::processPdu(std::size_t index, const std::uint8_t* data, std::size_t length,
                                 TimePoint now) {
    const auto& cfg = config_.pdus[index];
    if (length < cfg.length) {
        if (securityRecorder_) securityRecorder_->report(security::EventId::SecOcInput,
            static_cast<std::uint32_t>(index), now);
        ++stats_.lengthErrors;
        return;
    }
    ++stats_.pdusReceived;

    // SecOC: a secured PDU is only routed once its authenticity and freshness
    // are verified; from here on only the authentic part is used.
    const std::size_t authentic = authenticLength(cfg);
    if (cfg.secoc) {
        const auto result = secoc_->verify(*cfg.secoc, data, length, authentic);
        if (result != secoc::VerifyResult::Ok) {
            reportSecurityEvent(index, result, now);
            return;
        }
        ++stats_.secocVerified;
    }

    // Message routing: the (authentic) PDU is forwarded unchanged, E2E stays end-to-end.
    for (const std::size_t r : pdus_[index].pduRoutes) {
        for (const std::size_t target : pduRouteTargets_[r]) {
            forwardPdu(target, data, authentic, now);
        }
    }

    if (!pdus_[index].signalRoutes.empty()) {
        routeSignals(index, data, now);
    }
}

// ---------------------------------------------------------------------------
// Signal routing and frame assembly
// ---------------------------------------------------------------------------

void EthernetGateway::routeSignals(std::size_t index, const std::uint8_t* data, TimePoint now) {
    const auto& cfg = config_.pdus[index];
    auto& st = pdus_[index];

    if (st.e2eRx) {
        switch (st.e2eRx->check(data, authenticLength(cfg))) {
            case e2e::CheckStatus::Ok:
            case e2e::CheckStatus::OkSomeLost:
                break;
            case e2e::CheckStatus::Repeated:
                ++stats_.e2eRepeated;
                return;
            case e2e::CheckStatus::WrongSequence:
            case e2e::CheckStatus::CrcError:
                ++stats_.e2eErrors;
                onE2EError(index, now);
                return;
        }
    }
    st.consecutiveE2EErrors = 0;
    st.sourceFaulty = false;
    st.timedOut = false;
    st.received = true;
    st.lastRx = now;

    std::vector<std::size_t> triggered;
    for (const std::size_t r : st.signalRoutes) {
        const auto& route = config_.signalRoutes[r];
        const auto& rt = routes_[r];
        const auto& src = cfg.signals[rt.sourceSignal];
        const auto& tgt = config_.pdus[rt.targetPdu].signals[rt.targetSignal];

        const std::uint64_t raw = can::extractRaw(data, src);
        std::uint64_t out;
        if (src.invalidRaw && raw == *src.invalidRaw) {
            out = tgt.invalidRaw ? *tgt.invalidRaw : tgt.initRaw;  // propagate "not available"
        } else if (route.conversion == Conversion::Raw) {
            out = raw;
        } else {
            out = can::physicalToRaw(tgt, can::rawToPhysical(src, raw));
        }
        ++stats_.signalsRouted;

        const bool changed = writeTargetSignal(r, out);
        if (route.triggering) {
            if (changed) pdus_[rt.targetPdu].changedSinceTx = true;
            if (std::find(triggered.begin(), triggered.end(), rt.targetPdu) == triggered.end()) {
                triggered.push_back(rt.targetPdu);
            }
        }
    }
    for (const std::size_t t : triggered) {
        evaluateAssembled(t, true, now);
    }
}

void EthernetGateway::onE2EError(std::size_t index, TimePoint now) {
    auto& st = pdus_[index];
    ++st.consecutiveE2EErrors;
    if (!st.sourceFaulty &&
        st.consecutiveE2EErrors >= config_.pdus[index].e2e->maxConsecutiveErrors) {
        st.sourceFaulty = true;
        substituteSignals(index, now);
    }
}

void EthernetGateway::substituteSignals(std::size_t index, TimePoint now) {
    std::vector<std::size_t> changedTargets;
    for (const std::size_t r : pdus_[index].signalRoutes) {
        const auto& route = config_.signalRoutes[r];
        const auto& rt = routes_[r];
        const auto& tgt = config_.pdus[rt.targetPdu].signals[rt.targetSignal];
        std::uint64_t out;
        switch (route.substitution) {
            case Substitution::HoldLast: continue;
            case Substitution::InitValue: out = tgt.initRaw; break;
            case Substitution::InvalidValue: out = *tgt.invalidRaw; break;
            default: continue;
        }
        if (writeTargetSignal(r, out) && route.triggering) {
            pdus_[rt.targetPdu].changedSinceTx = true;
            if (std::find(changedTargets.begin(), changedTargets.end(), rt.targetPdu) ==
                changedTargets.end()) {
                changedTargets.push_back(rt.targetPdu);
            }
        }
    }
    for (const std::size_t t : changedTargets) {
        evaluateAssembled(t, true, now);
    }
}

bool EthernetGateway::writeTargetSignal(std::size_t route, std::uint64_t raw) {
    const auto& rt = routes_[route];
    const auto& spec = config_.pdus[rt.targetPdu].signals[rt.targetSignal];
    auto& buffer = pdus_[rt.targetPdu].buffer;
    raw &= can::rawMask(spec.length);
    if (can::extractRaw(buffer.data(), spec) == raw) {
        return false;
    }
    can::insertRaw(buffer.data(), spec, raw);
    return true;
}

void EthernetGateway::evaluateAssembled(std::size_t index, bool triggered, TimePoint now) {
    auto& st = pdus_[index];
    bool send = false;
    switch (config_.pdus[index].txMode) {
        case TxMode::OnUpdate: send = triggered; break;
        case TxMode::OnChange:
        case TxMode::CyclicAndOnChange: send = st.changedSinceTx; break;
        case TxMode::Cyclic: send = false; break;
    }
    if (!send) {
        return;
    }
    if (minDelayActive(index, now)) {
        st.pending = true;  // sent by mainFunction() once the minimum delay has elapsed
        return;
    }
    transmitAssembled(index, now);
}

bool EthernetGateway::minDelayActive(std::size_t index, TimePoint now) const {
    const auto& st = pdus_[index];
    return st.transmitted && now - st.lastTx < config_.pdus[index].minDelay;
}

void EthernetGateway::transmitAssembled(std::size_t index, TimePoint now) {
    auto& st = pdus_[index];
    if (st.e2eTx) {
        st.e2eTx->protect(st.buffer.data(), st.buffer.size());
    }
    if (!sendPdu(index, st.buffer.data(), st.buffer.size(), now)) {
        return;  // SecOC could not authenticate: nothing sent, retried on the next trigger
    }
    ++stats_.assembledPdusSent;
    st.transmitted = true;
    st.lastTx = now;
    st.pending = false;
    st.changedSinceTx = false;
}

// ---------------------------------------------------------------------------
// Message routing and transmission
// ---------------------------------------------------------------------------

void EthernetGateway::forwardPdu(std::size_t target, const std::uint8_t* data, std::size_t length,
                                 TimePoint now) {
    const auto& cfg = config_.pdus[target];
    std::vector<std::uint8_t> payload(authenticLength(cfg), cfg.padding);
    std::memcpy(payload.data(), data, std::min(length, payload.size()));
    if (sendPdu(target, payload.data(), payload.size(), now)) {
        ++stats_.pdusForwarded;
    }
}

bool EthernetGateway::sendPdu(std::size_t index, const std::uint8_t* authentic, std::size_t length,
                              TimePoint now) {
    const auto& cfg = config_.pdus[index];
    if (!cfg.secoc) {
        sendOnChannel(index, authentic, length, now);
        return true;
    }
    // The gateway re-authenticates with the key and freshness of the target PDU.
    const auto secured = secoc_->protect(*cfg.secoc, authentic, length);
    if (!secured) {
        if (securityRecorder_) securityRecorder_->report(security::EventId::SecOcTransmit,
            static_cast<std::uint32_t>(index), now);
        ++stats_.secocTxFailures;
        return false;
    }
    ++stats_.secocProtected;
    sendOnChannel(index, secured->data(), secured->size(), now);
    return true;
}

void EthernetGateway::reportSecurityEvent(std::size_t index, secoc::VerifyResult result,
                                          TimePoint now) {
    if (securityRecorder_) securityRecorder_->report(
        result == secoc::VerifyResult::FreshnessFailure ? security::EventId::SecOcFreshness :
        result == secoc::VerifyResult::InvalidInput ? security::EventId::SecOcInput : security::EventId::SecOcMac,
        static_cast<std::uint32_t>(index), now);
    if (result == secoc::VerifyResult::FreshnessFailure) {
        ++stats_.secocFreshnessFailures;
    } else {
        ++stats_.secocMacFailures;
    }
    if (securityEvents_.size() >= 64) {
        securityEvents_.pop_front();
    }
    securityEvents_.push_back({config_.pdus[index].name, pdus_[index].channel, result, now});
}

void EthernetGateway::sendOnChannel(std::size_t index, const std::uint8_t* data,
                                    std::size_t length, TimePoint now) {
    const auto& cfg = config_.pdus[index];
    const std::size_t channel = pdus_[index].channel;
    const auto& ch = config_.channels[channel];

    if (ch.type != BusType::Ethernet) {
        can::CanFrame frame;
        frame.id = cfg.id;
        frame.extended = cfg.extended;
        frame.fd = cfg.fd;
        frame.length = static_cast<std::uint8_t>(length);
        std::memcpy(frame.data.data(), data, length);
        if (tx_.transmitCan(channel, frame)) {
            ++stats_.canFramesSent;
        } else {
            ++stats_.canTxFailures;
        }
        return;
    }

    // Frame assembly on Ethernet: collect PDUs into one datagram.
    auto& c = containers_[channel];
    if (c.pduCount > 0 && c.datagram.size() + kPduHeaderSize + length > ch.maxDatagramSize) {
        flushContainer(channel, now);
    }
    appendPdu(c.datagram, cfg.id, data, length);
    if (c.pduCount++ == 0) {
        c.firstEnqueued = now;
        c.deadline = now + ch.collectionTimeout;
    }
    if (cfg.urgent || ch.collectionTimeout.count() <= 0) {
        flushContainer(channel, now);
    }
}

void EthernetGateway::flushContainer(std::size_t channel, TimePoint now) {
    auto& c = containers_[channel];
    if (c.pduCount == 0) {
        return;
    }
    if (tx_.transmitEthernet(channel, c.datagram)) {
        ++stats_.datagramsSent;
    } else {
        ++stats_.ethTxFailures;
    }
    const auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(now - c.firstEnqueued);
    stats_.maxDatagramCollectionDelay = std::max(stats_.maxDatagramCollectionDelay, delay);
    c.datagram.clear();
    c.pduCount = 0;
}

// ---------------------------------------------------------------------------
// Periodic processing
// ---------------------------------------------------------------------------

void EthernetGateway::mainFunction(TimePoint now) {
    if (!started_) {
        return;
    }

    // FV master: reset counter and sync message on every bus, before any secured
    // PDU of this cycle is built with the new counters.
    if (fvMaster_) {
        if (const auto sync = fvMaster_->mainFunction(now)) {
            for (const std::size_t p : syncPdus_) {
                const auto& cfg = config_.pdus[p];
                std::vector<std::uint8_t> payload(cfg.length, cfg.padding);
                std::copy(sync->begin(), sync->end(), payload.begin());
                sendOnChannel(p, payload.data(), payload.size(), now);
                ++stats_.fvSyncMessagesSent;
            }
        }
    }

    // Deadline monitoring of signal-routing sources.
    for (std::size_t p = 0; p < pdus_.size(); ++p) {
        auto& st = pdus_[p];
        const auto timeout = config_.pdus[p].timeout;
        if (st.signalRoutes.empty() || timeout.count() <= 0 || st.timedOut) {
            continue;
        }
        const TimePoint reference = st.received ? st.lastRx : startTime_;
        if (now - reference >= timeout) {
            st.timedOut = true;
            ++stats_.rxTimeouts;
            if (st.e2eRx) {
                st.e2eRx->reset();
            }
            substituteSignals(p, now);
        }
    }

    // Assembled PDUs: delayed (minimum delay) and cyclic transmissions.
    for (std::size_t p = 0; p < pdus_.size(); ++p) {
        auto& st = pdus_[p];
        if (!st.assembled) {
            continue;
        }
        const auto& cfg = config_.pdus[p];
        if (st.pending && !minDelayActive(p, now)) {
            transmitAssembled(p, now);
        }
        if (isCyclic(cfg.txMode) && now >= st.nextCyclic && !minDelayActive(p, now)) {
            transmitAssembled(p, now);
            st.nextCyclic += cfg.cycleTime;
            if (st.nextCyclic <= now) {
                st.nextCyclic = now + cfg.cycleTime;  // overrun: no catch-up burst
            }
        }
    }

    // Ethernet containers whose collection time is over.
    for (std::size_t c = 0; c < containers_.size(); ++c) {
        if (containers_[c].pduCount > 0 && now >= containers_[c].deadline) {
            flushContainer(c, now);
        }
    }
}

std::optional<std::uint64_t> EthernetGateway::assembledSignalRaw(const std::string& pdu,
                                                                 const std::string& signal) const {
    const auto it = pduByName_.find(pdu);
    if (it == pduByName_.end()) return std::nullopt;
    const auto& cfg = config_.pdus[it->second];
    const std::size_t s = signalIndex(cfg, signal);
    if (s >= cfg.signals.size()) return std::nullopt;
    return can::extractRaw(pdus_[it->second].buffer.data(), cfg.signals[s]);
}

}  // namespace ccg::ethgw
