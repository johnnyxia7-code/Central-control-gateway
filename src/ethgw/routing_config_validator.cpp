#include <map>
#include <set>
#include <sstream>
#include <tuple>

#include "ccg/can/can_frame.hpp"
#include "ccg/can/signal_layout.hpp"
#include "ccg/ethgw/pdu_header_codec.hpp"
#include "ccg/ethgw/routing_config.hpp"

namespace ccg::ethgw {

namespace {

std::string hex(std::uint32_t v) {
    std::ostringstream os;
    os << "0x" << std::hex << std::uppercase << v;
    return os.str();
}

template <typename... Args>
void add(std::vector<std::string>& errors, Args&&... args) {
    std::ostringstream os;
    (os << ... << args);
    errors.push_back(os.str());
}

std::string str(const SignalRef& ref) { return ref.pdu + "." + ref.signal; }

}  // namespace

const char* toString(BusType type) {
    switch (type) {
        case BusType::Can: return "CAN";
        case BusType::CanFd: return "CAN-FD";
        case BusType::Ethernet: return "Ethernet";
    }
    return "unknown";
}

std::vector<std::string> validateRoutingConfig(const RoutingConfig& config) {
    std::vector<std::string> errors;

    // ------------------------------------------------------------- channels
    std::map<std::string, const Channel*> channels;
    for (const auto& ch : config.channels) {
        if (ch.name.empty() || !channels.emplace(ch.name, &ch).second) {
            add(errors, "channel '", ch.name, "': empty or duplicate name");
        }
        if (ch.type == BusType::Ethernet &&
            (ch.maxDatagramSize <= kPduHeaderSize || ch.maxDatagramSize > 65507)) {
            add(errors, "channel '", ch.name, "': maxDatagramSize must be 9..65507");
        }
    }

    // ----------------------------------------------------------------- PDUs
    std::map<std::string, const PduDefinition*> pdus;
    std::set<std::tuple<std::string, std::uint32_t, bool>> identifiers;
    for (const auto& pdu : config.pdus) {
        const std::string where = "PDU '" + pdu.name + "'";
        if (pdu.name.empty() || !pdus.emplace(pdu.name, &pdu).second) {
            add(errors, where, ": empty or duplicate name");
        }
        const auto ch = channels.find(pdu.channel);
        if (ch == channels.end()) {
            add(errors, where, ": unknown channel '", pdu.channel, "'");
            continue;
        }
        if (!identifiers.insert({pdu.channel, pdu.id, pdu.extended}).second) {
            add(errors, where, ": identifier ", hex(pdu.id), " already used on ", pdu.channel);
        }

        bool lengthOk = true;
        switch (ch->second->type) {
            case BusType::Can:
            case BusType::CanFd: {
                if (pdu.id > (pdu.extended ? 0x1FFFFFFFU : 0x7FFU)) {
                    add(errors, where, ": CAN ID ", hex(pdu.id), " out of range");
                }
                if (pdu.fd && ch->second->type != BusType::CanFd) {
                    add(errors, where, ": CAN FD frame on classic CAN channel ", pdu.channel);
                }
                lengthOk = pdu.fd ? (pdu.length <= can::kMaxFdLength &&
                                     can::isValidFdLength(pdu.length))
                                  : pdu.length <= can::kMaxClassicLength;
                break;
            }
            case BusType::Ethernet:
                if (pdu.extended || pdu.fd) {
                    add(errors, where, ": CAN frame flags on Ethernet channel ", pdu.channel);
                }
                lengthOk = pdu.length + kPduHeaderSize <= ch->second->maxDatagramSize;
                break;
        }
        if (!lengthOk) {
            add(errors, where, ": length ", pdu.length, " not possible on ", pdu.channel, " (",
                toString(ch->second->type), ")");
            continue;
        }
        can::checkSignalLayout(where, pdu.length, pdu.signals, pdu.e2e, errors);
    }

    auto findSignal = [&](const SignalRef& ref) -> const can::SignalSpec* {
        const auto it = pdus.find(ref.pdu);
        if (it == pdus.end()) return nullptr;
        for (const auto& s : it->second->signals) {
            if (s.name == ref.signal) return &s;
        }
        return nullptr;
    };

    // ------------------------------------------------------- routing roles
    std::set<std::string> received;           // sources of any route
    std::set<std::string> pduRouteTargets;    // forwarded PDUs
    std::set<std::string> assembledTargets;   // PDUs built from signals
    std::set<std::string> triggeredTargets;   // assembled PDUs with a triggering route

    for (const auto& route : config.pduRoutes) {
        const std::string where = "PDU route '" + route.name + "'";
        const auto src = pdus.find(route.source);
        if (src == pdus.end()) {
            add(errors, where, ": unknown source PDU '", route.source, "'");
            continue;
        }
        received.insert(route.source);
        if (route.targets.empty()) {
            add(errors, where, ": no target PDU");
        }
        for (const auto& target : route.targets) {
            const auto tgt = pdus.find(target);
            if (tgt == pdus.end()) {
                add(errors, where, ": unknown target PDU '", target, "'");
                continue;
            }
            if (target == route.source) {
                add(errors, where, ": PDU '", target, "' routed to itself");
                continue;
            }
            if (!pduRouteTargets.insert(target).second) {
                add(errors, where, ": PDU '", target, "' is the target of more than one PDU route");
            }
            if (tgt->second->length < src->second->length) {
                add(errors, where, ": target '", target, "' (", tgt->second->length,
                    " bytes) shorter than source '", route.source, "' (", src->second->length,
                    " bytes)");
            }
            if (tgt->second->e2e) {
                add(errors, where, ": target '", target,
                    "' has E2E protection, but routed PDUs are forwarded unchanged");
            }
        }
    }

    std::set<std::pair<std::string, std::string>> writtenSignals;
    for (const auto& route : config.signalRoutes) {
        const std::string where = "signal route " + str(route.source) + " -> " + str(route.target);
        const auto* src = findSignal(route.source);
        const auto* tgt = findSignal(route.target);
        if (!src) add(errors, where, ": unknown source signal");
        if (!tgt) add(errors, where, ": unknown target signal");
        if (!src || !tgt) continue;
        if (route.source.pdu == route.target.pdu) {
            add(errors, where, ": source and target in the same PDU");
            continue;
        }
        received.insert(route.source.pdu);
        assembledTargets.insert(route.target.pdu);
        if (route.triggering) {
            triggeredTargets.insert(route.target.pdu);
        }
        if (!writtenSignals.insert({route.target.pdu, route.target.signal}).second) {
            add(errors, where, ": target signal written by more than one route");
        }
        if (route.conversion == Conversion::Raw &&
            (src->length != tgt->length || src->isSigned != tgt->isSigned)) {
            add(errors, where, ": raw copy needs equal length and signedness");
        }
        if (route.substitution == Substitution::InvalidValue && !tgt->invalidRaw) {
            add(errors, where, ": substitution InvalidValue but target has no invalid value");
        }
    }

    for (const auto& name : received) {
        if (pduRouteTargets.count(name) || assembledTargets.count(name)) {
            add(errors, "PDU '", name, "' is both received and transmitted by the gateway");
        }
    }
    for (const auto& name : assembledTargets) {
        if (pduRouteTargets.count(name)) {
            add(errors, "PDU '", name, "' is written by a PDU route and by signal routes");
        }
        const auto* pdu = pdus.at(name);
        const bool cyclic =
            pdu->txMode == TxMode::Cyclic || pdu->txMode == TxMode::CyclicAndOnChange;
        if (cyclic && pdu->cycleTime.count() <= 0) {
            add(errors, "PDU '", name, "': cyclic transmission needs a cycle time");
        }
        if (!cyclic && !triggeredTargets.count(name)) {
            add(errors, "PDU '", name, "': never transmitted (no cycle and no triggering route)");
        }
    }

    return errors;
}

}  // namespace ccg::ethgw
