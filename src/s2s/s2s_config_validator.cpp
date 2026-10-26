#include <set>
#include <sstream>
#include <tuple>
#include <vector>

#include "ccg/can/can_frame.hpp"
#include "ccg/can/signal_layout.hpp"
#include "ccg/s2s/s2s_config.hpp"

namespace ccg::s2s {

namespace {

class Errors {
public:
    template <typename... Args>
    void add(Args&&... args) {
        std::ostringstream os;
        (os << ... << args);
        list.push_back(os.str());
    }
    std::vector<std::string> list;
};

std::string hex(std::uint32_t v) {
    std::ostringstream os;
    os << "0x" << std::hex << std::uppercase << v;
    return os.str();
}

template <typename Message>
void checkMessage(const Message& msg, const char* direction, Errors& errors) {
    const std::string where = std::string(direction) + " message '" + msg.name + "'";
    const std::uint32_t idLimit = msg.extended ? 0x1FFFFFFFU : 0x7FFU;
    if (msg.canId > idLimit) {
        errors.add(where, ": CAN ID ", hex(msg.canId), " out of range");
    }
    if (msg.fd ? !can::isValidFdLength(msg.length) : msg.length > can::kMaxClassicLength) {
        errors.add(where, ": invalid payload length ", int{msg.length});
        return;
    }

    can::checkSignalLayout(where, msg.length, msg.signals, msg.e2e, errors.list);
}

template <typename Message>
const can::SignalSpec* findSignal(const std::vector<Message>& messages, const SignalRef& ref) {
    for (const auto& m : messages) {
        if (m.name != ref.message) continue;
        for (const auto& s : m.signals) {
            if (s.name == ref.signal) return &s;
        }
    }
    return nullptr;
}

}  // namespace

std::vector<std::string> validateConfig(const GatewayConfig& config) {
    Errors errors;

    std::set<std::string> messageNames;
    std::set<std::pair<std::uint32_t, bool>> rxIds;
    std::set<std::pair<std::uint32_t, bool>> txIds;
    for (const auto& m : config.rxMessages) {
        checkMessage(m, "Rx", errors);
        if (!messageNames.insert(m.name).second) {
            errors.add("duplicate message name '", m.name, "'");
        }
        if (!rxIds.insert({m.canId, m.extended}).second) {
            errors.add("Rx message '", m.name, "': duplicate CAN ID ", hex(m.canId));
        }
    }
    for (const auto& m : config.txMessages) {
        checkMessage(m, "Tx", errors);
        if (!messageNames.insert(m.name).second) {
            errors.add("duplicate message name '", m.name, "'");
        }
        if (!txIds.insert({m.canId, m.extended}).second) {
            errors.add("Tx message '", m.name, "': duplicate CAN ID ", hex(m.canId));
        }
        if (m.cycleTime.count() == 0 && m.eventRepetitions == 0) {
            errors.add("Tx message '", m.name, "': neither cyclic nor event transmission");
        }
        if (m.eventRepetitions > 1 && m.repetitionInterval.count() <= 0) {
            errors.add("Tx message '", m.name, "': repetitions need a repetition interval");
        }
    }

    std::set<std::pair<std::uint16_t, std::uint16_t>> services;
    for (const auto& s : config.services) {
        if (!services.insert({s.serviceId, s.instanceId}).second) {
            errors.add("duplicate service instance ", hex(s.serviceId), "/", hex(s.instanceId));
        }
    }

    // (service, instance, id) must be unique across events, getters and methods.
    std::set<std::tuple<std::uint16_t, std::uint16_t, std::uint16_t>> ids;
    auto claimId = [&](std::uint16_t svc, std::uint16_t inst, std::uint16_t id,
                       const std::string& what) {
        if (!ids.insert({svc, inst, id}).second) {
            errors.add(what, ": ID ", hex(id), " already used in service ", hex(svc));
        }
    };

    for (const auto& e : config.events) {
        const std::string where = "event '" + e.name + "'";
        if (!services.count({e.serviceId, e.instanceId})) {
            errors.add(where, ": service ", hex(e.serviceId), "/", hex(e.instanceId),
                       " not configured");
        }
        if ((e.eventId & 0x8000U) == 0) {
            errors.add(where, ": event ID ", hex(e.eventId), " must have bit 15 set");
        }
        claimId(e.serviceId, e.instanceId, e.eventId, where);
        if (e.getterMethodId) {
            if (!e.isField) {
                errors.add(where, ": getter configured for a non-field event");
            }
            if (*e.getterMethodId & 0x8000U) {
                errors.add(where, ": getter ID ", hex(*e.getterMethodId),
                           " must have bit 15 clear");
            }
            claimId(e.serviceId, e.instanceId, *e.getterMethodId, where + " getter");
        }
        if (e.updateMode != UpdateMode::OnChange && e.cycleTime.count() <= 0) {
            errors.add(where, ": cyclic update mode requires a cycle time");
        }
        if (e.elements.empty()) {
            errors.add(where, ": no elements");
        }
        for (const auto& el : e.elements) {
            if (!findSignal(config.rxMessages, el.source)) {
                errors.add(where, ": element '", el.name, "' references unknown Rx signal ",
                           el.source.message, ".", el.source.signal);
            }
        }
    }

    std::set<std::tuple<std::string, std::string>> writtenSignals;
    for (const auto& m : config.methods) {
        const std::string where = "method '" + m.name + "'";
        if (!services.count({m.serviceId, m.instanceId})) {
            errors.add(where, ": service ", hex(m.serviceId), "/", hex(m.instanceId),
                       " not configured");
        }
        if (m.methodId & 0x8000U) {
            errors.add(where, ": method ID ", hex(m.methodId), " must have bit 15 clear");
        }
        claimId(m.serviceId, m.instanceId, m.methodId, where);
        for (const auto& a : m.arguments) {
            if (!findSignal(config.txMessages, a.target)) {
                errors.add(where, ": argument '", a.name, "' references unknown Tx signal ",
                           a.target.message, ".", a.target.signal);
            }
            if (!writtenSignals.insert({a.target.message, a.target.signal}).second) {
                errors.add(where, ": Tx signal ", a.target.message, ".", a.target.signal,
                           " is written by more than one argument");
            }
        }
    }

    return errors.list;
}

}  // namespace ccg::s2s
