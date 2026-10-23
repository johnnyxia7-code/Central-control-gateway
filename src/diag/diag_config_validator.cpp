#include <map>
#include <set>
#include <sstream>
#include <tuple>

#include "ccg/diag/diag_config.hpp"

namespace ccg::diag {

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

}  // namespace

std::vector<std::string> validateDiagConfig(const DiagRoutingConfig& config) {
    std::vector<std::string> errors;
    const auto& e = config.entity;

    if (e.vin.size() != 17) {
        add(errors, "entity: VIN must have 17 characters");
    }
    if (e.protocolVersion != 0x02 && e.protocolVersion != 0x03) {
        add(errors, "entity: protocol version must be 0x02 (2012) or 0x03 (2019)");
    }
    if (e.testerAddressMin > e.testerAddressMax) {
        add(errors, "entity: tester address range is empty");
    }
    auto isTester = [&](std::uint16_t la) {
        return la >= e.testerAddressMin && la <= e.testerAddressMax;
    };
    if (isTester(e.logicalAddress) || e.logicalAddress == e.functionalAddress) {
        add(errors, "entity: logical address ", hex(e.logicalAddress),
            " collides with the tester range or the functional address");
    }
    if (e.maxTcpConnections == 0) {
        add(errors, "entity: at least one TCP connection is required");
    }
    if (e.maxDiagnosticMessageSize < 8) {
        add(errors, "entity: maxDiagnosticMessageSize must be >= 8");
    }

    std::map<std::string, const DiagCanChannel*> channels;
    for (const auto& ch : config.channels) {
        if (ch.name.empty() || !channels.emplace(ch.name, &ch).second) {
            add(errors, "channel '", ch.name, "': empty or duplicate name");
        }
        if (ch.functionalRequestId > 0x7FF) {
            add(errors, "channel '", ch.name, "': functional request ID must be 11 bit");
        }
    }

    std::set<std::uint16_t> addresses = {e.logicalAddress, e.functionalAddress};
    std::set<std::tuple<std::string, std::uint32_t, bool>> canIds;
    for (const auto& ch : config.channels) {
        canIds.insert({ch.name, ch.functionalRequestId, false});
    }
    for (const auto& ecu : config.ecus) {
        const std::string where = "ECU '" + ecu.name + "'";
        if (!addresses.insert(ecu.logicalAddress).second) {
            add(errors, where, ": logical address ", hex(ecu.logicalAddress), " already used");
        }
        if (isTester(ecu.logicalAddress)) {
            add(errors, where, ": logical address ", hex(ecu.logicalAddress),
                " is in the tester range");
        }
        const auto ch = channels.find(ecu.channel);
        if (ch == channels.end()) {
            add(errors, where, ": unknown channel '", ecu.channel, "'");
            continue;
        }
        if (ecu.fd && !ch->second->fd) {
            add(errors, where, ": CAN FD ISO-TP on classic channel ", ecu.channel);
        }
        const std::uint32_t limit = ecu.extended ? 0x1FFFFFFFU : 0x7FFU;
        if (ecu.requestId > limit || ecu.responseId > limit) {
            add(errors, where, ": CAN ID out of range");
        }
        if (ecu.maxRequestLength == 0 || ecu.maxRequestLength > e.maxDiagnosticMessageSize) {
            add(errors, where, ": maxRequestLength must be 1..maxDiagnosticMessageSize");
        }
        if (ecu.requestId == ecu.responseId) {
            add(errors, where, ": request and response ID are equal");
        }
        for (const auto id : {ecu.requestId, ecu.responseId}) {
            if (!canIds.insert({ecu.channel, id, ecu.extended}).second) {
                add(errors, where, ": CAN ID ", hex(id), " already used on ", ecu.channel);
            }
        }
    }
    return errors;
}

}  // namespace ccg::diag
