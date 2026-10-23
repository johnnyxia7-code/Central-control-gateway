#include "ccg/can/signal_layout.hpp"

#include <set>

namespace ccg::can {

void checkSignalLayout(const std::string& where, std::size_t length,
                       const std::vector<SignalSpec>& signals,
                       const std::optional<e2e::CanE2EConfig>& e2e,
                       std::vector<std::string>& errors) {
    std::vector<std::string> owner(length * 8);
    auto claim = [&](const SignalSpec& spec) {
        if (!fitsInFrame(spec, length)) {
            errors.push_back(where + ": signal '" + spec.name + "' does not fit into " +
                             std::to_string(length) + " bytes");
            return;
        }
        forEachBitMsbFirst(spec, [&](std::size_t pos) {
            if (!owner[pos].empty()) {
                errors.push_back(where + ": signal '" + spec.name + "' overlaps '" + owner[pos] +
                                 "' at bit " + std::to_string(pos));
            }
            owner[pos] = spec.name;
        });
    };

    std::set<std::string> names;
    for (const auto& s : signals) {
        if (!names.insert(s.name).second) {
            errors.push_back(where + ": duplicate signal '" + s.name + "'");
        }
        if (s.factor == 0.0) {
            errors.push_back(where + ": signal '" + s.name + "' has factor 0");
        }
        if (s.min > s.max) {
            errors.push_back(where + ": signal '" + s.name + "' has min > max");
        }
        claim(s);
    }

    if (!e2e) {
        return;
    }
    if (e2e->crcByte >= length) {
        errors.push_back(where + ": E2E CRC byte outside payload");
    } else {
        SignalSpec crc;
        crc.name = "E2E_CRC";
        crc.startBit = static_cast<std::uint16_t>(e2e->crcByte * 8);
        crc.length = 8;
        claim(crc);
    }
    SignalSpec counter;
    counter.name = "E2E_Counter";
    counter.startBit = e2e->counterStartBit;
    counter.length = 4;
    claim(counter);
    if (e2e->maxDeltaCounter == 0 || e2e->maxDeltaCounter >= e2e::kCounterModulo) {
        errors.push_back(where + ": E2E maxDeltaCounter must be 1..14");
    }
    if (e2e->maxConsecutiveErrors == 0) {
        errors.push_back(where + ": E2E maxConsecutiveErrors must be >= 1");
    }
}

}  // namespace ccg::can
