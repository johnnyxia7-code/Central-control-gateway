#include "ccg/keym/key_management_service.hpp"

#include <algorithm>

namespace ccg::keym {

namespace {

constexpr std::uint8_t kSidRead = 0x22;
constexpr std::uint8_t kSidRoutine = 0x31;
constexpr std::uint8_t kExtendedSession = 0x03;
constexpr std::size_t kLoadKeyLength = 4 + 16 + 32 + 16;

std::vector<std::uint8_t> nrc(std::uint8_t sid, std::uint8_t code) { return {0x7F, sid, code}; }

void putU32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>(v >> shift));
}

}  // namespace

std::optional<std::vector<std::uint8_t>> KeyManagementService::handle(
    const std::vector<std::uint8_t>& request, const diag::LocalRequestContext& context) {
    if (request.empty()) return std::nullopt;
    if (request[0] == kSidRead) {
        if (request.size() != 3 || ((request[1] << 8) | request[2]) != uds::kDidKeyStatus) return std::nullopt;
        return keyStatus();
    }
    if (request[0] == kSidRoutine && !context.functional) {
        return routineControl(request, context);
    }
    return std::nullopt;
}

std::optional<std::vector<std::uint8_t>> KeyManagementService::routineControl(
    const std::vector<std::uint8_t>& request, const diag::LocalRequestContext& context) {
    // NRC order of ISO 14229-1: session, length, sub-function, routine ID.
    if (context.session != kExtendedSession) return nrc(kSidRoutine, 0x7F);
    if (request.size() < 4) return nrc(kSidRoutine, 0x13);
    const std::uint8_t sub = request[1] & 0x7F;
    const bool suppress = request[1] & 0x80;
    const auto rid = static_cast<std::uint16_t>((request[2] << 8) | request[3]);
    if (sub != 0x01) return nrc(kSidRoutine, 0x12);  // only startRoutine
    if (rid != uds::kRidLoadKey && rid != uds::kRidActivateKeys && rid != uds::kRidDiscardKeys) {
        return nrc(kSidRoutine, 0x31);  // requestOutOfRange
    }

    std::vector<std::uint8_t> out = {0x71, 0x01, request[2], request[3]};
    switch (rid) {
        case uds::kRidLoadKey: {
            if (request.size() != kLoadKeyLength) return nrc(kSidRoutine, 0x13);
            if (keys_.lockedOut(context.now)) return nrc(kSidRoutine, 0x37);  // requiredTimeDelayNotExpired
            she::UpdateRequest r;
            auto it = request.begin() + 4;
            std::copy(it, it + 16, r.m1.begin());
            std::copy(it + 16, it + 48, r.m2.begin());
            std::copy(it + 48, it + 64, r.m3.begin());
            const auto result = keys_.loadKey(r, context.now);
            if (result.error == she::ErrorCode::NoError && !persisted()) return nrc(kSidRoutine, 0x72);
            out.push_back(static_cast<std::uint8_t>(result.error));
            if (result.proof) {
                out.insert(out.end(), result.proof->m4.begin(), result.proof->m4.end());
                out.insert(out.end(), result.proof->m5.begin(), result.proof->m5.end());
            }
            return out;  // M4/M5 are the result: never suppressed
        }
        case uds::kRidActivateKeys:
        case uds::kRidDiscardKeys: {
            if (request.size() != 4) return nrc(kSidRoutine, 0x13);
            if (!keys_.hasPending()) return nrc(kSidRoutine, 0x24);  // requestSequenceError
            const std::size_t n = rid == uds::kRidActivateKeys ? keys_.activatePending(context.now)
                                                               : keys_.discardPending(context.now);
            if (!persisted()) return nrc(kSidRoutine, 0x72);
            if (suppress) return std::vector<std::uint8_t>{};
            out.push_back(static_cast<std::uint8_t>(n));
            return out;
        }
        default:
            return nrc(kSidRoutine, 0x31);
    }
}

std::vector<std::uint8_t> KeyManagementService::keyStatus() const {
    const auto slots = keys_.status();
    std::vector<std::uint8_t> out = {0x62, static_cast<std::uint8_t>(uds::kDidKeyStatus >> 8),
                                     static_cast<std::uint8_t>(uds::kDidKeyStatus & 0xFF),
                                     static_cast<std::uint8_t>(slots.size())};
    for (const auto& s : slots) {
        std::uint8_t state = 0;
        if (s.active) state |= uds::kStatusActive;
        if (s.pending) state |= uds::kStatusPending;
        if (s.previous) state |= uds::kStatusPrevious;
        if (s.flags.writeProtection) state |= uds::kStatusWriteProtected;
        if (s.flags.keyUsage) state |= uds::kStatusMacKey;
        out.push_back(s.slot);
        out.push_back(state);
        putU32(out, s.counter);
        putU32(out, s.pendingCounter);
    }
    return out;
}

}  // namespace ccg::keym
