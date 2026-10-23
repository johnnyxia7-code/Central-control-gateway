#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ccg/secoc/secoc.hpp"

// Freshness value synchronisation (AUTOSAR SecOC "multiple freshness counters",
// JASPAR FV master / slave).
//
// The FV master (the central gateway) owns the trip counter and the reset
// counter and broadcasts them in an authenticated sync message:
//
//   | TripCounter (tripBits) | ResetCounter (resetBits) | MAC (macTxBits) | pad |
//   MAC = AES-128-CMAC(key, DataID | TripCounter (4 B) | ResetCounter (4 B)), MSBs
//
//   power-up            : TripCounter + 1 (persisted before use), ResetCounter = 0
//   every reset cycle   : ResetCounter + 1, sync message on every bus
//   ResetCounter overflow: TripCounter + 1, ResetCounter = 0
//
// ECUs (FV slaves) adopt the counters only from authentic, newer sync messages.
namespace ccg::secoc {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

struct SyncMessageConfig {
    std::uint16_t dataId = 0;
    std::string keyId;
    std::uint8_t macTxBits = 28;
    std::chrono::milliseconds resetCycle{1000};
};

std::size_t syncMessageLength(const TripResetLayout& layout, const SyncMessageConfig& config);

// Problems with layout and sync parameters, without prefix (empty = valid).
std::vector<std::string> validateFreshnessSync(const TripResetLayout& layout,
                                               const SyncMessageConfig& config);

enum class SyncResult : std::uint8_t {
    Accepted,
    MacFailure,   // forged or corrupted sync message
    Stale,        // counters not newer than the current ones (replay)
    LengthError,
    CryptoError,
};

const char* toString(SyncResult result);

class FreshnessSyncMaster {
public:
    FreshnessSyncMaster(SyncMessageConfig config, ICryptoService& crypto, FreshnessManager& freshness);

    // Power-up: trip counter = stored + 1, reset counter = 0. The new trip counter
    // is flagged for persistence (FreshnessManager::takePersistRequest) and must be
    // stored before the first secured PDU leaves the gateway. false = trip counter
    // exhausted, synchronised freshness is unavailable until key renewal.
    bool start(TimePoint now);

    // The sync message when one is due: right after start, after every reset
    // counter increment and after requestSync().
    std::optional<std::vector<std::uint8_t>> mainFunction(TimePoint now);

    // Resend the current counters at the next mainFunction (e.g. an ECU woke up).
    void requestSync() { syncDue_ = true; }

    bool active() const { return active_; }
    std::uint64_t syncMessagesSent() const { return sent_; }

private:
    std::optional<std::vector<std::uint8_t>> encode();

    SyncMessageConfig cfg_;
    ICryptoService& crypto_;
    FreshnessManager& freshness_;
    bool active_ = false;
    bool syncDue_ = false;
    TimePoint nextReset_{};
    std::uint64_t sent_ = 0;
};

class FreshnessSyncSlave {
public:
    FreshnessSyncSlave(SyncMessageConfig config, ICryptoService& crypto, FreshnessManager& freshness)
        : cfg_(std::move(config)), crypto_(crypto), freshness_(freshness) {}

    SyncResult onSyncMessage(const std::uint8_t* data, std::size_t length);

private:
    SyncMessageConfig cfg_;
    ICryptoService& crypto_;
    FreshnessManager& freshness_;
};

// Shared by master and slave: MAC over DataID | trip | reset.
bool syncAuthenticator(ICryptoService& crypto, const SyncMessageConfig& config, std::uint32_t trip,
                       std::uint32_t reset, crypto::Block& mac);

}  // namespace ccg::secoc
