#pragma once
#include "ccg/security/event_recorder.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "ccg/crypto/aes_cmac.hpp"
#include "ccg/keym/she.hpp"
#include "ccg/secoc/secoc.hpp"

// SecOC key management of the gateway (AUTOSAR KeyM + Csm/CryIf key slots).
//
//  - Key slots with SHE semantics: MASTER_ECU_KEY authorises updates, every
//    key has a 28-bit update counter (anti-rollback) and protection flags.
//  - Keys are loaded with the SHE memory update protocol (M1..M3 in, M4/M5
//    out); plain-text keys are only accepted at production (EOL) provisioning.
//  - Rollover: a new SecOC key is staged as "pending" until the backend
//    activates the new key generation vehicle-wide. On activation the old key
//    becomes "previous" and is still accepted for MAC verification during a
//    grace period, so ECUs that switch a little later are not cut off; MACs
//    from ECUs that switched earlier verify with the pending key. The gateway
//    itself always transmits with the active key.
//  - Brute-force protection: consecutive authentication failures lock the
//    key update for a while.
//
// Implements secoc::ICryptoService, so SecOC and the FV master use it directly.
namespace ccg::keym {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

struct SlotConfig {
    std::uint8_t slot = 0;  // SHE key ID: MASTER_ECU_KEY or KEY_1..KEY_10
    std::string keyId;      // name used by SecOC (empty for MASTER_ECU_KEY)
    bool staged = true;     // new key waits for activation (false: active at once)
};

struct KeyManagerConfig {
    she::Uid uid{};                                           // unique ID of the gateway HSM
    std::vector<SlotConfig> slots;
    std::chrono::milliseconds gracePeriod{std::chrono::minutes(10)};  // previous key still verified
    std::uint8_t maxFailedAttempts = 3;                       // then key updates are locked
    std::chrono::milliseconds lockoutTime{std::chrono::seconds(10)};
    // Key master: slot holding the vehicle key master secret from which the
    // ECUs' MASTER_ECU_KEYs are derived (0 = this device is no key master).
    std::uint8_t keyMasterSlot = 0;
};

// Problems with the configuration (empty = valid).
std::vector<std::string> validateKeyManagerConfig(const KeyManagerConfig& config);

// MASTER_ECU_KEY of the ECU with `uid` under a vehicle key master secret:
// KDF(secret, UID | 'M'). The plant provisions the ECUs with it; the key
// master derives it inside the HSM.
crypto::Block deriveEcuMasterKey(const crypto::Block& keyMasterSecret, const she::Uid& uid);

struct KeyEvent {
    enum class Kind : std::uint8_t {
        Provisioned,         // plain-text EOL provisioning
        KeyLoaded,           // SHE update, active at once
        KeyStaged,           // SHE update, pending activation
        UpdateRejected,      // SHE update refused (error)
        UpdateLocked,        // too many authentication failures
        KeysActivated,       // pending -> active, active -> previous
        PendingDiscarded,
        PreviousKeyExpired,  // grace period over
    };
    Kind kind;
    std::uint8_t slot = 0;
    std::uint32_t counter = 0;
    she::ErrorCode error = she::ErrorCode::NoError;
    TimePoint time{};
};

const char* toString(KeyEvent::Kind kind);

class KeyManager final : public secoc::ICryptoService {
public:
    void setSecurityRecorder(security::EventRecorder& recorder) { securityRecorder_ = &recorder; }
    explicit KeyManager(KeyManagerConfig config);  // throws std::invalid_argument

    // Production (EOL) provisioning in the secure plant: plain-text key into an
    // empty slot. False if the slot is unknown or not empty.
    bool provision(std::uint8_t slot, const crypto::Block& key, std::uint32_t counter,
                   const she::Flags& flags, TimePoint now);

    struct LoadResult {
        she::ErrorCode error = she::ErrorCode::GeneralError;
        std::optional<she::UpdateProof> proof;  // M4/M5 on success
        bool staged = false;                    // waiting for activation
    };
    // SHE CMD_LOAD_KEY.
    LoadResult loadKey(const she::UpdateRequest& request, TimePoint now);
    bool lockedOut(TimePoint now) const { return lockedUntil_ && now < *lockedUntil_; }

    // Switches pending keys to active (all slots, or only `slots`). Returns
    // the number of keys switched.
    std::size_t activatePending(TimePoint now, const std::vector<std::uint8_t>& slots = {});
    std::size_t discardPending(TimePoint now, const std::vector<std::uint8_t>& slots = {});
    bool hasPending(const std::vector<std::uint8_t>& slots = {}) const;

    // --- key master (HSM-internal operations, the keys never leave the HSM)
    // MASTER_ECU_KEY of the ECU with `uid`: KDF(key master secret, UID | 'M').
    // nullopt if this device has no key master secret.
    std::optional<crypto::Block> deriveEcuMasterKey(const she::Uid& uid) const;
    // Stores a key generated inside the HSM like a SHE update (write
    // protection, anti-rollback, staging), without the M1..M3 container.
    she::ErrorCode stageInternal(std::uint8_t slot, const crypto::Block& key, std::uint32_t counter,
                                 const she::Flags& flags, TimePoint now);

    // Expires previous keys after the grace period.
    void mainFunction(TimePoint now);

    struct SlotStatus {
        std::uint8_t slot = 0;
        std::string keyId;
        bool active = false;
        std::uint32_t counter = 0;
        she::Flags flags;
        bool pending = false;
        std::uint32_t pendingCounter = 0;
        bool previous = false;  // previous key still accepted
        std::uint32_t updateCounter = 0;  // includes discarded generations
    };
    std::vector<SlotStatus> status() const;

    // --- secoc::ICryptoService
    bool hasKey(const std::string& keyId) const override;
    bool generateMac(const std::string& keyId, const std::uint8_t* data, std::size_t length,
                     crypto::Block& mac) override;
    std::optional<bool> verifyMac(const std::string& keyId, const std::uint8_t* data, std::size_t length,
                                  const std::uint8_t* mac, std::size_t macBits) override;

    // MACs accepted with the previous or the pending key during a rollover.
    std::uint64_t rolloverVerifications() const { return rolloverVerifications_; }
    const std::deque<KeyEvent>& events() const { return events_; }  // latest 64
    std::uint64_t eventCount() const { return eventCount_; }          // all events so far
    const KeyManagerConfig& config() const { return config_; }

    // Persistence (HSM NvM). The remaining grace period of previous keys is kept.
    struct StoredKey {
        enum class State : std::uint8_t { Active, Pending, Previous };
        std::uint8_t slot = 0;
        State state = State::Active;
        crypto::Block key{};
        std::uint32_t counter = 0;
        std::uint8_t flags = 0;
        std::chrono::milliseconds remaining{0};  // Previous only
    };
    struct Snapshot {
        std::vector<StoredKey> keys;
        std::map<std::uint8_t, std::uint32_t> updateCounters;
    };
    Snapshot snapshot(TimePoint now) const;
    // Validate the entire snapshot before replacing any live state.
    // A durable callback must commit the proposed state or throw before publication.
    using Persist = std::function<void(const Snapshot&)>;
    void setPersistence(Persist persist) { persist_ = std::move(persist); }
    void restore(const Snapshot& snapshot, TimePoint now);
    // True once after the stored keys changed: persist the snapshot now.
    bool takePersistRequest();

private:
    security::EventRecorder* securityRecorder_ = nullptr;
    struct Key {
        Key(const crypto::Block& v, std::uint32_t c, const she::Flags& f) : value(v), counter(c), flags(f), cmac(v) {}
        crypto::Block value;
        std::uint32_t counter;
        she::Flags flags;
        crypto::Cmac cmac;
    };
    struct Slot {
        SlotConfig config;
        std::optional<Key> active;
        std::optional<Key> pending;
        std::optional<Key> previous;
        TimePoint previousExpiry{};
        std::uint32_t updateCounter = 0;
    };

    Slot* findSlot(std::uint8_t slot);
    const Slot* findSlot(std::uint8_t slot) const;
    const Slot* findKey(const std::string& keyId) const;
    LoadResult reject(std::uint8_t slot, she::ErrorCode error, TimePoint now);
    // Installs a new generation: staged as pending or active at once. Returns true if staged.
    bool install(Slot& slot, const she::UpdatePayload& payload, TimePoint now);
    static bool selected(const Slot& slot, const std::vector<std::uint8_t>& slots);
    void log(KeyEvent::Kind kind, std::uint8_t slot, std::uint32_t counter, she::ErrorCode error, TimePoint now);

    Snapshot snapshotOf(const std::vector<Slot>& slots, TimePoint now) const;
    void commit(std::vector<Slot> slots, TimePoint now);
    Persist persist_;
    KeyManagerConfig config_;
    std::vector<Slot> slots_;
    std::uint8_t failedAttempts_ = 0;
    std::optional<TimePoint> lockedUntil_;
    std::uint64_t rolloverVerifications_ = 0;
    std::deque<KeyEvent> events_;
    std::uint64_t eventCount_ = 0;
    bool persistRequest_ = false;
};

}  // namespace ccg::keym
