#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/keym/key_manager.hpp"

// In-vehicle SecOC key master: the gateway generates the SecOC keys and
// distributes them to the ECUs that share them.
//
// Every ECU's MASTER_ECU_KEY is derived from the vehicle key master secret in
// the gateway HSM and the ECU's SHE UID (the plant provisions the ECUs with the
// same derivation). With it the gateway builds SHE update containers (M1..M3)
// for the ECUs and checks their M4/M5 proofs, so new keys are never visible on
// the bus and every ECU proves that it stored the key.
//
// A campaign renews key groups (one SecOC key and every ECU slot holding it):
//
//   1 prepare   per ECU: extended session, SHE UID (22 F2A1), key status (22 F2A0)
//   2 load      per group: new random key, generation = newest member counter + 1;
//               staged in the gateway HSM; per member: 31 01 F200 M1 M2 M3,
//               M4/M5 verified
//   3 activate  groups confirmed by every member: 31 01 F201 <slots> in the
//               ECUs, then in the gateway. Groups with a failed member are
//               discarded everywhere (31 01 F202 <slots>) and keep their key.
//
// Groups are atomic: a key is only activated when every member holds it.
namespace ccg::keym {

struct KeyGroupMember {
    std::uint16_t ecu = 0;  // diagnostic logical address
    std::uint8_t slot = 0;  // SHE key slot in that ECU (KEY_1..KEY_10)
};

struct KeyGroup {
    std::string keyId;             // SecOC key ID
    std::uint8_t gatewaySlot = 0;  // the gateway's own copy (0: gateway is no member)
    std::vector<KeyGroupMember> ecus;
};

struct KeyMasterConfig {
    std::vector<KeyGroup> groups;
    she::Flags flags;  // protection flags of distributed keys (KEY_USAGE must be set)
};

// Problems with the configuration against the gateway's key slots (empty = valid).
std::vector<std::string> validateKeyMasterConfig(const KeyMasterConfig& config, const KeyManagerConfig& keys);

// Key generation (HSM TRNG on the target).
class IRandom {
public:
    virtual ~IRandom() = default;
    virtual crypto::Block randomKey() = 0;
};

// AES-CTR with a fixed seed: reproducible keys for tests and simulation only.
class DeterministicRandom final : public IRandom {
public:
    explicit DeterministicRandom(const crypto::Block& seed) : aes_(seed) {}
    crypto::Block randomKey() override;

private:
    crypto::Aes128 aes_;
    std::uint64_t counter_ = 0;
};

class KeyMaster final : public diag::ILocalServiceHandler {
public:
    enum class State : std::uint8_t { Idle, Running, Finished };

    enum class GroupResult : std::uint8_t {
        NotRun = 0,
        Activated = 1,
        Running = 2,
        EcuUnreachable = 3,    // no response / transport error / timeout
        EcuRefused = 4,        // negative response (session, UID, status)
        KeyRejected = 5,       // SHE error code from the ECU
        ProofMismatch = 6,     // M4/M5 wrong: ECU did not store the key
        GatewayKeyError = 7,   // gateway HSM refused the new key
        ActivationFailed = 8,  // an ECU did not confirm the activation
    };

    struct GroupStatus {
        GroupResult result = GroupResult::NotRun;
        std::uint32_t generation = 0;
        std::uint16_t failedEcu = 0;                      // ECU that failed the group
        she::ErrorCode error = she::ErrorCode::NoError;  // SHE error (KeyRejected, GatewayKeyError)
    };

    // `keys` must have a key master slot (KeyManagerConfig::keyMasterSlot).
    KeyMaster(KeyMasterConfig config, KeyManager& keys, diag::IDiagClient& client, IRandom& random);

    // Starts a campaign for all groups or the given group indices. False if a
    // campaign is running or an index is invalid.
    bool start(TimePoint now, const std::vector<std::size_t>& groups = {});
    void mainFunction(TimePoint now);  // every few ms

    State state() const { return state_; }
    const std::vector<GroupStatus>& results() const { return results_; }
    const KeyMasterConfig& config() const { return config_; }

    // Progress messages (bench, simulation).
    void setTrace(std::function<void(const std::string&)> trace) { trace_ = std::move(trace); }

    // UDS on the gateway's address:
    //   31 01 F2 10 [group ..]  start campaign (extended session) -> 71 01 F2 10 00
    //   31 03 F2 10             results -> 71 03 F2 10 <state> <n> {result, generation (4), ECU (2), SHE error}
    std::optional<std::vector<std::uint8_t>> handle(const std::vector<std::uint8_t>& request,
                                                    const diag::LocalRequestContext& context) override;

private:
    enum class Phase : std::uint8_t { Prepare, Load, Activate };

    struct Step {
        enum class Kind : std::uint8_t { Session, ReadUid, ReadStatus, Load, Activate, Discard };
        Kind kind;
        std::uint16_t ecu = 0;
        std::vector<std::size_t> groups;  // Load: one group; Activate/Discard: their slots in the ECU
    };

    struct Ecu {
        bool failed = false;
        she::Uid uid{};
        std::map<std::uint8_t, std::uint32_t> newest;  // slot -> newest stored generation
    };

    void issueNext(TimePoint now);
    void process(const Step& step, diag::ClientResult result, const std::vector<std::uint8_t>& response);
    void nextPhase(TimePoint now);
    void failEcu(std::uint16_t ecu, GroupResult result);
    void failGroup(std::size_t group, GroupResult result, std::uint16_t ecu,
                   she::ErrorCode error = she::ErrorCode::NoError);
    bool running(std::size_t group) const { return results_[group].result == GroupResult::Running; }
    std::vector<std::uint8_t> slotsOf(std::uint16_t ecu, const std::vector<std::size_t>& groups) const;
    std::vector<std::uint8_t> requestFor(const Step& step) const;
    void trace(const std::string& text) const {
        if (trace_) trace_(text);
    }

    KeyMasterConfig config_;
    KeyManager& keys_;
    diag::IDiagClient& client_;
    IRandom& random_;
    std::function<void(const std::string&)> trace_;

    State state_ = State::Idle;
    Phase phase_ = Phase::Prepare;
    std::vector<std::size_t> selected_;
    std::vector<std::uint16_t> ecuOrder_;
    std::map<std::uint16_t, Ecu> ecus_;
    std::vector<GroupStatus> results_;
    std::vector<crypto::Block> newKeys_;
    std::set<std::pair<std::size_t, std::uint16_t>> loaded_;  // (group, ECU) holding the new key
    std::set<std::size_t> gatewayStaged_;

    std::deque<Step> steps_;
    bool waiting_ = false;
    std::optional<std::pair<diag::ClientResult, std::vector<std::uint8_t>>> reply_;
};

const char* toString(KeyMaster::GroupResult result);

}  // namespace ccg::keym
