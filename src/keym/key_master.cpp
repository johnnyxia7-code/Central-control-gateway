#include "ccg/keym/key_master.hpp"

#include <algorithm>
#include <sstream>
#include <stdexcept>

#include "ccg/keym/key_management_service.hpp"

namespace ccg::keym {

namespace {

constexpr std::uint16_t kRidKeyCampaign = 0xF210;
constexpr std::uint8_t kSidRoutine = 0x31;

std::vector<std::uint8_t> nrc(std::uint8_t code) { return {0x7F, kSidRoutine, code}; }

std::string hexAddress(std::uint16_t a) {
    std::ostringstream os;
    os << "0x" << std::hex << std::uppercase << a;
    return os.str();
}

std::uint32_t readU32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
}

}  // namespace

const char* toString(KeyMaster::GroupResult result) {
    using R = KeyMaster::GroupResult;
    switch (result) {
        case R::NotRun: return "NOT_RUN";
        case R::Activated: return "ACTIVATED";
        case R::Running: return "RUNNING";
        case R::EcuUnreachable: return "ECU_UNREACHABLE";
        case R::EcuRefused: return "ECU_REFUSED";
        case R::KeyRejected: return "KEY_REJECTED";
        case R::ProofMismatch: return "PROOF_MISMATCH";
        case R::GatewayKeyError: return "GATEWAY_KEY_ERROR";
        case R::ActivationFailed: return "ACTIVATION_FAILED";
    }
    return "UNKNOWN";
}

std::vector<std::string> validateKeyMasterConfig(const KeyMasterConfig& c, const KeyManagerConfig& keys) {
    std::vector<std::string> errors;
    if (keys.keyMasterSlot == 0) errors.push_back("gateway key slots have no key master slot");
    if (!c.flags.keyUsage) errors.push_back("distributed keys need the KEY_USAGE flag (MAC keys)");
    if (c.groups.empty()) errors.push_back("no key groups");
    std::set<std::string> ids;
    std::set<std::pair<std::uint16_t, std::uint8_t>> ecuSlots;
    std::set<std::uint8_t> gatewaySlots;
    for (const auto& g : c.groups) {
        const std::string name = "group '" + g.keyId + "'";
        if (!ids.insert(g.keyId).second) errors.push_back(name + ": defined twice");
        if (g.ecus.empty()) errors.push_back(name + ": no ECU members");
        for (const auto& m : g.ecus) {
            if (m.slot < she::kKey1 || m.slot > she::kKey10) {
                errors.push_back(name + ": ECU " + hexAddress(m.ecu) + " slot must be KEY_1..KEY_10");
            }
            if (!ecuSlots.insert({m.ecu, m.slot}).second) {
                errors.push_back(name + ": ECU " + hexAddress(m.ecu) + " slot " + std::to_string(m.slot) +
                                 " used by two groups");
            }
        }
        if (g.gatewaySlot == 0) continue;
        if (!gatewaySlots.insert(g.gatewaySlot).second) errors.push_back(name + ": gateway slot used twice");
        const auto it = std::find_if(keys.slots.begin(), keys.slots.end(),
                                     [&](const SlotConfig& s) { return s.slot == g.gatewaySlot; });
        if (it == keys.slots.end()) {
            errors.push_back(name + ": gateway slot " + std::to_string(g.gatewaySlot) + " not configured");
        } else if (it->keyId != g.keyId || g.gatewaySlot == keys.keyMasterSlot) {
            errors.push_back(name + ": gateway slot " + std::to_string(g.gatewaySlot) + " holds '" + it->keyId + "'");
        }
    }
    return errors;
}

crypto::Block DeterministicRandom::randomKey() {
    crypto::Block block{};
    const std::uint64_t n = counter_++;
    for (std::size_t i = 0; i < 8; ++i) block[15 - i] = static_cast<std::uint8_t>(n >> (8 * i));
    return aes_.encrypt(block);
}

KeyMaster::KeyMaster(KeyMasterConfig config, KeyManager& keys, diag::IDiagClient& client, IRandom& random)
    : config_(std::move(config)), keys_(keys), client_(client), random_(random) {
    const auto errors = validateKeyMasterConfig(config_, keys_.config());
    if (!errors.empty()) {
        std::ostringstream os;
        os << "invalid key master configuration";
        for (const auto& e : errors) os << "\n  - " << e;
        throw std::invalid_argument(os.str());
    }
    results_.resize(config_.groups.size());
}

bool KeyMaster::start(TimePoint now, const std::vector<std::size_t>& groups) {
    if (state_ == State::Running) return false;
    if (!keys_.deriveEcuMasterKey(she::Uid{})) return false;  // key master secret not provisioned
    std::vector<std::size_t> selected = groups;
    if (selected.empty()) {
        for (std::size_t g = 0; g < config_.groups.size(); ++g) selected.push_back(g);
    }
    for (const auto g : selected) {
        if (g >= config_.groups.size()) return false;
    }
    std::sort(selected.begin(), selected.end());
    selected.erase(std::unique(selected.begin(), selected.end()), selected.end());

    state_ = State::Running;
    phase_ = Phase::Prepare;
    selected_ = selected;
    ecus_.clear();
    ecuOrder_.clear();
    loaded_.clear();
    gatewayStaged_.clear();
    steps_.clear();
    waiting_ = false;
    reply_.reset();
    newKeys_.assign(config_.groups.size(), crypto::Block{});
    for (auto& r : results_) r = GroupStatus{};
    for (const auto g : selected_) {
        results_[g].result = GroupResult::Running;
        for (const auto& m : config_.groups[g].ecus) {
            if (!ecus_.count(m.ecu)) {
                ecus_[m.ecu] = Ecu{};
                ecuOrder_.push_back(m.ecu);
            }
        }
    }
    for (const auto ecu : ecuOrder_) {
        steps_.push_back({Step::Kind::Session, ecu, {}});
        steps_.push_back({Step::Kind::ReadUid, ecu, {}});
        steps_.push_back({Step::Kind::ReadStatus, ecu, {}});
    }
    trace("key master: campaign for " + std::to_string(selected_.size()) + " key group(s), " +
          std::to_string(ecuOrder_.size()) + " ECU(s)");
    (void)now;  // the first request goes out from mainFunction (start may run inside the UDS server)
    return true;
}

void KeyMaster::mainFunction(TimePoint now) {
    if (state_ != State::Running) return;
    if (waiting_) {
        if (!reply_) return;
        const Step step = steps_.front();
        steps_.pop_front();
        const auto reply = std::move(*reply_);
        waiting_ = false;
        reply_.reset();
        process(step, reply.first, reply.second);
    }
    issueNext(now);
}

void KeyMaster::issueNext(TimePoint now) {
    while (state_ == State::Running) {
        while (!steps_.empty()) {
            const Step& s = steps_.front();
            bool skip = ecus_[s.ecu].failed && s.kind != Step::Kind::Discard;
            if (s.kind == Step::Kind::Load) skip = skip || !running(s.groups.front());
            if (!skip) break;
            steps_.pop_front();
        }
        if (steps_.empty()) {
            nextPhase(now);
            continue;
        }
        waiting_ = true;
        client_.request(steps_.front().ecu, requestFor(steps_.front()), now,
                        [this](diag::ClientResult r, std::vector<std::uint8_t> data) {
                            reply_.emplace(r, std::move(data));
                        });
        return;  // the reply is processed in the next main function call
    }
}

std::vector<std::uint8_t> KeyMaster::slotsOf(std::uint16_t ecu, const std::vector<std::size_t>& groups) const {
    std::vector<std::uint8_t> slots;
    for (const auto g : groups) {
        for (const auto& m : config_.groups[g].ecus) {
            if (m.ecu == ecu) slots.push_back(m.slot);
        }
    }
    return slots;
}

std::vector<std::uint8_t> KeyMaster::requestFor(const Step& s) const {
    switch (s.kind) {
        case Step::Kind::Session: return {0x10, 0x03};
        case Step::Kind::ReadUid: return {0x22, uds::kDidUid >> 8, uds::kDidUid & 0xFF};
        case Step::Kind::ReadStatus: return {0x22, uds::kDidKeyStatus >> 8, uds::kDidKeyStatus & 0xFF};
        case Step::Kind::Load: {
            const std::size_t g = s.groups.front();
            const auto& ecu = ecus_.at(s.ecu);
            const auto slots = slotsOf(s.ecu, s.groups);
            const auto authKey = keys_.deriveEcuMasterKey(ecu.uid);
            const auto r = she::buildUpdate(ecu.uid, slots.front(), she::kMasterEcuKey, authKey.value_or(crypto::Block{}),
                                            newKeys_[g], results_[g].generation, config_.flags);
            std::vector<std::uint8_t> out = {kSidRoutine, 0x01, uds::kRidLoadKey >> 8, uds::kRidLoadKey & 0xFF};
            out.insert(out.end(), r.m1.begin(), r.m1.end());
            out.insert(out.end(), r.m2.begin(), r.m2.end());
            out.insert(out.end(), r.m3.begin(), r.m3.end());
            return out;
        }
        case Step::Kind::Activate:
        case Step::Kind::Discard: {
            const std::uint16_t rid = s.kind == Step::Kind::Activate ? uds::kRidActivateKeys : uds::kRidDiscardKeys;
            std::vector<std::uint8_t> out = {kSidRoutine, 0x01, static_cast<std::uint8_t>(rid >> 8),
                                             static_cast<std::uint8_t>(rid & 0xFF)};
            const auto slots = slotsOf(s.ecu, s.groups);
            out.insert(out.end(), slots.begin(), slots.end());
            return out;
        }
    }
    return {};
}

void KeyMaster::process(const Step& s, diag::ClientResult result, const std::vector<std::uint8_t>& rsp) {
    const std::string ecuName = "ECU " + hexAddress(s.ecu);
    if (result != diag::ClientResult::Ok) {
        trace("key master: " + ecuName + " " + diag::toString(result));
        switch (s.kind) {
            case Step::Kind::Load: failGroup(s.groups.front(), GroupResult::EcuUnreachable, s.ecu); break;
            case Step::Kind::Activate:
                for (const auto g : s.groups) failGroup(g, GroupResult::ActivationFailed, s.ecu);
                break;
            case Step::Kind::Discard: break;  // best effort: the key stays pending in the ECU
            default:
                failEcu(s.ecu, phase_ == Phase::Activate ? GroupResult::ActivationFailed : GroupResult::EcuUnreachable);
        }
        return;
    }
    const bool negative = !rsp.empty() && rsp[0] == 0x7F;
    switch (s.kind) {
        case Step::Kind::Session:
            if (rsp.size() < 2 || rsp[0] != 0x50) {
                failEcu(s.ecu, phase_ == Phase::Activate ? GroupResult::ActivationFailed : GroupResult::EcuRefused);
            }
            return;
        case Step::Kind::ReadUid: {
            auto& ecu = ecus_[s.ecu];
            if (negative || rsp.size() != 3 + ecu.uid.size()) {
                failEcu(s.ecu, GroupResult::EcuRefused);
                return;
            }
            std::copy(rsp.begin() + 3, rsp.end(), ecu.uid.begin());
            return;
        }
        case Step::Kind::ReadStatus: {
            auto& ecu = ecus_[s.ecu];
            if (negative || rsp.size() < 4 || rsp.size() != 4u + 10u * rsp[3]) {
                failEcu(s.ecu, GroupResult::EcuRefused);
                return;
            }
            for (std::size_t i = 0; i < rsp[3]; ++i) {
                const std::uint8_t* e = &rsp[4 + 10 * i];
                ecu.newest[e[0]] = std::max(readU32(e + 2), readU32(e + 6));
            }
            return;
        }
        case Step::Kind::Load: {
            const std::size_t g = s.groups.front();
            if (negative || rsp.size() < 5 || rsp[0] != 0x71) {
                failGroup(g, GroupResult::EcuRefused, s.ecu);
                return;
            }
            const auto error = static_cast<she::ErrorCode>(rsp[4]);
            if (error != she::ErrorCode::NoError) {
                trace("key master: " + ecuName + " rejected " + config_.groups[g].keyId + ": " + she::toString(error));
                failGroup(g, GroupResult::KeyRejected, s.ecu, error);
                return;
            }
            const auto proof = she::buildProof(ecus_[s.ecu].uid, slotsOf(s.ecu, s.groups).front(), she::kMasterEcuKey,
                                               newKeys_[g], results_[g].generation);
            std::vector<std::uint8_t> expected(proof.m4.begin(), proof.m4.end());
            expected.insert(expected.end(), proof.m5.begin(), proof.m5.end());
            if (rsp.size() != 5 + expected.size() || !std::equal(expected.begin(), expected.end(), rsp.begin() + 5)) {
                trace("key master: " + ecuName + " M4/M5 MISMATCH for " + config_.groups[g].keyId);
                failGroup(g, GroupResult::ProofMismatch, s.ecu);
                return;
            }
            loaded_.insert({g, s.ecu});
            trace("key master: " + ecuName + " holds " + config_.groups[g].keyId + " generation " +
                  std::to_string(results_[g].generation) + " (M4/M5 verified)");
            return;
        }
        case Step::Kind::Activate:
            if (negative || rsp.size() < 5 || rsp[0] != 0x71) {
                for (const auto g : s.groups) failGroup(g, GroupResult::ActivationFailed, s.ecu);
            }
            return;
        case Step::Kind::Discard:
            return;
    }
}

void KeyMaster::failEcu(std::uint16_t ecu, GroupResult result) {
    ecus_[ecu].failed = true;
    for (const auto g : selected_) {
        for (const auto& m : config_.groups[g].ecus) {
            if (m.ecu == ecu) failGroup(g, result, ecu);
        }
    }
}

void KeyMaster::failGroup(std::size_t g, GroupResult result, std::uint16_t ecu, she::ErrorCode error) {
    if (!running(g)) return;
    results_[g].result = result;
    results_[g].failedEcu = ecu;
    results_[g].error = error;
    trace("key master: group " + config_.groups[g].keyId + " " + toString(result) + " (ECU " + hexAddress(ecu) + ")");
}

void KeyMaster::nextPhase(TimePoint now) {
    switch (phase_) {
        case Phase::Prepare: {
            // New generation per group: above everything any member stores.
            const auto local = keys_.status();
            for (const auto g : selected_) {
                if (!running(g)) continue;
                const auto& group = config_.groups[g];
                std::uint32_t newest = 0;
                for (const auto& st : local) {
                    if (group.gatewaySlot != 0 && st.slot == group.gatewaySlot) {
                        newest = std::max({newest, st.counter, st.pendingCounter});
                    }
                }
                for (const auto& m : group.ecus) {
                    const auto& known = ecus_[m.ecu].newest;
                    const auto it = known.find(m.slot);
                    if (it != known.end()) newest = std::max(newest, it->second);
                }
                if (newest >= she::kMaxCounter) {
                    failGroup(g, GroupResult::GatewayKeyError, 0, she::ErrorCode::KeyUpdateError);
                    continue;
                }
                results_[g].generation = newest + 1;
                newKeys_[g] = random_.randomKey();
                if (group.gatewaySlot != 0) {
                    const auto error =
                        keys_.stageInternal(group.gatewaySlot, newKeys_[g], newest + 1, config_.flags, now);
                    if (error != she::ErrorCode::NoError) {
                        failGroup(g, GroupResult::GatewayKeyError, 0, error);
                        continue;
                    }
                    gatewayStaged_.insert(g);
                }
                trace("key master: " + group.keyId + " generation " + std::to_string(newest + 1) + " generated");
            }
            for (const auto ecu : ecuOrder_) {
                std::vector<Step> loads;
                for (const auto g : selected_) {
                    for (const auto& m : config_.groups[g].ecus) {
                        if (m.ecu == ecu && running(g)) loads.push_back({Step::Kind::Load, ecu, {g}});
                    }
                }
                if (loads.empty()) continue;
                steps_.push_back({Step::Kind::Session, ecu, {}});
                steps_.insert(steps_.end(), loads.begin(), loads.end());
            }
            phase_ = Phase::Load;
            return;
        }
        case Phase::Load: {
            // Groups still running are confirmed by every member.
            for (const auto ecu : ecuOrder_) {
                std::vector<std::size_t> activate;
                std::vector<std::size_t> discard;
                for (const auto g : selected_) {
                    if (!loaded_.count({g, ecu})) continue;
                    (running(g) ? activate : discard).push_back(g);
                }
                if (activate.empty() && discard.empty()) continue;
                ecus_[ecu].failed = false;  // a failed load must not block the clean-up
                steps_.push_back({Step::Kind::Session, ecu, {}});
                if (!activate.empty()) steps_.push_back({Step::Kind::Activate, ecu, activate});
                if (!discard.empty()) steps_.push_back({Step::Kind::Discard, ecu, discard});
            }
            phase_ = Phase::Activate;
            return;
        }
        case Phase::Activate: {
            // Gateway last: it keeps verifying the previous key during the grace
            // period, so ECUs that missed the activation still get through.
            std::vector<std::uint8_t> activate;
            std::vector<std::uint8_t> discard;
            for (const auto g : selected_) {
                const bool ok = running(g) || results_[g].result == GroupResult::ActivationFailed;
                if (running(g)) results_[g].result = GroupResult::Activated;
                if (!gatewayStaged_.count(g)) continue;
                (ok ? activate : discard).push_back(config_.groups[g].gatewaySlot);
            }
            if (!activate.empty()) keys_.activatePending(now, activate);
            if (!discard.empty()) keys_.discardPending(now, discard);
            std::size_t ok = 0;
            for (const auto g : selected_) ok += results_[g].result == GroupResult::Activated;
            trace("key master: campaign finished, " + std::to_string(ok) + " of " + std::to_string(selected_.size()) +
                  " group(s) activated");
            state_ = State::Finished;
            return;
        }
    }
}

std::optional<std::vector<std::uint8_t>> KeyMaster::handle(const std::vector<std::uint8_t>& request,
                                                           const diag::LocalRequestContext& context) {
    if (request.size() < 4 || request[0] != kSidRoutine || context.functional) return std::nullopt;
    if (((request[2] << 8) | request[3]) != kRidKeyCampaign) return std::nullopt;
    const std::uint8_t sub = request[1] & 0x7F;
    if (sub == 0x01) {
        if (context.session != 0x03) return nrc(0x7F);
        if (state_ == State::Running || !keys_.deriveEcuMasterKey(she::Uid{})) {
            return nrc(0x22);  // conditionsNotCorrect: campaign running / no key master secret
        }
        std::vector<std::size_t> groups(request.begin() + 4, request.end());
        if (!start(context.now, groups)) return nrc(0x31);
        return std::vector<std::uint8_t>{0x71, 0x01, request[2], request[3], 0x00};
    }
    if (sub == 0x03) {
        if (request.size() != 4) return nrc(0x13);
        std::vector<std::uint8_t> out = {0x71, 0x03, request[2], request[3], static_cast<std::uint8_t>(state_),
                                         static_cast<std::uint8_t>(results_.size())};
        for (const auto& r : results_) {
            out.push_back(static_cast<std::uint8_t>(r.result));
            for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>(r.generation >> shift));
            out.push_back(static_cast<std::uint8_t>(r.failedEcu >> 8));
            out.push_back(static_cast<std::uint8_t>(r.failedEcu));
            out.push_back(static_cast<std::uint8_t>(r.error));
        }
        return out;
    }
    return nrc(0x12);
}

}  // namespace ccg::keym
