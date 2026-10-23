#include "ccg/keym/key_manager.hpp"

#include <algorithm>
#include <set>
#include <sstream>
#include <stdexcept>

namespace ccg::keym {

namespace {

constexpr std::size_t kMaxEvents = 64;

bool isZero(const she::Uid& uid) {
    return std::all_of(uid.begin(), uid.end(), [](std::uint8_t b) { return b == 0; });
}

std::string slotName(std::uint8_t slot) {
    if (slot == she::kMasterEcuKey) return "MASTER_ECU_KEY";
    if (slot >= she::kKey1 && slot <= she::kKey10) return "KEY_" + std::to_string(slot - she::kKey1 + 1);
    return "slot " + std::to_string(slot);
}

}  // namespace

const char* toString(KeyEvent::Kind kind) {
    switch (kind) {
        case KeyEvent::Kind::Provisioned: return "PROVISIONED";
        case KeyEvent::Kind::KeyLoaded: return "KEY_LOADED";
        case KeyEvent::Kind::KeyStaged: return "KEY_STAGED";
        case KeyEvent::Kind::UpdateRejected: return "UPDATE_REJECTED";
        case KeyEvent::Kind::UpdateLocked: return "UPDATE_LOCKED";
        case KeyEvent::Kind::KeysActivated: return "KEY_ACTIVATED";
        case KeyEvent::Kind::PendingDiscarded: return "PENDING_DISCARDED";
        case KeyEvent::Kind::PreviousKeyExpired: return "PREVIOUS_KEY_EXPIRED";
    }
    return "UNKNOWN";
}

std::vector<std::string> validateKeyManagerConfig(const KeyManagerConfig& c) {
    std::vector<std::string> errors;
    if (isZero(c.uid)) errors.push_back("UID must not be the wildcard UID (all zero)");
    if (c.maxFailedAttempts == 0) errors.push_back("maxFailedAttempts must be at least 1");
    if (c.gracePeriod.count() < 0) errors.push_back("gracePeriod must not be negative");
    std::set<std::uint8_t> slots;
    std::set<std::string> ids;
    bool master = false;
    for (const auto& s : c.slots) {
        const std::string name = slotName(s.slot);
        if (!slots.insert(s.slot).second) errors.push_back(name + ": configured twice");
        if (s.slot == she::kMasterEcuKey) {
            master = true;
            if (!s.keyId.empty()) errors.push_back("MASTER_ECU_KEY must not be used as SecOC key");
            continue;
        }
        if (s.slot < she::kKey1 || s.slot > she::kKey10) {
            errors.push_back(name + ": only MASTER_ECU_KEY and KEY_1..KEY_10 are updatable key slots");
            continue;
        }
        if (s.keyId.empty()) errors.push_back(name + ": key ID missing");
        else if (!ids.insert(s.keyId).second) errors.push_back(name + ": key ID '" + s.keyId + "' used twice");
    }
    if (!master) errors.push_back("MASTER_ECU_KEY slot missing (authorises key updates)");
    if (c.keyMasterSlot != 0 && !slots.count(c.keyMasterSlot)) {
        errors.push_back("key master slot " + slotName(c.keyMasterSlot) + " not configured");
    }
    return errors;
}

KeyManager::KeyManager(KeyManagerConfig config) : config_(std::move(config)) {
    const auto errors = validateKeyManagerConfig(config_);
    if (!errors.empty()) {
        std::ostringstream os;
        os << "invalid key manager configuration";
        for (const auto& e : errors) os << "\n  - " << e;
        throw std::invalid_argument(os.str());
    }
    for (const auto& s : config_.slots) slots_.push_back(Slot{s, {}, {}, {}, {}});
}

KeyManager::Slot* KeyManager::findSlot(std::uint8_t slot) {
    for (auto& s : slots_) {
        if (s.config.slot == slot) return &s;
    }
    return nullptr;
}

const KeyManager::Slot* KeyManager::findSlot(std::uint8_t slot) const {
    return const_cast<KeyManager*>(this)->findSlot(slot);
}

const KeyManager::Slot* KeyManager::findKey(const std::string& keyId) const {
    for (const auto& s : slots_) {
        if (!s.config.keyId.empty() && s.config.keyId == keyId) return &s;
    }
    return nullptr;
}

void KeyManager::log(KeyEvent::Kind kind, std::uint8_t slot, std::uint32_t counter, she::ErrorCode error,
                     TimePoint now) {
    events_.push_back(KeyEvent{kind, slot, counter, error, now});
    ++eventCount_;
    if (events_.size() > kMaxEvents) events_.pop_front();
}

bool KeyManager::provision(std::uint8_t slot, const crypto::Block& key, std::uint32_t counter,
                           const she::Flags& flags, TimePoint now) {
    Slot* s = findSlot(slot);
    if (!s || s->active || counter > she::kMaxCounter) return false;
    s->active.emplace(key, counter, flags);
    persistRequest_ = true;
    log(KeyEvent::Kind::Provisioned, slot, counter, she::ErrorCode::NoError, now);
    return true;
}

KeyManager::LoadResult KeyManager::reject(std::uint8_t slot, she::ErrorCode error, TimePoint now) {
    log(KeyEvent::Kind::UpdateRejected, slot, 0, error, now);
    LoadResult r;
    r.error = error;
    return r;
}

KeyManager::LoadResult KeyManager::loadKey(const she::UpdateRequest& request, TimePoint now) {
    const std::uint8_t slotId = she::slotOf(request);
    const std::uint8_t authId = she::authSlotOf(request);
    if (lockedOut(now)) return reject(slotId, she::ErrorCode::Busy, now);

    // Authorisation rules: MASTER_ECU_KEY authorises every slot, KEY_n may
    // also be updated with its own current value.
    Slot* target = findSlot(slotId);
    const Slot* auth = findSlot(authId);
    if (!target || !auth) return reject(slotId, she::ErrorCode::KeyInvalid, now);
    if (authId != she::kMasterEcuKey && authId != slotId) {
        return reject(slotId, she::ErrorCode::KeyInvalid, now);
    }
    if (!auth->active) return reject(slotId, she::ErrorCode::KeyEmpty, now);
    if (target->active && target->active->flags.writeProtection) {
        return reject(slotId, she::ErrorCode::KeyWriteProtected, now);
    }

    const crypto::Block authKey = auth->active->value;
    if (!she::verifyM3(request, authKey)) {
        auto r = reject(slotId, she::ErrorCode::KeyUpdateError, now);
        if (++failedAttempts_ >= config_.maxFailedAttempts) {
            failedAttempts_ = 0;
            lockedUntil_ = now + config_.lockoutTime;
            log(KeyEvent::Kind::UpdateLocked, slotId, 0, she::ErrorCode::KeyUpdateError, now);
        }
        return r;
    }
    failedAttempts_ = 0;

    // Addressed to this device, or the wildcard UID if the key allows it.
    const auto uid = she::uidOf(request);
    const bool wildcardAllowed = !target->active || !target->active->flags.wildcard;
    if (uid != config_.uid && !(isZero(uid) && wildcardAllowed)) {
        return reject(slotId, she::ErrorCode::KeyUpdateError, now);
    }

    // Anti-rollback: the counter must exceed every stored generation.
    const auto payload = she::decryptM2(request, authKey);
    std::uint32_t newest = 0;
    bool any = false;
    for (const auto* k : {&target->active, &target->pending}) {
        if (*k) {
            newest = std::max(newest, (*k)->counter);
            any = true;
        }
    }
    if (any && payload.counter <= newest) return reject(slotId, she::ErrorCode::KeyUpdateError, now);

    LoadResult r;
    r.error = she::ErrorCode::NoError;
    r.staged = install(*target, payload, now);
    // M4 carries the real UID, also for a wildcard update.
    r.proof = she::buildProof(config_.uid, slotId, authId, payload.key, payload.counter);
    persistRequest_ = true;
    return r;
}

bool KeyManager::install(Slot& target, const she::UpdatePayload& payload, TimePoint now) {
    const bool secocKey = !target.config.keyId.empty();
    if (target.active && target.config.staged) {
        target.pending.emplace(payload.key, payload.counter, payload.flags);
        log(KeyEvent::Kind::KeyStaged, target.config.slot, payload.counter, she::ErrorCode::NoError, now);
        persistRequest_ = true;
        return true;
    }
    if (target.active && secocKey && config_.gracePeriod.count() > 0) {
        target.previous = target.active;
        target.previousExpiry = now + config_.gracePeriod;
    }
    target.active.emplace(payload.key, payload.counter, payload.flags);
    target.pending.reset();
    log(KeyEvent::Kind::KeyLoaded, target.config.slot, payload.counter, she::ErrorCode::NoError, now);
    persistRequest_ = true;
    return false;
}

bool KeyManager::selected(const Slot& slot, const std::vector<std::uint8_t>& slots) {
    return slots.empty() || std::find(slots.begin(), slots.end(), slot.config.slot) != slots.end();
}

bool KeyManager::hasPending(const std::vector<std::uint8_t>& slots) const {
    return std::any_of(slots_.begin(), slots_.end(),
                       [&](const Slot& s) { return s.pending.has_value() && selected(s, slots); });
}

crypto::Block deriveEcuMasterKey(const crypto::Block& keyMasterSecret, const she::Uid& uid) {
    crypto::Block context{};
    std::copy(uid.begin(), uid.end(), context.begin());
    context[15] = 'M';
    return crypto::deriveKey(keyMasterSecret, context);
}

std::optional<crypto::Block> KeyManager::deriveEcuMasterKey(const she::Uid& uid) const {
    const Slot* s = config_.keyMasterSlot ? findSlot(config_.keyMasterSlot) : nullptr;
    if (!s || !s->active) return std::nullopt;
    return keym::deriveEcuMasterKey(s->active->value, uid);
}

she::ErrorCode KeyManager::stageInternal(std::uint8_t slot, const crypto::Block& key, std::uint32_t counter,
                                         const she::Flags& flags, TimePoint now) {
    Slot* target = findSlot(slot);
    if (!target || slot == she::kMasterEcuKey || slot == config_.keyMasterSlot) return she::ErrorCode::KeyInvalid;
    if (target->active && target->active->flags.writeProtection) return she::ErrorCode::KeyWriteProtected;
    for (const auto* k : {&target->active, &target->pending}) {
        if (*k && counter <= (*k)->counter) return she::ErrorCode::KeyUpdateError;
    }
    if (counter > she::kMaxCounter) return she::ErrorCode::KeyUpdateError;
    install(*target, she::UpdatePayload{counter, flags, key}, now);
    return she::ErrorCode::NoError;
}

std::size_t KeyManager::activatePending(TimePoint now, const std::vector<std::uint8_t>& slots) {
    std::size_t count = 0;
    for (auto& s : slots_) {
        if (!s.pending || !selected(s, slots)) continue;
        if (s.active && !s.config.keyId.empty() && config_.gracePeriod.count() > 0) {
            s.previous = s.active;
            s.previousExpiry = now + config_.gracePeriod;
        }
        s.active = s.pending;
        s.pending.reset();
        log(KeyEvent::Kind::KeysActivated, s.config.slot, s.active->counter, she::ErrorCode::NoError, now);
        ++count;
    }
    if (count) persistRequest_ = true;
    return count;
}

std::size_t KeyManager::discardPending(TimePoint now, const std::vector<std::uint8_t>& slots) {
    std::size_t count = 0;
    for (auto& s : slots_) {
        if (!s.pending || !selected(s, slots)) continue;
        log(KeyEvent::Kind::PendingDiscarded, s.config.slot, s.pending->counter, she::ErrorCode::NoError, now);
        s.pending.reset();
        ++count;
    }
    if (count) persistRequest_ = true;
    return count;
}

void KeyManager::mainFunction(TimePoint now) {
    for (auto& s : slots_) {
        if (s.previous && now >= s.previousExpiry) {
            log(KeyEvent::Kind::PreviousKeyExpired, s.config.slot, s.previous->counter, she::ErrorCode::NoError,
                now);
            s.previous.reset();
            persistRequest_ = true;
        }
    }
}

std::vector<KeyManager::SlotStatus> KeyManager::status() const {
    std::vector<SlotStatus> out;
    for (const auto& s : slots_) {
        SlotStatus st;
        st.slot = s.config.slot;
        st.keyId = s.config.keyId;
        st.active = s.active.has_value();
        if (s.active) {
            st.counter = s.active->counter;
            st.flags = s.active->flags;
        }
        st.pending = s.pending.has_value();
        if (s.pending) st.pendingCounter = s.pending->counter;
        st.previous = s.previous.has_value();
        out.push_back(st);
    }
    return out;
}

// --- crypto service -------------------------------------------------------------

bool KeyManager::hasKey(const std::string& keyId) const {
    const Slot* s = findKey(keyId);
    return s && s->config.slot != config_.keyMasterSlot && s->active && s->active->flags.keyUsage;
}

bool KeyManager::generateMac(const std::string& keyId, const std::uint8_t* data, std::size_t length,
                             crypto::Block& mac) {
    if (!hasKey(keyId)) return false;  // SHE: CMAC only with KEY_USAGE set
    mac = findKey(keyId)->active->cmac.compute(data, length);
    return true;
}

std::optional<bool> KeyManager::verifyMac(const std::string& keyId, const std::uint8_t* data,
                                          std::size_t length, const std::uint8_t* mac, std::size_t macBits) {
    if (!hasKey(keyId)) return std::nullopt;
    const Slot* s = findKey(keyId);
    if (crypto::equalBits(s->active->cmac.compute(data, length).data(), mac, macBits)) return true;
    // Rollover: a sender that has not switched yet (previous) or already
    // switched (pending, activated earlier on that ECU).
    for (const auto* k : {&s->previous, &s->pending}) {
        if (*k && (*k)->flags.keyUsage &&
            crypto::equalBits((*k)->cmac.compute(data, length).data(), mac, macBits)) {
            ++rolloverVerifications_;
            return true;
        }
    }
    return false;
}

// --- persistence ----------------------------------------------------------------

KeyManager::Snapshot KeyManager::snapshot(TimePoint now) const {
    Snapshot snap;
    auto add = [&](const Slot& s, const Key& k, StoredKey::State state) {
        StoredKey sk;
        sk.slot = s.config.slot;
        sk.state = state;
        sk.key = k.value;
        sk.counter = k.counter;
        sk.flags = k.flags.encode();
        if (state == StoredKey::State::Previous) {
            sk.remaining = std::max(std::chrono::milliseconds(0),
                                    std::chrono::duration_cast<std::chrono::milliseconds>(s.previousExpiry - now));
        }
        snap.keys.push_back(sk);
    };
    for (const auto& s : slots_) {
        if (s.active) add(s, *s.active, StoredKey::State::Active);
        if (s.pending) add(s, *s.pending, StoredKey::State::Pending);
        if (s.previous) add(s, *s.previous, StoredKey::State::Previous);
    }
    return snap;
}

void KeyManager::restore(const Snapshot& snapshot, TimePoint now) {
    for (auto& s : slots_) {
        s.active.reset();
        s.pending.reset();
        s.previous.reset();
    }
    for (const auto& k : snapshot.keys) {
        Slot* s = findSlot(k.slot);
        if (!s) continue;
        const auto flags = she::Flags::decode(k.flags);
        switch (k.state) {
            case StoredKey::State::Active: s->active.emplace(k.key, k.counter, flags); break;
            case StoredKey::State::Pending: s->pending.emplace(k.key, k.counter, flags); break;
            case StoredKey::State::Previous:
                s->previous.emplace(k.key, k.counter, flags);
                s->previousExpiry = now + k.remaining;
                break;
        }
    }
}

bool KeyManager::takePersistRequest() {
    const bool r = persistRequest_;
    persistRequest_ = false;
    return r;
}

}  // namespace ccg::keym
