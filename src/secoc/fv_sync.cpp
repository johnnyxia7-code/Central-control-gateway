#include "ccg/secoc/fv_sync.hpp"

#include <array>

namespace ccg::secoc {

namespace {

std::uint64_t maxValue(std::uint8_t bits) {
    return bits >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << bits) - 1);
}

void putBits(std::vector<std::uint8_t>& out, std::size_t& pos, std::uint64_t value, std::size_t bits) {
    for (std::size_t i = bits; i > 0; --i) {
        if ((value >> (i - 1)) & 1) out[pos / 8] = static_cast<std::uint8_t>(out[pos / 8] | (0x80 >> (pos % 8)));
        ++pos;
    }
}

std::uint64_t getBits(const std::uint8_t* in, std::size_t& pos, std::size_t bits) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < bits; ++i, ++pos) v = (v << 1) | ((in[pos / 8] >> (7 - pos % 8)) & 1);
    return v;
}

}  // namespace

std::size_t syncMessageLength(const TripResetLayout& layout, const SyncMessageConfig& c) {
    return (static_cast<std::size_t>(layout.tripBits) + layout.resetBits + c.macTxBits + 7) / 8;
}

std::vector<std::string> validateFreshnessSync(const TripResetLayout& l, const SyncMessageConfig& c) {
    std::vector<std::string> errors;
    if (l.tripBits == 0 || l.tripBits > 32) errors.push_back("trip counter must have 1..32 bits");
    if (l.resetBits == 0 || l.resetBits > 32) errors.push_back("reset counter must have 1..32 bits");
    if (l.resetFlagBits == 0 || l.resetFlagBits >= l.resetBits) {
        errors.push_back("reset flag must have 1..resetBits-1 bits");
    }
    if (l.messageBits == 0) errors.push_back("message counter must have at least 1 bit");
    if (l.totalBits() > 64) errors.push_back("trip + reset + message counter exceed 64 bits");
    if (c.keyId.empty()) errors.push_back("sync message key ID missing");
    if (c.macTxBits < 8 || c.macTxBits > 128) errors.push_back("sync message macTxBits must be 8..128");
    if (c.resetCycle.count() <= 0) errors.push_back("reset cycle must be > 0");
    return errors;
}

const char* toString(SyncResult result) {
    switch (result) {
        case SyncResult::Accepted: return "ACCEPTED";
        case SyncResult::MacFailure: return "MAC_FAILURE";
        case SyncResult::Stale: return "STALE";
        case SyncResult::LengthError: return "LENGTH_ERROR";
        case SyncResult::CryptoError: return "CRYPTO_ERROR";
    }
    return "UNKNOWN";
}

static std::array<std::uint8_t, 10> syncDataToAuthenticator(const SyncMessageConfig& c, std::uint32_t trip,
                                                            std::uint32_t reset) {
    return {
        static_cast<std::uint8_t>(c.dataId >> 8), static_cast<std::uint8_t>(c.dataId),
        static_cast<std::uint8_t>(trip >> 24),    static_cast<std::uint8_t>(trip >> 16),
        static_cast<std::uint8_t>(trip >> 8),     static_cast<std::uint8_t>(trip),
        static_cast<std::uint8_t>(reset >> 24),   static_cast<std::uint8_t>(reset >> 16),
        static_cast<std::uint8_t>(reset >> 8),    static_cast<std::uint8_t>(reset)};
}

bool syncAuthenticator(ICryptoService& crypto, const SyncMessageConfig& c, std::uint32_t trip,
                       std::uint32_t reset, crypto::Block& mac) {
    const auto data = syncDataToAuthenticator(c, trip, reset);
    return crypto.generateMac(c.keyId, data.data(), data.size(), mac);
}

// ---------------------------------------------------------------------------
// Master
// ---------------------------------------------------------------------------

FreshnessSyncMaster::FreshnessSyncMaster(SyncMessageConfig config, ICryptoService& crypto,
                                         FreshnessManager& freshness)
    : cfg_(std::move(config)), crypto_(crypto), freshness_(freshness) {}

bool FreshnessSyncMaster::start(TimePoint now) {
    const auto& layout = freshness_.layout();
    const std::uint64_t stored = freshness_.storedTrip();
    if (stored >= maxValue(layout.tripBits)) {
        active_ = false;  // trip counter exhausted
        return false;
    }
    const auto trip = static_cast<std::uint32_t>(stored + 1);
    freshness_.setStoredTrip(trip);
    freshness_.setTripReset(trip, 0);
    active_ = true;
    syncDue_ = true;
    nextReset_ = now + cfg_.resetCycle;
    return true;
}

std::optional<std::vector<std::uint8_t>> FreshnessSyncMaster::mainFunction(TimePoint now) {
    if (!active_) {
        return std::nullopt;
    }
    if (now >= nextReset_) {
        const auto& layout = freshness_.layout();
        std::uint32_t trip = freshness_.tripCounter();
        std::uint32_t reset = freshness_.resetCounter();
        if (reset >= maxValue(layout.resetBits)) {
            // Reset counter exhausted: next trip, persisted before it is used.
            if (trip >= maxValue(layout.tripBits)) {
                active_ = false;
                return std::nullopt;
            }
            ++trip;
            reset = 0;
            freshness_.setStoredTrip(trip);
        } else {
            ++reset;
        }
        freshness_.setTripReset(trip, reset);
        syncDue_ = true;
        nextReset_ += cfg_.resetCycle;
        if (nextReset_ <= now) nextReset_ = now + cfg_.resetCycle;
    }
    if (!syncDue_) {
        return std::nullopt;
    }
    auto message = encode();
    if (message) {
        syncDue_ = false;
        ++sent_;
    }
    return message;
}

std::optional<std::vector<std::uint8_t>> FreshnessSyncMaster::encode() {
    const auto& layout = freshness_.layout();
    const std::uint32_t trip = freshness_.tripCounter();
    const std::uint32_t reset = freshness_.resetCounter();
    crypto::Block mac;
    if (!syncAuthenticator(crypto_, cfg_, trip, reset, mac)) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> out(syncMessageLength(layout, cfg_), 0x00);
    std::size_t pos = 0;
    putBits(out, pos, trip, layout.tripBits);
    putBits(out, pos, reset, layout.resetBits);
    for (std::size_t i = 0; i < cfg_.macTxBits; ++i, ++pos) {
        if ((mac[i / 8] >> (7 - i % 8)) & 1) out[pos / 8] = static_cast<std::uint8_t>(out[pos / 8] | (0x80 >> (pos % 8)));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Slave
// ---------------------------------------------------------------------------

SyncResult FreshnessSyncSlave::onSyncMessage(const std::uint8_t* data, std::size_t length) {
    const auto& layout = freshness_.layout();
    if (length < syncMessageLength(layout, cfg_)) {
        return SyncResult::LengthError;
    }
    std::size_t pos = 0;
    const auto trip = static_cast<std::uint32_t>(getBits(data, pos, layout.tripBits));
    const auto reset = static_cast<std::uint32_t>(getBits(data, pos, layout.resetBits));
    crypto::Block received{};
    for (std::size_t i = 0; i < cfg_.macTxBits; ++i, ++pos) {
        if ((data[pos / 8] >> (7 - pos % 8)) & 1) received[i / 8] = static_cast<std::uint8_t>(received[i / 8] | (0x80 >> (i % 8)));
    }
    const auto dta = syncDataToAuthenticator(cfg_, trip, reset);
    const auto ok = crypto_.verifyMac(cfg_.keyId, dta.data(), dta.size(), received.data(), cfg_.macTxBits);
    if (!ok) {
        return SyncResult::CryptoError;
    }
    if (!*ok) {
        return SyncResult::MacFailure;
    }
    if (freshness_.synchronized()) {
        const auto current = (static_cast<std::uint64_t>(freshness_.tripCounter()) << 32) | freshness_.resetCounter();
        const auto offered = (static_cast<std::uint64_t>(trip) << 32) | reset;
        if (offered <= current) {
            return SyncResult::Stale;
        }
    }
    freshness_.setTripReset(trip, reset);
    return SyncResult::Accepted;
}

}  // namespace ccg::secoc
