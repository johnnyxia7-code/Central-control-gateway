#include "ccg/secoc/secoc.hpp"
#include <limits>
#include <stdexcept>

namespace ccg::secoc {

namespace {

std::uint64_t maxValue(std::uint8_t bits) {
    return bits >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << bits) - 1);
}

bool valid(const SecOcConfig& c) {
    return !c.keyId.empty() && c.freshnessBits >= 1 && c.freshnessBits <= 64 &&
           c.freshnessTxBits <= c.freshnessBits && c.macTxBits >= 8 && c.macTxBits <= 128 &&
           c.verifyAttempts != 0 && (c.freshnessMode == FreshnessMode::Counter || c.freshnessMode == FreshnessMode::TripReset);
}

class BitWriter {
public:
    BitWriter(std::vector<std::uint8_t>& out, std::size_t bitOffset) : out_(out), pos_(bitOffset) {}
    void put(bool bit) {
        if (bit) out_[pos_ / 8] = static_cast<std::uint8_t>(out_[pos_ / 8] | (0x80 >> (pos_ % 8)));
        ++pos_;
    }

private:
    std::vector<std::uint8_t>& out_;
    std::size_t pos_;
};

class BitReader {
public:
    BitReader(const std::uint8_t* in, std::size_t bitOffset) : in_(in), pos_(bitOffset) {}
    bool get() {
        const bool bit = (in_[pos_ / 8] >> (7 - pos_ % 8)) & 1;
        ++pos_;
        return bit;
    }

private:
    const std::uint8_t* in_;
    std::size_t pos_;
};

}  // namespace

std::size_t overheadBytes(const SecOcConfig& c) {
    return (static_cast<std::size_t>(c.freshnessTxBits) + c.macTxBits + 7) / 8;
}

std::vector<std::string> validateSecOcConfig(const SecOcConfig& c) {
    std::vector<std::string> errors;
    if (c.keyId.empty()) errors.push_back("SecOC key ID missing");
    if (c.freshnessBits == 0 || c.freshnessBits > 64) errors.push_back("SecOC freshnessBits must be 1..64");
    if (c.freshnessTxBits > c.freshnessBits) errors.push_back("SecOC freshnessTxBits > freshnessBits");
    if (c.macTxBits < 8 || c.macTxBits > 128) errors.push_back("SecOC macTxBits must be 8..128");
    if (c.verifyAttempts == 0) errors.push_back("SecOC verifyAttempts must be >= 1");
    return errors;
}

const char* toString(VerifyResult result) {
    switch (result) {
        case VerifyResult::Ok: return "VERIFICATION_SUCCESS";
        case VerifyResult::MacFailure: return "VERIFICATION_FAILURE";
        case VerifyResult::FreshnessFailure: return "FRESHNESS_FAILURE";
        case VerifyResult::CryptoError: return "CRYPTO_ERROR";
        case VerifyResult::InvalidInput: return "INVALID_INPUT";
    }
    return "UNKNOWN";
}

// --- crypto service -----------------------------------------------------------

std::optional<bool> ICryptoService::verifyMac(const std::string& keyId, const std::uint8_t* data,
                                              std::size_t length, const std::uint8_t* mac,
                                              std::size_t macBits) {
    if (macBits == 0 || macBits > 128 || !mac || (!data && length)) return std::nullopt;
    crypto::Block expected;
    if (!generateMac(keyId, data, length, expected)) return std::nullopt;
    return crypto::equalBits(expected.data(), mac, macBits);
}

void SoftwareCryptoService::setKey(const std::string& keyId, const crypto::Block& key) {
    keys_.erase(keyId);
    keys_.emplace(keyId, crypto::Cmac(key));
}

bool SoftwareCryptoService::hasKey(const std::string& keyId) const { return keys_.count(keyId) > 0; }

bool SoftwareCryptoService::generateMac(const std::string& keyId, const std::uint8_t* data,
                                        std::size_t length, crypto::Block& mac) {
    const auto it = keys_.find(keyId);
    if (it == keys_.end()) return false;
    mac = it->second.compute(data, length);
    return true;
}

// --- freshness ----------------------------------------------------------------

std::optional<std::uint64_t> FreshnessManager::nextTx(std::uint16_t dataId, std::uint8_t bits) {
    if (bits == 0 || bits > 64) return std::nullopt;
    auto& counter = tx_[dataId];
    if (counter >= maxValue(bits)) {
        return std::nullopt;  // counter exhausted: key renewal / counter reset required
    }
    if (persist_) {
        auto next = snapshot();
        next.tx[dataId] = counter + 1;
        persist_(next);
    }
    return ++counter;
}

std::uint64_t FreshnessManager::latestRx(std::uint16_t dataId) const {
    const auto it = rx_.find(dataId);
    return it == rx_.end() ? 0 : it->second;
}

void FreshnessManager::acceptRx(std::uint16_t dataId, std::uint64_t value) {
    if (persist_) {
        auto next = snapshot();
        next.rx[dataId] = value;
        persist_(next);
    }
    rx_[dataId] = value;
}

void FreshnessManager::restore(const Snapshot& snapshot, std::uint64_t txMargin) {
    rx_ = snapshot.rx;
    storedTrip_ = snapshot.trip;
    tx_.clear();
    for (const auto& [id, value] : snapshot.tx) {
        tx_[id] = value > ~std::uint64_t{0} - txMargin ? ~std::uint64_t{0} : value + txMargin;
    }
}

void FreshnessManager::setLayout(const TripResetLayout& l) {
    if (l.tripBits == 0 || l.tripBits > 32 || l.resetBits == 0 || l.resetBits > 32 ||
        l.messageBits == 0 || l.totalBits() > 64 || l.resetFlagBits == 0 || l.resetFlagBits >= l.resetBits)
        throw std::invalid_argument("invalid freshness layout");
    if (synchronized_) throw std::logic_error("cannot change synchronized freshness layout");
    layout_ = l;
}

void FreshnessManager::setTripReset(std::uint32_t trip, std::uint32_t reset) {
    if (trip > maxValue(layout_.tripBits) || reset > maxValue(layout_.resetBits) ||
        (synchronized_ && (trip < trip_ || (trip == trip_ && reset < reset_))))
        throw std::invalid_argument("invalid or regressing freshness epoch");
    trip_ = trip;
    reset_ = reset;
    synchronized_ = true;
}

void FreshnessManager::setStoredTrip(std::uint64_t trip) {
    if (persist_) {
        auto next = snapshot();
        next.trip = trip;
        persist_(next);
    }
    storedTrip_ = trip;
    persistRequest_ = true;
}

bool FreshnessManager::takePersistRequest() {
    const bool request = persistRequest_;
    persistRequest_ = false;
    return request;
}

std::optional<FreshnessManager::TxFreshness> FreshnessManager::nextTxSynchronized(std::uint16_t dataId,
                                                                                std::uint8_t txBits) {
    if (!synchronized_ || txBits <= layout_.resetFlagBits ||
        txBits > layout_.resetFlagBits + layout_.messageBits) {
        return std::nullopt;
    }
    const std::uint64_t epoch = (static_cast<std::uint64_t>(trip_) << layout_.resetBits) | reset_;
    auto& st = syncTx_[dataId];
    if (st.epoch != epoch) {  // new reset period: message counter starts again
        st.epoch = epoch;
        st.message = 0;
    }
    if (st.message >= maxValue(layout_.messageBits)) {
        return std::nullopt;  // wait for the next reset counter
    }
    ++st.message;
    const std::uint8_t messageTxBits = static_cast<std::uint8_t>(txBits - layout_.resetFlagBits);
    const std::uint64_t flag = reset_ & maxValue(layout_.resetFlagBits);
    return TxFreshness{(epoch << layout_.messageBits) | st.message,
                       (flag << messageTxBits) | (st.message & maxValue(messageTxBits))};
}

std::optional<std::uint64_t> FreshnessManager::rxSynchronizedCandidate(std::uint16_t dataId,
                                                                       std::uint64_t truncated,
                                                                       std::uint8_t txBits,
                                                                       std::uint8_t attempt) const {
    if (!synchronized_ || txBits <= layout_.resetFlagBits ||
        txBits > layout_.resetFlagBits + layout_.messageBits) {
        return std::nullopt;
    }
    const std::uint8_t messageTxBits = static_cast<std::uint8_t>(txBits - layout_.resetFlagBits);
    const std::uint64_t flagMask = maxValue(layout_.resetFlagBits);
    const std::uint64_t flag = (truncated >> messageTxBits) & flagMask;
    const std::uint64_t messageLow = truncated & maxValue(messageTxBits);

    // Reset counter: the current one, or one period older / newer (sync skew
    // between sender and receiver).
    std::optional<std::uint64_t> reset;
    const std::uint64_t current = reset_;
    for (const std::int64_t delta : {0, -1, 1}) {
        if (delta < 0 && current == 0) continue;
        const std::uint64_t r = current + static_cast<std::uint64_t>(delta);
        if (r > maxValue(layout_.resetBits)) continue;
        if ((r & flagMask) == flag) {
            reset = r;
            break;
        }
    }
    if (!reset) {
        return std::nullopt;
    }
    const std::uint64_t epoch = (static_cast<std::uint64_t>(trip_) << layout_.resetBits) | *reset;

    // Message counter relative to the last accepted value of the same period.
    const std::uint64_t last = latestRx(dataId);
    const std::uint64_t base = (last >> layout_.messageBits) == epoch ? (last & maxValue(layout_.messageBits)) : 0;
    std::uint64_t message;
    if (messageTxBits >= layout_.messageBits) {
        message = messageLow;
    } else {
        const std::uint64_t mask = maxValue(messageTxBits);
        const std::uint64_t msb = base & ~mask;
        message = messageLow > (base & mask) ? (msb | messageLow) : ((msb + mask + 1) | messageLow);
        message += static_cast<std::uint64_t>(attempt) * (mask + 1);
    }
    if (message == 0 || message > maxValue(layout_.messageBits)) {
        return std::nullopt;
    }
    return (epoch << layout_.messageBits) | message;
}

// --- protect / verify ------------------------------------------------------------

std::size_t SecOcProcessor::completeFreshnessBits(const SecOcConfig& c) const {
    return c.freshnessMode == FreshnessMode::TripReset ? freshness_.layout().totalBits() : c.freshnessBits;
}

std::vector<std::uint8_t> SecOcProcessor::dataToAuthenticator(const SecOcConfig& c,
                                                              const std::uint8_t* authentic,
                                                              std::size_t length, std::uint64_t fv) const {
    std::vector<std::uint8_t> dta;
    const std::size_t fvBytes = (completeFreshnessBits(c) + 7u) / 8u;
    dta.reserve(2 + length + fvBytes);
    dta.push_back(static_cast<std::uint8_t>(c.dataId >> 8));
    dta.push_back(static_cast<std::uint8_t>(c.dataId));
    if (length) dta.insert(dta.end(), authentic, authentic + length);
    for (std::size_t i = fvBytes; i > 0; --i) {
        dta.push_back(static_cast<std::uint8_t>(fv >> (8 * (i - 1))));
    }
    return dta;
}

std::optional<std::vector<std::uint8_t>> SecOcProcessor::protect(const SecOcConfig& c,
                                                                 const std::uint8_t* authentic,
                                                                 std::size_t length) {
    if (!valid(c) || (!authentic && length) || length > (std::numeric_limits<std::size_t>::max() / 8) - 32)
        return std::nullopt;
    std::uint64_t complete;
    std::uint64_t truncated;
    if (c.freshnessMode == FreshnessMode::TripReset) {
        const auto fv = freshness_.nextTxSynchronized(c.dataId, c.freshnessTxBits);
        if (!fv) return std::nullopt;
        complete = fv->complete;
        truncated = fv->truncated;
    } else {
        const auto fv = freshness_.nextTx(c.dataId, c.freshnessBits);
        if (!fv) return std::nullopt;
        complete = *fv;
        truncated = *fv;  // LSBs are taken below
    }
    crypto::Block mac;
    const auto dta = dataToAuthenticator(c, authentic, length, complete);
    if (!crypto_.generateMac(c.keyId, dta.data(), dta.size(), mac)) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> out;
    if (length) out.assign(authentic, authentic + length);
    out.resize(length + overheadBytes(c), 0x00);
    BitWriter w(out, length * 8);
    for (int i = c.freshnessTxBits - 1; i >= 0; --i) w.put((truncated >> i) & 1);
    for (std::size_t i = 0; i < c.macTxBits; ++i) w.put((mac[i / 8] >> (7 - i % 8)) & 1);
    return out;
}

bool SecOcProcessor::matches(const SecOcConfig& c, const std::uint8_t* authentic, std::size_t length,
                             std::uint64_t fv, const crypto::Block& receivedMac, VerifyResult& error) {
    const auto dta = dataToAuthenticator(c, authentic, length, fv);
    const auto ok = crypto_.verifyMac(c.keyId, dta.data(), dta.size(), receivedMac.data(), c.macTxBits);
    if (!ok) {
        error = VerifyResult::CryptoError;
        return false;
    }
    return *ok;
}

VerifyResult SecOcProcessor::verify(const SecOcConfig& c, const std::uint8_t* secured,
                                    std::size_t authenticLength) {
    if (!valid(c) || authenticLength > (std::numeric_limits<std::size_t>::max() / 8) - 32)
        return VerifyResult::InvalidInput;
    return verify(c, secured, authenticLength + overheadBytes(c), authenticLength);
}

VerifyResult SecOcProcessor::verify(const SecOcConfig& c, const std::uint8_t* secured,
                                    std::size_t securedLength, std::size_t authenticLength) {
    if (!valid(c) || !secured || authenticLength > (std::numeric_limits<std::size_t>::max() / 8) - 32 ||
        securedLength < authenticLength || securedLength - authenticLength < overheadBytes(c))
        return VerifyResult::InvalidInput;
    BitReader r(secured, authenticLength * 8);
    std::uint64_t receivedFv = 0;
    for (std::size_t i = 0; i < c.freshnessTxBits; ++i) receivedFv = (receivedFv << 1) | (r.get() ? 1 : 0);
    crypto::Block receivedMac{};
    for (std::size_t i = 0; i < c.macTxBits; ++i) {
        if (r.get()) receivedMac[i / 8] = static_cast<std::uint8_t>(receivedMac[i / 8] | (0x80 >> (i % 8)));
    }
    const std::uint64_t latest = freshness_.latestRx(c.dataId);
    VerifyResult error = VerifyResult::MacFailure;

    if (c.freshnessMode == FreshnessMode::TripReset) {
        for (std::uint8_t attempt = 0; attempt < c.verifyAttempts; ++attempt) {
            const auto candidate =
                freshness_.rxSynchronizedCandidate(c.dataId, receivedFv, c.freshnessTxBits, attempt);
            if (!candidate || *candidate <= latest) {
                return attempt == 0 ? VerifyResult::FreshnessFailure : error;
            }
            if (matches(c, secured, authenticLength, *candidate, receivedMac, error)) {
                freshness_.acceptRx(c.dataId, *candidate);
                return VerifyResult::Ok;
            }
            if (error == VerifyResult::CryptoError) return error;
        }
        return error;
    }

    // Counter mode: rebuild the complete freshness value from the latest accepted one.
    const bool fullFv = c.freshnessTxBits >= c.freshnessBits;
    std::uint64_t candidate;
    std::uint64_t step = 0;
    if (fullFv) {
        candidate = receivedFv;
    } else if (c.freshnessTxBits == 0) {
        candidate = latest + 1;
        step = 1;
    } else {
        const std::uint64_t mask = maxValue(c.freshnessTxBits);
        const std::uint64_t msb = latest & ~mask;
        candidate = receivedFv > (latest & mask) ? (msb | receivedFv) : ((msb + mask + 1) | receivedFv);
        step = mask + 1;
    }
    for (std::uint8_t attempt = 0; attempt < c.verifyAttempts; ++attempt) {
        if (candidate <= latest || candidate > maxValue(c.freshnessBits) ||
            (c.acceptanceWindow != 0 && candidate - latest > c.acceptanceWindow)) {
            return attempt == 0 ? VerifyResult::FreshnessFailure : error;
        }
        if (matches(c, secured, authenticLength, candidate, receivedMac, error)) {
            freshness_.acceptRx(c.dataId, candidate);
            return VerifyResult::Ok;
        }
        if (error == VerifyResult::CryptoError) return error;
        if (fullFv) break;
        candidate += step;  // try the next counter epoch (lost PDUs)
    }
    return error;
}

}  // namespace ccg::secoc
