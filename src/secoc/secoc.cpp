#include "ccg/secoc/secoc.hpp"

namespace ccg::secoc {

namespace {

std::uint64_t maxValue(std::uint8_t bits) {
    return bits >= 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << bits) - 1);
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
    }
    return "UNKNOWN";
}

// --- crypto service -----------------------------------------------------------

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
    auto& counter = tx_[dataId];
    if (counter >= maxValue(bits)) {
        return std::nullopt;  // counter exhausted: key renewal / counter reset required
    }
    return ++counter;
}

std::uint64_t FreshnessManager::latestRx(std::uint16_t dataId) const {
    const auto it = rx_.find(dataId);
    return it == rx_.end() ? 0 : it->second;
}

void FreshnessManager::acceptRx(std::uint16_t dataId, std::uint64_t value) { rx_[dataId] = value; }

void FreshnessManager::restore(const Snapshot& snapshot, std::uint64_t txMargin) {
    rx_ = snapshot.rx;
    tx_.clear();
    for (const auto& [id, value] : snapshot.tx) {
        tx_[id] = value > ~std::uint64_t{0} - txMargin ? ~std::uint64_t{0} : value + txMargin;
    }
}

// --- protect / verify ------------------------------------------------------------

bool SecOcProcessor::authenticator(const SecOcConfig& c, const std::uint8_t* authentic,
                                   std::size_t length, std::uint64_t fv, crypto::Block& mac) {
    std::vector<std::uint8_t> dta;
    const std::size_t fvBytes = (c.freshnessBits + 7u) / 8u;
    dta.reserve(2 + length + fvBytes);
    dta.push_back(static_cast<std::uint8_t>(c.dataId >> 8));
    dta.push_back(static_cast<std::uint8_t>(c.dataId));
    dta.insert(dta.end(), authentic, authentic + length);
    for (std::size_t i = fvBytes; i > 0; --i) {
        dta.push_back(static_cast<std::uint8_t>(fv >> (8 * (i - 1))));
    }
    return crypto_.generateMac(c.keyId, dta.data(), dta.size(), mac);
}

std::optional<std::vector<std::uint8_t>> SecOcProcessor::protect(const SecOcConfig& c,
                                                                 const std::uint8_t* authentic,
                                                                 std::size_t length) {
    const auto fv = freshness_.nextTx(c.dataId, c.freshnessBits);
    if (!fv) {
        return std::nullopt;
    }
    crypto::Block mac;
    if (!authenticator(c, authentic, length, *fv, mac)) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> out(authentic, authentic + length);
    out.resize(length + overheadBytes(c), 0x00);
    BitWriter w(out, length * 8);
    for (int i = c.freshnessTxBits - 1; i >= 0; --i) w.put((*fv >> i) & 1);
    for (std::size_t i = 0; i < c.macTxBits; ++i) w.put((mac[i / 8] >> (7 - i % 8)) & 1);
    return out;
}

VerifyResult SecOcProcessor::verify(const SecOcConfig& c, const std::uint8_t* secured,
                                    std::size_t authenticLength) {
    BitReader r(secured, authenticLength * 8);
    std::uint64_t receivedFv = 0;
    for (std::size_t i = 0; i < c.freshnessTxBits; ++i) receivedFv = (receivedFv << 1) | (r.get() ? 1 : 0);
    crypto::Block receivedMac{};
    for (std::size_t i = 0; i < c.macTxBits; ++i) {
        if (r.get()) receivedMac[i / 8] = static_cast<std::uint8_t>(receivedMac[i / 8] | (0x80 >> (i % 8)));
    }

    // Rebuild the complete freshness value from the latest accepted one.
    const std::uint64_t latest = freshness_.latestRx(c.dataId);
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

    VerifyResult result = VerifyResult::MacFailure;
    for (std::uint8_t attempt = 0; attempt < c.verifyAttempts; ++attempt) {
        if (candidate <= latest || candidate > maxValue(c.freshnessBits) ||
            (c.acceptanceWindow != 0 && candidate - latest > c.acceptanceWindow)) {
            return attempt == 0 ? VerifyResult::FreshnessFailure : result;
        }
        crypto::Block mac;
        if (!authenticator(c, secured, authenticLength, candidate, mac)) {
            return VerifyResult::CryptoError;
        }
        if (crypto::equalBits(mac.data(), receivedMac.data(), c.macTxBits)) {
            freshness_.acceptRx(c.dataId, candidate);
            return VerifyResult::Ok;
        }
        result = VerifyResult::MacFailure;
        if (fullFv) break;
        candidate += step;  // try the next counter epoch (lost PDUs)
    }
    return result;
}

}  // namespace ccg::secoc
