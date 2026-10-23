#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "ccg/crypto/aes_cmac.hpp"

// AUTOSAR SecOC (Secure Onboard Communication).
//
//   Secured I-PDU      = Authentic I-PDU | truncated FV | truncated MAC
//                        (FV and MAC packed MSB first, padded to a byte)
//   DataToAuthenticator = Data ID (16 bit) | Authentic I-PDU | complete FV
//   MAC                = AES-128-CMAC(key, DataToAuthenticator), MSBs transmitted
//
// The freshness value (FV) is a monotonic counter per Data ID. Only its least
// significant bits are transmitted; the receiver rebuilds the complete value
// from the latest accepted one.
namespace ccg::secoc {

struct SecOcConfig {
    std::uint16_t dataId = 0;
    std::string keyId;
    std::uint8_t freshnessBits = 64;      // complete freshness counter
    std::uint8_t freshnessTxBits = 8;     // transmitted LSBs (0 = none, = freshnessBits: full)
    std::uint8_t macTxBits = 24;          // transmitted MSBs of the MAC
    std::uint64_t acceptanceWindow = 0;   // max FV increase accepted on reception, 0 = unlimited
    std::uint8_t verifyAttempts = 1;      // FV candidates tried (recovers > 2^txBits lost PDUs)
};

// Bytes appended to the authentic PDU.
std::size_t overheadBytes(const SecOcConfig& config);

// Problems with the parameters, without prefix (empty = valid).
std::vector<std::string> validateSecOcConfig(const SecOcConfig& config);

enum class VerifyResult : std::uint8_t {
    Ok,
    MacFailure,        // authenticator wrong: tampered, wrong key or replay with truncated FV
    FreshnessFailure,  // FV not newer than the last accepted one or outside the window
    CryptoError,       // key not available / crypto service failed
};

const char* toString(VerifyResult result);

// Crypto service (AUTOSAR Csm). On the target this is backed by the HSM; keys
// never leave it. Key IDs name the key slots.
class ICryptoService {
public:
    virtual ~ICryptoService() = default;
    virtual bool hasKey(const std::string& keyId) const = 0;
    virtual bool generateMac(const std::string& keyId, const std::uint8_t* data, std::size_t length,
                             crypto::Block& mac) = 0;
};

// Software AES-128-CMAC implementation for bench, simulation and tests.
class SoftwareCryptoService final : public ICryptoService {
public:
    void setKey(const std::string& keyId, const crypto::Block& key);
    bool hasKey(const std::string& keyId) const override;
    bool generateMac(const std::string& keyId, const std::uint8_t* data, std::size_t length,
                     crypto::Block& mac) override;

private:
    std::map<std::string, crypto::Cmac> keys_;
};

// Freshness value manager: counter-based, one Tx and one Rx counter per Data ID.
class FreshnessManager {
public:
    // Increments and returns the Tx counter; nullopt once `bits` would overflow
    // (the PDU must not be sent any more).
    std::optional<std::uint64_t> nextTx(std::uint16_t dataId, std::uint8_t bits);
    std::uint64_t latestRx(std::uint16_t dataId) const;
    void acceptRx(std::uint16_t dataId, std::uint64_t value);

    // Persistence (NvM). Tx counters skip `txMargin` values on restore so that
    // a value used after the last snapshot is never sent again.
    struct Snapshot {
        std::map<std::uint16_t, std::uint64_t> tx;
        std::map<std::uint16_t, std::uint64_t> rx;
    };
    Snapshot snapshot() const { return {tx_, rx_}; }
    void restore(const Snapshot& snapshot, std::uint64_t txMargin);

private:
    std::map<std::uint16_t, std::uint64_t> tx_;
    std::map<std::uint16_t, std::uint64_t> rx_;
};

class SecOcProcessor {
public:
    SecOcProcessor(ICryptoService& crypto, FreshnessManager& freshness)
        : crypto_(crypto), freshness_(freshness) {}

    // Authentic PDU -> secured PDU. nullopt on crypto error or exhausted FV.
    std::optional<std::vector<std::uint8_t>> protect(const SecOcConfig& config,
                                                     const std::uint8_t* authentic,
                                                     std::size_t length);

    // Verifies a secured PDU whose authentic part is `authenticLength` bytes.
    // On success the Rx freshness counter advances.
    VerifyResult verify(const SecOcConfig& config, const std::uint8_t* secured,
                        std::size_t authenticLength);

    FreshnessManager& freshness() { return freshness_; }

private:
    bool authenticator(const SecOcConfig& config, const std::uint8_t* authentic, std::size_t length,
                       std::uint64_t fv, crypto::Block& mac);

    ICryptoService& crypto_;
    FreshnessManager& freshness_;
};

}  // namespace ccg::secoc
