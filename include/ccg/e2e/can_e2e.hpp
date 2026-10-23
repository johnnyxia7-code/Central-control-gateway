#pragma once

#include <cstddef>
#include <cstdint>

namespace ccg::e2e {

// CRC-8 SAE J1850: poly 0x1D, init 0xFF, xor-out 0xFF ("123456789" -> 0x4B).
std::uint8_t crc8SaeJ1850(const std::uint8_t* data, std::size_t length);

// End-to-end protection of a CAN PDU, modelled on AUTOSAR E2E Profile 1:
//  - 4-bit alive counter (0..14, 15 is invalid) in Intel layout at counterStartBit
//  - CRC-8 SAE J1850 over [DataID low byte, DataID high byte, payload without CRC byte]
struct CanE2EConfig {
    std::uint16_t dataId = 0;
    std::uint8_t crcByte = 7;
    std::uint16_t counterStartBit = 48;
    std::uint8_t maxDeltaCounter = 1;        // tolerated counter jump (lost frames)
    std::uint8_t maxConsecutiveErrors = 3;   // debounce before the data is declared faulty
};

inline constexpr std::uint8_t kCounterModulo = 15;

std::uint8_t computeCrc(const CanE2EConfig& cfg, const std::uint8_t* data, std::size_t length);

enum class CheckStatus : std::uint8_t {
    Ok,             // valid, counter incremented by 1 (or first reception)
    OkSomeLost,     // valid, counter jumped by <= maxDeltaCounter
    Repeated,       // valid CRC but same counter: stale data
    WrongSequence,  // counter jump too large or invalid counter value
    CrcError,       // CRC mismatch
};

const char* toString(CheckStatus status);

class CanE2EReceiver {
public:
    explicit CanE2EReceiver(const CanE2EConfig& cfg) : cfg_(cfg) {}

    CheckStatus check(const std::uint8_t* data, std::size_t length);
    void reset() { initialized_ = false; }

private:
    CanE2EConfig cfg_;
    bool initialized_ = false;
    std::uint8_t lastCounter_ = 0;
};

class CanE2ESender {
public:
    explicit CanE2ESender(const CanE2EConfig& cfg) : cfg_(cfg) {}

    // Writes the next alive counter and the CRC into the payload.
    void protect(std::uint8_t* data, std::size_t length);

private:
    CanE2EConfig cfg_;
    std::uint8_t counter_ = kCounterModulo - 1;  // first protected frame carries 0
};

}  // namespace ccg::e2e
