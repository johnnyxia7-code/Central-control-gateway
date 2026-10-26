#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace ccg::can {

// DBC byte order. Intel = little endian ("@1"), Motorola = big endian ("@0").
enum class ByteOrder : std::uint8_t { Intel, Motorola };

// Signal definition following DBC conventions:
//  - Intel:    startBit is the position of the LSB.
//  - Motorola: startBit is the position of the MSB (DBC "sawtooth" bit numbering,
//              bit 7 of byte 0 is position 7, bit 0 of byte 1 is position 8).
//  physical = raw * factor + offset
struct SignalSpec {
    std::string name;
    std::uint16_t startBit = 0;
    std::uint8_t length = 1;  // 1..64 bits
    ByteOrder byteOrder = ByteOrder::Intel;
    bool isSigned = false;
    double factor = 1.0;
    double offset = 0.0;
    double min = 0.0;  // physical range, inclusive
    double max = 0.0;
    std::uint64_t initRaw = 0;                // init / default raw value
    std::optional<std::uint64_t> invalidRaw;  // raw pattern meaning "signal invalid" (SNA)
};

std::uint64_t rawMask(std::uint8_t length);

// True if every bit of the signal lies inside a payload of frameLength bytes.
bool fitsInFrame(const SignalSpec& spec, std::size_t frameLength);

// Calls fn(bitPosition) for every bit of the signal, MSB first.
template <typename Fn>
void forEachBitMsbFirst(const SignalSpec& spec, Fn&& fn) {
    if (spec.byteOrder == ByteOrder::Intel) {
        for (int i = spec.length - 1; i >= 0; --i) {
            fn(static_cast<std::size_t>(spec.startBit) + static_cast<std::size_t>(i));
        }
        return;
    }
    std::size_t pos = spec.startBit;
    for (std::uint8_t i = 0; i < spec.length; ++i) {
        fn(pos);
        pos = (pos % 8 == 0) ? pos + 15 : pos - 1;
    }
}

// Raw (unsigned, unscaled) value of the signal. Caller guarantees fitsInFrame().
std::uint64_t extractRaw(const std::uint8_t* data, const SignalSpec& spec);

// Writes the low `length` bits of raw into the payload. Caller guarantees fitsInFrame().
void insertRaw(std::uint8_t* data, const SignalSpec& spec, std::uint64_t raw);

std::int64_t signExtend(std::uint64_t raw, std::uint8_t length);

// Raw value as a number (two's complement interpreted for signed signals), unscaled.
double rawToNumber(const SignalSpec& spec, std::uint64_t raw);

double rawToPhysical(const SignalSpec& spec, std::uint64_t raw);

// Rounds and saturates to the raw range of the signal; result is masked to `length` bits.
std::uint64_t physicalToRaw(const SignalSpec& spec, double physical);

// Converts an unscaled number (as produced by rawToNumber) back to a raw bit pattern.
// Returns nullopt if the number is not an integer or does not fit into the signal.
std::optional<std::uint64_t> numberToRaw(const SignalSpec& spec, double number);

}  // namespace ccg::can
