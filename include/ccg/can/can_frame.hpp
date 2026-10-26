#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace ccg::can {

inline constexpr std::size_t kMaxClassicLength = 8;
inline constexpr std::size_t kMaxFdLength = 64;

// Bus-agnostic CAN / CAN FD frame as seen by the gateway core.
struct CanFrame {
    std::uint32_t id = 0;       // 11-bit or 29-bit identifier (without flags)
    bool extended = false;      // 29-bit identifier
    bool fd = false;            // CAN FD frame
    std::uint8_t length = 0;    // payload length in bytes (0..8 classic, 0..64 FD)
    std::array<std::uint8_t, kMaxFdLength> data{};
};

// Valid CAN FD payload lengths (DLC 0..15 mapped to bytes).
constexpr bool isValidFdLength(std::size_t len) {
    return len <= 8 || len == 12 || len == 16 || len == 20 || len == 24 || len == 32 ||
           len == 48 || len == 64;
}

}  // namespace ccg::can
