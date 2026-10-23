#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// Software AES-128 (FIPS-197, encryption only) and AES-CMAC (RFC 4493 /
// NIST SP 800-38B). Used as the default MAC provider for SecOC; on the target
// the MAC is computed by the HSM behind secoc::ICryptoService.
namespace ccg::crypto {

using Block = std::array<std::uint8_t, 16>;

class Aes128 {
public:
    explicit Aes128(const Block& key);
    Block encrypt(const Block& plaintext) const;

private:
    std::array<std::uint8_t, 176> roundKeys_{};
};

class Cmac {
public:
    explicit Cmac(const Block& key);
    Block compute(const std::uint8_t* data, std::size_t length) const;

private:
    Aes128 aes_;
    Block k1_{};
    Block k2_{};
};

// Constant-time comparison of the first `bits` bits (MSB first).
bool equalBits(const std::uint8_t* a, const std::uint8_t* b, std::size_t bits);

}  // namespace ccg::crypto
