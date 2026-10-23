#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// Software AES-128 (FIPS-197) and AES-CMAC (RFC 4493 / NIST SP 800-38B), plus
// the Miyaguchi-Preneel compression used by the SHE key derivation. Used as the
// default crypto provider for SecOC and the key manager; on the target these run
// in the HSM behind secoc::ICryptoService.
namespace ccg::crypto {

using Block = std::array<std::uint8_t, 16>;

class Aes128 {
public:
    explicit Aes128(const Block& key);
    Block encrypt(const Block& plaintext) const;
    Block decrypt(const Block& ciphertext) const;

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

// AES-MP: Miyaguchi-Preneel one-way compression with AES-128 (SHE spec 7.3).
// `length` must be a multiple of 16 bytes (SHE pads before compressing).
Block mpCompress(const std::uint8_t* data, std::size_t length);

// SHE key derivation: KDF(K, C) = AES-MP(K | C).
Block deriveKey(const Block& key, const Block& constant);

// Constant-time comparison of the first `bits` bits (MSB first).
bool equalBits(const std::uint8_t* a, const std::uint8_t* b, std::size_t bits);

}  // namespace ccg::crypto
