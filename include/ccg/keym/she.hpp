#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "ccg/crypto/aes_cmac.hpp"

// SHE (Secure Hardware Extension, HIS/AUTOSAR) memory update protocol: the
// cryptographic container used to load a key into an HSM key slot without
// ever exposing it in plain text on the bus.
//
//   M1 = UID (120) | KeyID (4) | AuthID (4)
//   M2 = AES-CBC(K1, IV 0)( Counter (28) | Flags (5) | 0 (95) | NewKey (128) )
//   M3 = AES-CMAC(K2, M1 | M2)
//   M4 = M1 | AES-ECB(K3)( Counter (28) | 1 | 0 (99) )      confirmation
//   M5 = AES-CMAC(K4, M4)
//
//   K1 = KDF(AuthKey, KEY_UPDATE_ENC_C)   K2 = KDF(AuthKey, KEY_UPDATE_MAC_C)
//   K3 = KDF(NewKey,  KEY_UPDATE_ENC_C)   K4 = KDF(NewKey,  KEY_UPDATE_MAC_C)
//
// Only the owner of the authorising key (the backend key server) can build
// M1..M3; M4/M5 prove to the backend that the slot now holds the new key.
namespace ccg::keym::she {

// Key slots (SHE key IDs).
inline constexpr std::uint8_t kSecretKey = 0x0;  // not updatable
inline constexpr std::uint8_t kMasterEcuKey = 0x1;
inline constexpr std::uint8_t kBootMacKey = 0x2;
inline constexpr std::uint8_t kBootMac = 0x3;
inline constexpr std::uint8_t kKey1 = 0x4;  // KEY_1 .. KEY_10 = 0x4 .. 0xD
inline constexpr std::uint8_t kKey10 = 0xD;
inline constexpr std::uint8_t kRamKey = 0xE;  // volatile, not updatable with this protocol

inline constexpr std::uint32_t kMaxCounter = 0x0FFFFFFF;  // 28 bit

using Uid = std::array<std::uint8_t, 15>;

// SHE error codes (returned to the backend in the routine status).
enum class ErrorCode : std::uint8_t {
    NoError = 0x0,
    SequenceError = 0x1,
    KeyNotAvailable = 0x2,
    KeyInvalid = 0x3,
    KeyEmpty = 0x4,
    KeyWriteProtected = 0x6,
    KeyUpdateError = 0x7,
    Busy = 0xA,
    GeneralError = 0xC,
};

const char* toString(ErrorCode code);

// Key protection flags (FID, 5 bits, MSB first in M2).
struct Flags {
    bool writeProtection = false;     // slot can never be updated again
    bool bootProtection = false;      // locked if secure boot failed
    bool debuggerProtection = false;  // locked while a debugger is attached
    bool keyUsage = false;            // 1 = MAC key (CMAC generate/verify), 0 = cipher key
    bool wildcard = false;            // 1 = update with the wildcard UID (0) is forbidden

    std::uint8_t encode() const;
    static Flags decode(std::uint8_t fid);
    bool operator==(const Flags& o) const { return encode() == o.encode(); }
};

struct UpdateRequest {
    std::array<std::uint8_t, 16> m1{};
    std::array<std::uint8_t, 32> m2{};
    std::array<std::uint8_t, 16> m3{};
};

struct UpdateProof {
    std::array<std::uint8_t, 32> m4{};
    std::array<std::uint8_t, 16> m5{};
    bool operator==(const UpdateProof& o) const { return m4 == o.m4 && m5 == o.m5; }
};

// KDF constants (SHE spec 7.4).
const crypto::Block& keyUpdateEncC();
const crypto::Block& keyUpdateMacC();

// Backend side: builds M1..M3. `uid` may be all zero (wildcard) if the target
// key allows it.
UpdateRequest buildUpdate(const Uid& uid, std::uint8_t slot, std::uint8_t authSlot,
                          const crypto::Block& authKey, const crypto::Block& newKey,
                          std::uint32_t counter, const Flags& flags);

// M4/M5 a device with `uid` returns after loading `newKey` (the backend
// compares it with the received proof).
UpdateProof buildProof(const Uid& uid, std::uint8_t slot, std::uint8_t authSlot,
                       const crypto::Block& newKey, std::uint32_t counter);

// Device side, step 1: authenticates M1|M2 with the authorising key (M3).
bool verifyM3(const UpdateRequest& request, const crypto::Block& authKey);

// Device side, step 2: decrypts M2.
struct UpdatePayload {
    std::uint32_t counter = 0;
    Flags flags;
    crypto::Block key{};
};
UpdatePayload decryptM2(const UpdateRequest& request, const crypto::Block& authKey);

// Fields of M1.
Uid uidOf(const UpdateRequest& request);
inline std::uint8_t slotOf(const UpdateRequest& r) { return static_cast<std::uint8_t>(r.m1[15] >> 4); }
inline std::uint8_t authSlotOf(const UpdateRequest& r) { return static_cast<std::uint8_t>(r.m1[15] & 0x0F); }

}  // namespace ccg::keym::she
