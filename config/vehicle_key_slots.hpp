#pragma once

#include "ccg/keym/key_manager.hpp"

namespace ccg::config {

// Key slots of the gateway HSM: MASTER_ECU_KEY authorises updates, KEY_1..KEY_5
// hold the SecOC keys of the reference routing table and the FV master key,
// KEY_10 the vehicle key master secret (never usable as MAC key).
// Gateway UID 00..00 43 43 47 00 00 00 01 ("CCG", serial 1), grace period 10 min.
keym::KeyManagerConfig makeVehicleKeySlots();

// EOL provisioning with TEST KEYS for bench and simulation: MASTER_ECU_KEY and
// the SecOC keys (= provisionDemoSecOcKeys) with update counter 1.
void provisionDemoKeyStore(keym::KeyManager& keys, keym::TimePoint now);

// Demo MASTER_ECU_KEY (the backend key server owns it in a real vehicle).
crypto::Block demoMasterEcuKey();

// Demo vehicle key master secret (backend and gateway HSM in a real vehicle).
crypto::Block demoKeyMasterSecret();

namespace keyslot {
inline constexpr std::uint8_t kAdasGw = 0x4;    // KEY_1  K_ADAS_GW
inline constexpr std::uint8_t kGwAdas = 0x5;    // KEY_2  K_GW_ADAS
inline constexpr std::uint8_t kVcuGw = 0x6;     // KEY_3  K_VCU_GW
inline constexpr std::uint8_t kGwChs = 0x7;     // KEY_4  K_GW_CHS
inline constexpr std::uint8_t kFvMaster = 0x8;  // KEY_5  K_FV_MASTER
inline constexpr std::uint8_t kKeyMaster = 0xD; // KEY_10 K_KEY_MASTER (vehicle key master secret)
}  // namespace keyslot

}  // namespace ccg::config
