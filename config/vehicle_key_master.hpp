#pragma once

#include <cstdint>
#include <vector>

#include "ccg/keym/key_manager.hpp"
#include "ccg/keym/key_master.hpp"

namespace ccg::config {

// Key groups the gateway distributes as in-vehicle key master:
//   0 K_VCU_GW     gateway KEY_3 + VCU KEY_1
//   1 K_GW_CHS     gateway KEY_4 + EPS KEY_1
//   2 K_FV_MASTER  gateway KEY_5 + VCU KEY_2, EPS KEY_2, BCM KEY_1
// The ADAS keys (Ethernet, DoIP-native ECU) stay with the backend.
keym::KeyMasterConfig makeVehicleKeyMaster();

// ECUs taking part in the key distribution and their HSM key slots.
std::vector<std::uint16_t> keyMasterEcus();
keym::KeyManagerConfig makeEcuKeySlots(std::uint16_t ecu);  // throws for other ECUs

// Plant provisioning of a simulated ECU with TEST KEYS: MASTER_ECU_KEY derived
// from the demo key master secret and its UID, SecOC keys generation 1.
void provisionDemoEcuKeyStore(keym::KeyManager& keys, keym::TimePoint now);

}  // namespace ccg::config
