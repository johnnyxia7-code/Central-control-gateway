#include "vehicle_key_slots.hpp"

#include "vehicle_eth_gateway_matrix.hpp"

namespace ccg::config {

keym::KeyManagerConfig makeVehicleKeySlots() {
    keym::KeyManagerConfig c;
    c.uid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x43, 0x47, 0x00, 0x00, 0x00, 0x00, 0x01};
    c.slots = {
        {keym::she::kMasterEcuKey, "", false},
        {keyslot::kAdasGw, "K_ADAS_GW", true},
        {keyslot::kGwAdas, "K_GW_ADAS", true},
        {keyslot::kVcuGw, "K_VCU_GW", true},
        {keyslot::kGwChs, "K_GW_CHS", true},
        {keyslot::kFvMaster, "K_FV_MASTER", true},
        {keyslot::kKeyMaster, "K_KEY_MASTER", false},
    };
    c.keyMasterSlot = keyslot::kKeyMaster;
    c.gracePeriod = std::chrono::minutes(10);
    c.maxFailedAttempts = 3;
    c.lockoutTime = std::chrono::seconds(10);
    return c;
}

crypto::Block demoMasterEcuKey() { return demoKey(0x4D); }

crypto::Block demoKeyMasterSecret() { return demoKey(0x6B); }

void provisionDemoKeyStore(keym::KeyManager& keys, keym::TimePoint now) {
    keym::she::Flags mac;
    mac.keyUsage = true;
    mac.wildcard = true;  // updates must name this gateway's UID
    keym::she::Flags master;
    master.wildcard = true;
    keys.provision(keym::she::kMasterEcuKey, demoMasterEcuKey(), 1, master, now);
    keys.provision(keyslot::kAdasGw, demoKey(1), 1, mac, now);
    keys.provision(keyslot::kGwAdas, demoKey(2), 1, mac, now);
    keys.provision(keyslot::kVcuGw, demoKey(3), 1, mac, now);
    keys.provision(keyslot::kGwChs, demoKey(4), 1, mac, now);
    keys.provision(keyslot::kFvMaster, demoKey(5), 1, mac, now);
    keys.provision(keyslot::kKeyMaster, demoKeyMasterSecret(), 1, master, now);  // cipher key, no KEY_USAGE
}

}  // namespace ccg::config
