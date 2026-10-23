#include "vehicle_key_master.hpp"

#include <stdexcept>

#include "vehicle_diag_routing.hpp"
#include "vehicle_eth_gateway_matrix.hpp"
#include "vehicle_key_slots.hpp"

namespace ccg::config {

namespace {

constexpr std::uint8_t kKey1 = keym::she::kKey1;
constexpr std::uint8_t kKey2 = keym::she::kKey1 + 1;

keym::she::Flags macKeyFlags() {
    keym::she::Flags f;
    f.keyUsage = true;
    f.wildcard = true;  // updates must name the ECU's UID
    return f;
}

}  // namespace

keym::KeyMasterConfig makeVehicleKeyMaster() {
    keym::KeyMasterConfig c;
    c.groups = {
        {"K_VCU_GW", keyslot::kVcuGw, {{dg::kVcu, kKey1}}},
        {"K_GW_CHS", keyslot::kGwChs, {{dg::kEps, kKey1}}},
        {"K_FV_MASTER", keyslot::kFvMaster, {{dg::kVcu, kKey2}, {dg::kEps, kKey2}, {dg::kBcm, kKey1}}},
    };
    c.flags = macKeyFlags();
    return c;
}

std::vector<std::uint16_t> keyMasterEcus() { return {dg::kVcu, dg::kEps, dg::kBcm}; }

keym::KeyManagerConfig makeEcuKeySlots(std::uint16_t ecu) {
    keym::KeyManagerConfig c;
    c.uid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             static_cast<std::uint8_t>(ecu >> 8), static_cast<std::uint8_t>(ecu)};
    c.uid[7] = 0xEC;  // "ECU" serial range
    c.slots.push_back({keym::she::kMasterEcuKey, "", false});
    switch (ecu) {
        case dg::kVcu:
            c.slots.push_back({kKey1, "K_VCU_GW", true});
            c.slots.push_back({kKey2, "K_FV_MASTER", true});
            break;
        case dg::kEps:
            c.slots.push_back({kKey1, "K_GW_CHS", true});
            c.slots.push_back({kKey2, "K_FV_MASTER", true});
            break;
        case dg::kBcm:
            c.slots.push_back({kKey1, "K_FV_MASTER", true});
            break;
        default:
            throw std::invalid_argument("ECU without SecOC keys");
    }
    return c;
}

void provisionDemoEcuKeyStore(keym::KeyManager& keys, keym::TimePoint now) {
    keym::she::Flags master;
    master.wildcard = true;
    keys.provision(keym::she::kMasterEcuKey, keym::deriveEcuMasterKey(demoKeyMasterSecret(), keys.config().uid), 1,
                   master, now);
    for (const auto& s : keys.config().slots) {
        if (s.keyId == "K_VCU_GW") keys.provision(s.slot, demoKey(3), 1, macKeyFlags(), now);
        if (s.keyId == "K_GW_CHS") keys.provision(s.slot, demoKey(4), 1, macKeyFlags(), now);
        if (s.keyId == "K_FV_MASTER") keys.provision(s.slot, demoKey(5), 1, macKeyFlags(), now);
    }
}

}  // namespace ccg::config
