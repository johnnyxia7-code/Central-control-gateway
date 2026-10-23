#include "vehicle_eth_gateway_matrix.hpp"

#include <optional>
#include <string>

namespace ccg::config {

namespace {

using can::ByteOrder;
using can::SignalSpec;
using namespace ethgw;
using namespace std::chrono_literals;

SignalSpec sig(std::string name, std::uint16_t startBit, std::uint8_t length, bool isSigned,
               double factor, double offset, double min, double max,
               std::optional<std::uint64_t> invalidRaw = std::nullopt, std::uint64_t initRaw = 0) {
    SignalSpec s;
    s.name = std::move(name);
    s.startBit = startBit;
    s.length = length;
    s.byteOrder = ByteOrder::Intel;
    s.isSigned = isSigned;
    s.factor = factor;
    s.offset = offset;
    s.min = min;
    s.max = max;
    s.invalidRaw = invalidRaw;
    s.initRaw = initRaw;
    return s;
}

PduDefinition pdu(std::string name, std::string channel, std::uint32_t id, std::uint16_t length) {
    PduDefinition p;
    p.name = std::move(name);
    p.channel = std::move(channel);
    p.id = id;
    p.length = length;
    return p;
}

e2e::CanE2EConfig e2eConfig(std::uint16_t dataId, std::uint8_t crcByte, std::uint16_t counterBit) {
    e2e::CanE2EConfig cfg;
    cfg.dataId = dataId;
    cfg.crcByte = crcByte;
    cfg.counterStartBit = counterBit;
    cfg.maxDeltaCounter = 2;
    cfg.maxConsecutiveErrors = 3;
    return cfg;
}

// CAN / CAN FD: synchronised freshness value from the gateway's FV master
// (trip | reset | message counter). Transmitted: 2-bit reset flag + 6-bit message
// counter, 24-bit MAC - a 4-byte trailer like AUTOSAR profile 1.
secoc::SecOcConfig secocCan(std::uint16_t dataId, std::string keyId) {
    secoc::SecOcConfig c;
    c.dataId = dataId;
    c.keyId = std::move(keyId);
    c.freshnessMode = secoc::FreshnessMode::TripReset;
    c.freshnessBits = 62;  // trip 16 + reset 20 + message 26 (layout below)
    c.freshnessTxBits = 8;
    c.macTxBits = 24;
    c.verifyAttempts = 2;  // tolerate up to 127 lost PDUs within a reset period
    return c;
}

// Ethernet: full 64-bit freshness value and 64-bit MAC.
secoc::SecOcConfig secocEth(std::uint16_t dataId, std::string keyId) {
    secoc::SecOcConfig c;
    c.dataId = dataId;
    c.keyId = std::move(keyId);
    c.freshnessBits = 64;
    c.freshnessTxBits = 64;
    c.macTxBits = 64;
    c.acceptanceWindow = 1000;
    return c;
}

SignalRoute route(std::string srcPdu, std::string srcSig, std::string dstPdu, std::string dstSig,
                  Conversion conversion, Substitution substitution, bool triggering = true) {
    SignalRoute r;
    r.source = {std::move(srcPdu), std::move(srcSig)};
    r.target = {std::move(dstPdu), std::move(dstSig)};
    r.conversion = conversion;
    r.substitution = substitution;
    r.triggering = triggering;
    return r;
}

}  // namespace

RoutingConfig makeVehicleEthGatewayMatrix() {
    RoutingConfig cfg;

    // ------------------------------------------------------------- channels
    cfg.channels = {
        {"PT_CAN", BusType::CanFd, 0ms, 0},
        {"CHS_CAN", BusType::Can, 0ms, 0},
        {"BODY_CAN", BusType::Can, 0ms, 0},
        {"ETH_ADAS", BusType::Ethernet, 5ms, 1400},
        {"ETH_IVI", BusType::Ethernet, 10ms, 1400},
    };

    // ------------------------------------------------------- received PDUs
    {
        auto p = pdu("ESP_WheelSpeeds", "CHS_CAN", gw::kEspWheelSpeeds, 8);
        p.timeout = 50ms;
        p.signals = {
            sig("ESP_WhlSpdFL", 0, 14, false, 0.03125, 0, 0, 511.9, 0x3FFF),
            sig("ESP_WhlSpdFR", 14, 14, false, 0.03125, 0, 0, 511.9, 0x3FFF),
            sig("ESP_WhlSpdRL", 28, 14, false, 0.03125, 0, 0, 511.9, 0x3FFF),
            sig("ESP_WhlSpdRR", 42, 14, false, 0.03125, 0, 0, 511.9, 0x3FFF),
        };
        cfg.pdus.push_back(p);
    }
    {
        auto p = pdu("VCU_DriveState", "PT_CAN", gw::kVcuDriveState, 16);
        p.fd = true;
        p.timeout = 100ms;
        p.signals = {
            sig("VCU_VehSpd", 0, 16, false, 0.01, 0, 0, 350, 0xFFFF),
            // 0 = P, 1 = R, 2 = N, 3 = D
            sig("VCU_GearPos", 16, 4, false, 1, 0, 0, 3, 0xF),
            sig("VCU_DrvMode", 20, 3, false, 1, 0, 0, 4, 0x7),
            sig("VCU_ReadySts", 23, 1, false, 1, 0, 0, 1),
            sig("VCU_AccelPedal", 24, 8, false, 0.4, 0, 0, 100, 0xFF),
            sig("VCU_MotorTorque", 32, 16, true, 0.1, 0, -3000, 3000, 0x8000),
        };
        p.e2e = e2eConfig(0x0120, 15, 112);
        cfg.pdus.push_back(p);
    }
    {
        auto p = pdu("BCM_Status", "BODY_CAN", gw::kBcmStatus, 8);
        p.timeout = 500ms;
        p.signals = {
            // 0 = off, 1 = acc, 2 = on, 3 = crank
            sig("BCM_IgnState", 0, 3, false, 1, 0, 0, 3, 0x7),
            sig("BCM_DoorOpenAny", 3, 1, false, 1, 0, 0, 1),
            sig("BCM_HazardSts", 4, 1, false, 1, 0, 0, 1),
            sig("BCM_OutsideTemp", 8, 8, false, 0.5, -40, -40, 87, 0xFF, 80),
        };
        cfg.pdus.push_back(p);
    }
    {
        // Secured steering torque request from the ADAS domain (8 B authentic + 16 B SecOC).
        auto p = pdu("ADAS_SteerTorqueReq", "ETH_ADAS", gw::kAdasSteerTorqueReq, 24);
        p.timeout = 100ms;
        p.signals = {
            sig("ADAS_SteerTqReq", 0, 16, true, 0.01, 0, -10, 10, 0x8000),
            sig("ADAS_SteerReqActive", 16, 1, false, 1, 0, 0, 1),
        };
        p.secoc = secocEth(0x1003, "K_ADAS_GW");
        cfg.pdus.push_back(p);
    }
    {
        // Secured power limits from the VCU (CAN FD: 12 B authentic + 4 B SecOC).
        auto p = pdu("VCU_PowerLimit", "PT_CAN", gw::kVcuPowerLimit, 16);
        p.fd = true;
        p.signals = {
            sig("VCU_MaxDischrgPwr", 0, 16, false, 0.1, 0, 0, 500),
            sig("VCU_MaxChrgPwr", 16, 16, false, 0.1, 0, 0, 500),
        };
        p.secoc = secocCan(0x0130, "K_VCU_GW");
        cfg.pdus.push_back(p);
    }
    cfg.pdus.push_back(pdu("ADAS_LatCtrlReq", "ETH_ADAS", gw::kAdasLatCtrlReq, 8));
    cfg.pdus.push_back(pdu("ADAS_HmiInfo", "ETH_ADAS", gw::kAdasHmiInfo, 32));

    // -------------------------------------------- forwarded PDUs (message routing)
    cfg.pdus.push_back(pdu("ESP_WheelSpeeds_ADAS", "ETH_ADAS", gw::kEspWheelSpeeds, 8));
    cfg.pdus.push_back(pdu("ESP_WheelSpeeds_PT", "PT_CAN", gw::kEspWheelSpeeds, 8));
    cfg.pdus.push_back(pdu("VCU_DriveState_ADAS", "ETH_ADAS", gw::kVcuDriveState, 16));
    cfg.pdus.push_back(pdu("VCU_DriveState_IVI", "ETH_IVI", gw::kVcuDriveState, 16));
    {
        auto p = pdu("ADAS_LatCtrlReq_CHS", "CHS_CAN", gw::kChsLatCtrlReq, 8);
        cfg.pdus.push_back(p);
    }
    cfg.pdus.push_back(pdu("ADAS_HmiInfo_IVI", "ETH_IVI", gw::kAdasHmiInfo, 32));
    {
        // Re-authenticated for the ADAS domain with the gateway's key (12 B + 16 B SecOC).
        auto p = pdu("VCU_PowerLimit_ADAS", "ETH_ADAS", gw::kVcuPowerLimitAdas, 28);
        p.secoc = secocEth(0x2130, "K_GW_ADAS");
        cfg.pdus.push_back(p);
    }

    // ------------------------------------------- assembled PDUs (frame assembly)
    {
        auto p = pdu("GW_VehicleState", "CHS_CAN", gw::kGwVehicleState, 8);
        p.txMode = TxMode::CyclicAndOnChange;
        p.cycleTime = 100ms;
        p.minDelay = 10ms;
        p.signals = {
            sig("GW_VehSpd", 0, 12, false, 0.1, 0, 0, 350, 0xFFF),
            sig("GW_GearPos", 12, 4, false, 1, 0, 0, 3, 0xF),
            sig("GW_IgnState", 16, 3, false, 1, 0, 0, 3, 0x7),
            sig("GW_ReadySts", 19, 1, false, 1, 0, 0, 1),
            sig("GW_OutsideTemp", 24, 8, false, 0.5, -40, -40, 87, 0xFF, 80),
        };
        p.e2e = e2eConfig(0x03E0, 7, 48);
        cfg.pdus.push_back(p);
    }
    {
        auto p = pdu("GW_BodyInfo", "PT_CAN", gw::kGwBodyInfo, 8);
        p.txMode = TxMode::OnChange;
        p.minDelay = 20ms;
        p.signals = {
            sig("GW_IgnState", 0, 3, false, 1, 0, 0, 3, 0x7),
            sig("GW_DoorOpenAny", 3, 1, false, 1, 0, 0, 1),
            sig("GW_HazardSts", 4, 1, false, 1, 0, 0, 1),
        };
        cfg.pdus.push_back(p);
    }
    {
        // Steering request towards the EPS, re-authenticated for CHS_CAN (4 B + 4 B SecOC).
        auto p = pdu("GW_SteerTorqueReq", "CHS_CAN", gw::kGwSteerTorqueReq, 8);
        p.txMode = TxMode::OnUpdate;
        p.signals = {
            sig("GW_SteerTqReq", 0, 16, true, 0.01, 0, -10, 10, 0x8000),
            sig("GW_SteerReqActive", 16, 1, false, 1, 0, 0, 1),
        };
        p.secoc = secocCan(0x01B0, "K_GW_CHS");
        cfg.pdus.push_back(p);
    }
    {
        auto p = pdu("GW_ADAS_VehicleInfo", "ETH_ADAS", gw::kGwAdasVehicleInfo, 16);
        p.txMode = TxMode::Cyclic;
        p.cycleTime = 20ms;
        p.signals = {
            sig("GW_WhlSpdFL", 0, 16, false, 0.01, 0, 0, 511.9, 0xFFFF),
            sig("GW_WhlSpdFR", 16, 16, false, 0.01, 0, 0, 511.9, 0xFFFF),
            sig("GW_WhlSpdRL", 32, 16, false, 0.01, 0, 0, 511.9, 0xFFFF),
            sig("GW_WhlSpdRR", 48, 16, false, 0.01, 0, 0, 511.9, 0xFFFF),
            sig("GW_VehSpd", 64, 16, false, 0.01, 0, 0, 350, 0xFFFF),
            sig("GW_GearPos", 80, 4, false, 1, 0, 0, 3, 0xF),
            sig("GW_IgnState", 84, 3, false, 1, 0, 0, 3, 0x7),
            sig("GW_AccelPedal", 88, 8, false, 0.4, 0, 0, 100, 0xFF),
        };
        cfg.pdus.push_back(p);
    }

    // ------------------------------------- freshness value master (sync messages)
    for (const char* channel : {"PT_CAN", "CHS_CAN", "BODY_CAN"}) {
        cfg.pdus.push_back(pdu(std::string("GW_FvSync_") + channel, channel, gw::kFvSyncCan, 8));
    }
    {
        auto p = pdu("GW_FvSync_ETH_ADAS", "ETH_ADAS", gw::kFvSyncEth, 8);
        p.urgent = true;  // not held back by the datagram collection time
        cfg.pdus.push_back(p);
    }
    {
        FreshnessSyncConfig sync;
        sync.layout = secoc::TripResetLayout{16, 20, 2, 26};
        sync.message.dataId = 0x00F0;
        sync.message.keyId = "K_FV_MASTER";
        sync.message.macTxBits = 28;  // 16 + 20 + 28 = 64 bits: one classic CAN frame
        sync.message.resetCycle = 1000ms;
        sync.syncPdus = {"GW_FvSync_PT_CAN", "GW_FvSync_CHS_CAN", "GW_FvSync_BODY_CAN",
                         "GW_FvSync_ETH_ADAS"};
        cfg.freshnessSync = sync;
    }

    // ------------------------------------------------------- message routing
    cfg.pduRoutes = {
        {"WheelSpeeds CHS->ADAS,PT", "ESP_WheelSpeeds", {"ESP_WheelSpeeds_ADAS", "ESP_WheelSpeeds_PT"}},
        {"DriveState PT->ADAS,IVI", "VCU_DriveState", {"VCU_DriveState_ADAS", "VCU_DriveState_IVI"}},
        {"LatCtrlReq ADAS->CHS", "ADAS_LatCtrlReq", {"ADAS_LatCtrlReq_CHS"}},
        {"HmiInfo ADAS->IVI", "ADAS_HmiInfo", {"ADAS_HmiInfo_IVI"}},
        {"PowerLimit PT->ADAS (SecOC re-authentication)", "VCU_PowerLimit", {"VCU_PowerLimit_ADAS"}},
    };

    // -------------------------------------------------------- signal routing
    constexpr auto Raw = Conversion::Raw;
    constexpr auto Phys = Conversion::Physical;
    constexpr auto Hold = Substitution::HoldLast;
    constexpr auto Init = Substitution::InitValue;
    constexpr auto Inval = Substitution::InvalidValue;
    cfg.signalRoutes = {
        // GW_VehicleState on CHS_CAN, assembled from PT_CAN and BODY_CAN
        route("VCU_DriveState", "VCU_VehSpd", "GW_VehicleState", "GW_VehSpd", Phys, Inval),
        route("VCU_DriveState", "VCU_GearPos", "GW_VehicleState", "GW_GearPos", Raw, Inval),
        route("VCU_DriveState", "VCU_ReadySts", "GW_VehicleState", "GW_ReadySts", Raw, Init),
        route("BCM_Status", "BCM_IgnState", "GW_VehicleState", "GW_IgnState", Raw, Inval),
        route("BCM_Status", "BCM_OutsideTemp", "GW_VehicleState", "GW_OutsideTemp", Raw, Hold,
              false),
        // BCM_Status decomposed: body information for the powertrain bus
        route("BCM_Status", "BCM_IgnState", "GW_BodyInfo", "GW_IgnState", Raw, Inval),
        route("BCM_Status", "BCM_DoorOpenAny", "GW_BodyInfo", "GW_DoorOpenAny", Raw, Init),
        route("BCM_Status", "BCM_HazardSts", "GW_BodyInfo", "GW_HazardSts", Raw, Init),
        // GW_ADAS_VehicleInfo on ETH_ADAS, assembled from three CAN buses
        route("ESP_WheelSpeeds", "ESP_WhlSpdFL", "GW_ADAS_VehicleInfo", "GW_WhlSpdFL", Phys, Inval),
        route("ESP_WheelSpeeds", "ESP_WhlSpdFR", "GW_ADAS_VehicleInfo", "GW_WhlSpdFR", Phys, Inval),
        route("ESP_WheelSpeeds", "ESP_WhlSpdRL", "GW_ADAS_VehicleInfo", "GW_WhlSpdRL", Phys, Inval),
        route("ESP_WheelSpeeds", "ESP_WhlSpdRR", "GW_ADAS_VehicleInfo", "GW_WhlSpdRR", Phys, Inval),
        route("VCU_DriveState", "VCU_VehSpd", "GW_ADAS_VehicleInfo", "GW_VehSpd", Raw, Inval),
        route("VCU_DriveState", "VCU_GearPos", "GW_ADAS_VehicleInfo", "GW_GearPos", Raw, Inval),
        route("BCM_Status", "BCM_IgnState", "GW_ADAS_VehicleInfo", "GW_IgnState", Raw, Inval),
        route("VCU_DriveState", "VCU_AccelPedal", "GW_ADAS_VehicleInfo", "GW_AccelPedal", Raw,
              Inval),
        // Secured steering request ETH_ADAS -> CHS_CAN: verify, re-authenticate; on timeout
        // or authentication failure the request falls back to "inactive, 0 Nm".
        route("ADAS_SteerTorqueReq", "ADAS_SteerTqReq", "GW_SteerTorqueReq", "GW_SteerTqReq", Raw,
              Init),
        route("ADAS_SteerTorqueReq", "ADAS_SteerReqActive", "GW_SteerTorqueReq",
              "GW_SteerReqActive", Raw, Init),
    };

    return cfg;
}

crypto::Block demoKey(std::uint8_t seed) {
    // Deterministic test keys - not for production use.
    crypto::Block k{};
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>(seed * 31 + i * 7);
    return k;
}

void provisionDemoSecOcKeys(secoc::SoftwareCryptoService& crypto) {
    const auto key = demoKey;
    crypto.setKey("K_ADAS_GW", key(1));
    crypto.setKey("K_GW_ADAS", key(2));
    crypto.setKey("K_VCU_GW", key(3));
    crypto.setKey("K_GW_CHS", key(4));
    crypto.setKey("K_FV_MASTER", key(5));
}

}  // namespace ccg::config
