#include "vehicle_s2s_matrix.hpp"

#include <optional>
#include <string>

namespace ccg::config {

namespace {

using can::ByteOrder;
using can::SignalSpec;
using namespace s2s;
using namespace std::chrono_literals;

SignalSpec sig(std::string name, std::uint16_t startBit, std::uint8_t length, ByteOrder order,
               bool isSigned, double factor, double offset, double min, double max,
               std::uint64_t initRaw = 0, std::optional<std::uint64_t> invalidRaw = std::nullopt) {
    SignalSpec s;
    s.name = std::move(name);
    s.startBit = startBit;
    s.length = length;
    s.byteOrder = order;
    s.isSigned = isSigned;
    s.factor = factor;
    s.offset = offset;
    s.min = min;
    s.max = max;
    s.initRaw = initRaw;
    s.invalidRaw = invalidRaw;
    return s;
}

e2e::CanE2EConfig e2eP1(std::uint16_t dataId) {
    e2e::CanE2EConfig cfg;
    cfg.dataId = dataId;
    cfg.crcByte = 7;
    cfg.counterStartBit = 48;
    cfg.maxDeltaCounter = 2;
    cfg.maxConsecutiveErrors = 3;
    return cfg;
}

ElementMapping element(std::string name, DataType type, std::string msg, std::string signal,
                       Representation repr = Representation::Physical,
                       SubstitutionKind subst = SubstitutionKind::InitValue) {
    ElementMapping e;
    e.name = std::move(name);
    e.type = type;
    e.source = {std::move(msg), std::move(signal)};
    e.representation = repr;
    e.substitution.kind = subst;
    return e;
}

ArgumentMapping argument(std::string name, DataType type, std::string msg, std::string signal,
                         Representation repr, bool pulse) {
    ArgumentMapping a;
    a.name = std::move(name);
    a.type = type;
    a.target = {std::move(msg), std::move(signal)};
    a.representation = repr;
    a.pulse = pulse;
    return a;
}

}  // namespace

GatewayConfig makeVehicleS2SMatrix() {
    GatewayConfig cfg;
    constexpr auto I = ByteOrder::Intel;
    constexpr auto M = ByteOrder::Motorola;
    constexpr auto Raw = Representation::Raw;
    constexpr auto Phys = Representation::Physical;

    // ------------------------------------------------------------------ services
    cfg.services = {
        {"VehicleMotionService", ids::kVehicleMotionService, ids::kInstance, 1, 0},
        {"BodyService", ids::kBodyService, ids::kInstance, 1, 0},
        {"EnergyService", ids::kEnergyService, ids::kInstance, 1, 0},
        {"ClimateService", ids::kClimateService, ids::kInstance, 1, 0},
    };

    // ------------------------------------------------------------ CAN Rx (in)
    {
        CanRxMessage m;
        m.name = "ESP_VehicleSpeed";
        m.canId = ids::kCanEspVehicleSpeed;
        m.cycleTime = 10ms;
        m.timeout = 50ms;
        m.signals = {
            sig("ESP_VehSpd", 0, 16, I, false, 0.01, 0.0, 0.0, 350.0, 0, 0xFFFF),
            sig("ESP_LongAccel", 16, 16, I, true, 0.001, 0.0, -16.0, 16.0, 0, 0x8000),
            sig("ESP_YawRate", 32, 16, I, true, 0.01, 0.0, -180.0, 180.0, 0, 0x8000),
        };
        m.e2e = e2eP1(0x00FD);
        cfg.rxMessages.push_back(m);
    }
    {
        CanRxMessage m;
        m.name = "EPS_SteeringAngle";
        m.canId = ids::kCanEpsSteering;
        m.cycleTime = 10ms;
        m.timeout = 50ms;
        m.signals = {
            sig("EPS_SteerWhlAng", 7, 16, M, true, 0.1, 0.0, -780.0, 780.0, 0, 0x7FFF),
            sig("EPS_SteerWhlSpd", 23, 16, M, false, 1.0, 0.0, 0.0, 1500.0, 0, 0xFFFF),
        };
        m.e2e = e2eP1(0x00A5);
        cfg.rxMessages.push_back(m);
    }
    {
        CanRxMessage m;
        m.name = "BCM_DoorStatus";
        m.canId = ids::kCanBcmDoorStatus;
        m.cycleTime = 100ms;
        m.timeout = 500ms;
        // 0 = closed, 1 = ajar, 2 = open, 3 = signal not available
        m.signals = {
            sig("BCM_DoorFLSts", 0, 2, I, false, 1, 0, 0, 2, 0, 3),
            sig("BCM_DoorFRSts", 2, 2, I, false, 1, 0, 0, 2, 0, 3),
            sig("BCM_DoorRLSts", 4, 2, I, false, 1, 0, 0, 2, 0, 3),
            sig("BCM_DoorRRSts", 6, 2, I, false, 1, 0, 0, 2, 0, 3),
            sig("BCM_TrunkSts", 8, 2, I, false, 1, 0, 0, 2, 0, 3),
            // 0 = unlocked, 1 = locked, 2 = super-locked, 3 = signal not available
            sig("BCM_CentralLockSts", 16, 2, I, false, 1, 0, 0, 2, 0, 3),
        };
        cfg.rxMessages.push_back(m);
    }
    {
        CanRxMessage m;
        m.name = "BMS_PackStatus";
        m.canId = ids::kCanBmsPackStatus;
        m.cycleTime = 100ms;
        m.timeout = 500ms;
        m.signals = {
            sig("BMS_SoC", 0, 10, I, false, 0.1, 0.0, 0.0, 100.0, 0, 0x3FF),
            sig("BMS_PackVolt", 16, 13, I, false, 0.1, 0.0, 0.0, 800.0, 0, 0x1FFF),
            sig("BMS_PackCurr", 32, 16, I, true, 0.05, 0.0, -1000.0, 1000.0, 0, 0x8000),
        };
        cfg.rxMessages.push_back(m);
    }

    // ----------------------------------------------------------- CAN Tx (out)
    {
        CanTxMessage m;
        m.name = "HPC_BodyCommand";
        m.canId = ids::kCanHpcBodyCommand;
        m.cycleTime = 100ms;
        m.eventRepetitions = 3;  // mixed mode: immediate burst of 3 frames, 20 ms apart
        m.repetitionInterval = 20ms;
        m.minDelay = 10ms;
        m.signals = {
            // 0 = no request, 1 = lock, 2 = unlock
            sig("HPC_CentralLockReq", 0, 2, I, false, 1, 0, 0, 2, 0, 3),
            sig("HPC_TrunkOpenReq", 2, 1, I, false, 1, 0, 0, 1, 0),
        };
        m.e2e = e2eP1(0x03A0);
        cfg.txMessages.push_back(m);
    }
    {
        CanTxMessage m;
        m.name = "HPC_ClimateCommand";
        m.canId = ids::kCanHpcClimateCommand;
        m.cycleTime = 200ms;
        m.eventRepetitions = 1;  // send the new set-point immediately, then keep it cyclic
        m.minDelay = 10ms;
        m.signals = {
            // physical = raw * 0.5 + 10 degC, init raw 22 -> 21.0 degC
            sig("HPC_CabinTempSetpt", 0, 8, I, false, 0.5, 10.0, 16.0, 32.0, 22, 0xFF),
            sig("HPC_FanLevel", 8, 3, I, false, 1, 0, 0, 7, 0),
        };
        cfg.txMessages.push_back(m);
    }

    // ----------------------------------------------- Signal -> Service (events)
    {
        EventMapping e;
        e.name = "VehicleDynamics";
        e.serviceId = ids::kVehicleMotionService;
        e.instanceId = ids::kInstance;
        e.eventId = ids::kEvtVehicleDynamics;
        e.eventgroupId = ids::kEgDynamics;
        e.updateMode = UpdateMode::Cyclic;
        e.cycleTime = 20ms;
        e.elements = {
            element("vehicleSpeedKph", DataType::Float32, "ESP_VehicleSpeed", "ESP_VehSpd"),
            element("longitudinalAccel", DataType::Float32, "ESP_VehicleSpeed", "ESP_LongAccel"),
            element("yawRateDps", DataType::Float32, "ESP_VehicleSpeed", "ESP_YawRate"),
        };
        cfg.events.push_back(e);
    }
    {
        EventMapping e;
        e.name = "SteeringWheel";
        e.serviceId = ids::kVehicleMotionService;
        e.instanceId = ids::kInstance;
        e.eventId = ids::kFldSteeringWheel;
        e.eventgroupId = ids::kEgSteering;
        e.isField = true;
        e.getterMethodId = ids::kGetSteeringWheel;
        e.updateMode = UpdateMode::OnChange;
        e.minInterval = 20ms;
        e.elements = {
            element("angleDeg", DataType::Float32, "EPS_SteeringAngle", "EPS_SteerWhlAng", Phys,
                    SubstitutionKind::HoldLastValid),
            element("speedDps", DataType::UInt16, "EPS_SteeringAngle", "EPS_SteerWhlSpd"),
        };
        cfg.events.push_back(e);
    }
    {
        EventMapping e;
        e.name = "DoorStatus";
        e.serviceId = ids::kBodyService;
        e.instanceId = ids::kInstance;
        e.eventId = ids::kFldDoorStatus;
        e.eventgroupId = ids::kEgDoors;
        e.isField = true;
        e.getterMethodId = ids::kGetDoorStatus;
        e.updateMode = UpdateMode::OnChange;
        e.elements = {
            element("frontLeft", DataType::UInt8, "BCM_DoorStatus", "BCM_DoorFLSts", Raw),
            element("frontRight", DataType::UInt8, "BCM_DoorStatus", "BCM_DoorFRSts", Raw),
            element("rearLeft", DataType::UInt8, "BCM_DoorStatus", "BCM_DoorRLSts", Raw),
            element("rearRight", DataType::UInt8, "BCM_DoorStatus", "BCM_DoorRRSts", Raw),
            element("trunk", DataType::UInt8, "BCM_DoorStatus", "BCM_TrunkSts", Raw),
            element("centralLock", DataType::UInt8, "BCM_DoorStatus", "BCM_CentralLockSts", Raw,
                    SubstitutionKind::HoldLastValid),
        };
        cfg.events.push_back(e);
    }
    {
        EventMapping e;
        e.name = "BatteryStatus";
        e.serviceId = ids::kEnergyService;
        e.instanceId = ids::kInstance;
        e.eventId = ids::kFldBatteryStatus;
        e.eventgroupId = ids::kEgBattery;
        e.isField = true;
        e.getterMethodId = ids::kGetBatteryStatus;
        e.updateMode = UpdateMode::OnChangeAndCyclic;
        e.cycleTime = 1000ms;
        e.minInterval = 100ms;
        e.elements = {
            element("socPercent", DataType::Float32, "BMS_PackStatus", "BMS_SoC", Phys,
                    SubstitutionKind::HoldLastValid),
            element("packVoltage", DataType::Float32, "BMS_PackStatus", "BMS_PackVolt"),
            element("packCurrent", DataType::Float32, "BMS_PackStatus", "BMS_PackCurr"),
        };
        cfg.events.push_back(e);
    }

    // ---------------------------------------------- Service -> Signal (methods)
    {
        MethodMapping m;
        m.name = "SetCentralLock";
        m.serviceId = ids::kBodyService;
        m.instanceId = ids::kInstance;
        m.methodId = ids::kMtdSetCentralLock;
        m.arguments = {argument("request", DataType::UInt8, "HPC_BodyCommand",
                                "HPC_CentralLockReq", Raw, true)};
        cfg.methods.push_back(m);
    }
    {
        MethodMapping m;
        m.name = "OpenTrunk";
        m.serviceId = ids::kBodyService;
        m.instanceId = ids::kInstance;
        m.methodId = ids::kMtdOpenTrunk;
        m.fireAndForget = true;
        m.arguments = {argument("open", DataType::Bool, "HPC_BodyCommand", "HPC_TrunkOpenReq",
                                Raw, true)};
        cfg.methods.push_back(m);
    }
    {
        MethodMapping m;
        m.name = "SetCabinClimate";
        m.serviceId = ids::kClimateService;
        m.instanceId = ids::kInstance;
        m.methodId = ids::kMtdSetCabinClimate;
        m.arguments = {
            argument("setpointDegC", DataType::Float32, "HPC_ClimateCommand",
                     "HPC_CabinTempSetpt", Phys, false),
            argument("fanLevel", DataType::UInt8, "HPC_ClimateCommand", "HPC_FanLevel", Raw,
                     false),
        };
        cfg.methods.push_back(m);
    }

    return cfg;
}

}  // namespace ccg::config
