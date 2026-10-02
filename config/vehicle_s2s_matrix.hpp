#pragma once

#include "ccg/s2s/s2s_config.hpp"

namespace ccg::config {

// Reference S2S matrix of the HPC central gateway (chassis / body / energy / climate).
// In a series project this file is generated from the DBC/ARXML communication
// matrix and the service interface definitions; see docs/S2S_DESIGN.md.
s2s::GatewayConfig makeVehicleS2SMatrix();

namespace ids {
// Service instances
inline constexpr std::uint16_t kVehicleMotionService = 0x6001;
inline constexpr std::uint16_t kBodyService = 0x6002;
inline constexpr std::uint16_t kEnergyService = 0x6003;
inline constexpr std::uint16_t kClimateService = 0x6004;
inline constexpr std::uint16_t kInstance = 0x0001;

// VehicleMotionService
inline constexpr std::uint16_t kEvtVehicleDynamics = 0x8001;
inline constexpr std::uint16_t kFldSteeringWheel = 0x8002;
inline constexpr std::uint16_t kGetSteeringWheel = 0x0001;
inline constexpr std::uint16_t kEgDynamics = 0x0001;
inline constexpr std::uint16_t kEgSteering = 0x0002;

// BodyService
inline constexpr std::uint16_t kFldDoorStatus = 0x8001;
inline constexpr std::uint16_t kGetDoorStatus = 0x0001;
inline constexpr std::uint16_t kMtdSetCentralLock = 0x0010;
inline constexpr std::uint16_t kMtdOpenTrunk = 0x0011;
inline constexpr std::uint16_t kEgDoors = 0x0001;

// EnergyService
inline constexpr std::uint16_t kFldBatteryStatus = 0x8001;
inline constexpr std::uint16_t kGetBatteryStatus = 0x0001;
inline constexpr std::uint16_t kEgBattery = 0x0001;

// ClimateService
inline constexpr std::uint16_t kMtdSetCabinClimate = 0x0001;

// CAN identifiers
inline constexpr std::uint32_t kCanEspVehicleSpeed = 0x0FD;
inline constexpr std::uint32_t kCanEpsSteering = 0x0A5;
inline constexpr std::uint32_t kCanBcmDoorStatus = 0x2F0;
inline constexpr std::uint32_t kCanBmsPackStatus = 0x3C0;
inline constexpr std::uint32_t kCanHpcBodyCommand = 0x3A0;
inline constexpr std::uint32_t kCanHpcClimateCommand = 0x3A1;
}  // namespace ids

}  // namespace ccg::config
