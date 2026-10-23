#pragma once

#include <cstdint>

#include "ccg/ethgw/routing_config.hpp"
#include "ccg/secoc/secoc.hpp"

namespace ccg::config {

// Reference routing table of the HPC central Ethernet gateway:
// PT_CAN (CAN FD), CHS_CAN, BODY_CAN, ETH_ADAS and ETH_IVI.
// In a series project it is generated from the communication matrix (DBC/ARXML).
ethgw::RoutingConfig makeVehicleEthGatewayMatrix();

// Loads the SecOC keys used by the reference table into a software crypto
// service. TEST KEYS for bench and simulation only - in a vehicle the keys are
// provisioned into the HSM and never leave it.
void provisionDemoSecOcKeys(secoc::SoftwareCryptoService& crypto);

namespace gw {
// channel indices (order in RoutingConfig::channels)
inline constexpr std::size_t kPtCan = 0;
inline constexpr std::size_t kChsCan = 1;
inline constexpr std::size_t kBodyCan = 2;
inline constexpr std::size_t kEthAdas = 3;
inline constexpr std::size_t kEthIvi = 4;

// received PDUs
inline constexpr std::uint32_t kEspWheelSpeeds = 0x0B0;     // CHS_CAN
inline constexpr std::uint32_t kVcuDriveState = 0x120;      // PT_CAN (CAN FD, 16 bytes)
inline constexpr std::uint32_t kBcmStatus = 0x2A0;          // BODY_CAN
inline constexpr std::uint32_t kAdasLatCtrlReq = 0x00001001; // ETH_ADAS header ID
inline constexpr std::uint32_t kAdasHmiInfo = 0x00001002;    // ETH_ADAS header ID

// transmitted PDUs
inline constexpr std::uint32_t kChsLatCtrlReq = 0x1A1;      // CHS_CAN (ID translated)
inline constexpr std::uint32_t kGwVehicleState = 0x3E0;     // CHS_CAN, assembled
inline constexpr std::uint32_t kGwBodyInfo = 0x2A8;         // PT_CAN, assembled
inline constexpr std::uint32_t kGwAdasVehicleInfo = 0x00002001;  // ETH_ADAS, assembled

// SecOC secured PDUs
inline constexpr std::uint32_t kAdasSteerTorqueReq = 0x00001003;  // ETH_ADAS -> gateway
inline constexpr std::uint32_t kGwSteerTorqueReq = 0x1B0;         // gateway -> CHS_CAN
inline constexpr std::uint32_t kVcuPowerLimit = 0x130;            // PT_CAN (FD) -> gateway
inline constexpr std::uint32_t kVcuPowerLimitAdas = 0x00000130;   // gateway -> ETH_ADAS

// Freshness value sync message of the FV master (gateway), one per bus
inline constexpr std::uint32_t kFvSyncCan = 0x0F0;         // PT_CAN, CHS_CAN, BODY_CAN
inline constexpr std::uint32_t kFvSyncEth = 0x0000F000;    // ETH_ADAS
}  // namespace gw

}  // namespace ccg::config
