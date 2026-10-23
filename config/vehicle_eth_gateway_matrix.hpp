#pragma once

#include <cstdint>

#include "ccg/ethgw/routing_config.hpp"

namespace ccg::config {

// Reference routing table of the HPC central Ethernet gateway:
// PT_CAN (CAN FD), CHS_CAN, BODY_CAN, ETH_ADAS and ETH_IVI.
// In a series project it is generated from the communication matrix (DBC/ARXML).
ethgw::RoutingConfig makeVehicleEthGatewayMatrix();

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
}  // namespace gw

}  // namespace ccg::config
