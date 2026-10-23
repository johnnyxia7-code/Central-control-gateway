#pragma once

#include <cstdint>

#include "ccg/diag/diag_config.hpp"

namespace ccg::config {

// Reference diagnostic routing table of the HPC: DoIP entity + ECUs on
// PT_CAN (CAN FD), CHS_CAN and BODY_CAN.
diag::DiagRoutingConfig makeVehicleDiagRouting();

namespace dg {
inline constexpr std::size_t kPtCan = 0;
inline constexpr std::size_t kChsCan = 1;
inline constexpr std::size_t kBodyCan = 2;

inline constexpr std::uint16_t kGateway = 0x1001;
inline constexpr std::uint16_t kFunctional = 0xE400;
inline constexpr std::uint16_t kTester = 0x0E80;

inline constexpr std::uint16_t kVcu = 0x0010;  // PT_CAN, ISO-TP on CAN FD
inline constexpr std::uint16_t kBms = 0x0011;  // PT_CAN, classic frames
inline constexpr std::uint16_t kEsp = 0x0020;  // CHS_CAN
inline constexpr std::uint16_t kEps = 0x0021;  // CHS_CAN
inline constexpr std::uint16_t kBcm = 0x0030;  // BODY_CAN
}  // namespace dg

}  // namespace ccg::config
