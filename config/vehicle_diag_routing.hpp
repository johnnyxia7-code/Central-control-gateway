#pragma once

#include <cstdint>

#include "ccg/diag/diag_config.hpp"
#include "ccg/diag/doip_client.hpp"

namespace ccg::config {

// Reference diagnostic routing table of the HPC: DoIP entity + ECUs on
// PT_CAN (CAN FD), CHS_CAN and BODY_CAN.
diag::DiagRoutingConfig makeVehicleDiagRouting();

// ECUs on the vehicle Ethernet that are DoIP entities themselves, reached by
// the gateway's DoIP client (ADAS domain controller on ETH_ADAS).
diag::DoipClientConfig makeVehicleDoipClient();

// DoIP entity of the ADAS domain controller (for its simulation).
diag::DiagRoutingConfig makeAdasDoipEntity();

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
inline constexpr std::uint16_t kAdas = 0x1010;  // ETH_ADAS, DoIP entity
inline constexpr std::uint16_t kInternalTester = 0x0F00;  // the gateway as DoIP client
inline constexpr const char* kAdasEndpoint = "192.168.10.20:13400";
}  // namespace dg

}  // namespace ccg::config
