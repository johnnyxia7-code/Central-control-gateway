#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Diagnostic routing of the HPC: DoIP (ISO 13400-2) towards the tester,
// UDS on CAN via ISO-TP (ISO 15765-2) towards the ECUs.
namespace ccg::diag {

using Milliseconds = std::chrono::milliseconds;

struct DoipEntityConfig {
    std::string vin;                    // 17 characters
    std::uint16_t logicalAddress = 0x1001;
    std::array<std::uint8_t, 6> eid{};  // usually the MAC address
    std::array<std::uint8_t, 6> gid{};
    std::uint8_t protocolVersion = 0x02;  // ISO 13400-2:2012
    std::uint16_t testerAddressMin = 0x0E00;  // external test equipment
    std::uint16_t testerAddressMax = 0x0FFF;
    std::uint16_t functionalAddress = 0xE400;
    std::uint8_t maxTcpConnections = 2;
    std::size_t maxDiagnosticMessageSize = 4095;  // UDS bytes per request/response
    Milliseconds initialInactivity{2000};         // T_TCP_Initial_Inactivity
    Milliseconds generalInactivity{300000};       // T_TCP_General_Inactivity
    Milliseconds aliveCheckTimeout{500};          // T_TCP_Alive_Check
    std::uint8_t announceCount = 3;               // A_DoIP_Announce_Num
    Milliseconds announceInterval{500};           // A_DoIP_Announce_Interval
    // ISO 13400-2:2019 DoIP over TLS (TCP port 3496)
    bool requireTls = false;  // routing activation on a plain TCP socket is answered 0x07
    std::uint16_t tlsPort = 3496;
};

struct DiagCanChannel {
    std::string name;
    bool fd = false;                       // CAN FD capable channel
    std::uint32_t functionalRequestId = 0x7DF;
    std::uint8_t padding = 0xCC;
};

struct EcuRoute {
    std::string name;
    std::uint16_t logicalAddress = 0;
    std::string channel;
    std::uint32_t requestId = 0;   // gateway -> ECU (physical)
    std::uint32_t responseId = 0;  // ECU -> gateway
    bool extended = false;
    bool fd = false;               // ISO-TP with CAN FD frames (TX_DL 64)
    std::size_t maxRequestLength = 4095;  // > 4095 needs the ISO-TP escape FF (ISO 15765-2:2016)
    std::uint8_t blockSize = 0;    // our flow control for ECU responses
    std::uint8_t stMin = 0;
    Milliseconds nBs{1000};
    Milliseconds nCr{1000};
};

struct DiagRoutingConfig {
    DoipEntityConfig entity;
    std::vector<DiagCanChannel> channels;
    std::vector<EcuRoute> ecus;
};

std::vector<std::string> validateDiagConfig(const DiagRoutingConfig& config);

}  // namespace ccg::diag
