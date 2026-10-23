#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// ISO 13400-2 Diagnostics over IP (DoIP) message layer.
//
//   | version | ~version | payload type (16) | payload length (32) | payload ... |
namespace ccg::doip {

inline constexpr std::size_t kHeaderSize = 8;
inline constexpr std::uint8_t kVersion2012 = 0x02;
inline constexpr std::uint8_t kVersion2019 = 0x03;
inline constexpr std::uint8_t kVersionDefault = 0xFF;  // vehicle identification requests only
inline constexpr std::uint16_t kPort = 13400;

namespace payload {
inline constexpr std::uint16_t kGenericNack = 0x0000;
inline constexpr std::uint16_t kVehicleIdRequest = 0x0001;
inline constexpr std::uint16_t kVehicleIdRequestEid = 0x0002;
inline constexpr std::uint16_t kVehicleIdRequestVin = 0x0003;
inline constexpr std::uint16_t kVehicleAnnouncement = 0x0004;  // also the identification response
inline constexpr std::uint16_t kRoutingActivationRequest = 0x0005;
inline constexpr std::uint16_t kRoutingActivationResponse = 0x0006;
inline constexpr std::uint16_t kAliveCheckRequest = 0x0007;
inline constexpr std::uint16_t kAliveCheckResponse = 0x0008;
inline constexpr std::uint16_t kEntityStatusRequest = 0x4001;
inline constexpr std::uint16_t kEntityStatusResponse = 0x4002;
inline constexpr std::uint16_t kPowerModeRequest = 0x4003;
inline constexpr std::uint16_t kPowerModeResponse = 0x4004;
inline constexpr std::uint16_t kDiagnosticMessage = 0x8001;
inline constexpr std::uint16_t kDiagnosticAck = 0x8002;
inline constexpr std::uint16_t kDiagnosticNack = 0x8003;
}  // namespace payload

enum class HeaderNack : std::uint8_t {
    IncorrectPattern = 0x00,
    UnknownPayloadType = 0x01,
    MessageTooLarge = 0x02,
    OutOfMemory = 0x03,
    InvalidPayloadLength = 0x04,
};

enum class ActivationCode : std::uint8_t {
    UnknownSourceAddress = 0x00,
    NoFreeSocket = 0x01,
    SourceAddressMismatch = 0x02,
    SourceAddressInUse = 0x03,
    MissingAuthentication = 0x04,
    RejectedConfirmation = 0x05,
    UnsupportedActivationTypeTls = 0x07,  // ISO 13400-2:2019: activation type needs a TLS socket
    UnsupportedActivationType = 0x06,
    Success = 0x10,
    ConfirmationRequired = 0x11,
};

enum class DiagNack : std::uint8_t {
    InvalidSourceAddress = 0x02,
    UnknownTargetAddress = 0x03,
    MessageTooLarge = 0x04,
    OutOfMemory = 0x05,
    TargetUnreachable = 0x06,
    UnknownNetwork = 0x07,
    TransportProtocolError = 0x08,
};

const char* payloadTypeName(std::uint16_t type);

struct Header {
    std::uint8_t version = kVersion2012;
    std::uint16_t type = 0;
    std::uint32_t length = 0;
};

Header decodeHeader(const std::uint8_t* data);  // 8 bytes, no validation
bool isValidPattern(const std::uint8_t* data);  // version / inverse version consistent and supported

std::vector<std::uint8_t> encode(std::uint8_t version, std::uint16_t type,
                                 const std::vector<std::uint8_t>& payload);

// Reassembles DoIP messages from a TCP byte stream.
class StreamReassembler {
public:
    explicit StreamReassembler(std::size_t maxPayload) : maxPayload_(maxPayload) {}

    enum class Kind : std::uint8_t {
        Message,         // complete message
        IncorrectPattern,// header unusable: caller NACKs and closes the connection
        TooLarge,        // valid header, payload above the limit: payload is skipped
    };
    struct Item {
        Kind kind = Kind::Message;
        Header header;
        std::vector<std::uint8_t> payload;
    };

    void feed(const std::uint8_t* data, std::size_t length);
    std::optional<Item> next();

private:
    std::size_t maxPayload_;
    std::vector<std::uint8_t> buffer_;
    std::size_t discard_ = 0;
    bool broken_ = false;
};

// Payload builders -----------------------------------------------------------

struct EntityIdentity {
    std::string vin;                 // 17 characters
    std::uint16_t logicalAddress = 0;
    std::array<std::uint8_t, 6> eid{};
    std::array<std::uint8_t, 6> gid{};
};

std::vector<std::uint8_t> vehicleAnnouncementPayload(const EntityIdentity& id);
std::vector<std::uint8_t> routingActivationResponsePayload(std::uint16_t tester,
                                                           std::uint16_t entity,
                                                           ActivationCode code);
std::vector<std::uint8_t> diagnosticMessagePayload(std::uint16_t source, std::uint16_t target,
                                                   const std::vector<std::uint8_t>& data);
std::vector<std::uint8_t> diagnosticAckPayload(std::uint16_t source, std::uint16_t target,
                                               std::uint8_t code);
std::vector<std::uint8_t> entityStatusPayload(std::uint8_t nodeType, std::uint8_t maxSockets,
                                              std::uint8_t openSockets, std::uint32_t maxDataSize);

inline std::uint16_t readU16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

}  // namespace ccg::doip
