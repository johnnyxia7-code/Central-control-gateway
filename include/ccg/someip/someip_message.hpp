#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace ccg::someip {

inline constexpr std::size_t kHeaderSize = 16;
inline constexpr std::uint8_t kProtocolVersion = 0x01;

enum class MessageType : std::uint8_t {
    Request = 0x00,
    RequestNoReturn = 0x01,
    Notification = 0x02,
    Response = 0x80,
    Error = 0x81,
};

enum class ReturnCode : std::uint8_t {
    Ok = 0x00,
    NotOk = 0x01,
    UnknownService = 0x02,
    UnknownMethod = 0x03,
    NotReady = 0x04,
    NotReachable = 0x05,
    Timeout = 0x06,
    WrongProtocolVersion = 0x07,
    WrongInterfaceVersion = 0x08,
    MalformedMessage = 0x09,
    WrongMessageType = 0x0A,
};

const char* toString(MessageType type);
const char* toString(ReturnCode code);

struct Header {
    std::uint16_t serviceId = 0;
    std::uint16_t methodId = 0;  // method or event ID (bit 15 set for events)
    std::uint32_t length = 0;    // filled in by serialize(): payload size + 8
    std::uint16_t clientId = 0;
    std::uint16_t sessionId = 0;
    std::uint8_t protocolVersion = kProtocolVersion;
    std::uint8_t interfaceVersion = 0;
    MessageType messageType = MessageType::Request;
    ReturnCode returnCode = ReturnCode::Ok;
};

struct Message {
    Header header;
    std::vector<std::uint8_t> payload;
};

std::vector<std::uint8_t> serialize(const Message& message);

// Parses one SOME/IP message from the start of the buffer. On success `consumed`
// (if given) receives the number of bytes used, so several messages packed into
// one UDP datagram can be processed in a loop.
std::optional<Message> parse(const std::uint8_t* data, std::size_t length,
                             std::size_t* consumed = nullptr);

// Session IDs run 0x0001..0xFFFF; 0x0000 is reserved for "session handling off".
inline std::uint16_t nextSessionId(std::uint16_t& counter) {
    counter = (counter == 0xFFFF) ? 0x0001 : static_cast<std::uint16_t>(counter + 1);
    return counter;
}

// Big-endian payload serializer (SOME/IP default byte order).
class PayloadWriter {
public:
    void writeU8(std::uint8_t v) { buffer_.push_back(v); }
    void writeU16(std::uint16_t v);
    void writeU32(std::uint32_t v);
    void writeU64(std::uint64_t v);
    void writeF32(float v);
    void writeF64(double v);

    const std::vector<std::uint8_t>& data() const { return buffer_; }
    std::vector<std::uint8_t> take() { return std::move(buffer_); }

private:
    std::vector<std::uint8_t> buffer_;
};

class PayloadReader {
public:
    PayloadReader(const std::uint8_t* data, std::size_t length) : data_(data), length_(length) {}
    explicit PayloadReader(const std::vector<std::uint8_t>& v) : PayloadReader(v.data(), v.size()) {}

    bool readU8(std::uint8_t& v);
    bool readU16(std::uint16_t& v);
    bool readU32(std::uint32_t& v);
    bool readU64(std::uint64_t& v);
    bool readF32(float& v);
    bool readF64(double& v);

    std::size_t remaining() const { return length_ - pos_; }

private:
    bool readBigEndian(std::uint64_t& v, std::size_t bytes);

    const std::uint8_t* data_;
    std::size_t length_;
    std::size_t pos_ = 0;
};

}  // namespace ccg::someip
