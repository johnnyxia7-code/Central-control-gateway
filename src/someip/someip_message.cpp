#include "ccg/someip/someip_message.hpp"

#include <cstring>

namespace ccg::someip {

namespace {

void putBigEndian(std::vector<std::uint8_t>& out, std::uint64_t v, std::size_t bytes) {
    for (std::size_t i = bytes; i > 0; --i) {
        out.push_back(static_cast<std::uint8_t>(v >> (8 * (i - 1))));
    }
}

std::uint64_t getBigEndian(const std::uint8_t* p, std::size_t bytes) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < bytes; ++i) {
        v = (v << 8) | p[i];
    }
    return v;
}

}  // namespace

const char* toString(MessageType type) {
    switch (type) {
        case MessageType::Request: return "REQUEST";
        case MessageType::RequestNoReturn: return "REQUEST_NO_RETURN";
        case MessageType::Notification: return "NOTIFICATION";
        case MessageType::Response: return "RESPONSE";
        case MessageType::Error: return "ERROR";
    }
    return "UNKNOWN";
}

const char* toString(ReturnCode code) {
    switch (code) {
        case ReturnCode::Ok: return "E_OK";
        case ReturnCode::NotOk: return "E_NOT_OK";
        case ReturnCode::UnknownService: return "E_UNKNOWN_SERVICE";
        case ReturnCode::UnknownMethod: return "E_UNKNOWN_METHOD";
        case ReturnCode::NotReady: return "E_NOT_READY";
        case ReturnCode::NotReachable: return "E_NOT_REACHABLE";
        case ReturnCode::Timeout: return "E_TIMEOUT";
        case ReturnCode::WrongProtocolVersion: return "E_WRONG_PROTOCOL_VERSION";
        case ReturnCode::WrongInterfaceVersion: return "E_WRONG_INTERFACE_VERSION";
        case ReturnCode::MalformedMessage: return "E_MALFORMED_MESSAGE";
        case ReturnCode::WrongMessageType: return "E_WRONG_MESSAGE_TYPE";
    }
    return "UNKNOWN";
}

std::vector<std::uint8_t> serialize(const Message& message) {
    const Header& h = message.header;
    std::vector<std::uint8_t> out;
    out.reserve(kHeaderSize + message.payload.size());
    putBigEndian(out, h.serviceId, 2);
    putBigEndian(out, h.methodId, 2);
    putBigEndian(out, static_cast<std::uint32_t>(message.payload.size() + 8), 4);
    putBigEndian(out, h.clientId, 2);
    putBigEndian(out, h.sessionId, 2);
    out.push_back(h.protocolVersion);
    out.push_back(h.interfaceVersion);
    out.push_back(static_cast<std::uint8_t>(h.messageType));
    out.push_back(static_cast<std::uint8_t>(h.returnCode));
    out.insert(out.end(), message.payload.begin(), message.payload.end());
    return out;
}

std::optional<Message> parse(const std::uint8_t* data, std::size_t length, std::size_t* consumed) {
    if (length < kHeaderSize) {
        return std::nullopt;
    }
    Message m;
    Header& h = m.header;
    h.serviceId = static_cast<std::uint16_t>(getBigEndian(data, 2));
    h.methodId = static_cast<std::uint16_t>(getBigEndian(data + 2, 2));
    h.length = static_cast<std::uint32_t>(getBigEndian(data + 4, 4));
    if (h.length < 8 || h.length > length - 8) {
        return std::nullopt;
    }
    h.clientId = static_cast<std::uint16_t>(getBigEndian(data + 8, 2));
    h.sessionId = static_cast<std::uint16_t>(getBigEndian(data + 10, 2));
    h.protocolVersion = data[12];
    h.interfaceVersion = data[13];
    h.messageType = static_cast<MessageType>(data[14]);
    h.returnCode = static_cast<ReturnCode>(data[15]);
    const std::size_t total = 8 + static_cast<std::size_t>(h.length);
    m.payload.assign(data + kHeaderSize, data + total);
    if (consumed != nullptr) {
        *consumed = total;
    }
    return m;
}

void PayloadWriter::writeU16(std::uint16_t v) { putBigEndian(buffer_, v, 2); }
void PayloadWriter::writeU32(std::uint32_t v) { putBigEndian(buffer_, v, 4); }
void PayloadWriter::writeU64(std::uint64_t v) { putBigEndian(buffer_, v, 8); }

void PayloadWriter::writeF32(float v) {
    std::uint32_t bits;
    std::memcpy(&bits, &v, sizeof bits);
    writeU32(bits);
}

void PayloadWriter::writeF64(double v) {
    std::uint64_t bits;
    std::memcpy(&bits, &v, sizeof bits);
    writeU64(bits);
}

bool PayloadReader::readBigEndian(std::uint64_t& v, std::size_t bytes) {
    if (remaining() < bytes) {
        return false;
    }
    v = getBigEndian(data_ + pos_, bytes);
    pos_ += bytes;
    return true;
}

bool PayloadReader::readU8(std::uint8_t& v) {
    std::uint64_t t;
    if (!readBigEndian(t, 1)) return false;
    v = static_cast<std::uint8_t>(t);
    return true;
}

bool PayloadReader::readU16(std::uint16_t& v) {
    std::uint64_t t;
    if (!readBigEndian(t, 2)) return false;
    v = static_cast<std::uint16_t>(t);
    return true;
}

bool PayloadReader::readU32(std::uint32_t& v) {
    std::uint64_t t;
    if (!readBigEndian(t, 4)) return false;
    v = static_cast<std::uint32_t>(t);
    return true;
}

bool PayloadReader::readU64(std::uint64_t& v) { return readBigEndian(v, 8); }

bool PayloadReader::readF32(float& v) {
    std::uint32_t bits;
    if (!readU32(bits)) return false;
    std::memcpy(&v, &bits, sizeof v);
    return true;
}

bool PayloadReader::readF64(double& v) {
    std::uint64_t bits;
    if (!readU64(bits)) return false;
    std::memcpy(&v, &bits, sizeof v);
    return true;
}

}  // namespace ccg::someip
