#include "ccg/doip/doip_message.hpp"

#include <algorithm>

namespace ccg::doip {

namespace {

void putU16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v));
}

void putU32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    putU16(out, static_cast<std::uint16_t>(v >> 16));
    putU16(out, static_cast<std::uint16_t>(v));
}

}  // namespace

const char* payloadTypeName(std::uint16_t type) {
    switch (type) {
        case payload::kGenericNack: return "GenericNack";
        case payload::kVehicleIdRequest: return "VehicleIdRequest";
        case payload::kVehicleIdRequestEid: return "VehicleIdRequestEid";
        case payload::kVehicleIdRequestVin: return "VehicleIdRequestVin";
        case payload::kVehicleAnnouncement: return "VehicleAnnouncement";
        case payload::kRoutingActivationRequest: return "RoutingActivationRequest";
        case payload::kRoutingActivationResponse: return "RoutingActivationResponse";
        case payload::kAliveCheckRequest: return "AliveCheckRequest";
        case payload::kAliveCheckResponse: return "AliveCheckResponse";
        case payload::kEntityStatusRequest: return "EntityStatusRequest";
        case payload::kEntityStatusResponse: return "EntityStatusResponse";
        case payload::kPowerModeRequest: return "PowerModeRequest";
        case payload::kPowerModeResponse: return "PowerModeResponse";
        case payload::kDiagnosticMessage: return "DiagnosticMessage";
        case payload::kDiagnosticAck: return "DiagnosticAck";
        case payload::kDiagnosticNack: return "DiagnosticNack";
        default: return "Unknown";
    }
}

Header decodeHeader(const std::uint8_t* d) {
    Header h;
    h.version = d[0];
    h.type = readU16(d + 2);
    h.length = (static_cast<std::uint32_t>(d[4]) << 24) | (static_cast<std::uint32_t>(d[5]) << 16) |
               (static_cast<std::uint32_t>(d[6]) << 8) | d[7];
    return h;
}

bool isValidPattern(const std::uint8_t* d) {
    if (static_cast<std::uint8_t>(~d[0]) != d[1]) {
        return false;
    }
    return d[0] == 0x01 || d[0] == kVersion2012 || d[0] == kVersion2019 || d[0] == kVersionDefault;
}

std::vector<std::uint8_t> encode(std::uint8_t version, std::uint16_t type,
                                 const std::vector<std::uint8_t>& payloadBytes) {
    std::vector<std::uint8_t> out;
    out.reserve(kHeaderSize + payloadBytes.size());
    out.push_back(version);
    out.push_back(static_cast<std::uint8_t>(~version));
    putU16(out, type);
    putU32(out, static_cast<std::uint32_t>(payloadBytes.size()));
    out.insert(out.end(), payloadBytes.begin(), payloadBytes.end());
    return out;
}

void StreamReassembler::feed(const std::uint8_t* data, std::size_t length) {
    if (broken_) {
        return;
    }
    if (discard_ > 0) {
        const std::size_t skip = std::min(discard_, length);
        discard_ -= skip;
        data += skip;
        length -= skip;
    }
    buffer_.insert(buffer_.end(), data, data + length);
}

std::optional<StreamReassembler::Item> StreamReassembler::next() {
    if (broken_ || discard_ > 0 || buffer_.size() < kHeaderSize) {
        return std::nullopt;
    }
    Item item;
    if (!isValidPattern(buffer_.data()) || buffer_[0] == kVersionDefault) {
        broken_ = true;  // stream can no longer be framed
        buffer_.clear();
        item.kind = Kind::IncorrectPattern;
        return item;
    }
    item.header = decodeHeader(buffer_.data());
    if (item.header.length > maxPayload_) {
        item.kind = Kind::TooLarge;
        const std::size_t available = buffer_.size() - kHeaderSize;
        if (available >= item.header.length) {
            buffer_.erase(buffer_.begin(),
                          buffer_.begin() + static_cast<std::ptrdiff_t>(kHeaderSize + item.header.length));
        } else {
            discard_ = item.header.length - available;
            buffer_.clear();
        }
        return item;
    }
    if (buffer_.size() - kHeaderSize < item.header.length) {
        return std::nullopt;
    }
    const auto begin = buffer_.begin() + static_cast<std::ptrdiff_t>(kHeaderSize);
    const auto end = begin + static_cast<std::ptrdiff_t>(item.header.length);
    item.payload.assign(begin, end);
    buffer_.erase(buffer_.begin(), end);
    return item;
}

std::vector<std::uint8_t> vehicleAnnouncementPayload(const EntityIdentity& id) {
    std::vector<std::uint8_t> out(id.vin.begin(), id.vin.end());
    out.resize(17, 0x00);
    putU16(out, id.logicalAddress);
    out.insert(out.end(), id.eid.begin(), id.eid.end());
    out.insert(out.end(), id.gid.begin(), id.gid.end());
    out.push_back(0x00);  // further action: none
    out.push_back(0x00);  // VIN/GID synchronised
    return out;
}

std::vector<std::uint8_t> routingActivationResponsePayload(std::uint16_t tester,
                                                           std::uint16_t entity,
                                                           ActivationCode code) {
    std::vector<std::uint8_t> out;
    putU16(out, tester);
    putU16(out, entity);
    out.push_back(static_cast<std::uint8_t>(code));
    putU32(out, 0);  // reserved by ISO 13400
    return out;
}

std::vector<std::uint8_t> diagnosticMessagePayload(std::uint16_t source, std::uint16_t target,
                                                   const std::vector<std::uint8_t>& data) {
    std::vector<std::uint8_t> out;
    out.reserve(4 + data.size());
    putU16(out, source);
    putU16(out, target);
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

std::vector<std::uint8_t> diagnosticAckPayload(std::uint16_t source, std::uint16_t target,
                                               std::uint8_t code) {
    std::vector<std::uint8_t> out;
    putU16(out, source);
    putU16(out, target);
    out.push_back(code);
    return out;
}

std::vector<std::uint8_t> entityStatusPayload(std::uint8_t nodeType, std::uint8_t maxSockets,
                                              std::uint8_t openSockets, std::uint32_t maxDataSize) {
    std::vector<std::uint8_t> out = {nodeType, maxSockets, openSockets};
    putU32(out, maxDataSize);
    return out;
}

}  // namespace ccg::doip
