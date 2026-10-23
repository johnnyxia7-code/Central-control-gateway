#include "ccg/ethgw/pdu_header_codec.hpp"

namespace ccg::ethgw {

namespace {

void putU32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 24));
    out.push_back(static_cast<std::uint8_t>(v >> 16));
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v));
}

std::uint32_t getU32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | p[3];
}

}  // namespace

void appendPdu(std::vector<std::uint8_t>& datagram, std::uint32_t headerId,
               const std::uint8_t* payload, std::size_t length) {
    putU32(datagram, headerId);
    putU32(datagram, static_cast<std::uint32_t>(length));
    datagram.insert(datagram.end(), payload, payload + length);
}

DecodeResult decodeDatagram(const std::uint8_t* data, std::size_t length) {
    DecodeResult result;
    std::size_t offset = 0;
    while (offset < length) {
        if (length - offset < kPduHeaderSize) {
            result.complete = false;
            break;
        }
        ContainedPdu pdu;
        pdu.headerId = getU32(data + offset);
        pdu.length = getU32(data + offset + 4);
        offset += kPduHeaderSize;
        if (pdu.length > length - offset) {
            result.complete = false;
            break;
        }
        pdu.data = data + offset;
        offset += pdu.length;
        result.pdus.push_back(pdu);
    }
    return result;
}

}  // namespace ccg::ethgw
