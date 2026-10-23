#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// AUTOSAR SoAd "PDU header" framing: several PDUs share one UDP datagram,
// each prefixed by a 4-byte header ID and a 4-byte payload length (big endian).
//
//   | HeaderID (32) | Length (32) | payload ... | HeaderID | Length | payload ... |
//
// Frame assembly appends PDUs to a datagram, frame decomposition splits a
// received datagram back into its contained PDUs.
namespace ccg::ethgw {

inline constexpr std::size_t kPduHeaderSize = 8;

void appendPdu(std::vector<std::uint8_t>& datagram, std::uint32_t headerId,
               const std::uint8_t* payload, std::size_t length);

struct ContainedPdu {
    std::uint32_t headerId = 0;
    const std::uint8_t* data = nullptr;  // points into the decoded datagram
    std::size_t length = 0;
};

struct DecodeResult {
    std::vector<ContainedPdu> pdus;
    // false if the datagram ended inside a header or a header announced more
    // payload than present; the PDUs before the defect are still returned.
    bool complete = true;
};

DecodeResult decodeDatagram(const std::uint8_t* data, std::size_t length);

}  // namespace ccg::ethgw
