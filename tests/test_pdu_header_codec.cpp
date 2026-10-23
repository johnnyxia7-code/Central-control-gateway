#include <cstdint>
#include <vector>

#include "ccg/ethgw/pdu_header_codec.hpp"
#include "test_framework.hpp"

using namespace ccg::ethgw;

TEST_CASE("pdu header: assemble several PDUs into one datagram") {
    std::vector<std::uint8_t> datagram;
    const std::uint8_t a[] = {0x11, 0x22, 0x33};
    const std::uint8_t b[] = {0xAA};
    appendPdu(datagram, 0x000000B0, a, sizeof a);
    appendPdu(datagram, 0x00001001, nullptr, 0);
    appendPdu(datagram, 0xDEADBEEF, b, sizeof b);

    const std::vector<std::uint8_t> expected = {
        0x00, 0x00, 0x00, 0xB0, 0x00, 0x00, 0x00, 0x03, 0x11, 0x22, 0x33,  // PDU 1
        0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00,                    // PDU 2 (empty)
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x01, 0xAA,              // PDU 3
    };
    CHECK(datagram == expected);
}

TEST_CASE("pdu header: decompose a datagram into its PDUs") {
    std::vector<std::uint8_t> datagram;
    const std::vector<std::uint8_t> a(16, 0x5A);
    const std::vector<std::uint8_t> b = {1, 2, 3, 4, 5, 6, 7, 8};
    appendPdu(datagram, 0x120, a.data(), a.size());
    appendPdu(datagram, 0x0B0, b.data(), b.size());

    const auto result = decodeDatagram(datagram.data(), datagram.size());
    CHECK(result.complete);
    REQUIRE(result.pdus.size() == 2);
    CHECK_EQ(result.pdus[0].headerId, 0x120U);
    CHECK_EQ(result.pdus[0].length, 16U);
    CHECK(std::vector<std::uint8_t>(result.pdus[1].data, result.pdus[1].data + 8) == b);
}

TEST_CASE("pdu header: truncated datagrams keep the PDUs before the defect") {
    std::vector<std::uint8_t> datagram;
    const std::uint8_t p[] = {9, 9};
    appendPdu(datagram, 1, p, sizeof p);
    auto cutHeader = datagram;
    cutHeader.insert(cutHeader.end(), {0x00, 0x00, 0x00});  // 3 bytes of a next header
    auto result = decodeDatagram(cutHeader.data(), cutHeader.size());
    CHECK(!result.complete);
    CHECK_EQ(result.pdus.size(), 1U);

    auto overlong = datagram;
    const std::uint8_t q[] = {1, 2, 3, 4};
    appendPdu(overlong, 2, q, sizeof q);
    overlong.pop_back();  // announced 4 bytes, only 3 present
    result = decodeDatagram(overlong.data(), overlong.size());
    CHECK(!result.complete);
    CHECK_EQ(result.pdus.size(), 1U);

    result = decodeDatagram(datagram.data(), 0);
    CHECK(result.complete);
    CHECK(result.pdus.empty());
}
