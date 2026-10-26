#include <vector>

#include "ccg/doip/doip_message.hpp"
#include "test_framework.hpp"

using namespace ccg::doip;

namespace {
using Bytes = std::vector<std::uint8_t>;
}

TEST_CASE("doip: header encoding") {
    const auto msg = encode(kVersion2012, payload::kDiagnosticMessage,
                            diagnosticMessagePayload(0x0E80, 0x0020, {0x22, 0xF1, 0x90}));
    const Bytes expected = {0x02, 0xFD, 0x80, 0x01, 0x00, 0x00, 0x00, 0x07,
                            0x0E, 0x80, 0x00, 0x20, 0x22, 0xF1, 0x90};
    CHECK(msg == expected);
    const auto h = decodeHeader(msg.data());
    CHECK_EQ(h.version, 0x02);
    CHECK_EQ(h.type, payload::kDiagnosticMessage);
    CHECK_EQ(h.length, 7U);
}

TEST_CASE("doip: header pattern check") {
    const Bytes ok = {0x02, 0xFD, 0, 0, 0, 0, 0, 0};
    const Bytes v3 = {0x03, 0xFC, 0, 0, 0, 0, 0, 0};
    const Bytes inverse = {0x02, 0xFC, 0, 0, 0, 0, 0, 0};
    const Bytes unsupported = {0x07, 0xF8, 0, 0, 0, 0, 0, 0};
    CHECK(isValidPattern(ok.data()));
    CHECK(isValidPattern(v3.data()));
    CHECK(!isValidPattern(inverse.data()));
    CHECK(!isValidPattern(unsupported.data()));
}

TEST_CASE("doip: stream reassembly across TCP segments") {
    StreamReassembler s(100);
    auto a = encode(kVersion2012, payload::kAliveCheckResponse, {0x0E, 0x80});
    const auto b = encode(kVersion2012, payload::kDiagnosticMessage,
                          diagnosticMessagePayload(0x0E80, 0x0010, {0x3E, 0x00}));
    a.insert(a.end(), b.begin(), b.end());
    for (std::size_t i = 0; i < a.size(); ++i) {
        s.feed(&a[i], 1);  // byte by byte
        if (i < 9) CHECK(!s.next().has_value());
    }
    // first message was already complete after byte 10
    std::size_t messages = 0;
    StreamReassembler s2(100);
    s2.feed(a.data(), a.size());
    while (auto item = s2.next()) {
        CHECK(item->kind == StreamReassembler::Kind::Message);
        ++messages;
    }
    CHECK_EQ(messages, 2U);
}

TEST_CASE("doip: oversized payload is skipped, following message still framed") {
    StreamReassembler s(16);
    const auto big = encode(kVersion2012, payload::kDiagnosticMessage, Bytes(40, 0xAA));
    const auto next = encode(kVersion2012, payload::kAliveCheckResponse, {0x0E, 0x80});
    s.feed(big.data(), 20);  // header + part of the payload
    auto item = s.next();
    REQUIRE(item.has_value());
    CHECK(item->kind == StreamReassembler::Kind::TooLarge);
    s.feed(big.data() + 20, big.size() - 20);
    s.feed(next.data(), next.size());
    item = s.next();
    REQUIRE(item.has_value());
    CHECK(item->kind == StreamReassembler::Kind::Message);
    CHECK_EQ(item->header.type, payload::kAliveCheckResponse);
}

TEST_CASE("doip: incorrect pattern breaks the stream") {
    StreamReassembler s(100);
    const Bytes bad = {0x02, 0x02, 0x80, 0x01, 0, 0, 0, 0};
    s.feed(bad.data(), bad.size());
    auto item = s.next();
    REQUIRE(item.has_value());
    CHECK(item->kind == StreamReassembler::Kind::IncorrectPattern);
    const auto good = encode(kVersion2012, payload::kAliveCheckResponse, {0x0E, 0x80});
    s.feed(good.data(), good.size());
    CHECK(!s.next().has_value());
}

TEST_CASE("doip: vehicle announcement payload layout") {
    EntityIdentity id{"WCCG0HPC0RT000001", 0x1001, {1, 2, 3, 4, 5, 6}, {6, 5, 4, 3, 2, 1}};
    const auto p = vehicleAnnouncementPayload(id);
    REQUIRE(p.size() == 33);
    CHECK(std::string(p.begin(), p.begin() + 17) == "WCCG0HPC0RT000001");
    CHECK_EQ(readU16(p.data() + 17), 0x1001);
    CHECK_EQ(p[19], 1);
    CHECK_EQ(p[25], 6);
    CHECK_EQ(p[31], 0x00);

    const auto ra = routingActivationResponsePayload(0x0E80, 0x1001, ActivationCode::Success);
    const Bytes expected = {0x0E, 0x80, 0x10, 0x01, 0x10, 0, 0, 0, 0};
    CHECK(ra == expected);
}
