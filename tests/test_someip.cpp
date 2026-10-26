#include <cstdint>
#include <vector>

#include "ccg/s2s/data_type.hpp"
#include "ccg/someip/someip_message.hpp"
#include "test_framework.hpp"

using namespace ccg;
using namespace ccg::someip;

TEST_CASE("someip: header serialization matches the wire format") {
    Message m;
    m.header.serviceId = 0x6002;
    m.header.methodId = 0x8001;
    m.header.clientId = 0x0101;
    m.header.sessionId = 0x0007;
    m.header.interfaceVersion = 1;
    m.header.messageType = MessageType::Notification;
    m.payload = {0xAA, 0xBB};
    const auto bytes = serialize(m);
    const std::vector<std::uint8_t> expected = {0x60, 0x02, 0x80, 0x01, 0x00, 0x00, 0x00, 0x0A,
                                                0x01, 0x01, 0x00, 0x07, 0x01, 0x01, 0x02, 0x00,
                                                0xAA, 0xBB};
    CHECK(bytes == expected);
}

TEST_CASE("someip: parse round trip and packed datagrams") {
    Message a;
    a.header.serviceId = 0x1234;
    a.header.methodId = 0x0010;
    a.header.messageType = MessageType::Request;
    a.payload = {1, 2, 3};
    Message b = a;
    b.header.methodId = 0x0011;
    b.payload = {};
    auto buffer = serialize(a);
    const auto second = serialize(b);
    buffer.insert(buffer.end(), second.begin(), second.end());

    std::size_t consumed = 0;
    auto first = parse(buffer.data(), buffer.size(), &consumed);
    REQUIRE(first.has_value());
    CHECK_EQ(consumed, 19U);
    CHECK_EQ(first->header.length, 11U);
    CHECK(first->payload == a.payload);
    auto next = parse(buffer.data() + consumed, buffer.size() - consumed, &consumed);
    REQUIRE(next.has_value());
    CHECK_EQ(next->header.methodId, 0x0011);
    CHECK(next->payload.empty());
}

TEST_CASE("someip: truncated and inconsistent messages are rejected") {
    Message m;
    m.payload = {1, 2, 3, 4};
    auto bytes = serialize(m);
    CHECK(!parse(bytes.data(), 15).has_value());
    CHECK(!parse(bytes.data(), bytes.size() - 1).has_value());
    bytes[7] = 0x04;  // length < 8
    CHECK(!parse(bytes.data(), bytes.size()).has_value());
}

TEST_CASE("someip: session id wraps to 1") {
    std::uint16_t s = 0xFFFE;
    CHECK_EQ(nextSessionId(s), 0xFFFF);
    CHECK_EQ(nextSessionId(s), 0x0001);
}

TEST_CASE("someip: data types big endian, saturation, float") {
    PayloadWriter w;
    s2s::writeValue(w, s2s::DataType::UInt16, 0x1234);
    s2s::writeValue(w, s2s::DataType::Int8, -200.0);   // saturates to -128
    s2s::writeValue(w, s2s::DataType::UInt8, 300.0);   // saturates to 255
    s2s::writeValue(w, s2s::DataType::Float32, 1.5);
    s2s::writeValue(w, s2s::DataType::Bool, 2.0);
    const std::vector<std::uint8_t> expected = {0x12, 0x34, 0x80, 0xFF, 0x3F, 0xC0, 0x00, 0x00, 0x01};
    CHECK(w.data() == expected);

    PayloadReader r(w.data());
    CHECK_EQ(*s2s::readValue(r, s2s::DataType::UInt16), 0x1234);
    CHECK_EQ(*s2s::readValue(r, s2s::DataType::Int8), -128);
    CHECK_EQ(*s2s::readValue(r, s2s::DataType::UInt8), 255);
    CHECK_NEAR(*s2s::readValue(r, s2s::DataType::Float32), 1.5, 1e-9);
    CHECK_EQ(*s2s::readValue(r, s2s::DataType::Bool), 1);
    CHECK(!s2s::readValue(r, s2s::DataType::UInt8).has_value());
}
