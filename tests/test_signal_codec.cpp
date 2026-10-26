#include <array>
#include <cstdint>
#include <limits>

#include "ccg/can/signal_codec.hpp"
#include "test_framework.hpp"

using namespace ccg::can;

namespace {

SignalSpec spec(std::uint16_t start, std::uint8_t len, ByteOrder order, bool isSigned = false) {
    SignalSpec s;
    s.name = "S";
    s.startBit = start;
    s.length = len;
    s.byteOrder = order;
    s.isSigned = isSigned;
    s.min = -1e9;
    s.max = 1e9;
    return s;
}

}  // namespace

TEST_CASE("codec: Intel 16 bit little endian") {
    std::array<std::uint8_t, 8> d{0x34, 0x12};
    CHECK_EQ(extractRaw(d.data(), spec(0, 16, ByteOrder::Intel)), 0x1234U);
}

TEST_CASE("codec: Intel signal crossing bytes at odd bit") {
    // 12 bits starting at bit 4: low nibble from byte0[7:4], rest from byte1
    std::array<std::uint8_t, 8> d{0xA0, 0xBC};
    CHECK_EQ(extractRaw(d.data(), spec(4, 12, ByteOrder::Intel)), 0xBCAU);
}

TEST_CASE("codec: Motorola 16 bit big endian (start bit = MSB)") {
    std::array<std::uint8_t, 8> d{0x12, 0x34};
    CHECK_EQ(extractRaw(d.data(), spec(7, 16, ByteOrder::Motorola)), 0x1234U);
}

TEST_CASE("codec: Motorola 12 bit sawtooth across bytes") {
    std::array<std::uint8_t, 8> d{0xAB, 0xCD};
    // bits 3..0 of byte 0 are the MSBs, byte 1 the LSBs
    CHECK_EQ(extractRaw(d.data(), spec(3, 12, ByteOrder::Motorola)), 0xBCDU);
}

TEST_CASE("codec: insert/extract round trip leaves neighbours untouched") {
    for (auto order : {ByteOrder::Intel, ByteOrder::Motorola}) {
        for (std::uint8_t len : {1, 3, 7, 8, 13, 16, 31}) {
            for (std::uint16_t start = 0; start < 64; ++start) {
                const auto s = spec(start, len, order);
                if (!fitsInFrame(s, 8)) continue;
                std::array<std::uint8_t, 8> d;
                d.fill(0xFF);
                const std::uint64_t value = 0x5A5A5A5A5AULL & rawMask(len);
                insertRaw(d.data(), s, value);
                CHECK_EQ(extractRaw(d.data(), s), value);
                // every bit outside the signal is still 1
                std::array<std::uint8_t, 8> mask{};
                forEachBitMsbFirst(s, [&](std::size_t pos) {
                    mask[pos / 8] = static_cast<std::uint8_t>(mask[pos / 8] | (1U << (pos % 8)));
                });
                for (std::size_t i = 0; i < 8; ++i) {
                    CHECK_EQ(d[i] | mask[i], 0xFF);
                }
            }
        }
    }
}

TEST_CASE("codec: fitsInFrame detects overflow") {
    CHECK(fitsInFrame(spec(56, 8, ByteOrder::Intel), 8));
    CHECK(!fitsInFrame(spec(57, 8, ByteOrder::Intel), 8));
    CHECK(fitsInFrame(spec(7, 64, ByteOrder::Motorola), 8));
    CHECK(!fitsInFrame(spec(15, 64, ByteOrder::Motorola), 8));
    CHECK(!fitsInFrame(spec(0, 0, ByteOrder::Intel), 8));
}

TEST_CASE("codec: signed values and physical conversion") {
    auto s = spec(0, 16, ByteOrder::Intel, true);
    s.factor = 0.1;
    s.offset = 0.0;
    CHECK_EQ(signExtend(0xFFFF, 16), -1);
    CHECK_EQ(signExtend(0x7FFF, 16), 32767);
    CHECK_NEAR(rawToPhysical(s, 0xFF9C), -10.0, 1e-9);  // -100 * 0.1
    CHECK_EQ(physicalToRaw(s, -10.0), 0xFF9CU);
    CHECK_EQ(physicalToRaw(s, 1e9), 0x7FFFU);           // saturates to max
    CHECK_EQ(physicalToRaw(s, -1e9), 0x8000U);          // saturates to min
}

TEST_CASE("codec: factor/offset with rounding") {
    auto s = spec(0, 8, ByteOrder::Intel);
    s.factor = 0.5;
    s.offset = 10.0;
    CHECK_EQ(physicalToRaw(s, 21.5), 23U);
    CHECK_EQ(physicalToRaw(s, 21.74), 23U);
    CHECK_EQ(physicalToRaw(s, 21.76), 24U);
    CHECK_EQ(physicalToRaw(s, -50.0), 0U);
    CHECK_NEAR(rawToPhysical(s, 23), 21.5, 1e-9);
}

TEST_CASE("codec: numberToRaw rejects non integral and out of range") {
    const auto u = spec(0, 2, ByteOrder::Intel);
    CHECK(numberToRaw(u, 3.0).has_value());
    CHECK(!numberToRaw(u, 4.0).has_value());
    CHECK(!numberToRaw(u, -1.0).has_value());
    CHECK(!numberToRaw(u, 1.5).has_value());
    const auto s = spec(0, 8, ByteOrder::Intel, true);
    CHECK_EQ(*numberToRaw(s, -1.0), 0xFFU);
    CHECK(!numberToRaw(s, 128.0).has_value());
}

TEST_CASE("codec: integer bounds remain exact through 64 bits") {
    for (std::uint8_t bits : {1, 8, 32, 53, 54, 63, 64}) {
        for (bool signedValue : {false, true}) {
            const auto s = spec(0, bits, ByteOrder::Intel, signedValue);
            const double upper = std::ldexp(1.0, bits - (signedValue ? 1 : 0));
            CHECK(!numberToRaw(s, upper).has_value());
            CHECK(!numberToRaw(s, std::nextafter(upper, INFINITY)).has_value());
            const double below = std::floor(std::nextafter(upper, 0.0));
            REQUIRE(numberToRaw(s, below).has_value());
            CHECK_EQ(*numberToRaw(s, below), static_cast<std::uint64_t>(below));
            if (signedValue) {
                CHECK(numberToRaw(s, -upper).has_value());
                CHECK(!numberToRaw(s, std::nextafter(-upper, -INFINITY)).has_value());
            } else {
                CHECK_EQ(*numberToRaw(s, 0.0), 0u);
                CHECK(!numberToRaw(s, -1.0).has_value());
            }
        }
    }
    const auto s = spec(0, 64, ByteOrder::Intel);
    CHECK(!numberToRaw(s, std::numeric_limits<double>::infinity()).has_value());
    CHECK(!numberToRaw(s, -std::numeric_limits<double>::infinity()).has_value());
    CHECK(!numberToRaw(s, std::numeric_limits<double>::quiet_NaN()).has_value());
}
