#include <array>
#include <cstdint>

#include "ccg/e2e/can_e2e.hpp"
#include "test_framework.hpp"

using namespace ccg::e2e;

TEST_CASE("e2e: CRC-8 SAE J1850 check value") {
    const std::uint8_t data[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    CHECK_EQ(crc8SaeJ1850(data, sizeof data), 0x4B);
    const std::uint8_t zeros[] = {0x00, 0x00, 0x00, 0x00};
    CHECK_EQ(crc8SaeJ1850(zeros, sizeof zeros), 0x59);
}

TEST_CASE("e2e: protected frames pass the receiver") {
    CanE2EConfig cfg;
    cfg.dataId = 0x00FD;
    CanE2ESender tx(cfg);
    CanE2EReceiver rx(cfg);
    for (int i = 0; i < 40; ++i) {
        std::array<std::uint8_t, 8> d{static_cast<std::uint8_t>(i), 0x11, 0x22};
        tx.protect(d.data(), d.size());
        CHECK(rx.check(d.data(), d.size()) == CheckStatus::Ok);
    }
}

TEST_CASE("e2e: CRC, data ID, repetition and sequence errors are detected") {
    CanE2EConfig cfg;
    cfg.dataId = 0x0123;
    cfg.maxDeltaCounter = 2;
    CanE2ESender tx(cfg);
    CanE2EReceiver rx(cfg);

    std::array<std::uint8_t, 8> d{};
    tx.protect(d.data(), d.size());
    CHECK(rx.check(d.data(), d.size()) == CheckStatus::Ok);
    CHECK(rx.check(d.data(), d.size()) == CheckStatus::Repeated);

    auto corrupted = d;
    corrupted[2] ^= 0x01;
    CHECK(rx.check(corrupted.data(), corrupted.size()) == CheckStatus::CrcError);

    CanE2EConfig other = cfg;
    other.dataId = 0x0124;  // masquerading sender with another data ID
    CanE2ESender wrongSender(other);
    auto masq = d;
    wrongSender.protect(masq.data(), masq.size());
    CHECK(rx.check(masq.data(), masq.size()) == CheckStatus::CrcError);

    tx.protect(d.data(), d.size());  // counter 1, lost
    tx.protect(d.data(), d.size());  // counter 2 -> delta 2 accepted
    CHECK(rx.check(d.data(), d.size()) == CheckStatus::OkSomeLost);

    for (int i = 0; i < 3; ++i) tx.protect(d.data(), d.size());  // delta 3
    CHECK(rx.check(d.data(), d.size()) == CheckStatus::WrongSequence);
    tx.protect(d.data(), d.size());  // receiver resynchronised
    CHECK(rx.check(d.data(), d.size()) == CheckStatus::Ok);
}

TEST_CASE("e2e: counter wraps 14 -> 0") {
    CanE2EConfig cfg;
    CanE2ESender tx(cfg);
    CanE2EReceiver rx(cfg);
    std::array<std::uint8_t, 8> d{};
    for (int i = 0; i < 16; ++i) {
        tx.protect(d.data(), d.size());
        CHECK(rx.check(d.data(), d.size()) == CheckStatus::Ok);
        CHECK((d[6] & 0x0F) == i % 15);
    }
}
