#include <vector>
#include <stdexcept>

#include "ccg/secoc/secoc.hpp"
#include "test_framework.hpp"
#include "vehicle_eth_gateway_matrix.hpp"

using namespace ccg;
using namespace ccg::secoc;

namespace {

using Bytes = std::vector<std::uint8_t>;

crypto::Block key(std::uint8_t seed) {
    crypto::Block k{};
    for (std::size_t i = 0; i < 16; ++i) k[i] = static_cast<std::uint8_t>(seed + i * 17);
    return k;
}

SecOcConfig profile1(std::uint16_t dataId = 0x01B0) {  // AUTOSAR "24Bit-CMAC-8Bit-FV"
    SecOcConfig c;
    c.dataId = dataId;
    c.keyId = "K1";
    c.freshnessBits = 64;
    c.freshnessTxBits = 8;
    c.macTxBits = 24;
    return c;
}

// Sender and receiver with separate freshness managers sharing one key.
struct Pair {
    SoftwareCryptoService crypto;
    FreshnessManager txFvm, rxFvm;
    SecOcProcessor tx{crypto, txFvm};
    SecOcProcessor rx{crypto, rxFvm};
    Pair() { crypto.setKey("K1", key(1)); }
};

}  // namespace

TEST_CASE("secoc: secured PDU layout = authentic | FV LSBs | MAC MSBs") {
    Pair p;
    const Bytes authentic = {0x11, 0x22, 0x33, 0x44};
    const auto secured = p.tx.protect(profile1(), authentic.data(), authentic.size());
    REQUIRE(secured.has_value());
    REQUIRE(secured->size() == 8);
    CHECK(Bytes(secured->begin(), secured->begin() + 4) == authentic);
    CHECK_EQ((*secured)[4], 0x01);  // first FV = 1

    // MAC = CMAC(key, DataID | authentic | 64-bit FV), 3 MSBs transmitted.
    const Bytes dta = {0x01, 0xB0, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 0, 0x01};
    const auto mac = crypto::Cmac(key(1)).compute(dta.data(), dta.size());
    CHECK_EQ((*secured)[5], mac[0]);
    CHECK_EQ((*secured)[6], mac[1]);
    CHECK_EQ((*secured)[7], mac[2]);
    CHECK_EQ(overheadBytes(profile1()), 4U);
}

TEST_CASE("secoc: verification success and freshness advance") {
    Pair p;
    for (int i = 0; i < 300; ++i) {  // passes FV 0xFF -> 0x100 (truncated FV wraps)
        const Bytes a = {static_cast<std::uint8_t>(i), 0xAA, 0xBB, 0xCC};
        const auto s = p.tx.protect(profile1(), a.data(), a.size());
        CHECK(p.rx.verify(profile1(), s->data(), 4) == VerifyResult::Ok);
    }
    CHECK_EQ(p.rxFvm.latestRx(0x01B0), 300U);
}

TEST_CASE("secoc: tampered data, wrong key and wrong data ID are rejected") {
    Pair p;
    const Bytes a = {1, 2, 3, 4};
    auto s = *p.tx.protect(profile1(), a.data(), a.size());
    auto tampered = s;
    tampered[0] ^= 0x01;
    CHECK(p.rx.verify(profile1(), tampered.data(), 4) == VerifyResult::MacFailure);
    CHECK(p.rx.verify(profile1(0x01B1), s.data(), 4) == VerifyResult::MacFailure);  // other Data ID

    SoftwareCryptoService other;
    other.setKey("K1", key(9));
    FreshnessManager fvm;
    SecOcProcessor attacker(other, fvm);
    const auto forged = *attacker.protect(profile1(), a.data(), a.size());
    CHECK(p.rx.verify(profile1(), forged.data(), 4) == VerifyResult::MacFailure);

    CHECK(p.rx.verify(profile1(), s.data(), 4) == VerifyResult::Ok);  // original still valid
    CHECK_EQ(p.rxFvm.latestRx(0x01B0), 1U);  // failures did not advance the counter
}

TEST_CASE("secoc: replay is rejected") {
    Pair p;
    auto full = profile1();
    full.freshnessTxBits = 64;  // full FV on Ethernet: replay = freshness failure
    full.macTxBits = 64;
    const Bytes a = {9, 9};
    const auto first = *p.tx.protect(full, a.data(), a.size());
    const auto second = *p.tx.protect(full, a.data(), a.size());
    CHECK(p.rx.verify(full, first.data(), 2) == VerifyResult::Ok);
    CHECK(p.rx.verify(full, second.data(), 2) == VerifyResult::Ok);
    CHECK(p.rx.verify(full, first.data(), 2) == VerifyResult::FreshnessFailure);
    CHECK(p.rx.verify(full, second.data(), 2) == VerifyResult::FreshnessFailure);

    // With a truncated FV a replay maps to the next epoch and fails the MAC.
    Pair q;
    const auto msg = *q.tx.protect(profile1(), a.data(), a.size());
    CHECK(q.rx.verify(profile1(), msg.data(), 2) == VerifyResult::Ok);
    CHECK(q.rx.verify(profile1(), msg.data(), 2) == VerifyResult::MacFailure);
}

TEST_CASE("secoc: acceptance window and lost PDUs") {
    Pair p;
    auto c = profile1();
    c.verifyAttempts = 2;
    const Bytes a = {7};
    CHECK(p.rx.verify(c, p.tx.protect(c, a.data(), 1)->data(), 1) == VerifyResult::Ok);
    for (int i = 0; i < 300; ++i) p.tx.protect(c, a.data(), 1);  // 300 PDUs lost (> 256)
    const auto late = *p.tx.protect(c, a.data(), 1);
    CHECK(p.rx.verify(c, late.data(), 1) == VerifyResult::Ok);  // second attempt: next epoch
    CHECK_EQ(p.rxFvm.latestRx(c.dataId), 302U);

    Pair w;
    auto windowed = profile1();
    windowed.freshnessTxBits = 64;
    windowed.acceptanceWindow = 10;
    for (int i = 0; i < 20; ++i) w.tx.protect(windowed, a.data(), 1);
    CHECK(w.rx.verify(windowed, w.tx.protect(windowed, a.data(), 1)->data(), 1) ==
          VerifyResult::FreshnessFailure);  // jump of 21 > window 10
}

TEST_CASE("secoc: bit packed FV and MAC, counter overflow, persistence") {
    Pair p;
    SecOcConfig c;
    c.dataId = 7;
    c.keyId = "K1";
    c.freshnessBits = 12;
    c.freshnessTxBits = 4;
    c.macTxBits = 28;  // 4 + 28 = 32 bits
    const Bytes a = {0x5A};
    for (int i = 0; i < 20; ++i) {
        const auto s = p.tx.protect(c, a.data(), 1);
        REQUIRE(s.has_value());
        CHECK_EQ(s->size(), 5U);
        CHECK_EQ((*s)[1] >> 4, (i + 1) & 0xF);  // FV nibble in the high bits
        CHECK(p.rx.verify(c, s->data(), 1) == VerifyResult::Ok);
    }

    SecOcConfig tiny = c;
    tiny.freshnessBits = 2;
    tiny.freshnessTxBits = 2;
    FreshnessManager fvm;
    SecOcProcessor proc(p.crypto, fvm);
    for (int i = 0; i < 3; ++i) CHECK(proc.protect(tiny, a.data(), 1).has_value());
    CHECK(!proc.protect(tiny, a.data(), 1).has_value());  // counter exhausted

    auto snap = p.txFvm.snapshot();
    FreshnessManager restored;
    restored.restore(snap, 100);
    CHECK_EQ(*restored.nextTx(7, 12), 121U);  // 20 + margin 100 + 1
}

TEST_CASE("secoc: configuration checks and missing key") {
    SecOcConfig c;
    c.keyId = "";
    c.freshnessBits = 70;
    c.macTxBits = 4;
    c.verifyAttempts = 0;
    CHECK_EQ(validateSecOcConfig(c).size(), 4U);
    CHECK(validateSecOcConfig(profile1()).empty());

    SoftwareCryptoService none;
    FreshnessManager fvm;
    SecOcProcessor proc(none, fvm);
    const Bytes a = {1};
    CHECK(!proc.protect(profile1(), a.data(), 1).has_value());
    const Bytes s = {1, 1, 0, 0, 0};
    CHECK(proc.verify(profile1(), s.data(), 1) == VerifyResult::CryptoError);
}

TEST_CASE("secoc: durable TX restarts stay inside the reference Ethernet window") {
    const auto matrix = config::makeVehicleEthGatewayMatrix();
    bool exercised = false;
    for (const auto& pdu : matrix.pdus) {
        if (!pdu.secoc || pdu.secoc->freshnessMode != FreshnessMode::Counter) continue;
        exercised = true;
        const auto& c = *pdu.secoc;
        REQUIRE(c.acceptanceWindow == 1000);
        SoftwareCryptoService crypto;
        crypto.setKey(c.keyId, key(1));
        FreshnessManager receiver;
        SecOcProcessor rx(crypto, receiver);
        FreshnessManager::Snapshot durable;
        const Bytes data{1, 2, 3};
        for (int restart = 0; restart < 5; ++restart) {
            FreshnessManager sender;
            sender.restore(durable);  // application's durable mode: no restart margin
            sender.setPersistence([&](const FreshnessManager::Snapshot& s) { durable = s; });
            SecOcProcessor tx(crypto, sender);
            // Also model one counter stored before a crash prevented its transmission.
            tx.protect(c, data.data(), data.size());
            const auto packet = tx.protect(c, data.data(), data.size());
            REQUIRE(packet.has_value());
            CHECK_EQ(durable.tx.at(c.dataId), 2u * (restart + 1));
            CHECK(rx.verify(c, packet->data(), data.size()) == VerifyResult::Ok);
        }
    }
    CHECK(exercised);
}

TEST_CASE("secoc: RX state is durable before acceptance and replays fail after crash") {
    Pair p;
    auto c = profile1();
    c.freshnessTxBits = 64;
    c.macTxBits = 64;
    c.acceptanceWindow = 1000;
    FreshnessManager::Snapshot durable;
    unsigned writes = 0;
    p.rxFvm.setPersistence([&](const FreshnessManager::Snapshot& s) {
        CHECK(s.rx.at(c.dataId) > p.rxFvm.latestRx(c.dataId));
        durable = s;
        ++writes;
    });
    const Bytes data{1, 2, 3};
    const auto first = *p.tx.protect(c, data.data(), data.size());
    REQUIRE(p.rx.verify(c, first.data(), data.size()) == VerifyResult::Ok);
    const auto captured = *p.tx.protect(c, data.data(), data.size());
    auto tampered = captured;
    tampered[0] ^= 1;
    CHECK(p.rx.verify(c, tampered.data(), data.size()) == VerifyResult::MacFailure);
    CHECK_EQ(writes, 1u);
    REQUIRE(p.rx.verify(c, captured.data(), data.size()) == VerifyResult::Ok);
    CHECK_EQ(writes, 2u);
    FreshnessManager restarted;
    restarted.restore(durable); // no orderly shutdown or periodic save
    SecOcProcessor rx(p.crypto, restarted);
    CHECK(rx.verify(c, captured.data(), data.size()) == VerifyResult::FreshnessFailure);
    CHECK(rx.verify(c, first.data(), data.size()) == VerifyResult::FreshnessFailure);
    const auto next = *p.tx.protect(c, data.data(), data.size());
    CHECK(rx.verify(c, next.data(), data.size()) == VerifyResult::Ok);
}

TEST_CASE("secoc: failed persistence prevents TX and successful RX verification") {
    Pair p;
    auto c = profile1();
    c.freshnessTxBits = 64;
    const Bytes data{7};
    auto unavailable = [](const FreshnessManager::Snapshot&) { throw std::runtime_error("storage unavailable"); };
    p.txFvm.setPersistence(unavailable);
    bool failed = false;
    try { p.tx.protect(c, data.data(), data.size()); } catch (const std::runtime_error&) { failed = true; }
    CHECK(failed);
    CHECK_EQ(p.txFvm.snapshot().tx.at(c.dataId), 0u);
    p.txFvm.setPersistence({});
    const auto packet = *p.tx.protect(c, data.data(), data.size());
    p.rxFvm.setPersistence(unavailable);
    failed = false;
    try { p.rx.verify(c, packet.data(), data.size()); } catch (const std::runtime_error&) { failed = true; }
    CHECK(failed);
    CHECK_EQ(p.rxFvm.latestRx(c.dataId), 0u);
    p.rxFvm.setPersistence({});
    CHECK(p.rx.verify(c, packet.data(), data.size()) == VerifyResult::Ok);
}
