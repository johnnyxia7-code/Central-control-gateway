#include <vector>

#include "ccg/secoc/fv_sync.hpp"
#include "ccg/secoc/secoc.hpp"
#include "test_framework.hpp"

using namespace ccg;
using namespace ccg::secoc;
using namespace std::chrono_literals;

namespace {

using Bytes = std::vector<std::uint8_t>;

crypto::Block key(std::uint8_t seed) {
    crypto::Block k{};
    for (std::size_t i = 0; i < 16; ++i) k[i] = static_cast<std::uint8_t>(seed * 13 + i);
    return k;
}

SyncMessageConfig syncConfig() {
    SyncMessageConfig c;
    c.dataId = 0x00F0;
    c.keyId = "K_FV";
    c.macTxBits = 28;
    c.resetCycle = 1000ms;
    return c;
}

SecOcConfig synchronizedPdu() {  // reset flag 2 bit + message counter 6 bit, 24-bit MAC
    SecOcConfig c;
    c.dataId = 0x01B0;
    c.keyId = "K_PDU";
    c.freshnessMode = FreshnessMode::TripReset;
    c.freshnessBits = 62;
    c.freshnessTxBits = 8;
    c.macTxBits = 24;
    c.verifyAttempts = 2;
    return c;
}

// One FV master (gateway) and two slaves (sender ECU, receiver ECU).
struct Network {
    SoftwareCryptoService crypto;
    FreshnessManager masterFv, senderFv, receiverFv;
    FreshnessSyncMaster master{syncConfig(), crypto, masterFv};
    FreshnessSyncSlave sender{syncConfig(), crypto, senderFv};
    FreshnessSyncSlave receiver{syncConfig(), crypto, receiverFv};
    SecOcProcessor tx{crypto, senderFv};
    SecOcProcessor rx{crypto, receiverFv};
    TimePoint now = TimePoint{} + 1s;
    Bytes lastSync;

    Network() {
        crypto.setKey("K_FV", key(1));
        crypto.setKey("K_PDU", key(2));
    }

    // Runs the master; distributes each sync message to the slaves (optionally not to the receiver).
    void run(std::chrono::milliseconds d, bool receiverListens = true) {
        for (auto t = 0ms; t <= d; t += 1ms) {
            if (auto msg = master.mainFunction(now)) {
                lastSync = *msg;
                sender.onSyncMessage(msg->data(), msg->size());
                if (receiverListens) receiver.onSyncMessage(msg->data(), msg->size());
            }
            if (t < d) now += 1ms;
        }
    }
};

}  // namespace

TEST_CASE("fv sync: master increments the persisted trip counter at power-up") {
    Network n;
    n.masterFv.restore({{}, {}, 41}, 0);
    REQUIRE(n.master.start(n.now));
    CHECK_EQ(n.masterFv.tripCounter(), 42U);
    CHECK_EQ(n.masterFv.resetCounter(), 0U);
    CHECK(n.masterFv.takePersistRequest());   // store trip 42 before using it
    CHECK(!n.masterFv.takePersistRequest());
    CHECK_EQ(n.masterFv.snapshot().trip, 42U);

    const auto first = n.master.mainFunction(n.now);
    REQUIRE(first.has_value());
    REQUIRE(first->size() == 8);  // 16 + 20 + 28 bits
    CHECK_EQ((*first)[0], 0x00);  // trip 42 = 0x002A in the first 16 bits
    CHECK_EQ((*first)[1], 0x2A);
    CHECK_EQ((*first)[2], 0x00);  // reset 0
    CHECK(!n.master.mainFunction(n.now).has_value());  // nothing due

    n.now += 999ms;
    CHECK(!n.master.mainFunction(n.now).has_value());
    n.now += 1ms;
    const auto second = n.master.mainFunction(n.now);
    REQUIRE(second.has_value());
    CHECK_EQ(n.masterFv.resetCounter(), 1U);
    CHECK_EQ((*second)[4] >> 4, 0x1);  // reset counter bits 3..0 = high nibble of byte 4 (bits 32..35)

    n.master.requestSync();
    CHECK(n.master.mainFunction(n.now).has_value());
    CHECK_EQ(n.master.syncMessagesSent(), 3U);
}

TEST_CASE("fv sync: slave accepts authentic newer counters only") {
    Network n;
    REQUIRE(n.master.start(n.now));
    n.run(0ms);
    CHECK(n.senderFv.synchronized());
    CHECK_EQ(n.senderFv.tripCounter(), 1U);

    const Bytes old = n.lastSync;
    n.run(1000ms);
    CHECK_EQ(n.senderFv.resetCounter(), 1U);
    CHECK(n.sender.onSyncMessage(old.data(), old.size()) == SyncResult::Stale);           // replay
    CHECK(n.sender.onSyncMessage(n.lastSync.data(), n.lastSync.size()) == SyncResult::Stale);

    auto forged = n.lastSync;
    forged[2] ^= 0x10;  // reset counter pushed forward without the key
    CHECK(n.sender.onSyncMessage(forged.data(), forged.size()) == SyncResult::MacFailure);
    CHECK(n.sender.onSyncMessage(old.data(), 7) == SyncResult::LengthError);
    CHECK_EQ(n.senderFv.resetCounter(), 1U);
}

TEST_CASE("fv sync: reset counter overflow starts a new trip, exhausted trip stops the master") {
    SoftwareCryptoService crypto;
    crypto.setKey("K_FV", key(3));
    FreshnessManager fv;
    TripResetLayout small;
    small.tripBits = 2;
    small.resetBits = 2;
    small.resetFlagBits = 1;
    small.messageBits = 8;
    fv.setLayout(small);
    FreshnessSyncMaster master(syncConfig(), crypto, fv);
    TimePoint now{};
    REQUIRE(master.start(now));  // trip 1
    fv.takePersistRequest();
    for (int i = 1; i <= 3; ++i) {
        now += 1000ms;
        master.mainFunction(now);
        CHECK_EQ(fv.resetCounter(), static_cast<std::uint32_t>(i));
    }
    now += 1000ms;
    REQUIRE(master.mainFunction(now).has_value());
    CHECK_EQ(fv.tripCounter(), 2U);  // reset counter 3 -> overflow
    CHECK_EQ(fv.resetCounter(), 0U);
    CHECK(fv.takePersistRequest());

    FreshnessManager full;
    full.setLayout(small);
    full.restore({{}, {}, 3}, 0);  // trip counter already at its maximum
    FreshnessSyncMaster exhausted(syncConfig(), crypto, full);
    CHECK(!exhausted.start(now));
    CHECK(!exhausted.mainFunction(now).has_value());
    CHECK(!exhausted.active());
}

TEST_CASE("fv sync: synchronised freshness value end to end") {
    Network n;
    REQUIRE(n.master.start(n.now));
    const auto cfg = synchronizedPdu();
    const Bytes a = {0x12, 0x34, 0x56, 0x78};

    // Before the first sync message slaves can neither send nor verify.
    CHECK(!n.tx.protect(cfg, a.data(), a.size()).has_value());
    n.run(0ms);

    for (int period = 0; period < 3; ++period) {
        for (int i = 1; i <= 100; ++i) {  // message counter wraps its 6 transmitted bits
            const auto s = n.tx.protect(cfg, a.data(), a.size());
            REQUIRE(s.has_value());
            CHECK_EQ((*s)[4] >> 6, period & 0x3);  // reset flag
            CHECK_EQ((*s)[4] & 0x3F, i & 0x3F);    // message counter LSBs
            CHECK(n.rx.verify(cfg, s->data(), 4) == VerifyResult::Ok);
        }
        n.run(1000ms);
    }
    // complete FV = trip 1 | reset 2 | message 100
    const std::uint64_t expected = (((std::uint64_t{1} << 20) | 2) << 26) | 100;
    CHECK_EQ(n.receiverFv.latestRx(cfg.dataId), expected);
}

TEST_CASE("fv sync: one reset period of skew between sender and receiver is tolerated") {
    Network n;
    REQUIRE(n.master.start(n.now));
    n.run(0ms);
    const auto cfg = synchronizedPdu();
    const Bytes a = {1};

    // Receiver missed a sync message: the sender is one reset period ahead.
    n.run(1000ms, false);
    auto ahead = *n.tx.protect(cfg, a.data(), 1);
    CHECK(n.rx.verify(cfg, ahead.data(), 1) == VerifyResult::Ok);

    // Sender sent just before the next sync, the receiver already has it.
    auto late = *n.tx.protect(cfg, a.data(), 1);
    n.run(1000ms);
    CHECK(n.rx.verify(cfg, late.data(), 1) == VerifyResult::Ok);

    // Two periods old: no reset flag match any more.
    auto old = *n.tx.protect(cfg, a.data(), 1);
    n.run(2000ms);
    CHECK(n.rx.verify(cfg, old.data(), 1) == VerifyResult::FreshnessFailure);
}

TEST_CASE("fv sync: messages of a previous power cycle are rejected") {
    Network n;
    REQUIRE(n.master.start(n.now));
    n.run(0ms);
    const auto cfg = synchronizedPdu();
    const Bytes a = {7, 7};
    const auto recorded = *n.tx.protect(cfg, a.data(), a.size());  // trip 1, reset 0, message 1

    // Gateway restart: trip 2. Same reset flag and message counter in the replay,
    // but the complete FV is rebuilt with trip 2, so the MAC cannot match.
    const auto snapshot = n.masterFv.snapshot();
    FreshnessManager restarted;
    restarted.restore(snapshot, 0);
    FreshnessSyncMaster master2(syncConfig(), n.crypto, restarted);
    REQUIRE(master2.start(n.now));
    const auto sync = *master2.mainFunction(n.now);
    REQUIRE(n.receiver.onSyncMessage(sync.data(), sync.size()) == SyncResult::Accepted);
    CHECK_EQ(n.receiverFv.tripCounter(), 2U);
    CHECK(n.rx.verify(cfg, recorded.data(), 2) == VerifyResult::MacFailure);
}

TEST_CASE("fv sync: parameter checks") {
    TripResetLayout bad;
    bad.tripBits = 33;
    bad.resetBits = 20;
    bad.resetFlagBits = 20;
    bad.messageBits = 20;
    SyncMessageConfig c;
    c.macTxBits = 4;
    c.resetCycle = 0ms;
    const auto errors = validateFreshnessSync(bad, c);
    CHECK_EQ(errors.size(), 6U);  // trip, flag, > 64 bits, key, MAC, cycle
    CHECK(validateFreshnessSync(TripResetLayout{}, syncConfig()).empty());
    CHECK_EQ(syncMessageLength(TripResetLayout{}, syncConfig()), 8U);
}

TEST_CASE("fv sync: a new trip is persisted before any synchronization message") {
    Network n;
    std::uint64_t durableTrip = 0;
    n.masterFv.setPersistence([&](const FreshnessManager::Snapshot& s) {
        CHECK(s.trip > n.masterFv.storedTrip());
        durableTrip = s.trip;
    });
    REQUIRE(n.master.start(n.now));
    CHECK_EQ(durableTrip, 1u);
    REQUIRE(n.master.mainFunction(n.now).has_value());
    n.masterFv.setTripReset(1, (1u << n.masterFv.layout().resetBits) - 1);
    REQUIRE(n.master.mainFunction(n.now + 1000ms).has_value());
    CHECK_EQ(durableTrip, 2u); // reset overflow is committed before emitting its new trip
    CHECK_EQ(n.masterFv.tripCounter(), 2u);

    Network failed;
    failed.masterFv.setPersistence([](const FreshnessManager::Snapshot&) {
        throw std::runtime_error("NvM failed");
    });
    bool threw = false;
    try { failed.master.start(failed.now); } catch (const std::runtime_error&) { threw = true; }
    CHECK(threw);
    CHECK(!failed.master.mainFunction(failed.now).has_value());
    CHECK_EQ(failed.masterFv.storedTrip(), 0u);

    failed.masterFv.setPersistence({});
    REQUIRE(failed.master.start(failed.now));
    REQUIRE(failed.master.mainFunction(failed.now).has_value());
    failed.masterFv.setTripReset(1, (1u << failed.masterFv.layout().resetBits) - 1);
    failed.masterFv.setPersistence([](const FreshnessManager::Snapshot&) {
        throw std::runtime_error("NvM failed on overflow");
    });
    threw = false;
    try { failed.master.mainFunction(failed.now + 1000ms); } catch (const std::runtime_error&) { threw = true; }
    CHECK(threw);
    CHECK_EQ(failed.masterFv.tripCounter(), 1u);
    CHECK_EQ(failed.masterFv.storedTrip(), 1u);
}
