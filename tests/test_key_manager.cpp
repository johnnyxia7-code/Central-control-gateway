#include <map>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/doip/doip_message.hpp"
#include "ccg/ethgw/ethernet_gateway.hpp"
#include "ccg/keym/key_management_service.hpp"
#include "ccg/keym/key_manager.hpp"
#include "ccg/secoc/fv_sync.hpp"
#include "ccg/secoc/secoc.hpp"
#include "test_framework.hpp"
#include "vehicle_diag_routing.hpp"
#include "vehicle_eth_gateway_matrix.hpp"
#include "vehicle_key_slots.hpp"

using namespace ccg;
using namespace ccg::keym;
using namespace std::chrono_literals;
using Bytes = std::vector<std::uint8_t>;
namespace ks = config::keyslot;

namespace {

crypto::Block keyOf(std::uint8_t seed) {
    crypto::Block k{};
    for (std::size_t i = 0; i < 16; ++i) k[i] = static_cast<std::uint8_t>(0xA0 + seed + i * 3);
    return k;
}

she::Flags macFlags() {
    she::Flags f;
    f.keyUsage = true;
    f.wildcard = true;
    return f;
}

struct Keys {
    KeyManagerConfig cfg = config::makeVehicleKeySlots();
    TimePoint now = TimePoint{} + 100s;
    KeyManager km{cfg};

    Keys() { config::provisionDemoKeyStore(km, now); }

    she::UpdateRequest update(std::uint8_t slot, const crypto::Block& key, std::uint32_t counter,
                              she::Flags flags = macFlags(), std::uint8_t authSlot = she::kMasterEcuKey,
                              std::optional<crypto::Block> authKey = std::nullopt,
                              std::optional<she::Uid> uid = std::nullopt) {
        return she::buildUpdate(uid.value_or(cfg.uid), slot, authSlot, authKey.value_or(config::demoMasterEcuKey()),
                                key, counter, flags);
    }

    KeyManager::SlotStatus status(std::uint8_t slot) const {
        for (const auto& s : km.status()) {
            if (s.slot == slot) return s;
        }
        return {};
    }

    std::optional<crypto::Block> mac(const std::string& keyId, const Bytes& data) {
        crypto::Block m;
        if (!km.generateMac(keyId, data.data(), data.size(), m)) return std::nullopt;
        return m;
    }
};

crypto::Block cmac(const crypto::Block& key, const Bytes& data) {
    return crypto::Cmac(key).compute(data.data(), data.size());
}

std::optional<bool> verifyWith(KeyManager& km, const std::string& keyId, const crypto::Block& key,
                               const Bytes& data) {
    const auto m = cmac(key, data);
    return km.verifyMac(keyId, data.data(), data.size(), m.data(), 24);
}

}  // namespace

// ---------------------------------------------------------------- configuration

TEST_CASE("keym config: reference key slots are valid") {
    CHECK(validateKeyManagerConfig(config::makeVehicleKeySlots()).empty());
}

TEST_CASE("keym config: invalid slots are rejected") {
    auto c = config::makeVehicleKeySlots();
    c.uid = {};
    c.slots[0].slot = 0x2;                  // BOOT_MAC_KEY, MASTER_ECU_KEY now missing
    c.slots[2].keyId = c.slots[1].keyId;    // duplicate key ID
    c.slots.push_back({ks::kGwChs, "K_X", true});
    const auto errors = validateKeyManagerConfig(c);
    CHECK_EQ(errors.size(), 5u);
    bool threw = false;
    try {
        KeyManager km(c);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    CHECK(threw);
}

// ---------------------------------------------------------------- SHE key update

TEST_CASE("keym: provisioned keys serve SecOC; MASTER_ECU_KEY is never a MAC key") {
    Keys k;
    CHECK(k.km.hasKey("K_VCU_GW"));
    const Bytes data = {1, 2, 3};
    CHECK(k.mac("K_VCU_GW", data) == cmac(config::demoKey(3), data));
    CHECK(!k.km.hasKey(""));
    CHECK(!k.km.hasKey("K_UNKNOWN"));
    CHECK(!k.km.provision(ks::kVcuGw, keyOf(1), 5, macFlags(), k.now));  // slot not empty
}

TEST_CASE("keym: SHE update of a SecOC key is staged and returns the M4/M5 proof") {
    Keys k;
    const auto r = k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 2), k.now);
    CHECK(r.error == she::ErrorCode::NoError);
    CHECK(r.staged);
    REQUIRE(r.proof.has_value());
    CHECK(*r.proof == she::buildProof(k.cfg.uid, ks::kVcuGw, she::kMasterEcuKey, keyOf(1), 2));

    const auto st = k.status(ks::kVcuGw);
    CHECK(st.active && st.pending && !st.previous);
    CHECK_EQ(st.counter, 1u);
    CHECK_EQ(st.pendingCounter, 2u);
    // Still transmitting with the old key until activation.
    const Bytes data = {9, 8, 7};
    CHECK(k.mac("K_VCU_GW", data) == cmac(config::demoKey(3), data));
    CHECK(k.km.takePersistRequest());
}

TEST_CASE("keym: authentication failures, wrong UID and rollback are refused") {
    Keys k;
    // M3 made with a wrong MASTER_ECU_KEY
    auto r = k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 2, macFlags(), she::kMasterEcuKey, keyOf(9)), k.now);
    CHECK(r.error == she::ErrorCode::KeyUpdateError);
    CHECK(!r.proof);
    // other vehicle
    she::Uid other = k.cfg.uid;
    other[14] = 0x02;
    r = k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 2, macFlags(), she::kMasterEcuKey, std::nullopt, other), k.now);
    CHECK(r.error == she::ErrorCode::KeyUpdateError);
    // wildcard UID forbidden by the WILDCARD flag of the provisioned key
    r = k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 2, macFlags(), she::kMasterEcuKey, std::nullopt, she::Uid{}),
                     k.now);
    CHECK(r.error == she::ErrorCode::KeyUpdateError);
    // counter not newer (replay of an old update container)
    r = k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 1), k.now);
    CHECK(r.error == she::ErrorCode::KeyUpdateError);
    // KEY_n may not authorise another KEY_m
    r = k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 2, macFlags(), ks::kGwChs, config::demoKey(4)), k.now);
    CHECK(r.error == she::ErrorCode::KeyInvalid);
    // slot not configured
    r = k.km.loadKey(k.update(0xC, keyOf(1), 2), k.now);
    CHECK(r.error == she::ErrorCode::KeyInvalid);

    CHECK(!k.status(ks::kVcuGw).pending);
    std::size_t rejected = 0;
    for (const auto& e : k.km.events()) rejected += e.kind == KeyEvent::Kind::UpdateRejected;
    CHECK_EQ(rejected, 6u);
}

TEST_CASE("keym: a pending key can be replaced only by a newer generation") {
    Keys k;
    CHECK(k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 5), k.now).error == she::ErrorCode::NoError);
    CHECK(k.km.loadKey(k.update(ks::kVcuGw, keyOf(2), 5), k.now).error == she::ErrorCode::KeyUpdateError);
    CHECK(k.km.loadKey(k.update(ks::kVcuGw, keyOf(2), 6), k.now).error == she::ErrorCode::NoError);
    CHECK_EQ(k.status(ks::kVcuGw).pendingCounter, 6u);
}

TEST_CASE("keym: KEY_n can be updated with its own current value") {
    Keys k;
    const auto r =
        k.km.loadKey(k.update(ks::kGwChs, keyOf(3), 2, macFlags(), ks::kGwChs, config::demoKey(4)), k.now);
    CHECK(r.error == she::ErrorCode::NoError);
    CHECK(r.staged);
}

TEST_CASE("keym: write-protected keys cannot be updated") {
    Keys k;
    auto wp = macFlags();
    wp.writeProtection = true;
    CHECK(k.km.loadKey(k.update(ks::kFvMaster, keyOf(1), 2, wp), k.now).error == she::ErrorCode::NoError);
    CHECK_EQ(k.km.activatePending(k.now), 1u);
    CHECK(k.status(ks::kFvMaster).flags.writeProtection);
    CHECK(k.km.loadKey(k.update(ks::kFvMaster, keyOf(2), 3), k.now).error == she::ErrorCode::KeyWriteProtected);
}

TEST_CASE("keym: MASTER_ECU_KEY update is immediate and authorises the next updates") {
    Keys k;
    she::Flags master;
    master.wildcard = true;
    const auto r = k.km.loadKey(k.update(she::kMasterEcuKey, keyOf(7), 2, master), k.now);
    CHECK(r.error == she::ErrorCode::NoError);
    CHECK(!r.staged);
    CHECK_EQ(k.status(she::kMasterEcuKey).counter, 2u);
    // the old master key is no longer accepted, the new one is
    CHECK(k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 2), k.now).error == she::ErrorCode::KeyUpdateError);
    CHECK(k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 2, macFlags(), she::kMasterEcuKey, keyOf(7)), k.now).error ==
          she::ErrorCode::NoError);
}

TEST_CASE("keym: an empty slot is filled directly; empty authorising key is reported") {
    auto cfg = config::makeVehicleKeySlots();
    cfg.slots.push_back({0x9, "K_NEW", true});
    KeyManager km(cfg);
    const TimePoint now = TimePoint{} + 1s;
    auto req = she::buildUpdate(cfg.uid, 0x9, she::kMasterEcuKey, config::demoMasterEcuKey(), keyOf(1), 1, macFlags());
    CHECK(km.loadKey(req, now).error == she::ErrorCode::KeyEmpty);  // MASTER_ECU_KEY not provisioned
    km.provision(she::kMasterEcuKey, config::demoMasterEcuKey(), 1, she::Flags{}, now);
    const auto r = km.loadKey(req, now);
    CHECK(r.error == she::ErrorCode::NoError);
    CHECK(!r.staged);  // nothing to roll over
    CHECK(km.hasKey("K_NEW"));
}

TEST_CASE("keym: wildcard UID is accepted when the key allows it; M4 names the real UID") {
    auto cfg = config::makeVehicleKeySlots();
    KeyManager km(cfg);
    const TimePoint now = TimePoint{} + 1s;
    km.provision(she::kMasterEcuKey, config::demoMasterEcuKey(), 1, she::Flags{}, now);
    km.provision(ks::kVcuGw, config::demoKey(3), 1, she::Flags::decode(0x02), now);  // no WILDCARD flag
    const auto req =
        she::buildUpdate(she::Uid{}, ks::kVcuGw, she::kMasterEcuKey, config::demoMasterEcuKey(), keyOf(1), 2, macFlags());
    const auto r = km.loadKey(req, now);
    CHECK(r.error == she::ErrorCode::NoError);
    REQUIRE(r.proof.has_value());
    CHECK(*r.proof == she::buildProof(cfg.uid, ks::kVcuGw, she::kMasterEcuKey, keyOf(1), 2));
}

TEST_CASE("keym: repeated authentication failures lock the key update") {
    Keys k;
    const auto bad = k.update(ks::kVcuGw, keyOf(1), 2, macFlags(), she::kMasterEcuKey, keyOf(9));
    for (int i = 0; i < 3; ++i) CHECK(k.km.loadKey(bad, k.now).error == she::ErrorCode::KeyUpdateError);
    CHECK(k.km.lockedOut(k.now));
    const auto good = k.update(ks::kVcuGw, keyOf(1), 2);
    CHECK(k.km.loadKey(good, k.now + 9s).error == she::ErrorCode::Busy);
    CHECK(!k.km.lockedOut(k.now + 10s));
    CHECK(k.km.loadKey(good, k.now + 10s).error == she::ErrorCode::NoError);
    bool locked = false;
    for (const auto& e : k.km.events()) locked |= e.kind == KeyEvent::Kind::UpdateLocked;
    CHECK(locked);
}

// ---------------------------------------------------------------- rollover

TEST_CASE("keym: rollover accepts previous and pending keys, previous expires after the grace period") {
    Keys k;
    const Bytes data = {0x12, 0x34, 0x56, 0x78};
    REQUIRE(k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 2), k.now).error == she::ErrorCode::NoError);

    // VCU already switched (activated before the gateway): pending key verifies.
    CHECK(verifyWith(k.km, "K_VCU_GW", keyOf(1), data) == std::optional<bool>(true));
    CHECK(verifyWith(k.km, "K_VCU_GW", config::demoKey(3), data) == std::optional<bool>(true));
    CHECK_EQ(k.km.rolloverVerifications(), 1u);

    CHECK_EQ(k.km.activatePending(k.now), 1u);
    CHECK(k.mac("K_VCU_GW", data) == cmac(keyOf(1), data));  // gateway transmits with the new key
    const auto st = k.status(ks::kVcuGw);
    CHECK(st.active && !st.pending && st.previous);
    CHECK_EQ(st.counter, 2u);
    // VCU not switched yet: previous key still accepted
    CHECK(verifyWith(k.km, "K_VCU_GW", config::demoKey(3), data) == std::optional<bool>(true));
    CHECK_EQ(k.km.rolloverVerifications(), 2u);

    k.km.mainFunction(k.now + 10min - 1ms);
    CHECK(k.status(ks::kVcuGw).previous);
    k.km.mainFunction(k.now + 10min);
    CHECK(!k.status(ks::kVcuGw).previous);
    CHECK(verifyWith(k.km, "K_VCU_GW", config::demoKey(3), data) == std::optional<bool>(false));
    CHECK(verifyWith(k.km, "K_VCU_GW", keyOf(1), data) == std::optional<bool>(true));
    CHECK(k.km.events().back().kind == KeyEvent::Kind::PreviousKeyExpired);
    CHECK(verifyWith(k.km, "K_NONE", keyOf(1), data) == std::nullopt);
}

TEST_CASE("keym: pending keys can be discarded") {
    Keys k;
    REQUIRE(k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 2), k.now).error == she::ErrorCode::NoError);
    REQUIRE(k.km.loadKey(k.update(ks::kGwChs, keyOf(2), 2), k.now).error == she::ErrorCode::NoError);
    CHECK(k.km.hasPending());
    CHECK_EQ(k.km.discardPending(k.now), 2u);
    CHECK(!k.km.hasPending());
    CHECK_EQ(k.km.activatePending(k.now), 0u);
    CHECK_EQ(k.status(ks::kVcuGw).counter, 1u);
}

TEST_CASE("keym: snapshot and restore keep keys, generations and the remaining grace period") {
    Keys k;
    REQUIRE(k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 2), k.now).error == she::ErrorCode::NoError);
    k.km.activatePending(k.now);
    REQUIRE(k.km.loadKey(k.update(ks::kGwChs, keyOf(2), 3), k.now).error == she::ErrorCode::NoError);
    const auto snap = k.km.snapshot(k.now + 4min);

    KeyManager restored(k.cfg);
    const TimePoint later = TimePoint{} + 5000s;
    restored.restore(snap, later);
    CHECK_EQ(restored.status().size(), k.km.status().size());
    for (const auto& s : k.km.status()) {
        bool found = false;
        for (const auto& r : restored.status()) {
            if (r.slot != s.slot) continue;
            found = true;
            CHECK(r.active == s.active && r.pending == s.pending && r.previous == s.previous);
            CHECK_EQ(r.counter, s.counter);
            CHECK_EQ(r.pendingCounter, s.pendingCounter);
            CHECK(r.flags == s.flags);
        }
        CHECK(found);
    }
    const Bytes data = {1};
    CHECK(verifyWith(restored, "K_VCU_GW", config::demoKey(3), data) == std::optional<bool>(true));
    restored.mainFunction(later + 6min - 1ms);
    CHECK(verifyWith(restored, "K_VCU_GW", config::demoKey(3), data) == std::optional<bool>(true));
    restored.mainFunction(later + 6min);
    CHECK(verifyWith(restored, "K_VCU_GW", config::demoKey(3), data) == std::optional<bool>(false));
    // anti-rollback survives the restart
    CHECK(restored.loadKey(k.update(ks::kVcuGw, keyOf(5), 2), later).error == she::ErrorCode::KeyUpdateError);
}

// ---------------------------------------------------------------- SecOC integration

TEST_CASE("keym: SecOC verification during a key rollover") {
    Keys k;
    secoc::SecOcConfig sc;
    sc.dataId = 0x0130;
    sc.keyId = "K_VCU_GW";
    sc.freshnessBits = 32;
    sc.freshnessTxBits = 8;
    sc.macTxBits = 24;

    // VCU side: plain software crypto, old key
    secoc::SoftwareCryptoService vcuCrypto;
    vcuCrypto.setKey("K_VCU_GW", config::demoKey(3));
    secoc::FreshnessManager vcuFv;
    secoc::SecOcProcessor vcu(vcuCrypto, vcuFv);
    secoc::FreshnessManager gwFv;
    secoc::SecOcProcessor gw(k.km, gwFv);
    const Bytes pdu = {1, 2, 3, 4, 5, 6, 7, 8};

    auto roundTrip = [&] {
        const auto secured = vcu.protect(sc, pdu.data(), pdu.size());
        return gw.verify(sc, secured->data(), pdu.size());
    };
    CHECK(roundTrip() == secoc::VerifyResult::Ok);
    REQUIRE(k.km.loadKey(k.update(ks::kVcuGw, keyOf(1), 2), k.now).error == she::ErrorCode::NoError);
    k.km.activatePending(k.now);
    CHECK(roundTrip() == secoc::VerifyResult::Ok);  // previous key, grace period
    vcuCrypto.setKey("K_VCU_GW", keyOf(1));         // VCU switches
    CHECK(roundTrip() == secoc::VerifyResult::Ok);
    vcuCrypto.setKey("K_VCU_GW", config::demoKey(3));
    k.km.mainFunction(k.now + 10min);
    CHECK(roundTrip() == secoc::VerifyResult::MacFailure);  // old key no longer accepted
}

TEST_CASE("keym: Ethernet gateway with the key manager as crypto service") {
    Keys k;
    struct Tx final : ethgw::IGatewayTransmitter {
        std::vector<std::pair<std::size_t, can::CanFrame>> can;
        bool transmitCan(std::size_t ch, const can::CanFrame& f) override {
            can.emplace_back(ch, f);
            return true;
        }
        bool transmitEthernet(std::size_t, const std::vector<std::uint8_t>&) override { return true; }
    } tx;
    ethgw::EthernetGateway gw(config::makeVehicleEthGatewayMatrix(), tx, &k.km);
    ethgw::TimePoint now = ethgw::TimePoint{} + 1s;
    gw.start(now);
    gw.mainFunction(now);

    // FV slave on CHS_CAN with the current FV master key accepts the sync message.
    auto lastSync = [&]() -> std::optional<can::CanFrame> {
        for (auto it = tx.can.rbegin(); it != tx.can.rend(); ++it) {
            if (it->first == config::gw::kChsCan && it->second.id == config::gw::kFvSyncCan) return it->second;
        }
        return std::nullopt;
    };
    const auto sync = lastSync();
    REQUIRE(sync.has_value());
    const auto& cfg = gw.config();
    secoc::SoftwareCryptoService epsCrypto;
    epsCrypto.setKey("K_FV_MASTER", config::demoKey(5));
    secoc::FreshnessManager epsFv;
    epsFv.setLayout(cfg.freshnessSync->layout);
    secoc::FreshnessSyncSlave eps(cfg.freshnessSync->message, epsCrypto, epsFv);
    CHECK(eps.onSyncMessage(sync->data.data(), sync->length) == secoc::SyncResult::Accepted);

    // New FV master key activated: the next sync message uses it.
    REQUIRE(k.km.loadKey(k.update(ks::kFvMaster, keyOf(4), 2), k.now).error == she::ErrorCode::NoError);
    k.km.activatePending(k.now);
    tx.can.clear();
    for (int i = 0; i < 1100; ++i) {
        now += 1ms;
        gw.mainFunction(now);
    }
    const auto next = lastSync();
    REQUIRE(next.has_value());
    CHECK(eps.onSyncMessage(next->data.data(), next->length) == secoc::SyncResult::MacFailure);
    epsCrypto.setKey("K_FV_MASTER", keyOf(4));
    CHECK(eps.onSyncMessage(next->data.data(), next->length) == secoc::SyncResult::Accepted);
}

// ---------------------------------------------------------------- UDS

namespace {

struct DiagTx final : diag::IDiagTransport {
    std::vector<Bytes> tcp;
    void sendTcp(diag::ConnectionId, const Bytes& d) override { tcp.push_back(d); }
    void closeTcp(diag::ConnectionId) override {}
    void sendUdp(const diag::UdpPeer&, const Bytes&) override {}
    void broadcastUdp(const Bytes&) override {}
    bool transmitCan(std::size_t, const can::CanFrame&) override { return true; }
};

struct UdsFixture {
    Keys k;
    DiagTx tx;
    diag::DiagGateway gw{config::makeVehicleDiagRouting(), tx};
    KeyManagementService service{k.km};
    diag::TimePoint now = diag::TimePoint{} + 100s;

    UdsFixture() {
        gw.addLocalService(service);
        gw.start(now);
        gw.onTcpConnected(1, now);
        send(doip::payload::kRoutingActivationRequest, {0x0E, 0x80, 0x00, 0, 0, 0, 0});
    }
    void send(std::uint16_t type, const Bytes& payload) {
        const auto b = doip::encode(doip::kVersion2012, type, payload);
        gw.onTcpData(1, b.data(), b.size(), now);
    }
    // UDS response of the gateway (nullopt if none).
    std::optional<Bytes> request(const Bytes& uds, std::uint16_t target = config::dg::kGateway) {
        tx.tcp.clear();
        send(doip::payload::kDiagnosticMessage, doip::diagnosticMessagePayload(config::dg::kTester, target, uds));
        for (const auto& m : tx.tcp) {
            const auto h = doip::decodeHeader(m.data());
            if (h.type == doip::payload::kDiagnosticMessage) return Bytes(m.begin() + doip::kHeaderSize + 4, m.end());
        }
        return std::nullopt;
    }
    static Bytes loadKey(const she::UpdateRequest& r) {
        Bytes b = {0x31, 0x01, 0xF2, 0x00};
        b.insert(b.end(), r.m1.begin(), r.m1.end());
        b.insert(b.end(), r.m2.begin(), r.m2.end());
        b.insert(b.end(), r.m3.begin(), r.m3.end());
        return b;
    }
};

}  // namespace

TEST_CASE("keym uds: key update over DoIP needs the extended session") {
    UdsFixture f;
    const auto req = UdsFixture::loadKey(f.k.update(ks::kVcuGw, keyOf(1), 2));
    CHECK(f.request(req) == (Bytes{0x7F, 0x31, 0x7F}));
    CHECK(f.request({0x10, 0x03}).has_value());
    const auto rsp = f.request(req);
    REQUIRE(rsp.has_value());
    REQUIRE(rsp->size() == 5 + 48);
    CHECK(Bytes(rsp->begin(), rsp->begin() + 5) == (Bytes{0x71, 0x01, 0xF2, 0x00, 0x00}));
    const auto proof = she::buildProof(f.k.cfg.uid, ks::kVcuGw, she::kMasterEcuKey, keyOf(1), 2);
    CHECK(Bytes(rsp->begin() + 5, rsp->begin() + 37) == Bytes(proof.m4.begin(), proof.m4.end()));
    CHECK(Bytes(rsp->begin() + 37, rsp->end()) == Bytes(proof.m5.begin(), proof.m5.end()));
}

TEST_CASE("keym uds: SHE error codes, activation and key status") {
    UdsFixture f;
    f.request({0x10, 0x03});
    // replayed container (counter 1 = current generation)
    CHECK(f.request(UdsFixture::loadKey(f.k.update(ks::kVcuGw, keyOf(1), 1))) ==
          (Bytes{0x71, 0x01, 0xF2, 0x00, 0x07}));
    CHECK(f.request({0x31, 0x01, 0xF2, 0x01}) == (Bytes{0x7F, 0x31, 0x24}));  // nothing pending
    f.request(UdsFixture::loadKey(f.k.update(ks::kVcuGw, keyOf(1), 2)));

    auto status = f.request({0x22, 0xF2, 0xA0});
    REQUIRE(status.has_value());
    REQUIRE(status->size() == 4 + 7 * 10);
    CHECK_EQ((*status)[3], 7);
    const std::size_t vcu = 4 + 3 * 10;  // MASTER, KEY_1, KEY_2, KEY_3
    CHECK_EQ((*status)[vcu], ks::kVcuGw);
    CHECK_EQ((*status)[vcu + 1], uds::kStatusActive | uds::kStatusPending | uds::kStatusMacKey);
    CHECK_EQ((*status)[vcu + 5], 1);  // active counter
    CHECK_EQ((*status)[vcu + 9], 2);  // pending counter

    CHECK(f.request({0x31, 0x01, 0xF2, 0x01}) == (Bytes{0x71, 0x01, 0xF2, 0x01, 0x01}));
    status = f.request({0x22, 0xF2, 0xA0});
    CHECK_EQ((*status)[vcu + 1], uds::kStatusActive | uds::kStatusPrevious | uds::kStatusMacKey);
    CHECK_EQ((*status)[vcu + 5], 2);
}

TEST_CASE("keym uds: malformed requests and lockout") {
    UdsFixture f;
    f.request({0x10, 0x03});
    CHECK(f.request({0x31, 0x01, 0xF2, 0x00, 0x01}) == (Bytes{0x7F, 0x31, 0x13}));
    CHECK(f.request({0x31, 0x02, 0xF2, 0x00}) == (Bytes{0x7F, 0x31, 0x12}));
    CHECK(f.request({0x31, 0x01, 0xF2, 0x99}) == (Bytes{0x7F, 0x31, 0x31}));
    const auto bad = UdsFixture::loadKey(f.k.update(ks::kVcuGw, keyOf(1), 2, macFlags(), she::kMasterEcuKey, keyOf(9)));
    for (int i = 0; i < 3; ++i) CHECK(f.request(bad) == (Bytes{0x71, 0x01, 0xF2, 0x00, 0x07}));
    CHECK(f.request(bad) == (Bytes{0x7F, 0x31, 0x37}));
    // functional requests never update keys and stay silent
    CHECK(!f.request({0x31, 0x01, 0xF2, 0x01}, config::dg::kFunctional).has_value());
    // other local services still work
    CHECK(f.request({0x22, 0xF1, 0x86}) == (Bytes{0x62, 0xF1, 0x86, 0x03}));
}

TEST_CASE("keym uds: the key store is persisted before M4/M5 are returned") {
    Keys k;
    DiagTx tx;
    diag::DiagGateway gw(config::makeVehicleDiagRouting(), tx);
    int saves = 0;
    bool storageOk = false;
    KeyManagementService service(k.km, [&] {
        ++saves;
        return storageOk;
    });
    gw.addLocalService(service);
    diag::LocalRequestContext ctx{0x03, false, k.now};
    const auto req = UdsFixture::loadKey(k.update(ks::kVcuGw, keyOf(1), 2));
    CHECK(service.handle(req, ctx) == std::optional<Bytes>(Bytes{0x7F, 0x31, 0x72}));
    storageOk = true;
    const auto retry = UdsFixture::loadKey(k.update(ks::kVcuGw, keyOf(1), 3));
    const auto rsp = service.handle(retry, ctx);
    REQUIRE(rsp.has_value());
    CHECK_EQ((*rsp)[4], 0x00);
    CHECK(service.handle({0x31, 0x01, 0xF2, 0x01}, ctx) == std::optional<Bytes>(Bytes{0x71, 0x01, 0xF2, 0x01, 0x01}));
    CHECK_EQ(saves, 3);
    // rejected updates change nothing and are not persisted
    service.handle(retry, ctx);
    CHECK_EQ(saves, 3);
}
