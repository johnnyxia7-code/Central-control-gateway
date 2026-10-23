#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/doip/doip_message.hpp"
#include "ccg/keym/key_management_service.hpp"
#include "ccg/keym/key_master.hpp"
#include "ecu_key_store.hpp"
#include "test_framework.hpp"
#include "uds_ecu.hpp"
#include "vehicle_diag_routing.hpp"
#include "vehicle_eth_gateway_matrix.hpp"
#include "vehicle_key_master.hpp"
#include "vehicle_key_slots.hpp"

using namespace ccg;
using namespace std::chrono_literals;
using Bytes = std::vector<std::uint8_t>;
namespace dg = config::dg;
namespace ks = config::keyslot;
using GroupResult = keym::KeyMaster::GroupResult;

namespace {

struct Bus final : diag::IDiagTransport {
    std::deque<std::pair<std::size_t, can::CanFrame>> canOut;
    std::vector<Bytes> tcp;
    void sendTcp(diag::ConnectionId, const Bytes& d) override { tcp.push_back(d); }
    void closeTcp(diag::ConnectionId) override {}
    void sendUdp(const diag::UdpPeer&, const Bytes&) override {}
    void broadcastUdp(const Bytes&) override {}
    bool transmitCan(std::size_t ch, const can::CanFrame& f) override {
        canOut.emplace_back(ch, f);
        return true;
    }
};

// Gateway (diagnostic routing + HSM + key master) and the ECUs on CAN.
struct Vehicle {
    using Provision = std::function<void(std::uint16_t, keym::KeyManager&)>;

    diag::TimePoint now = diag::TimePoint{} + 100s;
    Bus bus;
    diag::DiagGateway gw{config::makeVehicleDiagRouting(), bus};
    keym::KeyManager gatewayKeys{config::makeVehicleKeySlots()};
    keym::DeterministicRandom random{config::demoKey(0x77)};
    keym::KeyMaster master{config::makeVehicleKeyMaster(), gatewayKeys, gw, random};
    keym::KeyManagementService keyService{gatewayKeys};

    struct EcuOnBus {
        std::size_t channel;
        std::unique_ptr<sim::UdsEcu> ecu;
        std::unique_ptr<sim::EcuKeyStore> hsm;
    };
    std::map<std::uint16_t, EcuOnBus> ecus;
    std::deque<std::pair<std::size_t, can::CanFrame>> ecuOut;
    std::vector<std::string> trace;

    explicit Vehicle(const Provision& provision = {}) {
        config::provisionDemoKeyStore(gatewayKeys, now);
        gw.addLocalService(keyService);
        gw.addLocalService(master);
        master.setTrace([this](const std::string& t) { trace.push_back(t); });
        const auto cfg = gw.config();
        for (const auto& route : cfg.ecus) {
            sim::UdsEcu::Config ec;
            ec.name = route.name;
            ec.requestId = route.requestId;
            ec.responseId = route.responseId;
            ec.fd = route.fd;
            const std::size_t channel = *gw.channelIndex(route.channel);
            EcuOnBus e{channel,
                       std::make_unique<sim::UdsEcu>(ec,
                                                     [this, channel](const can::CanFrame& f) {
                                                         ecuOut.emplace_back(channel, f);
                                                         return true;
                                                     }),
                       nullptr};
            const auto keyEcus = config::keyMasterEcus();
            if (std::find(keyEcus.begin(), keyEcus.end(), route.logicalAddress) != keyEcus.end()) {
                e.hsm = std::make_unique<sim::EcuKeyStore>(config::makeEcuKeySlots(route.logicalAddress));
                if (provision) {
                    provision(route.logicalAddress, e.hsm->keys());
                } else {
                    config::provisionDemoEcuKeyStore(e.hsm->keys(), now);
                }
                e.hsm->attach(*e.ecu);
            }
            ecus.emplace(route.logicalAddress, std::move(e));
        }
        gw.start(now);
    }

    keym::KeyManager& ecuKeys(std::uint16_t ecu) { return ecus.at(ecu).hsm->keys(); }

    void deliver() {
        for (int guard = 0; guard < 100000 && (!bus.canOut.empty() || !ecuOut.empty()); ++guard) {
            while (!bus.canOut.empty()) {
                const auto [ch, f] = bus.canOut.front();
                bus.canOut.pop_front();
                for (auto& [addr, e] : ecus) {
                    if (e.channel == ch) e.ecu->onFrame(f, now);
                }
            }
            while (!ecuOut.empty()) {
                const auto [ch, f] = ecuOut.front();
                ecuOut.pop_front();
                gw.onCanFrame(ch, f, now);
            }
        }
    }

    void tick() {
        now += 1ms;
        gw.mainFunction(now);
        for (auto& [addr, e] : ecus) e.ecu->mainFunction(now);
        deliver();
        master.mainFunction(now);
        gatewayKeys.mainFunction(now);
        deliver();
    }

    void advance(std::chrono::milliseconds d) {
        for (auto t = 0ms; t < d; t += 1ms) tick();
    }

    bool runCampaign(const std::vector<std::size_t>& groups = {}) {
        if (!master.start(now, groups)) return false;
        for (int i = 0; i < 20000 && master.state() == keym::KeyMaster::State::Running; ++i) tick();
        return master.state() == keym::KeyMaster::State::Finished;
    }

    static keym::KeyManager::SlotStatus status(const keym::KeyManager& keys, std::uint8_t slot) {
        for (const auto& s : keys.status()) {
            if (s.slot == slot) return s;
        }
        return {};
    }
};

std::optional<crypto::Block> mac(keym::KeyManager& keys, const std::string& keyId) {
    const Bytes data = {0xC0, 0xFF, 0xEE};
    crypto::Block m;
    if (!keys.generateMac(keyId, data.data(), data.size(), m)) return std::nullopt;
    return m;
}

constexpr std::uint8_t kKey1 = keym::she::kKey1;
constexpr std::uint8_t kKey2 = keym::she::kKey1 + 1;

}  // namespace

// ---------------------------------------------------------------- configuration

TEST_CASE("key master config: reference groups are valid") {
    CHECK(keym::validateKeyMasterConfig(config::makeVehicleKeyMaster(), config::makeVehicleKeySlots()).empty());
}

TEST_CASE("key master config: inconsistent groups are rejected") {
    auto c = config::makeVehicleKeyMaster();
    auto slots = config::makeVehicleKeySlots();
    c.flags.keyUsage = false;
    c.groups[0].gatewaySlot = ks::kGwChs;          // holds K_GW_CHS, also used by group 1
    c.groups[2].ecus.push_back({dg::kVcu, kKey1});  // VCU KEY_1 already in group 0
    c.groups.push_back({"K_EMPTY", 0, {}});
    c.groups.push_back({"K_X", 0, {{dg::kBcm, 0x1}}});  // MASTER_ECU_KEY is no SecOC slot
    const auto errors = keym::validateKeyMasterConfig(c, slots);
    CHECK_EQ(errors.size(), 6u);
    slots.keyMasterSlot = 0;
    CHECK_EQ(keym::validateKeyMasterConfig(config::makeVehicleKeyMaster(), slots).size(), 1u);
}

// ---------------------------------------------------------------- internal client

TEST_CASE("diag client: internal requests, response pending, busy, timeout") {
    Vehicle v;
    std::vector<std::pair<diag::ClientResult, Bytes>> results;
    auto collect = [&](diag::ClientResult r, Bytes d) { results.emplace_back(r, std::move(d)); };

    v.gw.request(0x0999, {0x10, 0x03}, v.now, collect);
    REQUIRE(results.size() == 1u);
    CHECK(results[0].first == diag::ClientResult::UnknownTarget);

    // BCM answers RoutineControl with 0x78 first: the client waits for the final answer.
    v.gw.request(dg::kBcm, {0x31, 0x01, 0xFF, 0x00}, v.now, collect);
    v.gw.request(dg::kBcm, {0x3E, 0x00}, v.now, collect);  // second request while one is open
    REQUIRE(results.size() == 2u);
    CHECK(results[1].first == diag::ClientResult::Busy);
    v.advance(1500ms);
    REQUIRE(results.size() == 3u);
    CHECK(results[2].first == diag::ClientResult::Ok);
    CHECK_EQ(results[2].second.at(0), 0x71);

    // Unpowered ECU: single frame goes out, no answer within P2.
    v.ecus.at(dg::kEps).ecu->setSilent(true);
    v.gw.request(dg::kEps, {0x10, 0x03}, v.now, collect);
    v.advance(999ms);
    CHECK_EQ(results.size(), 3u);
    v.advance(2ms);
    REQUIRE(results.size() == 4u);
    CHECK(results[3].first == diag::ClientResult::Timeout);

    // Multi-frame request to the unpowered ECU: no flow control -> transport error.
    v.gw.request(dg::kEps, Bytes(40, 0x22), v.now, collect);
    v.advance(1100ms);
    REQUIRE(results.size() == 5u);
    CHECK(results[4].first == diag::ClientResult::TransportError);
}

TEST_CASE("diag client: tester requests to an ECU in use by the gateway are refused") {
    Vehicle v;
    v.gw.onTcpConnected(1, v.now);
    auto send = [&](std::uint16_t type, const Bytes& payload) {
        const auto b = doip::encode(doip::kVersion2012, type, payload);
        v.gw.onTcpData(1, b.data(), b.size(), v.now);
    };
    send(doip::payload::kRoutingActivationRequest, {0x0E, 0x80, 0x00, 0, 0, 0, 0});
    bool done = false;
    v.gw.request(dg::kBcm, {0x31, 0x01, 0xFF, 0x00}, v.now, [&](diag::ClientResult, Bytes) { done = true; });
    v.bus.tcp.clear();
    send(doip::payload::kDiagnosticMessage, doip::diagnosticMessagePayload(dg::kTester, dg::kBcm, {0x3E, 0x00}));
    REQUIRE(!v.bus.tcp.empty());
    const auto h = doip::decodeHeader(v.bus.tcp.back().data());
    CHECK_EQ(h.type, doip::payload::kDiagnosticNack);
    v.advance(1500ms);
    CHECK(done);
}

// ---------------------------------------------------------------- campaigns

TEST_CASE("key master: campaign distributes and activates every key group") {
    Vehicle v;
    const auto oldVcuMac = mac(v.ecuKeys(dg::kVcu), "K_VCU_GW");
    REQUIRE(v.runCampaign());
    for (std::size_t g = 0; g < 3; ++g) {
        CHECK(v.master.results()[g].result == GroupResult::Activated);
        CHECK_EQ(v.master.results()[g].generation, 2u);
    }
    // Every member holds the same new key; it differs from the old one.
    const auto gwVcu = mac(v.gatewayKeys, "K_VCU_GW");
    CHECK(gwVcu == mac(v.ecuKeys(dg::kVcu), "K_VCU_GW"));
    CHECK(gwVcu != oldVcuMac);
    CHECK(mac(v.gatewayKeys, "K_GW_CHS") == mac(v.ecuKeys(dg::kEps), "K_GW_CHS"));
    const auto fv = mac(v.gatewayKeys, "K_FV_MASTER");
    CHECK(fv == mac(v.ecuKeys(dg::kVcu), "K_FV_MASTER"));
    CHECK(fv == mac(v.ecuKeys(dg::kEps), "K_FV_MASTER"));
    CHECK(fv == mac(v.ecuKeys(dg::kBcm), "K_FV_MASTER"));
    // All keys active, previous keys in their grace period, nothing pending.
    const auto vcu = Vehicle::status(v.ecuKeys(dg::kVcu), kKey1);
    CHECK(vcu.active && !vcu.pending && vcu.previous);
    CHECK_EQ(vcu.counter, 2u);
    const auto gw = Vehicle::status(v.gatewayKeys, ks::kFvMaster);
    CHECK(gw.active && !gw.pending && gw.previous);
    CHECK_EQ(gw.counter, 2u);
    // The other keys of the gateway are untouched.
    CHECK_EQ(Vehicle::status(v.gatewayKeys, ks::kAdasGw).counter, 1u);

    // Next campaign: next generation, different keys again.
    REQUIRE(v.runCampaign({0}));
    CHECK_EQ(v.master.results()[0].generation, 3u);
    CHECK(v.master.results()[0].result == GroupResult::Activated);
    CHECK(v.master.results()[1].result == GroupResult::NotRun);
    CHECK(mac(v.gatewayKeys, "K_VCU_GW") == mac(v.ecuKeys(dg::kVcu), "K_VCU_GW"));
    CHECK(mac(v.gatewayKeys, "K_VCU_GW") != gwVcu);
}

TEST_CASE("key master: an unpowered ECU fails its groups, they are discarded everywhere") {
    Vehicle v;
    v.ecus.at(dg::kEps).ecu->setSilent(true);
    REQUIRE(v.runCampaign());
    const auto& r = v.master.results();
    CHECK(r[0].result == GroupResult::Activated);
    CHECK(r[1].result == GroupResult::EcuUnreachable);
    CHECK(r[2].result == GroupResult::EcuUnreachable);
    CHECK_EQ(r[2].failedEcu, dg::kEps);
    // FV master key: loaded into VCU and BCM, then discarded; gateway keeps generation 1.
    for (const auto ecu : {dg::kVcu, dg::kBcm}) {
        const auto st = Vehicle::status(v.ecuKeys(ecu), ecu == dg::kVcu ? kKey2 : kKey1);
        CHECK(st.active && !st.pending);
        CHECK_EQ(st.counter, 1u);
    }
    const auto gwFv = Vehicle::status(v.gatewayKeys, ks::kFvMaster);
    CHECK(!gwFv.pending);
    CHECK_EQ(gwFv.counter, 1u);
    CHECK(mac(v.gatewayKeys, "K_FV_MASTER") == mac(v.ecuKeys(dg::kBcm), "K_FV_MASTER"));
    CHECK(mac(v.gatewayKeys, "K_VCU_GW") == mac(v.ecuKeys(dg::kVcu), "K_VCU_GW"));

    // EPS powered: the failed groups are renewed.
    v.ecus.at(dg::kEps).ecu->setSilent(false);
    REQUIRE(v.runCampaign({1, 2}));
    CHECK(r[1].result == GroupResult::Activated);
    CHECK(r[2].result == GroupResult::Activated);
    CHECK(mac(v.gatewayKeys, "K_GW_CHS") == mac(v.ecuKeys(dg::kEps), "K_GW_CHS"));
    CHECK(mac(v.gatewayKeys, "K_FV_MASTER") == mac(v.ecuKeys(dg::kEps), "K_FV_MASTER"));
}

TEST_CASE("key master: an ECU with another MASTER_ECU_KEY rejects the container") {
    Vehicle v([](std::uint16_t ecu, keym::KeyManager& keys) {
        if (ecu != dg::kBcm) {
            config::provisionDemoEcuKeyStore(keys, keym::TimePoint{});
            return;
        }
        keym::she::Flags f;
        f.keyUsage = true;
        keys.provision(keym::she::kMasterEcuKey, config::demoKey(0x11), 1, keym::she::Flags{}, keym::TimePoint{});
        keys.provision(kKey1, config::demoKey(5), 1, f, keym::TimePoint{});
    });
    REQUIRE(v.runCampaign());
    const auto& r = v.master.results();
    CHECK(r[0].result == GroupResult::Activated);
    CHECK(r[1].result == GroupResult::Activated);
    CHECK(r[2].result == GroupResult::KeyRejected);
    CHECK(r[2].error == keym::she::ErrorCode::KeyUpdateError);
    CHECK_EQ(r[2].failedEcu, dg::kBcm);
    CHECK(!Vehicle::status(v.ecuKeys(dg::kEps), kKey2).pending);
    CHECK_EQ(Vehicle::status(v.ecuKeys(dg::kEps), kKey2).counter, 1u);
}

TEST_CASE("key master: an ECU that does not store the key fails the M4/M5 check") {
    Vehicle v;
    v.ecus.at(dg::kEps).hsm->setTamperProof(true);
    REQUIRE(v.runCampaign());
    const auto& r = v.master.results();
    CHECK(r[0].result == GroupResult::Activated);
    CHECK(r[1].result == GroupResult::ProofMismatch);
    CHECK(r[2].result == GroupResult::ProofMismatch);
    CHECK_EQ(Vehicle::status(v.gatewayKeys, ks::kGwChs).counter, 1u);
}

TEST_CASE("key master: the generation follows the newest member key") {
    Vehicle v([](std::uint16_t ecu, keym::KeyManager& keys) {
        if (ecu != dg::kVcu) {
            config::provisionDemoEcuKeyStore(keys, keym::TimePoint{});
            return;
        }
        keym::she::Flags f;
        f.keyUsage = true;
        keys.provision(keym::she::kMasterEcuKey,
                       keym::deriveEcuMasterKey(config::demoKeyMasterSecret(), keys.config().uid), 1,
                       keym::she::Flags{}, keym::TimePoint{});
        keys.provision(kKey1, config::demoKey(3), 41, f, keym::TimePoint{});  // renewed by the backend before
        keys.provision(kKey2, config::demoKey(5), 1, f, keym::TimePoint{});
    });
    REQUIRE(v.runCampaign({0}));
    CHECK(v.master.results()[0].result == GroupResult::Activated);
    CHECK_EQ(v.master.results()[0].generation, 42u);
    CHECK_EQ(Vehicle::status(v.gatewayKeys, ks::kVcuGw).counter, 42u);
}

TEST_CASE("key master: campaign over UDS on the gateway address") {
    Vehicle v;
    v.gw.onTcpConnected(1, v.now);
    auto request = [&](const Bytes& uds) -> Bytes {
        v.bus.tcp.clear();
        auto b = doip::encode(doip::kVersion2012, doip::payload::kDiagnosticMessage,
                              doip::diagnosticMessagePayload(dg::kTester, dg::kGateway, uds));
        v.gw.onTcpData(1, b.data(), b.size(), v.now);
        for (const auto& m : v.bus.tcp) {
            if (doip::decodeHeader(m.data()).type == doip::payload::kDiagnosticMessage) {
                return Bytes(m.begin() + doip::kHeaderSize + 4, m.end());
            }
        }
        return {};
    };
    const auto b = doip::encode(doip::kVersion2012, doip::payload::kRoutingActivationRequest,
                                {0x0E, 0x80, 0x00, 0, 0, 0, 0});
    v.gw.onTcpData(1, b.data(), b.size(), v.now);

    CHECK(request({0x31, 0x01, 0xF2, 0x10}) == (Bytes{0x7F, 0x31, 0x7F}));
    request({0x10, 0x03});
    CHECK(request({0x31, 0x01, 0xF2, 0x10, 0x07}) == (Bytes{0x7F, 0x31, 0x31}));  // no group 7
    CHECK(request({0x31, 0x01, 0xF2, 0x10, 0x00, 0x02}) == (Bytes{0x71, 0x01, 0xF2, 0x10, 0x00}));
    CHECK(request({0x31, 0x01, 0xF2, 0x10}) == (Bytes{0x7F, 0x31, 0x22}));  // already running
    v.advance(10ms);
    auto results = request({0x31, 0x03, 0xF2, 0x10});
    REQUIRE(results.size() == 6u + 3u * 8u);
    CHECK_EQ(results[4], static_cast<std::uint8_t>(keym::KeyMaster::State::Running));
    for (int i = 0; i < 20000 && v.master.state() == keym::KeyMaster::State::Running; ++i) v.tick();
    results = request({0x31, 0x03, 0xF2, 0x10});
    REQUIRE(results.size() == 6u + 3u * 8u);
    CHECK_EQ(results[4], static_cast<std::uint8_t>(keym::KeyMaster::State::Finished));
    CHECK_EQ(results[5], 3);
    CHECK_EQ(results[6], static_cast<std::uint8_t>(GroupResult::Activated));       // group 0
    CHECK_EQ(results[10], 2);                                                       // generation
    CHECK_EQ(results[14], static_cast<std::uint8_t>(GroupResult::NotRun));          // group 1
    CHECK_EQ(results[22], static_cast<std::uint8_t>(GroupResult::Activated));       // group 2
    CHECK(request({0x31, 0x02, 0xF2, 0x10}) == (Bytes{0x7F, 0x31, 0x12}));
}

TEST_CASE("key master: no campaign without the key master secret") {
    Vehicle v;
    keym::KeyManager empty(config::makeVehicleKeySlots());
    keym::KeyMaster master(config::makeVehicleKeyMaster(), empty, v.gw, v.random);
    CHECK(!master.start(v.now));
    CHECK(!v.gatewayKeys.hasKey("K_KEY_MASTER"));  // the secret is never a SecOC key
    CHECK(v.gatewayKeys.deriveEcuMasterKey(v.ecuKeys(dg::kVcu).config().uid) ==
          keym::deriveEcuMasterKey(config::demoKeyMasterSecret(), v.ecuKeys(dg::kVcu).config().uid));
}
