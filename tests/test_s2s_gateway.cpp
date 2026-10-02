#include <map>
#include <string>
#include <utility>
#include <vector>

#include "ccg/can/signal_codec.hpp"
#include "ccg/e2e/can_e2e.hpp"
#include "ccg/s2s/s2s_gateway.hpp"
#include "test_framework.hpp"
#include "vehicle_s2s_matrix.hpp"

using namespace ccg;
using namespace ccg::s2s;
using namespace std::chrono_literals;
namespace ids = ccg::config::ids;

namespace {

struct MockCan final : ICanTransmitter {
    std::vector<can::CanFrame> frames;
    bool accept = true;
    bool transmit(const can::CanFrame& f) override {
        frames.push_back(f);
        return accept;
    }
    std::vector<can::CanFrame> withId(std::uint32_t id) const {
        std::vector<can::CanFrame> out;
        for (const auto& f : frames) {
            if (f.id == id) out.push_back(f);
        }
        return out;
    }
};

struct Notification {
    std::uint16_t service;
    std::uint16_t instance;
    std::uint16_t eventgroup;
    someip::Message message;
};

struct MockSomeIp final : ISomeIpBinding {
    std::vector<ServiceInstance> offered;
    std::vector<Notification> notifications;
    std::vector<std::pair<Peer, someip::Message>> unicast;

    void offerService(const ServiceInstance& s) override { offered.push_back(s); }
    void notify(std::uint16_t svc, std::uint16_t inst, std::uint16_t eg,
                const someip::Message& m) override {
        notifications.push_back({svc, inst, eg, m});
    }
    void sendTo(const Peer& p, const someip::Message& m) override { unicast.emplace_back(p, m); }

    std::vector<someip::Message> events(std::uint16_t svc, std::uint16_t eventId) const {
        std::vector<someip::Message> out;
        for (const auto& n : notifications) {
            if (n.service == svc && n.message.header.methodId == eventId) out.push_back(n.message);
        }
        return out;
    }
};

struct Element {
    double value;
    SignalStatus status;
};

// Decodes an event payload according to the matrix (value + status per element).
std::vector<Element> decode(const GatewayConfig& cfg, std::uint16_t svc, std::uint16_t eventId,
                            const std::vector<std::uint8_t>& payload) {
    for (const auto& ev : cfg.events) {
        if (ev.serviceId != svc || ev.eventId != eventId) continue;
        someip::PayloadReader r(payload);
        std::vector<Element> out;
        for (const auto& el : ev.elements) {
            const auto v = readValue(r, el.type);
            std::uint8_t st = 0;
            if (ev.appendStatus) r.readU8(st);
            out.push_back({v.value_or(-9999.0), static_cast<SignalStatus>(st)});
        }
        CHECK_EQ(r.remaining(), 0U);
        return out;
    }
    return {};
}

struct Fixture {
    GatewayConfig cfg = config::makeVehicleS2SMatrix();
    MockCan can;
    MockSomeIp someip;
    S2SGateway gw{cfg, can, someip};
    TimePoint now = TimePoint{} + 10s;
    std::map<std::string, e2e::CanE2ESender> senders;
    RequestContext client{ids::kInstance, Peer{0xC0A80A0A7595ULL}};
    std::uint16_t session = 0;

    Fixture() { gw.start(now); }

    void advance(Milliseconds duration) {
        for (Milliseconds t{0}; t < duration; t += 5ms) {
            now += 5ms;
            gw.mainFunction(now);
        }
    }

    const CanRxMessage& rxMessage(const std::string& name) const {
        for (const auto& m : cfg.rxMessages) {
            if (m.name == name) return m;
        }
        throw std::invalid_argument(name);
    }

    can::CanFrame frame(const std::string& name,
                        const std::vector<std::pair<std::string, double>>& physical,
                        const std::vector<std::pair<std::string, std::uint64_t>>& raw = {},
                        bool corruptCrc = false) {
        const auto& m = rxMessage(name);
        can::CanFrame f;
        f.id = m.canId;
        f.length = m.length;
        for (const auto& s : m.signals) {
            for (const auto& [n, v] : physical) {
                if (n == s.name) can::insertRaw(f.data.data(), s, can::physicalToRaw(s, v));
            }
            for (const auto& [n, v] : raw) {
                if (n == s.name) can::insertRaw(f.data.data(), s, v);
            }
        }
        if (m.e2e) {
            auto it = senders.find(name);
            if (it == senders.end()) it = senders.emplace(name, e2e::CanE2ESender(*m.e2e)).first;
            it->second.protect(f.data.data(), f.length);
            if (corruptCrc) f.data[m.e2e->crcByte] ^= 0xFF;
        }
        return f;
    }

    void rx(const std::string& name, const std::vector<std::pair<std::string, double>>& physical,
            const std::vector<std::pair<std::string, std::uint64_t>>& raw = {},
            bool corruptCrc = false) {
        gw.onCanFrame(frame(name, physical, raw, corruptCrc), now);
    }

    someip::Message request(std::uint16_t svc, std::uint16_t method,
                            std::vector<std::uint8_t> payload = {},
                            someip::MessageType type = someip::MessageType::Request) {
        someip::Message m;
        m.header.serviceId = svc;
        m.header.methodId = method;
        m.header.clientId = 0x0101;
        m.header.sessionId = ++session;
        m.header.interfaceVersion = 1;
        m.header.messageType = type;
        m.payload = std::move(payload);
        return m;
    }

    void call(const someip::Message& m) { gw.onSomeIpRequest(m, client, now); }

    std::vector<Element> last(std::uint16_t svc, std::uint16_t eventId) const {
        const auto evs = someip.events(svc, eventId);
        REQUIRE(!evs.empty());
        return decode(cfg, svc, eventId, evs.back().payload);
    }

    const someip::Message& lastUnicast() const {
        REQUIRE(!someip.unicast.empty());
        return someip.unicast.back().second;
    }
};

}  // namespace

// ------------------------------------------------------------------ start-up

TEST_CASE("gateway: invalid configuration is refused") {
    auto cfg = config::makeVehicleS2SMatrix();
    cfg.events[0].elements[0].source.signal = "DoesNotExist";
    MockCan can;
    MockSomeIp someip;
    bool thrown = false;
    try {
        S2SGateway gw(cfg, can, someip);
    } catch (const ConfigError& e) {
        thrown = true;
        CHECK_EQ(e.errors().size(), 1U);
    }
    CHECK(thrown);
}

TEST_CASE("gateway: offers all service instances on start") {
    Fixture f;
    REQUIRE(f.someip.offered.size() == 4);
    CHECK_EQ(f.someip.offered[0].serviceId, ids::kVehicleMotionService);
    CHECK_EQ(f.someip.offered[3].serviceId, ids::kClimateService);
}

// ---------------------------------------------------------- signal -> service

TEST_CASE("gateway: cyclic event carries physical values and header fields") {
    Fixture f;
    f.rx("ESP_VehicleSpeed", {{"ESP_VehSpd", 123.45}, {"ESP_LongAccel", -2.5}, {"ESP_YawRate", 3.2}});
    CHECK(f.someip.events(ids::kVehicleMotionService, ids::kEvtVehicleDynamics).empty());
    f.advance(20ms);

    const auto evs = f.someip.events(ids::kVehicleMotionService, ids::kEvtVehicleDynamics);
    REQUIRE(evs.size() == 1);
    const auto& h = evs[0].header;
    CHECK(h.messageType == someip::MessageType::Notification);
    CHECK(h.returnCode == someip::ReturnCode::Ok);
    CHECK_EQ(h.interfaceVersion, 1);
    CHECK_EQ(h.clientId, 0);
    CHECK_EQ(h.sessionId, 1);
    CHECK_EQ(f.someip.notifications.back().eventgroup, ids::kEgDynamics);
    CHECK_EQ(evs[0].payload.size(), 15U);  // 3 x (float32 + status)

    const auto el = decode(f.cfg, ids::kVehicleMotionService, ids::kEvtVehicleDynamics,
                           evs[0].payload);
    CHECK_NEAR(el[0].value, 123.45, 1e-3);
    CHECK_NEAR(el[1].value, -2.5, 1e-6);
    CHECK_NEAR(el[2].value, 3.2, 1e-5);
    CHECK(el[0].status == SignalStatus::Valid);

    f.rx("ESP_VehicleSpeed", {{"ESP_VehSpd", 123.45}, {"ESP_LongAccel", -2.5}, {"ESP_YawRate", 3.2}});
    f.advance(20ms);
    const auto again = f.someip.events(ids::kVehicleMotionService, ids::kEvtVehicleDynamics);
    REQUIRE(again.size() == 2);  // cyclic: sent although unchanged
    CHECK_EQ(again[1].header.sessionId, 2);
}

TEST_CASE("gateway: cyclic event before first reception reports NOT_AVAILABLE") {
    Fixture f;
    f.advance(20ms);
    const auto el = f.last(ids::kVehicleMotionService, ids::kEvtVehicleDynamics);
    CHECK(el[0].status == SignalStatus::NotAvailable);
    CHECK_NEAR(el[0].value, 0.0, 1e-9);
}

TEST_CASE("gateway: on-change field only notifies on value change") {
    Fixture f;
    f.rx("BCM_DoorStatus", {{"BCM_DoorFLSts", 2}, {"BCM_CentralLockSts", 1}});
    REQUIRE(f.someip.events(ids::kBodyService, ids::kFldDoorStatus).size() == 1);
    auto el = f.last(ids::kBodyService, ids::kFldDoorStatus);
    CHECK_EQ(el[0].value, 2.0);
    CHECK_EQ(el[5].value, 1.0);

    f.advance(100ms);
    f.rx("BCM_DoorStatus", {{"BCM_DoorFLSts", 2}, {"BCM_CentralLockSts", 1}});
    CHECK_EQ(f.someip.events(ids::kBodyService, ids::kFldDoorStatus).size(), 1U);

    f.advance(100ms);
    f.rx("BCM_DoorStatus", {{"BCM_DoorFLSts", 0}, {"BCM_CentralLockSts", 1}});
    REQUIRE(f.someip.events(ids::kBodyService, ids::kFldDoorStatus).size() == 2);
    CHECK_EQ(f.last(ids::kBodyService, ids::kFldDoorStatus)[0].value, 0.0);
}

TEST_CASE("gateway: on-change debounce (minInterval) sends the latest value") {
    Fixture f;
    f.rx("EPS_SteeringAngle", {{"EPS_SteerWhlAng", 10.0}});
    REQUIRE(f.someip.events(ids::kVehicleMotionService, ids::kFldSteeringWheel).size() == 1);

    f.advance(5ms);
    f.rx("EPS_SteeringAngle", {{"EPS_SteerWhlAng", 11.0}});
    f.advance(5ms);
    f.rx("EPS_SteeringAngle", {{"EPS_SteerWhlAng", -12.3}});
    CHECK_EQ(f.someip.events(ids::kVehicleMotionService, ids::kFldSteeringWheel).size(), 1U);

    f.advance(10ms);  // 20 ms after the first notification
    const auto evs = f.someip.events(ids::kVehicleMotionService, ids::kFldSteeringWheel);
    REQUIRE(evs.size() == 2);
    const auto el = decode(f.cfg, ids::kVehicleMotionService, ids::kFldSteeringWheel,
                           evs.back().payload);
    CHECK_NEAR(el[0].value, -12.3, 1e-4);
}

TEST_CASE("gateway: Rx timeout reports TIMEOUT with substitution, recovery reports VALID") {
    Fixture f;
    f.rx("BMS_PackStatus", {{"BMS_SoC", 80.0}, {"BMS_PackVolt", 400.0}, {"BMS_PackCurr", -12.5}});
    auto el = f.last(ids::kEnergyService, ids::kFldBatteryStatus);
    CHECK_NEAR(el[0].value, 80.0, 1e-4);
    CHECK_NEAR(el[2].value, -12.5, 1e-4);

    f.advance(495ms);
    CHECK(f.gw.rxSignal("BMS_PackStatus", "BMS_SoC")->status == SignalStatus::Valid);
    f.advance(5ms);
    CHECK(f.gw.rxSignal("BMS_PackStatus", "BMS_SoC")->status == SignalStatus::Timeout);

    el = f.last(ids::kEnergyService, ids::kFldBatteryStatus);
    CHECK(el[0].status == SignalStatus::Timeout);
    CHECK_NEAR(el[0].value, 80.0, 1e-4);  // HoldLastValid
    CHECK(el[1].status == SignalStatus::Timeout);
    CHECK_NEAR(el[1].value, 0.0, 1e-9);   // InitValue

    f.rx("BMS_PackStatus", {{"BMS_SoC", 79.5}, {"BMS_PackVolt", 399.0}});
    f.advance(100ms);  // minInterval of BatteryStatus
    el = f.last(ids::kEnergyService, ids::kFldBatteryStatus);
    CHECK(el[0].status == SignalStatus::Valid);
    CHECK_NEAR(el[0].value, 79.5, 1e-4);
}

TEST_CASE("gateway: deadline monitoring starts at start-up") {
    Fixture f;
    f.advance(45ms);
    CHECK(f.someip.events(ids::kVehicleMotionService, ids::kFldSteeringWheel).empty());
    f.advance(5ms);
    const auto el = f.last(ids::kVehicleMotionService, ids::kFldSteeringWheel);
    CHECK(el[0].status == SignalStatus::Timeout);
}

TEST_CASE("gateway: SNA pattern and out-of-range values are INVALID") {
    Fixture f;
    f.rx("BMS_PackStatus", {{"BMS_SoC", 50.0}, {"BMS_PackVolt", 400.0}});
    f.advance(100ms);
    f.rx("BMS_PackStatus", {{"BMS_PackCurr", 0.0}}, {{"BMS_SoC", 0x3FF}, {"BMS_PackVolt", 8100}});
    const auto el = f.last(ids::kEnergyService, ids::kFldBatteryStatus);
    CHECK(el[0].status == SignalStatus::Invalid);
    CHECK_NEAR(el[0].value, 50.0, 1e-4);  // HoldLastValid
    CHECK(el[1].status == SignalStatus::Invalid);  // 810 V > 800 V
    CHECK_NEAR(el[1].value, 0.0, 1e-9);
    CHECK(el[2].status == SignalStatus::Valid);
}

TEST_CASE("gateway: E2E errors are debounced and resynchronised") {
    Fixture f;
    f.rx("EPS_SteeringAngle", {{"EPS_SteerWhlAng", 5.0}});
    f.advance(20ms);
    const std::size_t before = f.someip.events(ids::kVehicleMotionService, ids::kFldSteeringWheel).size();

    f.rx("EPS_SteeringAngle", {{"EPS_SteerWhlAng", 99.0}}, {}, true);
    f.rx("EPS_SteeringAngle", {{"EPS_SteerWhlAng", 99.0}}, {}, true);
    CHECK_EQ(f.someip.events(ids::kVehicleMotionService, ids::kFldSteeringWheel).size(), before);
    CHECK(f.gw.rxSignal("EPS_SteeringAngle", "EPS_SteerWhlAng")->status == SignalStatus::Valid);
    CHECK_NEAR(f.gw.rxSignal("EPS_SteeringAngle", "EPS_SteerWhlAng")->physical, 5.0, 1e-9);

    f.rx("EPS_SteeringAngle", {{"EPS_SteerWhlAng", 99.0}}, {}, true);  // 3rd in a row
    auto el = f.last(ids::kVehicleMotionService, ids::kFldSteeringWheel);
    CHECK(el[0].status == SignalStatus::E2EError);
    CHECK_NEAR(el[0].value, 5.0, 1e-4);  // corrupted data never reached the service
    CHECK_EQ(f.gw.statistics().e2eCrcErrors, 3U);

    // First good frame after the burst has a counter jump of 4 -> resync only.
    f.rx("EPS_SteeringAngle", {{"EPS_SteerWhlAng", 7.0}});
    CHECK_EQ(f.gw.statistics().e2eSequenceErrors, 1U);
    f.rx("EPS_SteeringAngle", {{"EPS_SteerWhlAng", 7.0}});
    f.advance(20ms);
    el = f.last(ids::kVehicleMotionService, ids::kFldSteeringWheel);
    CHECK(el[0].status == SignalStatus::Valid);
    CHECK_NEAR(el[0].value, 7.0, 1e-4);
}

TEST_CASE("gateway: repeated E2E counter is discarded as stale") {
    Fixture f;
    const auto frame = f.frame("ESP_VehicleSpeed", {{"ESP_VehSpd", 10.0}});
    f.gw.onCanFrame(frame, f.now);
    f.gw.onCanFrame(frame, f.now);
    CHECK_EQ(f.gw.statistics().canRxAccepted, 1U);
    CHECK_EQ(f.gw.statistics().e2eRepeated, 1U);
}

TEST_CASE("gateway: unknown CAN IDs and short frames are filtered") {
    Fixture f;
    can::CanFrame unknown;
    unknown.id = 0x555;
    unknown.length = 8;
    f.gw.onCanFrame(unknown, f.now);
    auto shortFrame = f.frame("BCM_DoorStatus", {{"BCM_DoorFLSts", 1}});
    shortFrame.length = 2;
    f.gw.onCanFrame(shortFrame, f.now);
    CHECK_EQ(f.gw.statistics().canRxUnknownId, 1U);
    CHECK_EQ(f.gw.statistics().canRxLengthError, 1U);
    CHECK_EQ(f.gw.statistics().canRxAccepted, 0U);
    CHECK(f.someip.notifications.empty());
}

// ------------------------------------------------------------- fields

TEST_CASE("gateway: field getter returns the current value") {
    Fixture f;
    f.rx("BCM_DoorStatus", {{"BCM_DoorRRSts", 1}, {"BCM_TrunkSts", 2}});
    const auto req = f.request(ids::kBodyService, ids::kGetDoorStatus);
    f.call(req);
    const auto& resp = f.lastUnicast();
    CHECK(resp.header.messageType == someip::MessageType::Response);
    CHECK(resp.header.returnCode == someip::ReturnCode::Ok);
    CHECK_EQ(resp.header.sessionId, req.header.sessionId);
    CHECK_EQ(resp.header.clientId, req.header.clientId);
    const auto el = decode(f.cfg, ids::kBodyService, ids::kFldDoorStatus, resp.payload);
    CHECK_EQ(el[3].value, 1.0);
    CHECK_EQ(el[4].value, 2.0);
    CHECK(el[4].status == SignalStatus::Valid);
    CHECK_EQ(f.someip.unicast.front().first.token, f.client.peer.token);
}

TEST_CASE("gateway: subscribe sends initial field values only for fields") {
    Fixture f;
    f.rx("BCM_DoorStatus", {{"BCM_DoorFLSts", 1}});
    const Peer subscriber{77};
    f.gw.onSubscribe(ids::kBodyService, ids::kInstance, ids::kEgDoors, subscriber, f.now);
    REQUIRE(f.someip.unicast.size() == 1);
    CHECK_EQ(f.someip.unicast[0].first.token, 77U);
    CHECK(f.someip.unicast[0].second.header.messageType == someip::MessageType::Notification);
    CHECK_EQ(f.someip.unicast[0].second.header.methodId, ids::kFldDoorStatus);

    f.gw.onSubscribe(ids::kVehicleMotionService, ids::kInstance, ids::kEgDynamics, subscriber,
                     f.now);
    CHECK_EQ(f.someip.unicast.size(), 1U);  // VehicleDynamics is a plain event
}

// ---------------------------------------------------------- service -> signal

TEST_CASE("gateway: method call -> E2E protected CAN burst with pulse reset") {
    Fixture f;
    f.gw.mainFunction(f.now);  // first cyclic frames at start-up
    f.advance(50ms);
    f.can.frames.clear();

    f.call(f.request(ids::kBodyService, ids::kMtdSetCentralLock, {0x01}));
    const auto& resp = f.lastUnicast();
    CHECK(resp.header.messageType == someip::MessageType::Response);
    CHECK(resp.header.returnCode == someip::ReturnCode::Ok);
    CHECK(resp.payload.empty());
    CHECK_EQ(f.can.withId(ids::kCanHpcBodyCommand).size(), 1U);  // sent immediately

    f.advance(100ms);
    const auto frames = f.can.withId(ids::kCanHpcBodyCommand);
    REQUIRE(frames.size() == 4);  // immediate + 2 repetitions (20 ms) + next cyclic

    const auto& m = f.cfg.txMessages[0];
    e2e::CanE2EReceiver checker(*m.e2e);
    for (std::size_t i = 0; i < frames.size(); ++i) {
        CHECK(checker.check(frames[i].data.data(), frames[i].length) == e2e::CheckStatus::Ok);
        const auto lockReq = can::extractRaw(frames[i].data.data(), m.signals[0]);
        CHECK_EQ(lockReq, i < 3 ? 1U : 0U);
    }
    CHECK_EQ(*f.gw.txSignalRaw("HPC_BodyCommand", "HPC_CentralLockReq"), 0U);
}

TEST_CASE("gateway: physical method argument is scaled and held cyclically") {
    Fixture f;
    f.gw.mainFunction(f.now);
    f.advance(50ms);
    f.can.frames.clear();

    someip::PayloadWriter w;
    w.writeF32(21.5F);
    w.writeU8(3);
    f.call(f.request(ids::kClimateService, ids::kMtdSetCabinClimate, w.take()));
    CHECK(f.lastUnicast().header.returnCode == someip::ReturnCode::Ok);

    auto frames = f.can.withId(ids::kCanHpcClimateCommand);
    REQUIRE(frames.size() == 1);  // sent immediately
    CHECK_EQ(frames[0].data[0], 23);      // (21.5 - 10) / 0.5
    CHECK_EQ(frames[0].data[1] & 0x7, 3);

    f.advance(150ms);
    frames = f.can.withId(ids::kCanHpcClimateCommand);
    REQUIRE(frames.size() == 2);  // next cyclic frame at t0 + 200 ms
    CHECK_EQ(frames[1].data[0], 23);  // not a pulse: value is kept
}

TEST_CASE("gateway: method arguments are range checked (all-or-nothing)") {
    Fixture f;
    f.gw.mainFunction(f.now);
    f.can.frames.clear();

    f.call(f.request(ids::kBodyService, ids::kMtdSetCentralLock, {0x03}));
    CHECK(f.lastUnicast().header.messageType == someip::MessageType::Error);
    CHECK(f.lastUnicast().header.returnCode == someip::ReturnCode::NotOk);

    someip::PayloadWriter w;
    w.writeF32(25.0F);  // valid set-point
    w.writeU8(9);       // fan level out of range
    f.call(f.request(ids::kClimateService, ids::kMtdSetCabinClimate, w.take()));
    CHECK(f.lastUnicast().header.returnCode == someip::ReturnCode::NotOk);
    CHECK_EQ(*f.gw.txSignalRaw("HPC_ClimateCommand", "HPC_CabinTempSetpt"), 22U);  // unchanged

    someip::PayloadWriter w2;
    w2.writeF32(40.0F);
    w2.writeU8(1);
    f.call(f.request(ids::kClimateService, ids::kMtdSetCabinClimate, w2.take()));
    CHECK(f.lastUnicast().header.returnCode == someip::ReturnCode::NotOk);

    CHECK(f.can.frames.empty());
    CHECK_EQ(f.gw.statistics().errorResponsesSent, 3U);
}

TEST_CASE("gateway: SOME/IP error codes") {
    Fixture f;
    using RC = someip::ReturnCode;
    auto expect = [&](someip::Message req, RC code) {
        f.call(req);
        CHECK(f.lastUnicast().header.messageType == someip::MessageType::Error);
        CHECK(f.lastUnicast().header.returnCode == code);
        CHECK_EQ(f.lastUnicast().header.sessionId, req.header.sessionId);
    };

    expect(f.request(0x7777, 0x0001), RC::UnknownService);
    expect(f.request(ids::kBodyService, 0x0099), RC::UnknownMethod);
    expect(f.request(ids::kBodyService, ids::kMtdSetCentralLock, {}), RC::MalformedMessage);
    expect(f.request(ids::kBodyService, ids::kMtdOpenTrunk, {0x01}), RC::WrongMessageType);

    auto wrongIf = f.request(ids::kBodyService, ids::kMtdSetCentralLock, {0x01});
    wrongIf.header.interfaceVersion = 2;
    expect(wrongIf, RC::WrongInterfaceVersion);

    auto wrongProto = f.request(ids::kBodyService, ids::kMtdSetCentralLock, {0x01});
    wrongProto.header.protocolVersion = 2;
    expect(wrongProto, RC::WrongProtocolVersion);

    const RequestContext otherInstance{0x0002, f.client.peer};
    const auto req = f.request(ids::kBodyService, ids::kGetDoorStatus);
    f.gw.onSomeIpRequest(req, otherInstance, f.now);
    CHECK(f.lastUnicast().header.returnCode == RC::UnknownService);
}

TEST_CASE("gateway: fire&forget method never answers") {
    Fixture f;
    f.gw.mainFunction(f.now);
    f.advance(50ms);
    f.can.frames.clear();

    f.call(f.request(ids::kBodyService, ids::kMtdOpenTrunk, {0x01},
                     someip::MessageType::RequestNoReturn));
    CHECK(f.someip.unicast.empty());
    const auto frames = f.can.withId(ids::kCanHpcBodyCommand);
    REQUIRE(frames.size() == 1);
    CHECK_EQ(can::extractRaw(frames[0].data.data(), f.cfg.txMessages[0].signals[1]), 1U);

    // Errors on REQUEST_NO_RETURN are silently dropped as well.
    f.call(f.request(ids::kBodyService, ids::kMtdSetCentralLock, {0x01},
                     someip::MessageType::RequestNoReturn));
    f.call(f.request(0x7777, 0x0001, {}, someip::MessageType::RequestNoReturn));
    CHECK(f.someip.unicast.empty());
    CHECK_EQ(f.gw.statistics().requestsDropped, 2U);

    // Responses / notifications sent to the gateway are ignored.
    f.call(f.request(ids::kBodyService, ids::kMtdSetCentralLock, {0x01},
                     someip::MessageType::Response));
    CHECK_EQ(f.gw.statistics().requestsDropped, 3U);
}

TEST_CASE("gateway: minimum delay time spaces event and cyclic frames") {
    Fixture f;
    f.gw.mainFunction(f.now);  // cyclic HPC_BodyCommand at t0
    f.can.frames.clear();

    f.call(f.request(ids::kBodyService, ids::kMtdSetCentralLock, {0x02}));
    CHECK(f.lastUnicast().header.returnCode == someip::ReturnCode::Ok);
    CHECK(f.can.withId(ids::kCanHpcBodyCommand).empty());  // MDT of 10 ms still running
    f.advance(5ms);
    CHECK(f.can.withId(ids::kCanHpcBodyCommand).empty());
    f.advance(5ms);
    auto frames = f.can.withId(ids::kCanHpcBodyCommand);
    REQUIRE(frames.size() == 1);
    CHECK_EQ(can::extractRaw(frames[0].data.data(), f.cfg.txMessages[0].signals[0]), 2U);

    f.advance(40ms);  // repetitions at t0 + 30 / 50 ms
    frames = f.can.withId(ids::kCanHpcBodyCommand);
    CHECK_EQ(frames.size(), 3U);
}

TEST_CASE("gateway: CAN Tx failures are counted") {
    Fixture f;
    f.can.accept = false;
    f.gw.mainFunction(f.now);
    CHECK_EQ(f.gw.statistics().canTxFailures, 2U);
    CHECK_EQ(f.gw.statistics().canTxFrames, 0U);
}
