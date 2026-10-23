#include <vector>

#include "ccg/ivi/vehicle_client.hpp"
#include "ccg/ivi/vehicle_services.hpp"
#include "ivi_harness.hpp"
#include "test_framework.hpp"

using namespace ccg;
using namespace ccg::ivi;
using namespace std::chrono_literals;
namespace ids = ccg::config::ids;

namespace {

struct RecordingListener final : IVehicleListener {
    std::vector<std::pair<std::uint16_t, bool>> availability;
    std::vector<VehicleDynamics> dynamics;
    std::vector<DoorStatus> doors;
    std::vector<BatteryStatus> battery;
    std::vector<SteeringWheel> steering;

    void onServiceAvailability(std::uint16_t s, bool a) override { availability.emplace_back(s, a); }
    void onVehicleDynamics(const VehicleDynamics& d) override { dynamics.push_back(d); }
    void onSteeringWheel(const SteeringWheel& s) override { steering.push_back(s); }
    void onDoorStatus(const DoorStatus& d) override { doors.push_back(d); }
    void onBatteryStatus(const BatteryStatus& b) override { battery.push_back(b); }
};

someip::Message notification(std::uint16_t svc, std::uint16_t event, std::vector<std::uint8_t> payload) {
    someip::Message m;
    m.header.serviceId = svc;
    m.header.methodId = event;
    m.header.interfaceVersion = 1;
    m.header.messageType = someip::MessageType::Notification;
    m.payload = std::move(payload);
    return m;
}

}  // namespace

TEST_CASE("ivi: quality values match the HPC signal status") {
    CHECK_EQ(static_cast<int>(Quality::Valid), static_cast<int>(s2s::SignalStatus::Valid));
    CHECK_EQ(static_cast<int>(Quality::Invalid), static_cast<int>(s2s::SignalStatus::Invalid));
    CHECK_EQ(static_cast<int>(Quality::Timeout), static_cast<int>(s2s::SignalStatus::Timeout));
    CHECK_EQ(static_cast<int>(Quality::E2EError), static_cast<int>(s2s::SignalStatus::E2EError));
    CHECK_EQ(static_cast<int>(Quality::NotAvailable),
             static_cast<int>(s2s::SignalStatus::NotAvailable));
}

TEST_CASE("ivi: service descriptors match the S2S matrix") {
    const auto cfg = config::makeVehicleS2SMatrix();
    CHECK_EQ(hpcServices().size(), cfg.services.size());
    for (const auto& svc : cfg.services) {
        const ServiceDescriptor* d = nullptr;
        for (const auto& s : hpcServices()) {
            if (s.serviceId == svc.serviceId) d = &s;
        }
        REQUIRE(d != nullptr);
        CHECK_EQ(d->instanceId, svc.instanceId);
        CHECK_EQ(d->majorVersion, svc.majorVersion);
        std::size_t events = 0;
        for (const auto& ev : cfg.events) {
            if (ev.serviceId != svc.serviceId) continue;
            ++events;
            bool found = false;
            for (const auto& e : d->events) {
                if (e.eventId != ev.eventId) continue;
                found = true;
                CHECK_EQ(e.eventgroupId, ev.eventgroupId);
                CHECK(e.isField == ev.isField);
                CHECK(e.getterId == ev.getterMethodId);
            }
            CHECK(found);
        }
        CHECK_EQ(d->events.size(), events);
    }
}

TEST_CASE("ivi: decoders reject short payloads and tolerate trailing bytes") {
    std::vector<std::uint8_t> p = encodeSetCabinClimate({21.5F, 3});  // 5 bytes
    CHECK(!decodeBatteryStatus(p));
    someip::PayloadWriter w;
    for (int i = 0; i < 3; ++i) {
        w.writeF32(1.5F * static_cast<float>(i));
        w.writeU8(0);
    }
    w.writeU8(0xEE);  // field added in a newer minor version
    const auto b = decodeBatteryStatus(w.data());
    REQUIRE(b.has_value());
    CHECK_NEAR(b->packCurrent.value, 3.0, 1e-6);
    CHECK(b->packCurrent.valid());

    // Unknown door state: malformed if valid, ignored if the element is substituted.
    std::vector<std::uint8_t> doors(12, 0);
    doors[0] = 7;
    CHECK(!decodeDoorStatus(doors));
    doors[1] = static_cast<std::uint8_t>(Quality::Invalid);
    REQUIRE(decodeDoorStatus(doors).has_value());
    CHECK(decodeDoorStatus(doors)->frontLeft.value == DoorState::Closed);
    // Status codes from a newer HPC map to Invalid.
    doors[3] = 9;
    CHECK(decodeDoorStatus(doors)->frontRight.quality == Quality::Invalid);
}

TEST_CASE("ivi: requests all services, fields refreshed by getter on availability") {
    test::IviHarness h;
    RecordingListener l;
    h.client.setListener(&l);
    CHECK_EQ(h.transport.requested.size(), 4U);

    h.rx("BCM_DoorStatus", {{"BCM_DoorFLSts", 2}, {"BCM_CentralLockSts", 1}});
    h.rx("BMS_PackStatus", {{"BMS_SoC", 80.5}, {"BMS_PackVolt", 400.0}, {"BMS_PackCurr", -12.5}});
    CHECK(!h.client.doorStatus());  // not available yet: notifications are not subscribed
    h.server.toClient.clear();

    h.offerAll();
    CHECK_EQ(l.availability.size(), 4U);
    h.pump();
    const auto doors = h.client.doorStatus();
    REQUIRE(doors.has_value());
    CHECK(doors->frontLeft.value == DoorState::Open);
    CHECK(doors->frontLeft.valid());
    CHECK(doors->centralLock.value == LockState::Locked);
    CHECK(doors->trunk.value == DoorState::Closed);
    const auto bat = h.client.batteryStatus();
    REQUIRE(bat.has_value());
    CHECK_NEAR(bat->socPercent.value, 80.5, 0.05);
    CHECK_NEAR(bat->packVoltage.value, 400.0, 0.05);
    CHECK_NEAR(bat->packCurrent.value, -12.5, 0.05);
    // Steering never received: getter reports NOT_AVAILABLE elements.
    REQUIRE(h.client.steeringWheel().has_value());
    CHECK(h.client.steeringWheel()->angleDeg.quality == Quality::NotAvailable);
    CHECK_EQ(h.client.statistics().responses, 3U);
}

TEST_CASE("ivi: events from the HPC gateway are decoded with their status") {
    test::IviHarness h;
    RecordingListener l;
    h.client.setListener(&l);
    h.offerAll();
    h.pump();

    h.rx("ESP_VehicleSpeed", {{"ESP_VehSpd", 87.25}, {"ESP_LongAccel", -1.5}, {"ESP_YawRate", 3.2}});
    h.advance(20ms);
    REQUIRE(!l.dynamics.empty());
    CHECK_NEAR(l.dynamics.back().speedKph.value, 87.25, 0.005);
    CHECK_NEAR(l.dynamics.back().longitudinalAccel.value, -1.5, 0.0005);
    CHECK_NEAR(l.dynamics.back().yawRateDps.value, 3.2, 0.005);
    CHECK(l.dynamics.back().speedKph.valid());

    // ESP stops sending: deadline monitoring on the HPC turns into TIMEOUT on the IVI.
    h.advance(100ms);
    CHECK(l.dynamics.back().speedKph.quality == Quality::Timeout);

    // Door opened: on-change field.
    const auto before = l.doors.size();
    h.rx("BCM_DoorStatus", {{"BCM_DoorRRSts", 1}});
    REQUIRE(l.doors.size() == before + 1);
    CHECK(l.doors.back().rearRight.value == DoorState::Ajar);
    CHECK(h.client.statistics().malformed == 0);
}

TEST_CASE("ivi: method calls reach the CAN bus and complete") {
    test::IviHarness h;
    h.offerAll();
    h.pump();

    std::vector<CallResult> results;
    h.client.setCabinClimate({23.5F, 4}, [&](const CallResult& r) { results.push_back(r); }, h.now);
    h.pump();
    REQUIRE(results.size() == 1);
    CHECK(results[0].ok());
    h.advance(10ms);
    CHECK_NEAR(*h.txSignal("HPC_ClimateCommand", "HPC_CabinTempSetpt"), 23.5, 1e-9);
    CHECK_NEAR(*h.txSignal("HPC_ClimateCommand", "HPC_FanLevel"), 4.0, 1e-9);

    // Out of the CAN signal range: the HPC answers E_NOT_OK.
    h.client.setCabinClimate({40.0F, 4}, [&](const CallResult& r) { results.push_back(r); }, h.now);
    h.pump();
    REQUIRE(results.size() == 2);
    CHECK(results[1].status == CallStatus::Error);
    CHECK(results[1].returnCode == someip::ReturnCode::NotOk);

    h.client.setCentralLock(LockRequest::Unlock, [&](const CallResult& r) { results.push_back(r); }, h.now);
    h.pump();
    REQUIRE(results.size() == 3);
    CHECK(results[2].ok());
    h.advance(5ms);
    CHECK_NEAR(*h.txSignal("HPC_BodyCommand", "HPC_CentralLockReq"), 2.0, 1e-9);

    CHECK(h.client.openTrunk(h.now));
    h.pump();
    h.advance(10ms);  // minimum delay time after the lock frame
    CHECK_NEAR(*h.txSignal("HPC_BodyCommand", "HPC_TrunkOpenReq"), 1.0, 1e-9);
    CHECK_EQ(h.gw.statistics().errorResponsesSent, 1U);
}

TEST_CASE("ivi: calls fail without service, on send failure and on timeout") {
    test::IviHarness h(ClientOptions{500ms, false});
    std::vector<CallResult> results;
    auto record = [&](const CallResult& r) { results.push_back(r); };

    h.client.setCentralLock(LockRequest::Lock, record, h.now);
    REQUIRE(results.size() == 1);
    CHECK(results[0].status == CallStatus::NotAvailable);
    CHECK(!h.client.openTrunk(h.now));
    CHECK(h.transport.outbox.empty());

    h.offerAll();
    CHECK(h.transport.outbox.empty());  // no field refresh configured
    h.transport.accept = false;
    h.client.setCentralLock(LockRequest::Lock, record, h.now);
    REQUIRE(results.size() == 2);
    CHECK(results[1].status == CallStatus::SendFailed);

    h.transport.accept = true;
    h.client.setCentralLock(LockRequest::Lock, record, h.now);
    h.transport.outbox.clear();  // lost on the network
    h.client.mainFunction(h.now + 499ms);
    CHECK_EQ(results.size(), 2U);
    h.client.mainFunction(h.now + 500ms);
    REQUIRE(results.size() == 3);
    CHECK(results[2].status == CallStatus::Timeout);
    CHECK_EQ(h.client.statistics().timeouts, 1U);

    // Pending call, then the HPC disappears (SD StopOffer / TTL expiry).
    h.client.setCentralLock(LockRequest::Lock, record, h.now);
    h.client.onAvailability(ids::kBodyService, ids::kInstance, false, h.now);
    REQUIRE(results.size() == 4);
    CHECK(results[3].status == CallStatus::NotAvailable);
    // A late response is ignored.
    h.pump();
    CHECK_EQ(results.size(), 4U);
    CHECK_EQ(h.client.statistics().unexpected, 1U);
}

TEST_CASE("ivi: unavailability clears cached values, header checks") {
    test::IviHarness h;
    RecordingListener l;
    h.client.setListener(&l);
    h.offerAll();
    h.pump();
    REQUIRE(h.client.doorStatus().has_value());

    h.client.onAvailability(ids::kBodyService, ids::kInstance, false, h.now);
    CHECK(!h.client.doorStatus());
    CHECK(!h.client.isAvailable(ids::kBodyService));
    CHECK(h.client.isAvailable(ids::kEnergyService));
    // Duplicate and foreign-instance availability reports are ignored.
    const auto reports = l.availability.size();
    h.client.onAvailability(ids::kBodyService, ids::kInstance, false, h.now);
    h.client.onAvailability(ids::kEnergyService, 0x0002, false, h.now);
    CHECK_EQ(l.availability.size(), reports);

    std::vector<std::uint8_t> battery;
    {
        someip::PayloadWriter w;
        for (int i = 0; i < 3; ++i) {
            w.writeF32(1.0F);
            w.writeU8(0);
        }
        battery = w.take();
    }
    auto m = notification(ids::kEnergyService, ids::kFldBatteryStatus, battery);
    m.header.interfaceVersion = 2;
    const auto before = l.battery.size();
    h.client.onMessage(m, h.now);
    CHECK_EQ(l.battery.size(), before);
    CHECK_EQ(h.client.statistics().malformed, 1U);
    m.header.interfaceVersion = 1;
    h.client.onMessage(m, h.now);
    CHECK_EQ(l.battery.size(), before + 1);
    h.client.onMessage(notification(0x7777, 0x8001, battery), h.now);
    h.client.onMessage(notification(ids::kEnergyService, 0x8005, battery), h.now);
    CHECK_EQ(h.client.statistics().unexpected, 2U);
}
