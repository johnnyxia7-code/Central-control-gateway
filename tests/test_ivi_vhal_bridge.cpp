#include <vector>

#include "ccg/ivi/vehicle_property_bridge.hpp"
#include "ivi_harness.hpp"
#include "test_framework.hpp"

using namespace ccg;
using namespace ccg::ivi;
using namespace ccg::ivi::vhal;
using namespace std::chrono_literals;
namespace ids = ccg::config::ids;

namespace {

struct BridgeFixture {
    test::IviHarness h;
    std::int64_t ns = 1000;
    VehiclePropertyBridge bridge{h.client, BridgeOptions{}, [this] { return ns; },
                                 [this] { return h.now; }};
    std::vector<PropertyValue> events;

    BridgeFixture() {
        h.client.setListener(&bridge);
        bridge.setChangeCallback([this](std::vector<PropertyValue> v) {
            events.insert(events.end(), v.begin(), v.end());
        });
    }

    void up() {
        h.offerAll();
        h.pump();
    }

    std::vector<PropertyValue> eventsOf(std::int32_t p, std::int32_t areaId = 0) const {
        std::vector<PropertyValue> out;
        for (const auto& e : events) {
            if (e.prop == p && e.areaId == areaId) out.push_back(e);
        }
        return out;
    }

    StatusCode set(std::int32_t p, std::int32_t areaId, std::vector<std::int32_t> ints,
                   std::vector<float> floats = {}) {
        PropertyValue v;
        v.prop = p;
        v.areaId = areaId;
        v.int32Values = std::move(ints);
        v.floatValues = std::move(floats);
        StatusCode result = StatusCode::InternalError;
        int calls = 0;
        bridge.set(v, [&](StatusCode c) {
            result = c;
            ++calls;
        });
        h.pump();
        CHECK_EQ(calls, 1);
        return result;
    }
};

const PropertyConfig* findConfig(const std::vector<PropertyConfig>& configs, std::int32_t p) {
    for (const auto& c : configs) {
        if (c.prop == p) return &c;
    }
    return nullptr;
}

}  // namespace

TEST_CASE("vhal: property ids encode group, area type and value type") {
    // VehiclePropertyGroup.SYSTEM | VehicleArea | VehiclePropertyType | id
    CHECK_EQ(prop::kPerfVehicleSpeed, 0x10000000 | 0x01000000 | 0x00600000 | 0x0207);
    CHECK_EQ(prop::kDoorLock, 0x10000000 | 0x06000000 | 0x00200000 | 0x0B02);
    CHECK_EQ(prop::kDoorPos, 0x10000000 | 0x06000000 | 0x00400000 | 0x0B00);
    CHECK_EQ(prop::kHvacTemperatureSet, 0x10000000 | 0x05000000 | 0x00600000 | 0x0503);
    CHECK_EQ(prop::kHvacFanSpeed, 0x10000000 | 0x05000000 | 0x00400000 | 0x0500);
    CHECK_EQ(prop::kEvBatteryLevel, 0x10000000 | 0x01000000 | 0x00600000 | 0x0309);
}

TEST_CASE("vhal: property configs") {
    BridgeFixture f;
    const auto configs = f.bridge.propertyConfigs();
    CHECK_EQ(configs.size(), 9U);
    const auto* speed = findConfig(configs, prop::kPerfVehicleSpeed);
    REQUIRE(speed != nullptr);
    CHECK(speed->changeMode == ChangeMode::Continuous);
    CHECK_NEAR(speed->maxSampleRate, 50.0, 1e-9);  // VehicleDynamics is cyclic 20 ms
    const auto* doorPos = findConfig(configs, prop::kDoorPos);
    REQUIRE(doorPos != nullptr);
    CHECK_EQ(doorPos->areaConfigs.size(), 5U);
    for (const auto& a : doorPos->areaConfigs) {
        CHECK(a.access == (a.areaId == area::kDoorRear ? Access::ReadWrite : Access::Read));
    }
    const auto* temp = findConfig(configs, prop::kHvacTemperatureSet);
    REQUIRE(temp != nullptr);
    CHECK_EQ(temp->configArray.size(), 6U);
    CHECK_EQ(temp->areaConfigs[0].areaId, area::kSeatRow1Left | area::kSeatRow1Right);
}

TEST_CASE("vhal: values follow the HPC signals and their status") {
    BridgeFixture f;
    CHECK(f.bridge.get(prop::kPerfVehicleSpeed, 0).first == StatusCode::NotAvailable);
    CHECK(f.bridge.get(prop::kInfoEvBatteryCapacity, 0).first == StatusCode::Ok);
    CHECK(f.bridge.get(prop::kDoorLock, 0x2).first == StatusCode::InvalidArg);  // no such area

    f.up();
    f.h.rx("ESP_VehicleSpeed", {{"ESP_VehSpd", 72.0}});
    f.h.rx("EPS_SteeringAngle", {{"EPS_SteerWhlAng", 90.0}});
    f.h.rx("BMS_PackStatus", {{"BMS_SoC", 50.0}, {"BMS_PackVolt", 400.0}, {"BMS_PackCurr", 10.0}});
    f.h.advance(20ms);

    auto [st, speed] = f.bridge.get(prop::kPerfVehicleSpeed, 0);
    CHECK(st == StatusCode::Ok);
    REQUIRE(speed.floatValues.size() == 1);
    CHECK_NEAR(speed.floatValues[0], 20.0, 1e-3);  // 72 km/h = 20 m/s
    const auto angle = f.bridge.get(prop::kPerfSteeringAngle, 0).second;
    REQUIRE(angle.floatValues.size() == 1);
    CHECK_NEAR(angle.floatValues[0], -6.0, 1e-3);  // 90 deg to the left / ratio 15, left negative
    CHECK_NEAR(f.bridge.get(prop::kEvBatteryLevel, 0).second.floatValues.at(0), 37500.0, 1.0);
    // 400 V * 10 A discharge = -4 kW charge rate.
    CHECK_NEAR(f.bridge.get(prop::kEvBatteryInstantaneousChargeRate, 0).second.floatValues.at(0),
               -4.0e6, 10.0);
    CHECK(!f.eventsOf(prop::kPerfVehicleSpeed).empty());

    // HPC deadline monitoring -> UNAVAILABLE event, get() reports NOT_AVAILABLE.
    f.h.advance(100ms);
    CHECK(f.eventsOf(prop::kPerfVehicleSpeed).back().status == PropertyStatus::Unavailable);
    CHECK(f.bridge.get(prop::kPerfVehicleSpeed, 0).first == StatusCode::NotAvailable);

    // SNA from the BCM -> ERROR.
    f.h.rx("BCM_DoorStatus", {}, {{"BCM_DoorFLSts", 3}});
    CHECK(f.eventsOf(prop::kDoorPos, area::kDoorRow1Left).back().status == PropertyStatus::Error);
    CHECK(f.bridge.get(prop::kDoorPos, area::kDoorRow1Left).first == StatusCode::InternalError);
}

TEST_CASE("vhal: on-change properties are only reported on change") {
    BridgeFixture f;
    f.up();
    f.h.rx("BCM_DoorStatus", {{"BCM_CentralLockSts", 1}});
    const auto locks = f.eventsOf(prop::kDoorLock, area::kDoorRow2Right).size();
    CHECK(locks >= 1);
    CHECK_EQ(f.eventsOf(prop::kDoorLock, area::kDoorRow2Right).back().int32Values.at(0), 1);
    // Trunk opens: one DOOR_POS event for the trunk, none for unchanged doors / locks.
    const auto frontLeft = f.eventsOf(prop::kDoorPos, area::kDoorRow1Left).size();
    f.h.rx("BCM_DoorStatus", {{"BCM_CentralLockSts", 1}, {"BCM_TrunkSts", 2}});
    CHECK_EQ(f.eventsOf(prop::kDoorPos, area::kDoorRear).back().int32Values.at(0), 2);
    CHECK_EQ(f.eventsOf(prop::kDoorPos, area::kDoorRow1Left).size(), frontLeft);
    CHECK_EQ(f.eventsOf(prop::kDoorLock, area::kDoorRow2Right).size(), locks);

    // BodyService lost: every body property reports UNAVAILABLE once.
    f.h.client.onAvailability(ids::kBodyService, ids::kInstance, false, f.h.now);
    CHECK(f.eventsOf(prop::kDoorLock, area::kDoorRow1Left).back().status ==
          PropertyStatus::Unavailable);
    CHECK(f.eventsOf(prop::kDoorPos, area::kDoorRear).back().status == PropertyStatus::Unavailable);
}

TEST_CASE("vhal: door lock and trunk writes") {
    BridgeFixture f;
    CHECK(f.set(prop::kDoorLock, area::kDoorRow1Left, {1}) == StatusCode::NotAvailable);
    f.up();
    CHECK(f.set(prop::kDoorLock, area::kDoorRow1Left, {1}) == StatusCode::Ok);
    f.h.advance(5ms);
    CHECK_NEAR(*f.h.txSignal("HPC_BodyCommand", "HPC_CentralLockReq"), 1.0, 1e-9);
    CHECK(f.set(prop::kDoorLock, area::kDoorRow2Right, {0}) == StatusCode::Ok);
    f.h.advance(10ms);
    CHECK_NEAR(*f.h.txSignal("HPC_BodyCommand", "HPC_CentralLockReq"), 2.0, 1e-9);

    CHECK(f.set(prop::kDoorPos, area::kDoorRow1Left, {2}) == StatusCode::AccessDenied);
    CHECK(f.set(prop::kDoorPos, area::kDoorRear, {0}) == StatusCode::InvalidArg);
    CHECK(f.set(prop::kDoorPos, area::kDoorRear, {2}) == StatusCode::Ok);
    f.h.advance(10ms);
    CHECK_NEAR(*f.h.txSignal("HPC_BodyCommand", "HPC_TrunkOpenReq"), 1.0, 1e-9);

    CHECK(f.set(prop::kPerfVehicleSpeed, 0, {}, {1.0F}) == StatusCode::AccessDenied);
    CHECK(f.set(0x7FFF, 0, {1}) == StatusCode::InvalidArg);
}

TEST_CASE("vhal: hvac writes combine set-point and fan level") {
    BridgeFixture f;
    const std::int32_t hvac = area::kSeatRow1Left | area::kSeatRow1Right;
    CHECK(f.bridge.get(prop::kHvacTemperatureSet, hvac).first == StatusCode::NotAvailable);
    f.up();
    auto temp = f.bridge.get(prop::kHvacTemperatureSet, hvac);
    CHECK(temp.first == StatusCode::Ok);
    CHECK_NEAR(temp.second.floatValues.at(0), 21.0, 1e-6);  // CAN init value

    CHECK(f.set(prop::kHvacTemperatureSet, hvac, {}, {24.5F}) == StatusCode::Ok);
    CHECK(f.set(prop::kHvacFanSpeed, hvac, {5}) == StatusCode::Ok);
    f.h.advance(20ms);
    CHECK_NEAR(*f.h.txSignal("HPC_ClimateCommand", "HPC_CabinTempSetpt"), 24.5, 1e-9);
    CHECK_NEAR(*f.h.txSignal("HPC_ClimateCommand", "HPC_FanLevel"), 5.0, 1e-9);
    CHECK_NEAR(f.eventsOf(prop::kHvacTemperatureSet, hvac).back().floatValues.at(0), 24.5, 1e-6);
    CHECK_EQ(f.bridge.get(prop::kHvacFanSpeed, hvac).second.int32Values.at(0), 5);

    CHECK(f.set(prop::kHvacTemperatureSet, hvac, {}, {35.0F}) == StatusCode::InvalidArg);
    CHECK(f.set(prop::kHvacFanSpeed, hvac, {8}) == StatusCode::InvalidArg);
    CHECK(f.set(prop::kHvacFanSpeed, area::kSeatRow1Left, {3}) == StatusCode::InvalidArg);

    // Lost request: TRY_AGAIN and the confirmed value stays.
    PropertyValue v;
    v.prop = prop::kHvacFanSpeed;
    v.areaId = hvac;
    v.int32Values = {2};
    StatusCode result = StatusCode::Ok;
    f.bridge.set(v, [&](StatusCode c) { result = c; });
    f.h.transport.outbox.clear();
    f.h.client.mainFunction(f.h.now + 1s);
    CHECK(result == StatusCode::TryAgain);
    CHECK_EQ(f.bridge.get(prop::kHvacFanSpeed, hvac).second.int32Values.at(0), 5);
    // The next write starts from the confirmed state, not from the lost one.
    CHECK(f.set(prop::kHvacTemperatureSet, hvac, {}, {22.0F}) == StatusCode::Ok);
    f.h.advance(20ms);
    CHECK_NEAR(*f.h.txSignal("HPC_ClimateCommand", "HPC_FanLevel"), 5.0, 1e-9);
}
