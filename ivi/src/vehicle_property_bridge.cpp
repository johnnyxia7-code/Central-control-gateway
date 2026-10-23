#include "ccg/ivi/vehicle_property_bridge.hpp"

#include <algorithm>

#include "vehicle_s2s_matrix.hpp"

namespace ccg::ivi::vhal {

namespace ids = config::ids;

namespace {

constexpr float kMinSetpointDegC = 16.0F;
constexpr float kMaxSetpointDegC = 32.0F;
constexpr std::int32_t kMaxFanLevel = 7;

constexpr std::int32_t kSideDoors[] = {area::kDoorRow1Left, area::kDoorRow1Right,
                                       area::kDoorRow2Left, area::kDoorRow2Right};

PropertyStatus statusOf(Quality q) {
    switch (q) {
        case Quality::Valid: return PropertyStatus::Available;
        case Quality::Invalid:
        case Quality::E2EError: return PropertyStatus::Error;
        case Quality::Timeout:
        case Quality::NotAvailable: return PropertyStatus::Unavailable;
    }
    return PropertyStatus::Unavailable;
}

// Error wins over Unavailable wins over Available.
PropertyStatus worst(PropertyStatus a, PropertyStatus b) {
    auto rank = [](PropertyStatus s) {
        return s == PropertyStatus::Error ? 2 : s == PropertyStatus::Unavailable ? 1 : 0;
    };
    return rank(a) >= rank(b) ? a : b;
}

std::uint16_t serviceOf(std::int32_t p) {
    switch (p) {
        case prop::kPerfVehicleSpeed:
        case prop::kPerfSteeringAngle: return ids::kVehicleMotionService;
        case prop::kDoorPos:
        case prop::kDoorLock: return ids::kBodyService;
        case prop::kEvBatteryLevel:
        case prop::kEvBatteryInstantaneousChargeRate: return ids::kEnergyService;
        case prop::kHvacTemperatureSet:
        case prop::kHvacFanSpeed: return ids::kClimateService;
        default: return 0;
    }
}

bool isContinuous(std::int32_t p) {
    return p == prop::kPerfVehicleSpeed || p == prop::kPerfSteeringAngle ||
           p == prop::kEvBatteryLevel || p == prop::kEvBatteryInstantaneousChargeRate;
}

StatusCode statusOf(const CallResult& r) {
    switch (r.status) {
        case CallStatus::Ok: return StatusCode::Ok;
        case CallStatus::NotAvailable: return StatusCode::NotAvailable;
        case CallStatus::SendFailed:
        case CallStatus::Timeout: return StatusCode::TryAgain;
        case CallStatus::Error:
            // E_NOT_OK: the HPC rejected the value against the CAN signal range.
            return r.returnCode == someip::ReturnCode::NotOk ? StatusCode::InvalidArg
                                                             : StatusCode::InternalError;
    }
    return StatusCode::InternalError;
}

}  // namespace

const char* toString(StatusCode code) {
    switch (code) {
        case StatusCode::Ok: return "OK";
        case StatusCode::TryAgain: return "TRY_AGAIN";
        case StatusCode::InvalidArg: return "INVALID_ARG";
        case StatusCode::NotAvailable: return "NOT_AVAILABLE";
        case StatusCode::AccessDenied: return "ACCESS_DENIED";
        case StatusCode::InternalError: return "INTERNAL_ERROR";
    }
    return "?";
}

const char* toString(PropertyStatus status) {
    switch (status) {
        case PropertyStatus::Available: return "AVAILABLE";
        case PropertyStatus::Unavailable: return "UNAVAILABLE";
        case PropertyStatus::Error: return "ERROR";
    }
    return "?";
}

const char* propertyName(std::int32_t p) {
    switch (p) {
        case prop::kInfoEvBatteryCapacity: return "INFO_EV_BATTERY_CAPACITY";
        case prop::kPerfVehicleSpeed: return "PERF_VEHICLE_SPEED";
        case prop::kPerfSteeringAngle: return "PERF_STEERING_ANGLE";
        case prop::kEvBatteryLevel: return "EV_BATTERY_LEVEL";
        case prop::kEvBatteryInstantaneousChargeRate: return "EV_BATTERY_INSTANTANEOUS_CHARGE_RATE";
        case prop::kHvacFanSpeed: return "HVAC_FAN_SPEED";
        case prop::kHvacTemperatureSet: return "HVAC_TEMPERATURE_SET";
        case prop::kDoorPos: return "DOOR_POS";
        case prop::kDoorLock: return "DOOR_LOCK";
        default: return "UNKNOWN";
    }
}

VehiclePropertyBridge::VehiclePropertyBridge(VehicleClient& client, BridgeOptions options,
                                             NowNs nowNs, Now now)
    : client_(client),
      options_(options),
      nowNs_(std::move(nowNs)),
      now_(std::move(now)),
      confirmedClimate_(options.initialClimate),
      desiredClimate_(options.initialClimate) {}

std::vector<PropertyConfig> VehiclePropertyBridge::propertyConfigs() const {
    std::vector<PropertyConfig> out;
    auto global = [](float minF = 0.0F, float maxF = 0.0F) {
        AreaConfig a;
        a.areaId = area::kGlobal;
        a.minFloatValue = minF;
        a.maxFloatValue = maxF;
        return std::vector<AreaConfig>{a};
    };

    out.push_back({prop::kInfoEvBatteryCapacity, Access::Read, ChangeMode::Static, global(), {}});
    out.push_back({prop::kPerfVehicleSpeed, Access::Read, ChangeMode::Continuous, global(), {},
                   1.0F, 50.0F});
    out.push_back({prop::kPerfSteeringAngle, Access::Read, ChangeMode::Continuous, global(), {},
                   1.0F, 50.0F});
    out.push_back({prop::kEvBatteryLevel, Access::Read, ChangeMode::Continuous,
                   global(0.0F, options_.batteryCapacityWh), {}, 1.0F, 10.0F});
    out.push_back({prop::kEvBatteryInstantaneousChargeRate, Access::Read, ChangeMode::Continuous,
                   global(), {}, 1.0F, 10.0F});

    PropertyConfig doorPos{prop::kDoorPos, Access::ReadWrite, ChangeMode::OnChange, {}, {}};
    PropertyConfig doorLock{prop::kDoorLock, Access::ReadWrite, ChangeMode::OnChange, {}, {}};
    for (const auto door : kSideDoors) {
        doorPos.areaConfigs.push_back({door, Access::Read, 0, 2});
        doorLock.areaConfigs.push_back({door, Access::ReadWrite});
    }
    // Only opening the trunk is actuated (BodyService.OpenTrunk).
    doorPos.areaConfigs.push_back({area::kDoorRear, Access::ReadWrite, 0, 2});
    out.push_back(doorPos);
    out.push_back(doorLock);

    AreaConfig hvacTemp;
    hvacTemp.areaId = options_.hvacAreaId;
    hvacTemp.access = Access::ReadWrite;
    hvacTemp.minFloatValue = kMinSetpointDegC;
    hvacTemp.maxFloatValue = kMaxSetpointDegC;
    // [min, max, increment] in 0.1 degC, then the same in 0.1 degF.
    out.push_back({prop::kHvacTemperatureSet, Access::ReadWrite, ChangeMode::OnChange, {hvacTemp},
                   {160, 320, 5, 608, 896, 9}});
    out.push_back({prop::kHvacFanSpeed, Access::ReadWrite, ChangeMode::OnChange,
                   {{options_.hvacAreaId, Access::ReadWrite, 0, kMaxFanLevel}}, {}});
    return out;
}

PropertyValue VehiclePropertyBridge::make(std::int32_t p, std::int32_t areaId,
                                          PropertyStatus status) const {
    PropertyValue v;
    v.prop = p;
    v.areaId = areaId;
    v.timestampNs = nowNs_();
    v.status = status;
    return v;
}

std::vector<PropertyValue> VehiclePropertyBridge::climateValues(PropertyStatus status) const {
    CabinClimateRequest climate;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        climate = confirmedClimate_;
    }
    auto temp = make(prop::kHvacTemperatureSet, options_.hvacAreaId, status);
    auto fan = make(prop::kHvacFanSpeed, options_.hvacAreaId, status);
    if (status == PropertyStatus::Available) {
        temp.floatValues = {climate.setpointDegC};
        fan.int32Values = {climate.fanLevel};
    }
    return {temp, fan};
}

std::vector<PropertyValue> VehiclePropertyBridge::valuesOf(std::uint16_t serviceId) const {
    std::vector<PropertyValue> out;
    constexpr auto kUnavailable = PropertyStatus::Unavailable;

    if (serviceId == ids::kVehicleMotionService) {
        const auto dyn = client_.vehicleDynamics();
        auto speed = make(prop::kPerfVehicleSpeed, area::kGlobal,
                          dyn ? statusOf(dyn->speedKph.quality) : kUnavailable);
        if (speed.status == PropertyStatus::Available) {
            speed.floatValues = {dyn->speedKph.value / 3.6F};  // VHAL: m/s
        }
        out.push_back(speed);

        const auto steer = client_.steeringWheel();
        auto angle = make(prop::kPerfSteeringAngle, area::kGlobal,
                          steer ? statusOf(steer->angleDeg.quality) : kUnavailable);
        if (angle.status == PropertyStatus::Available) {
            const float road = steer->angleDeg.value / options_.steeringRatio;
            angle.floatValues = {options_.steeringWheelLeftPositive ? -road : road};
        }
        out.push_back(angle);
    } else if (serviceId == ids::kBodyService) {
        const auto doors = client_.doorStatus();
        auto doorPos = [&](std::int32_t areaId, const Measured<DoorState>* m) {
            auto v = make(prop::kDoorPos, areaId, m ? statusOf(m->quality) : kUnavailable);
            if (v.status == PropertyStatus::Available) {
                v.int32Values = {static_cast<std::int32_t>(m->value)};
            }
            out.push_back(v);
        };
        doorPos(area::kDoorRow1Left, doors ? &doors->frontLeft : nullptr);
        doorPos(area::kDoorRow1Right, doors ? &doors->frontRight : nullptr);
        doorPos(area::kDoorRow2Left, doors ? &doors->rearLeft : nullptr);
        doorPos(area::kDoorRow2Right, doors ? &doors->rearRight : nullptr);
        doorPos(area::kDoorRear, doors ? &doors->trunk : nullptr);
        for (const auto door : kSideDoors) {
            auto v = make(prop::kDoorLock, door,
                          doors ? statusOf(doors->centralLock.quality) : kUnavailable);
            if (v.status == PropertyStatus::Available) {
                v.int32Values = {doors->centralLock.value != LockState::Unlocked ? 1 : 0};
            }
            out.push_back(v);
        }
    } else if (serviceId == ids::kEnergyService) {
        const auto bat = client_.batteryStatus();
        auto level = make(prop::kEvBatteryLevel, area::kGlobal,
                          bat ? statusOf(bat->socPercent.quality) : kUnavailable);
        if (level.status == PropertyStatus::Available) {
            level.floatValues = {bat->socPercent.value / 100.0F * options_.batteryCapacityWh};
        }
        out.push_back(level);

        auto rate = make(prop::kEvBatteryInstantaneousChargeRate, area::kGlobal,
                         bat ? worst(statusOf(bat->packVoltage.quality),
                                     statusOf(bat->packCurrent.quality))
                             : kUnavailable);
        if (rate.status == PropertyStatus::Available) {
            const float watts = bat->packVoltage.value * bat->packCurrent.value;
            rate.floatValues = {(options_.packCurrentPositiveIsDischarge ? -watts : watts) * 1000.0F};
        }
        out.push_back(rate);
    } else if (serviceId == ids::kClimateService) {
        return climateValues(client_.isAvailable(serviceId) ? PropertyStatus::Available
                                                            : kUnavailable);
    }
    return out;
}

std::pair<StatusCode, PropertyValue> VehiclePropertyBridge::get(std::int32_t p,
                                                                std::int32_t areaId) const {
    if (p == prop::kInfoEvBatteryCapacity) {
        auto v = make(p, area::kGlobal, PropertyStatus::Available);
        v.floatValues = {options_.batteryCapacityWh};
        return {areaId == area::kGlobal ? StatusCode::Ok : StatusCode::InvalidArg, v};
    }
    for (auto& v : valuesOf(serviceOf(p))) {
        if (v.prop != p || v.areaId != areaId) continue;
        switch (v.status) {
            case PropertyStatus::Available: return {StatusCode::Ok, v};
            case PropertyStatus::Unavailable: return {StatusCode::NotAvailable, v};
            case PropertyStatus::Error: return {StatusCode::InternalError, v};
        }
    }
    return {StatusCode::InvalidArg, make(p, areaId, PropertyStatus::Unavailable)};
}

void VehiclePropertyBridge::set(const PropertyValue& value, SetCallback done) {
    auto reply = [&done](StatusCode code) {
        if (done) done(code);
    };
    const auto isSideDoor = std::find(std::begin(kSideDoors), std::end(kSideDoors),
                                      value.areaId) != std::end(kSideDoors);

    switch (value.prop) {
        case prop::kDoorLock: {
            if (!isSideDoor || value.int32Values.empty()) return reply(StatusCode::InvalidArg);
            // The doors are locked centrally: any door area locks / unlocks the car.
            // The new state is reported by the DoorStatus field once the BCM confirms.
            const auto request = value.int32Values[0] != 0 ? LockRequest::Lock : LockRequest::Unlock;
            client_.setCentralLock(request,
                                   [done](const CallResult& r) {
                                       if (done) done(statusOf(r));
                                   },
                                   now_());
            return;
        }
        case prop::kDoorPos: {
            if (isSideDoor) return reply(StatusCode::AccessDenied);
            if (value.areaId != area::kDoorRear || value.int32Values.empty()) {
                return reply(StatusCode::InvalidArg);
            }
            if (value.int32Values[0] <= 0) return reply(StatusCode::InvalidArg);  // cannot close
            if (client_.openTrunk(now_())) return reply(StatusCode::Ok);
            return reply(client_.isAvailable(ids::kBodyService) ? StatusCode::TryAgain
                                                                : StatusCode::NotAvailable);
        }
        case prop::kHvacTemperatureSet: {
            if (value.areaId != options_.hvacAreaId || value.floatValues.empty()) {
                return reply(StatusCode::InvalidArg);
            }
            const float t = value.floatValues[0];
            if (!(t >= kMinSetpointDegC && t <= kMaxSetpointDegC)) {
                return reply(StatusCode::InvalidArg);
            }
            CabinClimateRequest desired;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                desiredClimate_.setpointDegC = t;
                desired = desiredClimate_;
            }
            return sendClimate(desired, std::move(done));
        }
        case prop::kHvacFanSpeed: {
            if (value.areaId != options_.hvacAreaId || value.int32Values.empty()) {
                return reply(StatusCode::InvalidArg);
            }
            const auto fan = value.int32Values[0];
            if (fan < 0 || fan > kMaxFanLevel) return reply(StatusCode::InvalidArg);
            CabinClimateRequest desired;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                desiredClimate_.fanLevel = static_cast<std::uint8_t>(fan);
                desired = desiredClimate_;
            }
            return sendClimate(desired, std::move(done));
        }
        case prop::kInfoEvBatteryCapacity:
        case prop::kPerfVehicleSpeed:
        case prop::kPerfSteeringAngle:
        case prop::kEvBatteryLevel:
        case prop::kEvBatteryInstantaneousChargeRate: return reply(StatusCode::AccessDenied);
        default: return reply(StatusCode::InvalidArg);
    }
}

void VehiclePropertyBridge::sendClimate(CabinClimateRequest desired, SetCallback done) {
    // SetCabinClimate always carries set-point and fan level; both come from the
    // desired state so that two writes in flight do not undo each other.
    client_.setCabinClimate(
        desired,
        [this, desired, done](const CallResult& r) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (r.ok()) {
                    confirmedClimate_ = desired;
                } else {
                    desiredClimate_ = confirmedClimate_;
                }
            }
            if (r.ok()) publish(climateValues(PropertyStatus::Available));
            if (done) done(statusOf(r));
        },
        now_());
}

void VehiclePropertyBridge::setChangeCallback(ChangeCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    onChange_ = std::move(callback);
}

void VehiclePropertyBridge::publish(std::vector<PropertyValue> values) {
    std::vector<PropertyValue> changed;
    ChangeCallback callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& v : values) {
            auto& last = lastPublished_[{v.prop, v.areaId}];
            const bool same = last.prop == v.prop && last.status == v.status &&
                              last.int32Values == v.int32Values &&
                              last.floatValues == v.floatValues;
            if (same && !isContinuous(v.prop)) continue;
            last = v;
            changed.push_back(std::move(v));
        }
        callback = onChange_;
    }
    if (callback && !changed.empty()) callback(std::move(changed));
}

void VehiclePropertyBridge::onServiceAvailability(std::uint16_t serviceId, bool) {
    publish(valuesOf(serviceId));
}

void VehiclePropertyBridge::onVehicleDynamics(const VehicleDynamics&) {
    auto values = valuesOf(ids::kVehicleMotionService);
    values.erase(std::remove_if(values.begin(), values.end(),
                                [](const PropertyValue& v) { return v.prop != prop::kPerfVehicleSpeed; }),
                 values.end());
    publish(std::move(values));
}

void VehiclePropertyBridge::onSteeringWheel(const SteeringWheel&) {
    auto values = valuesOf(ids::kVehicleMotionService);
    values.erase(std::remove_if(values.begin(), values.end(),
                                [](const PropertyValue& v) { return v.prop != prop::kPerfSteeringAngle; }),
                 values.end());
    publish(std::move(values));
}

void VehiclePropertyBridge::onDoorStatus(const DoorStatus&) {
    publish(valuesOf(ids::kBodyService));
}

void VehiclePropertyBridge::onBatteryStatus(const BatteryStatus&) {
    publish(valuesOf(ids::kEnergyService));
}

}  // namespace ccg::ivi::vhal
