#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <utility>
#include <vector>

#include "ccg/ivi/vehicle_client.hpp"

// Mapping of the HPC services onto Android Automotive Vehicle HAL properties.
//
// The types below mirror android.hardware.automotive.vehicle (AIDL) one to one
// (same numeric values), so that this layer stays testable on the host and the
// Android IVehicleHardware adapter (android/vendor/ccg/vhal) only converts
// structures.
namespace ccg::ivi::vhal {

namespace prop {
// VehicleProperty.aidl
inline constexpr std::int32_t kInfoEvBatteryCapacity = 0x11600106;
inline constexpr std::int32_t kPerfVehicleSpeed = 0x11600207;
inline constexpr std::int32_t kPerfSteeringAngle = 0x11600209;
inline constexpr std::int32_t kEvBatteryLevel = 0x11600309;
inline constexpr std::int32_t kEvBatteryInstantaneousChargeRate = 0x1160030C;
inline constexpr std::int32_t kHvacFanSpeed = 0x15400500;
inline constexpr std::int32_t kHvacTemperatureSet = 0x15600503;
inline constexpr std::int32_t kDoorPos = 0x16400B00;
inline constexpr std::int32_t kDoorLock = 0x16200B02;
}  // namespace prop

namespace area {
inline constexpr std::int32_t kGlobal = 0;
// VehicleAreaDoor.aidl
inline constexpr std::int32_t kDoorRow1Left = 0x00000001;
inline constexpr std::int32_t kDoorRow1Right = 0x00000004;
inline constexpr std::int32_t kDoorRow2Left = 0x00000010;
inline constexpr std::int32_t kDoorRow2Right = 0x00000040;
inline constexpr std::int32_t kDoorRear = 0x20000000;
// VehicleAreaSeat.aidl
inline constexpr std::int32_t kSeatRow1Left = 0x0001;
inline constexpr std::int32_t kSeatRow1Right = 0x0004;
}  // namespace area

enum class Access : std::int32_t { None = 0, Read = 1, Write = 2, ReadWrite = 3 };
enum class ChangeMode : std::int32_t { Static = 0, OnChange = 1, Continuous = 2 };
enum class PropertyStatus : std::int32_t { Available = 0, Unavailable = 1, Error = 2 };
enum class StatusCode : std::int32_t {
    Ok = 0,
    TryAgain = 1,
    InvalidArg = 2,
    NotAvailable = 3,
    AccessDenied = 4,
    InternalError = 5,
};

const char* toString(StatusCode code);
const char* toString(PropertyStatus status);
const char* propertyName(std::int32_t prop);  // VehicleProperty enumerator name

struct AreaConfig {
    std::int32_t areaId = 0;
    Access access = Access::Read;
    std::int32_t minInt32Value = 0;
    std::int32_t maxInt32Value = 0;
    float minFloatValue = 0.0F;
    float maxFloatValue = 0.0F;
};

struct PropertyConfig {
    std::int32_t prop = 0;
    Access access = Access::Read;
    ChangeMode changeMode = ChangeMode::OnChange;
    std::vector<AreaConfig> areaConfigs;
    std::vector<std::int32_t> configArray;
    float minSampleRate = 0.0F;
    float maxSampleRate = 0.0F;
};

struct PropertyValue {
    std::int32_t prop = 0;
    std::int32_t areaId = 0;
    std::int64_t timestampNs = 0;
    PropertyStatus status = PropertyStatus::Available;
    std::vector<std::int32_t> int32Values;  // also BOOLEAN properties (0 / 1)
    std::vector<float> floatValues;
};

struct BridgeOptions {
    float batteryCapacityWh = 75000.0F;
    // PERF_STEERING_ANGLE is the road wheel angle (left negative); the HPC
    // publishes the steering wheel angle as delivered by the EPS.
    float steeringRatio = 15.0F;
    bool steeringWheelLeftPositive = true;  // ISO 8855: counter-clockwise positive
    // Pack current sign of the BMS; the VHAL charge rate is positive when charging.
    bool packCurrentPositiveIsDischarge = true;
    std::int32_t hvacAreaId = area::kSeatRow1Left | area::kSeatRow1Right;
    // Must match the init values of HPC_ClimateCommand (the HPC sends no feedback).
    CabinClimateRequest initialClimate{21.0F, 0};
};

// Implements the property semantics; one instance per VHAL process. Thread safe.
class VehiclePropertyBridge final : public IVehicleListener {
public:
    using ChangeCallback = std::function<void(std::vector<PropertyValue>)>;
    using SetCallback = std::function<void(StatusCode)>;
    using NowNs = std::function<std::int64_t()>;  // elapsedRealtimeNano() on Android
    using Now = std::function<TimePoint()>;

    VehiclePropertyBridge(VehicleClient& client, BridgeOptions options, NowNs nowNs,
                          Now now = &Clock::now);

    std::vector<PropertyConfig> propertyConfigs() const;

    // Synchronous read of the cached value. Not Ok when the HPC service is not
    // available or the signal is not valid.
    std::pair<StatusCode, PropertyValue> get(std::int32_t prop, std::int32_t areaId) const;

    // Validates and forwards a write; `done` is called once with the result
    // (immediately for local rejections, else when the HPC answered).
    void set(const PropertyValue& value, SetCallback done);

    // Property events (VHAL onPropertyEvent). Continuous properties are reported
    // on every update, on-change properties only when value or status changed.
    void setChangeCallback(ChangeCallback callback);

    // IVehicleListener
    void onServiceAvailability(std::uint16_t serviceId, bool available) override;
    void onVehicleDynamics(const VehicleDynamics& dynamics) override;
    void onSteeringWheel(const SteeringWheel& steering) override;
    void onDoorStatus(const DoorStatus& doors) override;
    void onBatteryStatus(const BatteryStatus& battery) override;

private:
    std::vector<PropertyValue> valuesOf(std::uint16_t serviceId) const;
    std::vector<PropertyValue> climateValues(PropertyStatus status) const;
    PropertyValue make(std::int32_t prop, std::int32_t areaId, PropertyStatus status) const;
    void publish(std::vector<PropertyValue> values);
    void sendClimate(CabinClimateRequest desired, SetCallback done);

    VehicleClient& client_;
    const BridgeOptions options_;
    NowNs nowNs_;
    Now now_;

    mutable std::mutex mutex_;
    ChangeCallback onChange_;
    std::map<std::pair<std::int32_t, std::int32_t>, PropertyValue> lastPublished_;
    CabinClimateRequest confirmedClimate_;
    CabinClimateRequest desiredClimate_;
};

}  // namespace ccg::ivi::vhal
