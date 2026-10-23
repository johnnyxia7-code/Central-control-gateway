#pragma once

#include <cstdint>
#include <optional>
#include <vector>

// Client-side view of the SOME/IP services offered by the HPC S2S gateway
// (VehicleMotionService, BodyService, EnergyService, ClimateService).
//
// The wire layout follows the S2S matrix (config/vehicle_s2s_matrix.cpp): every
// element is followed by a uint8 status, big-endian, trailing bytes tolerated
// for forward compatibility with newer minor versions of the interface.
namespace ccg::ivi {

// Same numeric values as s2s::SignalStatus on the HPC.
enum class Quality : std::uint8_t {
    Valid = 0,
    Invalid = 1,
    Timeout = 2,
    E2EError = 3,
    NotAvailable = 4,
};

const char* toString(Quality quality);

template <typename T>
struct Measured {
    T value{};
    Quality quality = Quality::NotAvailable;

    bool valid() const { return quality == Quality::Valid; }
    bool operator==(const Measured& other) const {
        return value == other.value && quality == other.quality;
    }
    bool operator!=(const Measured& other) const { return !(*this == other); }
};

// --- VehicleMotionService (0x6001) -----------------------------------------
struct VehicleDynamics {
    Measured<float> speedKph;
    Measured<float> longitudinalAccel;  // m/s^2
    Measured<float> yawRateDps;
};

struct SteeringWheel {
    Measured<float> angleDeg;  // steering wheel angle, sign as provided by the EPS
    Measured<std::uint16_t> speedDps;
};

// --- BodyService (0x6002) ----------------------------------------------------
enum class DoorState : std::uint8_t { Closed = 0, Ajar = 1, Open = 2 };
enum class LockState : std::uint8_t { Unlocked = 0, Locked = 1, SuperLocked = 2 };
enum class LockRequest : std::uint8_t { None = 0, Lock = 1, Unlock = 2 };

struct DoorStatus {
    Measured<DoorState> frontLeft;
    Measured<DoorState> frontRight;
    Measured<DoorState> rearLeft;
    Measured<DoorState> rearRight;
    Measured<DoorState> trunk;
    Measured<LockState> centralLock;
};

// --- EnergyService (0x6003) --------------------------------------------------
struct BatteryStatus {
    Measured<float> socPercent;
    Measured<float> packVoltage;  // V
    Measured<float> packCurrent;  // A
};

// --- ClimateService (0x6004) -------------------------------------------------
struct CabinClimateRequest {
    float setpointDegC = 21.0F;  // 16.0 .. 32.0, 0.5 steps
    std::uint8_t fanLevel = 0;   // 0 .. 7
};

// Payload decoders; nullopt when the payload is too short or an enumeration is
// out of range (the notification is then dropped as malformed).
std::optional<VehicleDynamics> decodeVehicleDynamics(const std::vector<std::uint8_t>& payload);
std::optional<SteeringWheel> decodeSteeringWheel(const std::vector<std::uint8_t>& payload);
std::optional<DoorStatus> decodeDoorStatus(const std::vector<std::uint8_t>& payload);
std::optional<BatteryStatus> decodeBatteryStatus(const std::vector<std::uint8_t>& payload);

// Request payload encoders.
std::vector<std::uint8_t> encodeSetCentralLock(LockRequest request);
std::vector<std::uint8_t> encodeOpenTrunk(bool open);
std::vector<std::uint8_t> encodeSetCabinClimate(const CabinClimateRequest& request);

}  // namespace ccg::ivi
