#include "ccg/ivi/vehicle_services.hpp"

#include "ccg/someip/someip_message.hpp"

namespace ccg::ivi {

namespace {

bool readQuality(someip::PayloadReader& r, Quality& q) {
    std::uint8_t raw = 0;
    if (!r.readU8(raw)) return false;
    // Unknown status values from a newer HPC are treated as "invalid" rather
    // than dropping the whole notification.
    q = raw <= static_cast<std::uint8_t>(Quality::NotAvailable) ? static_cast<Quality>(raw)
                                                                : Quality::Invalid;
    return true;
}

bool read(someip::PayloadReader& r, Measured<float>& m) {
    return r.readF32(m.value) && readQuality(r, m.quality);
}

bool read(someip::PayloadReader& r, Measured<std::uint16_t>& m) {
    return r.readU16(m.value) && readQuality(r, m.quality);
}

template <typename Enum>
bool readEnum(someip::PayloadReader& r, Measured<Enum>& m, std::uint8_t max) {
    std::uint8_t raw = 0;
    if (!r.readU8(raw) || !readQuality(r, m.quality)) return false;
    // Substituted values of a non-valid element may be anything: only a valid
    // element with an unknown value is malformed.
    if (raw > max) {
        if (m.quality == Quality::Valid) return false;
        raw = 0;
    }
    m.value = static_cast<Enum>(raw);
    return true;
}

bool read(someip::PayloadReader& r, Measured<DoorState>& m) {
    return readEnum(r, m, static_cast<std::uint8_t>(DoorState::Open));
}

bool read(someip::PayloadReader& r, Measured<LockState>& m) {
    return readEnum(r, m, static_cast<std::uint8_t>(LockState::SuperLocked));
}

template <typename T, typename... Members>
std::optional<T> decode(const std::vector<std::uint8_t>& payload, Members T::*... members) {
    someip::PayloadReader r(payload);
    T out;
    if ((read(r, out.*members) && ...)) {
        return out;
    }
    return std::nullopt;
}

}  // namespace

const char* toString(Quality quality) {
    switch (quality) {
        case Quality::Valid: return "VALID";
        case Quality::Invalid: return "INVALID";
        case Quality::Timeout: return "TIMEOUT";
        case Quality::E2EError: return "E2E_ERROR";
        case Quality::NotAvailable: return "NOT_AVAILABLE";
    }
    return "?";
}

std::optional<VehicleDynamics> decodeVehicleDynamics(const std::vector<std::uint8_t>& payload) {
    return decode(payload, &VehicleDynamics::speedKph, &VehicleDynamics::longitudinalAccel,
                  &VehicleDynamics::yawRateDps);
}

std::optional<SteeringWheel> decodeSteeringWheel(const std::vector<std::uint8_t>& payload) {
    return decode(payload, &SteeringWheel::angleDeg, &SteeringWheel::speedDps);
}

std::optional<DoorStatus> decodeDoorStatus(const std::vector<std::uint8_t>& payload) {
    return decode(payload, &DoorStatus::frontLeft, &DoorStatus::frontRight,
                  &DoorStatus::rearLeft, &DoorStatus::rearRight, &DoorStatus::trunk,
                  &DoorStatus::centralLock);
}

std::optional<BatteryStatus> decodeBatteryStatus(const std::vector<std::uint8_t>& payload) {
    return decode(payload, &BatteryStatus::socPercent, &BatteryStatus::packVoltage,
                  &BatteryStatus::packCurrent);
}

std::vector<std::uint8_t> encodeSetCentralLock(LockRequest request) {
    return {static_cast<std::uint8_t>(request)};
}

std::vector<std::uint8_t> encodeOpenTrunk(bool open) { return {open ? std::uint8_t{1} : std::uint8_t{0}}; }

std::vector<std::uint8_t> encodeSetCabinClimate(const CabinClimateRequest& request) {
    someip::PayloadWriter w;
    w.writeF32(request.setpointDegC);
    w.writeU8(request.fanLevel);
    return w.take();
}

}  // namespace ccg::ivi
