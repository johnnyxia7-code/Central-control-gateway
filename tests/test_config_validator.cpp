#include <string>

#include "ccg/s2s/s2s_config.hpp"
#include "test_framework.hpp"
#include "vehicle_s2s_matrix.hpp"

using namespace ccg;
using namespace ccg::s2s;

namespace {

bool contains(const std::vector<std::string>& errors, const std::string& needle) {
    for (const auto& e : errors) {
        if (e.find(needle) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

TEST_CASE("validator: reference vehicle matrix is consistent") {
    const auto errors = validateConfig(config::makeVehicleS2SMatrix());
    for (const auto& e : errors) std::cerr << "    " << e << "\n";
    CHECK(errors.empty());
}

TEST_CASE("validator: overlapping signals and E2E bytes") {
    auto cfg = config::makeVehicleS2SMatrix();
    cfg.rxMessages[0].signals[1].startBit = 8;  // ESP_LongAccel over ESP_VehSpd
    cfg.rxMessages[1].signals[1].startBit = 55;  // EPS speed over the E2E counter/CRC
    const auto errors = validateConfig(cfg);
    CHECK(contains(errors, "'ESP_LongAccel' overlaps 'ESP_VehSpd'"));
    CHECK(contains(errors, "overlaps 'E2E_CRC'") || contains(errors, "'E2E_CRC' overlaps"));
}

TEST_CASE("validator: signal outside payload and bad length") {
    auto cfg = config::makeVehicleS2SMatrix();
    cfg.rxMessages[2].length = 2;  // BCM_DoorStatus: lock status lives in byte 2
    cfg.txMessages[0].length = 9;  // classic CAN max 8
    const auto errors = validateConfig(cfg);
    CHECK(contains(errors, "'BCM_CentralLockSts' does not fit"));
    CHECK(contains(errors, "HPC_BodyCommand': invalid payload length 9"));
}

TEST_CASE("validator: SOME/IP ID rules and dangling references") {
    auto cfg = config::makeVehicleS2SMatrix();
    cfg.events[0].eventId = 0x0001;                       // event without bit 15
    cfg.events[2].elements[0].source.signal = "Missing";  // unknown Rx signal
    cfg.methods[0].methodId = 0x8010;                     // method with bit 15
    cfg.methods[1].methodId = cfg.methods[0].methodId;    // duplicate ID
    cfg.methods[2].serviceId = 0x7777;                    // service not offered
    const auto errors = validateConfig(cfg);
    CHECK(contains(errors, "event 'VehicleDynamics': event ID 0x1 must have bit 15 set"));
    CHECK(contains(errors, "unknown Rx signal BCM_DoorStatus.Missing"));
    CHECK(contains(errors, "method 'SetCentralLock': method ID 0x8010 must have bit 15 clear"));
    CHECK(contains(errors, "method 'OpenTrunk': ID 0x8010 already used"));
    CHECK(contains(errors, "method 'SetCabinClimate': service 0x7777/0x1 not configured"));
}

TEST_CASE("validator: Tx message that is never sent") {
    auto cfg = config::makeVehicleS2SMatrix();
    cfg.txMessages[1].cycleTime = Milliseconds{0};
    cfg.txMessages[1].eventRepetitions = 0;
    CHECK(contains(validateConfig(cfg), "neither cyclic nor event transmission"));
}
