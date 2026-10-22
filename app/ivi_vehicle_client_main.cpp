// IVI vehicle client: consumes the HPC S2S services over vsomeip and prints
// what the Android Vehicle HAL would report. Same stack as the VHAL bridge on
// the IVI (VsomeipClientTransport -> VehicleClient -> VehiclePropertyBridge),
// usable on a Linux bench PC and on the IVI target from the shell.
//
//   VSOMEIP_CONFIGURATION=config/vsomeip/ivi_vehicle_client.json
//       ccg_ivi_vehicle_client --lock --climate 23.5:4 --duration-s 10
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <cstdio>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ccg/ivi/vehicle_client.hpp"
#include "ccg/ivi/vehicle_property_bridge.hpp"
#include "vehicle_s2s_matrix.hpp"
#include "vsomeip_client_transport.hpp"

namespace {

using namespace ccg;
using namespace ccg::ivi;
using namespace ccg::ivi::vhal;
namespace ids = config::ids;

std::atomic<bool> g_running{true};
void onSignal(int) { g_running = false; }

struct Command {
    std::string label;
    std::uint16_t service;
    PropertyValue value;
};

PropertyValue propertyValue(std::int32_t prop, std::int32_t areaId, std::vector<std::int32_t> ints,
                            std::vector<float> floats = {}) {
    PropertyValue v;
    v.prop = prop;
    v.areaId = areaId;
    v.int32Values = std::move(ints);
    v.floatValues = std::move(floats);
    return v;
}

std::string format(const PropertyValue& v) {
    std::string s = std::string(propertyName(v.prop));
    if (v.areaId != 0) {
        char area[16];
        std::snprintf(area, sizeof area, "[0x%X]", static_cast<unsigned>(v.areaId));
        s += area;
    }
    s += " ";
    if (v.status != PropertyStatus::Available) return s + toString(v.status);
    for (const auto i : v.int32Values) s += std::to_string(i) + " ";
    for (const auto f : v.floatValues) s += std::to_string(f) + " ";
    return s;
}

}  // namespace

int main(int argc, char** argv) {
    std::string appName = "ccg_ivi_vehicle";
    int durationS = 0;
    bool expectAll = false;
    std::vector<Command> commands;
    const std::int32_t hvac = BridgeOptions{}.hvacAreaId;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto value = [&]() -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "missing value for " << arg << "\n";
                std::exit(EXIT_FAILURE);
            }
            return argv[++i];
        };
        if (arg == "--app") {
            appName = value();
        } else if (arg == "--duration-s") {
            durationS = std::stoi(value());
        } else if (arg == "--expect-all-services") {
            expectAll = true;
        } else if (arg == "--lock" || arg == "--unlock") {
            commands.push_back({arg.substr(2), ids::kBodyService,
                                propertyValue(prop::kDoorLock, area::kDoorRow1Left,
                                              {arg == "--lock" ? 1 : 0})});
        } else if (arg == "--trunk") {
            commands.push_back({"trunk", ids::kBodyService,
                                propertyValue(prop::kDoorPos, area::kDoorRear, {2})});
        } else if (arg == "--climate") {
            const std::string v = value();
            const auto colon = v.find(':');
            if (colon == std::string::npos) {
                std::cerr << "expected --climate DEGC:FAN\n";
                return EXIT_FAILURE;
            }
            commands.push_back({"temperature " + v.substr(0, colon), ids::kClimateService,
                                propertyValue(prop::kHvacTemperatureSet, hvac, {},
                                              {std::stof(v.substr(0, colon))})});
            commands.push_back({"fan " + v.substr(colon + 1), ids::kClimateService,
                                propertyValue(prop::kHvacFanSpeed, hvac,
                                              {std::stoi(v.substr(colon + 1))})});
        } else {
            std::cerr << "usage: " << argv[0]
                      << " [--app NAME] [--duration-s N] [--expect-all-services] [--lock|--unlock]"
                         " [--trunk] [--climate DEGC:FAN]\n";
            return EXIT_FAILURE;
        }
    }

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    platform::VsomeipClientTransport transport(appName);
    if (!transport.init()) {
        std::cerr << "vsomeip application '" << appName
                  << "' could not be initialised (check VSOMEIP_CONFIGURATION)\n";
        return EXIT_FAILURE;
    }
    VehicleClient client(transport);
    const auto t0 = Clock::now();
    VehiclePropertyBridge bridge(client, BridgeOptions{}, [t0] {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - t0).count();
    });

    std::mutex printMutex;
    auto print = [&](const std::string& line) {
        std::lock_guard<std::mutex> lock(printMutex);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
        std::cout << "[" << ms << " ms] " << line << std::endl;
    };

    // Continuous properties are printed on a status change and else at most once per second.
    std::map<std::pair<std::int32_t, std::int32_t>, std::pair<Clock::time_point, PropertyStatus>>
        lastPrinted;
    bridge.setChangeCallback([&](std::vector<PropertyValue> values) {
        for (const auto& v : values) {
            if (v.prop == prop::kPerfVehicleSpeed || v.prop == prop::kPerfSteeringAngle ||
                v.prop == prop::kEvBatteryLevel || v.prop == prop::kEvBatteryInstantaneousChargeRate) {
                std::lock_guard<std::mutex> lock(printMutex);
                auto [it, first] = lastPrinted.try_emplace({v.prop, v.areaId});
                auto& [when, status] = it->second;
                if (!first && status == v.status && Clock::now() - when < std::chrono::seconds(1)) {
                    continue;
                }
                when = Clock::now();
                status = v.status;
            }
            print("VHAL event " + format(v));
        }
    });

    struct AvailabilityPrinter final : IVehicleListener {
        VehiclePropertyBridge& bridge;
        std::function<void(const std::string&)> print;
        std::mutex& m;
        std::condition_variable& cv;
        AvailabilityPrinter(VehiclePropertyBridge& b, std::function<void(const std::string&)> p,
                            std::mutex& mx, std::condition_variable& c)
            : bridge(b), print(std::move(p)), m(mx), cv(c) {}
        void onServiceAvailability(std::uint16_t s, bool a) override {
            char buf[64];
            std::snprintf(buf, sizeof buf, "service 0x%04X %s", s, a ? "available" : "not available");
            print(buf);
            bridge.onServiceAvailability(s, a);
            std::lock_guard<std::mutex> lock(m);
            cv.notify_all();
        }
        void onVehicleDynamics(const VehicleDynamics& d) override { bridge.onVehicleDynamics(d); }
        void onSteeringWheel(const SteeringWheel& s) override { bridge.onSteeringWheel(s); }
        void onDoorStatus(const DoorStatus& d) override { bridge.onDoorStatus(d); }
        void onBatteryStatus(const BatteryStatus& b) override { bridge.onBatteryStatus(b); }
    };
    std::mutex stateMutex;
    std::condition_variable stateCv;
    AvailabilityPrinter listener(bridge, print, stateMutex, stateCv);
    client.setListener(&listener);

    transport.setClient(&client);
    client.start();
    transport.start();

    // Request supervision.
    std::thread timer([&] {
        while (g_running) {
            client.mainFunction(Clock::now());
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });

    const auto deadline = durationS > 0 ? t0 + std::chrono::seconds(durationS)
                                        : Clock::time_point::max();
    bool ok = true;
    for (const auto& cmd : commands) {
        {
            std::unique_lock<std::mutex> lock(stateMutex);
            stateCv.wait_until(lock, deadline, [&] {
                return !g_running || client.isAvailable(cmd.service);
            });
        }
        if (!client.isAvailable(cmd.service)) {
            print("command " + cmd.label + ": service not available");
            ok = false;
            break;
        }
        std::promise<StatusCode> result;
        bridge.set(cmd.value, [&result](StatusCode c) { result.set_value(c); });
        const auto code = result.get_future().get();
        print("command " + cmd.label + ": " + toString(code));
        ok = ok && code == StatusCode::Ok;
    }

    while (g_running && Clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    g_running = false;
    timer.join();

    if (expectAll) {
        for (const auto& svc : hpcServices()) {
            if (!client.isAvailable(svc.serviceId)) {
                print(std::string("service ") + svc.name + " never became available");
                ok = false;
            }
        }
    }
    client.setListener(nullptr);
    transport.setClient(nullptr);
    transport.stop();

    const auto s = client.statistics();
    print("statistics: notifications=" + std::to_string(s.notifications) +
          " malformed=" + std::to_string(s.malformed) + " requests=" + std::to_string(s.requestsSent) +
          " responses=" + std::to_string(s.responses) + " errors=" + std::to_string(s.errors) +
          " timeouts=" + std::to_string(s.timeouts));
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
