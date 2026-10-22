// HPC bench: the S2S gateway on vsomeip (SOME/IP-SD) with simulated ECUs on a
// virtual CAN bus instead of SocketCAN. Used to bring up and test SOME/IP
// clients such as the Android IVI without vehicle hardware.
//
// The simulated BCM is closed loop: it applies the HPC_BodyCommand requests to
// its central lock / trunk state, so a lock request from the IVI comes back as
// a DoorStatus field update.
//
//   VSOMEIP_CONFIGURATION=config/vsomeip/hpc_s2s_gateway.json ccg_hpc_vsomeip_bench
#include <poll.h>

#include <atomic>
#include <cmath>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>

#include "ccg/can/signal_codec.hpp"
#include "ccg/e2e/can_e2e.hpp"
#include "ccg/s2s/s2s_gateway.hpp"
#include "vehicle_s2s_matrix.hpp"
#include "vsomeip_server_binding.hpp"

namespace {

using namespace ccg;
using namespace std::chrono_literals;

std::atomic<bool> g_running{true};
void onSignal(int) { g_running = false; }

const can::SignalSpec& signal(const std::vector<can::SignalSpec>& signals, const char* name) {
    for (const auto& s : signals) {
        if (s.name == name) return s;
    }
    throw std::invalid_argument(std::string("unknown signal ") + name);
}

// Virtual CAN bus: HPC Tx frames go to the simulated ECUs.
class VirtualVehicle final : public s2s::ICanTransmitter {
public:
    explicit VirtualVehicle(const s2s::GatewayConfig& cfg) : cfg_(cfg) {}

    bool transmit(const can::CanFrame& f) override {
        for (const auto& m : cfg_.txMessages) {
            if (m.canId != f.id) continue;
            std::string decoded;
            for (const auto& s : m.signals) {
                const double v = can::rawToPhysical(s, can::extractRaw(f.data.data(), s));
                decoded += " " + s.name + "=" + std::to_string(v);
            }
            // Print only frames that differ from the previous one of the PDU.
            if (decoded != lastTx_[m.name]) {
                std::cout << "[can] TX " << m.name << decoded << std::endl;
                lastTx_[m.name] = decoded;
            }
            if (m.name == "HPC_BodyCommand") {
                const auto lockReq = can::extractRaw(f.data.data(), signal(m.signals, "HPC_CentralLockReq"));
                if (lockReq == 1) locked_ = 1;
                if (lockReq == 2) locked_ = 0;
                if (can::extractRaw(f.data.data(), signal(m.signals, "HPC_TrunkOpenReq")) == 1) {
                    trunk_ = 2;
                }
            }
        }
        return true;
    }

    // Frames of the simulated ECUs for the time since start.
    std::vector<can::CanFrame> rxFrames(int ms) {
        std::vector<can::CanFrame> out;
        if (ms % 10 == 0) {
            const double speed = 60.0 + 20.0 * std::sin(ms / 5000.0);
            out.push_back(frame("ESP_VehicleSpeed", {{"ESP_VehSpd", speed},
                                                     {"ESP_LongAccel", 0.5},
                                                     {"ESP_YawRate", 1.2}}));
            out.push_back(frame("EPS_SteeringAngle", {{"EPS_SteerWhlAng", 45.0},
                                                      {"EPS_SteerWhlSpd", 0.0}}));
        }
        if (ms % 100 == 0) {
            out.push_back(frame("BCM_DoorStatus", {{"BCM_DoorFLSts", 0},
                                                   {"BCM_DoorFRSts", 0},
                                                   {"BCM_DoorRLSts", 0},
                                                   {"BCM_DoorRRSts", 1},
                                                   {"BCM_TrunkSts", static_cast<double>(trunk_)},
                                                   {"BCM_CentralLockSts", static_cast<double>(locked_)}}));
            out.push_back(frame("BMS_PackStatus", {{"BMS_SoC", 76.4},
                                                   {"BMS_PackVolt", 398.7},
                                                   {"BMS_PackCurr", 25.0}}));
        }
        return out;
    }

private:
    can::CanFrame frame(const std::string& message,
                        std::initializer_list<std::pair<const char*, double>> physical) {
        for (const auto& m : cfg_.rxMessages) {
            if (m.name != message) continue;
            can::CanFrame f;
            f.id = m.canId;
            f.length = m.length;
            for (const auto& [name, value] : physical) {
                const auto& s = signal(m.signals, name);
                can::insertRaw(f.data.data(), s, can::physicalToRaw(s, value));
            }
            if (m.e2e) {
                auto it = senders_.find(message);
                if (it == senders_.end()) it = senders_.emplace(message, e2e::CanE2ESender(*m.e2e)).first;
                it->second.protect(f.data.data(), f.length);
            }
            return f;
        }
        throw std::invalid_argument("unknown message " + message);
    }

    const s2s::GatewayConfig& cfg_;
    std::map<std::string, e2e::CanE2ESender> senders_;
    std::map<std::string, std::string> lastTx_;
    int locked_ = 0;
    int trunk_ = 0;
};

}  // namespace

int main(int argc, char** argv) {
    const std::string appName = argc > 1 ? argv[1] : "ccg_s2s_gateway";
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    auto config = config::makeVehicleS2SMatrix();
    VirtualVehicle vehicle(config);
    platform::VsomeipServerBinding someip(appName);
    if (!someip.init(config)) {
        std::cerr << "vsomeip application '" << appName << "' could not be initialised\n";
        return EXIT_FAILURE;
    }
    s2s::S2SGateway gateway(config, vehicle, someip);
    const auto t0 = s2s::Clock::now();
    gateway.start(t0);
    someip.start();
    std::cout << "[bench] HPC S2S gateway with virtual vehicle running" << std::endl;

    int tick = 0;
    auto next = t0;
    pollfd fds[1] = {{someip.fd(), POLLIN, 0}};
    while (g_running) {
        auto now = s2s::Clock::now();
        const auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(next - now).count();
        if (::poll(fds, 1, wait > 0 ? static_cast<int>(wait) : 0) > 0) {
            now = s2s::Clock::now();
            for (auto& in : someip.receive()) {
                if (in.kind == platform::VsomeipServerBinding::Inbound::Kind::Request) {
                    std::cout << "[someip] request 0x" << std::hex << in.message.header.serviceId
                              << ".0x" << in.message.header.methodId << std::dec << std::endl;
                    gateway.onSomeIpRequest(in.message, in.context, now);
                } else {
                    std::cout << "[someip] subscribe 0x" << std::hex << in.serviceId << " eventgroup 0x"
                              << in.eventgroupId << " client 0x" << (in.context.peer.token & 0xFFFF)
                              << std::dec << std::endl;
                    gateway.onSubscribe(in.serviceId, in.context.instanceId, in.eventgroupId,
                                        in.context.peer, now);
                }
            }
        }
        now = s2s::Clock::now();
        while (now >= next) {
            for (const auto& f : vehicle.rxFrames(tick * 5)) gateway.onCanFrame(f, next);
            gateway.mainFunction(next);
            ++tick;
            next += 5ms;
        }
    }
    someip.stop();
    const auto& s = gateway.statistics();
    std::cout << "[bench] notifications=" << s.notificationsSent << " requests=" << s.requestsReceived
              << " responses=" << s.responsesSent << " errors=" << s.errorResponsesSent
              << " canTx=" << s.canTxFrames << " droppedResponses=" << someip.droppedResponses()
              << std::endl;
    return EXIT_SUCCESS;
}
