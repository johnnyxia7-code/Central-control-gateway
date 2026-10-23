// HPC S2S gateway process: SocketCAN <-> SOME/IP via vsomeip (with SOME/IP-SD).
//
//   VSOMEIP_CONFIGURATION=config/vsomeip/hpc_s2s_gateway.json ccg_s2s_gateway_vsomeip --can vcan0
#include <poll.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <string>

#include "ccg/s2s/s2s_gateway.hpp"
#include "socketcan_transport.hpp"
#include "vehicle_s2s_matrix.hpp"
#include "vsomeip_server_binding.hpp"

namespace {

std::atomic<bool> g_running{true};

void onSignal(int) { g_running = false; }

struct Options {
    std::string canInterface = "vcan0";
    bool canFd = false;
    std::string appName = "ccg_s2s_gateway";
    int periodMs = 5;
};

bool parseOptions(int argc, char** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto value = [&]() -> std::string {
            if (i + 1 >= argc) throw std::invalid_argument("missing value for " + arg);
            return argv[++i];
        };
        if (arg == "--can") {
            opt.canInterface = value();
        } else if (arg == "--fd") {
            opt.canFd = true;
        } else if (arg == "--app") {
            opt.appName = value();
        } else if (arg == "--period-ms") {
            opt.periodMs = std::stoi(value());
        } else {
            return false;
        }
    }
    return opt.periodMs > 0;
}

}  // namespace

int main(int argc, char** argv) {
    using namespace ccg;
    Options opt;
    try {
        if (!parseOptions(argc, argv, opt)) {
            std::cerr << "usage: " << argv[0]
                      << " [--can IFACE] [--fd] [--app VSOMEIP_APP_NAME] [--period-ms N]\n";
            return EXIT_FAILURE;
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    }

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    try {
        auto config = config::makeVehicleS2SMatrix();

        platform::SocketCanTransport can(opt.canInterface, opt.canFd);
        std::vector<std::pair<std::uint32_t, bool>> rxIds;
        for (const auto& m : config.rxMessages) rxIds.emplace_back(m.canId, m.extended);
        can.setReceiveFilter(rxIds);

        platform::VsomeipServerBinding someip(opt.appName);
        if (!someip.init(config)) {
            std::cerr << "vsomeip application '" << opt.appName
                      << "' could not be initialised (check VSOMEIP_CONFIGURATION)\n";
            return EXIT_FAILURE;
        }

        s2s::S2SGateway gateway(std::move(config), can, someip);
        const auto period = std::chrono::milliseconds(opt.periodMs);
        auto now = s2s::Clock::now();
        gateway.start(now);  // offers the services (SOME/IP-SD once the network is up)
        someip.start();
        std::cout << "[s2s] running on " << opt.canInterface << ", vsomeip application '"
                  << opt.appName << "'\n";

        auto nextTick = now + period;
        pollfd fds[2] = {{can.fd(), POLLIN, 0}, {someip.fd(), POLLIN, 0}};
        while (g_running) {
            now = s2s::Clock::now();
            const auto wait =
                std::chrono::duration_cast<std::chrono::milliseconds>(nextTick - now).count();
            const int ready = ::poll(fds, 2, wait > 0 ? static_cast<int>(wait) : 0);
            now = s2s::Clock::now();
            if (ready > 0) {
                if (fds[0].revents & POLLIN) {
                    while (auto frame = can.receive()) {
                        gateway.onCanFrame(*frame, now);
                    }
                }
                if (fds[1].revents & POLLIN) {
                    for (auto& in : someip.receive()) {
                        if (in.kind == platform::VsomeipServerBinding::Inbound::Kind::Request) {
                            gateway.onSomeIpRequest(in.message, in.context, now);
                        } else {
                            gateway.onSubscribe(in.serviceId, in.context.instanceId,
                                                in.eventgroupId, in.context.peer, now);
                        }
                    }
                }
            }
            if (now >= nextTick) {
                gateway.mainFunction(now);
                nextTick += period;
                if (nextTick <= now) nextTick = now + period;
            }
        }
        someip.stop();
        const auto& s = gateway.statistics();
        std::cout << "[s2s] rx accepted=" << s.canRxAccepted << " notif=" << s.notificationsSent
                  << " req=" << s.requestsReceived << " resp=" << s.responsesSent
                  << " err=" << s.errorResponsesSent << " canTx=" << s.canTxFrames << "\n";
    } catch (const s2s::ConfigError& e) {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
