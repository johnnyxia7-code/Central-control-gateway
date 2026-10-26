// HPC S2S gateway process: SocketCAN <-> SOME/IP (UDP, static SD).
//
//   ccg_s2s_gateway --can vcan0 --port 30490 --subscriber 127.0.0.1:30501
#include <arpa/inet.h>
#include <poll.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "ccg/s2s/s2s_gateway.hpp"
#include "socketcan_transport.hpp"
#include "someip_udp_binding.hpp"
#include "vehicle_s2s_matrix.hpp"

namespace {

std::atomic<bool> g_running{true};

void onSignal(int) { g_running = false; }

struct Options {
    std::string canInterface = "vcan0";
    bool canFd = false;
    std::uint16_t port = 30490;
    std::vector<std::pair<std::string, std::uint16_t>> subscribers;
    int periodMs = 5;
};

void usage(const char* argv0) {
    std::cerr << "usage: " << argv0
              << " [--can IFACE] [--fd] [--port UDP_PORT] [--subscriber IP:PORT]... "
                 "[--period-ms N]\n";
}

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
        } else if (arg == "--port") {
            opt.port = static_cast<std::uint16_t>(std::stoul(value()));
        } else if (arg == "--subscriber") {
            const std::string v = value();
            const auto colon = v.rfind(':');
            if (colon == std::string::npos) throw std::invalid_argument("expected IP:PORT");
            opt.subscribers.emplace_back(v.substr(0, colon),
                                         static_cast<std::uint16_t>(std::stoul(v.substr(colon + 1))));
        } else if (arg == "--period-ms") {
            opt.periodMs = std::stoi(value());
        } else {
            return false;
        }
    }
    return opt.periodMs > 0;
}

void printStatistics(const ccg::s2s::Statistics& s) {
    std::cout << "[s2s] rx accepted=" << s.canRxAccepted << " unknown=" << s.canRxUnknownId
              << " dlcErr=" << s.canRxLengthError << " e2eCrc=" << s.e2eCrcErrors
              << " e2eSeq=" << s.e2eSequenceErrors << " e2eRep=" << s.e2eRepeated
              << " timeouts=" << s.rxTimeouts << " | notif=" << s.notificationsSent
              << " req=" << s.requestsReceived << " resp=" << s.responsesSent
              << " err=" << s.errorResponsesSent << " drop=" << s.requestsDropped
              << " | canTx=" << s.canTxFrames << " canTxFail=" << s.canTxFailures << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    using namespace ccg;
    Options opt;
    try {
        if (!parseOptions(argc, argv, opt)) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        usage(argv[0]);
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

        platform::SomeIpUdpBinding someip(opt.port, config::ids::kInstance);
        std::set<std::tuple<std::uint16_t, std::uint16_t, std::uint16_t>> eventgroups;
        for (const auto& e : config.events) {
            eventgroups.insert({e.serviceId, e.instanceId, e.eventgroupId});
        }
        for (const auto& [ip, port] : opt.subscribers) {
            for (const auto& [svc, inst, eg] : eventgroups) {
                someip.addStaticSubscriber(svc, inst, eg, ip, port);
            }
        }

        s2s::S2SGateway gateway(std::move(config), can, someip);
        const auto period = std::chrono::milliseconds(opt.periodMs);
        auto now = s2s::Clock::now();
        gateway.start(now);

        // With static SD every subscriber is subscribed from the start: send initial fields.
        for (const auto& [ip, port] : opt.subscribers) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            ::inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
            for (const auto& [svc, inst, eg] : eventgroups) {
                gateway.onSubscribe(svc, inst, eg, platform::SomeIpUdpBinding::toPeer(addr), now);
            }
        }

        std::cout << "[s2s] running on " << opt.canInterface << ", SOME/IP UDP port " << opt.port
                  << ", main function " << opt.periodMs << " ms\n";

        auto nextTick = now + period;
        auto nextStats = now + std::chrono::seconds(10);
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
                    for (auto& rx : someip.receive()) {
                        gateway.onSomeIpRequest(rx.message, rx.context, now);
                    }
                }
            }
            if (now >= nextTick) {
                gateway.mainFunction(now);
                nextTick += period;
                if (nextTick <= now) nextTick = now + period;
            }
            if (now >= nextStats) {
                printStatistics(gateway.statistics());
                nextStats = now + std::chrono::seconds(10);
            }
        }
        printStatistics(gateway.statistics());
    } catch (const s2s::ConfigError& e) {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
