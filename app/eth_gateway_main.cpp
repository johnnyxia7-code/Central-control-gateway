// HPC central Ethernet gateway process: routes PDUs and signals between
// SocketCAN interfaces and UDP socket connections.
//
//   ccg_eth_gateway --bind PT_CAN=can0 --bind CHS_CAN=can1 --bind BODY_CAN=can2
//                   --bind ETH_ADAS=udp:30500:192.168.10.20:30500
//                   --bind ETH_IVI=udp:30501:192.168.10.30:30501
//                   --key-store /var/lib/ccg/keys --fv-store /var/lib/ccg/freshness
//
// SecOC keys: --key-store follows the key store of the key manager (written by
// ccg_diag_gateway on key updates; reloaded when it changes, rollover with
// grace period). --keys loads a static key file, --demo-keys the test keys.
#include <poll.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ccg/ethgw/ethernet_gateway.hpp"
#include "ccg/keym/key_manager.hpp"
#include "key_store.hpp"
#include "socketcan_transport.hpp"
#include "secoc_storage.hpp"
#include "udp_socket.hpp"
#include "vehicle_eth_gateway_matrix.hpp"
#include "vehicle_key_slots.hpp"

namespace {

using namespace ccg;

std::atomic<bool> g_running{true};
void onSignal(int) { g_running = false; }

struct UdpBinding {
    std::uint16_t localPort;
    std::string remoteIp;
    std::uint16_t remotePort;
};

// "udp:LOCALPORT:REMOTEIP:REMOTEPORT"
UdpBinding parseUdp(const std::string& spec) {
    const auto p1 = spec.find(':', 4);
    const auto p2 = spec.rfind(':');
    if (spec.rfind("udp:", 0) != 0 || p1 == std::string::npos || p2 == p1) {
        throw std::invalid_argument("expected udp:LOCALPORT:REMOTEIP:REMOTEPORT, got " + spec);
    }
    return {static_cast<std::uint16_t>(std::stoul(spec.substr(4, p1 - 4))),
            spec.substr(p1 + 1, p2 - p1 - 1),
            static_cast<std::uint16_t>(std::stoul(spec.substr(p2 + 1)))};
}

class LinuxTransmitter final : public ethgw::IGatewayTransmitter {
public:
    explicit LinuxTransmitter(std::size_t channels) : can(channels), udp(channels) {}

    bool transmitCan(std::size_t channel, const can::CanFrame& frame) override {
        return can[channel] && can[channel]->transmit(frame);
    }
    bool transmitEthernet(std::size_t channel, const std::vector<std::uint8_t>& datagram) override {
        return udp[channel] && udp[channel]->send(datagram);
    }

    std::vector<std::unique_ptr<platform::SocketCanTransport>> can;
    std::vector<std::unique_ptr<platform::UdpSocket>> udp;
};

void printStatistics(const ethgw::GatewayStatistics& s) {
    std::cout << "[ethgw] rx can=" << s.canFramesReceived << " dgram=" << s.datagramsReceived
              << " pdu=" << s.pdusReceived << " unrouted=" << s.unroutedPdus
              << " lenErr=" << s.lengthErrors << " malformed=" << s.malformedDatagrams
              << " e2eErr=" << s.e2eErrors << " timeouts=" << s.rxTimeouts
              << " | fwd=" << s.pdusForwarded << " sig=" << s.signalsRouted
              << " asm=" << s.assembledPdusSent << " | tx can=" << s.canFramesSent
              << " canFail=" << s.canTxFailures << " dgram=" << s.datagramsSent
              << " ethFail=" << s.ethTxFailures << " | secoc ok=" << s.secocVerified
              << " macFail=" << s.secocMacFailures << " freshFail=" << s.secocFreshnessFailures
              << " protected=" << s.secocProtected
              << " maxCollect=" << s.maxDatagramCollectionDelay.count() << "ms\n";
}

}  // namespace

int main(int argc, char** argv) {
    std::map<std::string, std::string> bindings;
    int periodMs = 1;
    std::string keyFile;
    std::string fvStore;
    std::string keyStore;
    bool demoKeys = false;
    try {
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--demo-keys") {
                demoKeys = true;
                continue;
            }
            if ((arg == "--bind" || arg == "--period-ms" || arg == "--keys" || arg == "--fv-store" ||
                 arg == "--key-store") &&
                i + 1 < argc) {
                const std::string value = argv[++i];
                if (arg == "--period-ms") {
                    periodMs = std::stoi(value);
                    continue;
                }
                if (arg == "--keys") {
                    keyFile = value;
                    continue;
                }
                if (arg == "--fv-store") {
                    fvStore = value;
                    continue;
                }
                if (arg == "--key-store") {
                    keyStore = value;
                    continue;
                }
                const auto eq = value.find('=');
                if (eq == std::string::npos) throw std::invalid_argument("expected NAME=TARGET");
                bindings[value.substr(0, eq)] = value.substr(eq + 1);
            } else {
                throw std::invalid_argument("unknown argument " + arg);
            }
        }
        if (periodMs <= 0) throw std::invalid_argument("--period-ms must be > 0");
        if (!keyStore.empty() && (demoKeys || !keyFile.empty())) {
            throw std::invalid_argument("--key-store excludes --keys and --demo-keys");
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\nusage: " << argv[0]
                  << " --bind CHANNEL=IFACE | --bind CHANNEL=udp:LPORT:IP:RPORT ... "
                     "(--key-store FILE | --keys FILE | --demo-keys) [--fv-store FILE] [--period-ms N]\n";
        return EXIT_FAILURE;
    }

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    try {
        auto config = config::makeVehicleEthGatewayMatrix();
        LinuxTransmitter transmitter(config.channels.size());

        // Kernel acceptance filters: only identifiers the gateway routes.
        std::set<std::string> sources;
        for (const auto& r : config.pduRoutes) sources.insert(r.source);
        for (const auto& r : config.signalRoutes) sources.insert(r.source.pdu);
        std::map<std::string, std::vector<std::pair<std::uint32_t, bool>>> filters;
        for (const auto& p : config.pdus) {
            if (sources.count(p.name)) filters[p.channel].emplace_back(p.id, p.extended);
        }

        std::vector<pollfd> fds;
        std::vector<std::size_t> fdChannel;
        for (std::size_t c = 0; c < config.channels.size(); ++c) {
            const auto& ch = config.channels[c];
            const auto it = bindings.find(ch.name);
            if (it == bindings.end()) {
                throw std::invalid_argument("channel " + ch.name + " is not bound (--bind)");
            }
            if (ch.type == ethgw::BusType::Ethernet) {
                const auto u = parseUdp(it->second);
                transmitter.udp[c] =
                    std::make_unique<platform::UdpSocket>(u.localPort, u.remoteIp, u.remotePort);
                fds.push_back({transmitter.udp[c]->fd(), POLLIN, 0});
            } else {
                transmitter.can[c] = std::make_unique<platform::SocketCanTransport>(
                    it->second, ch.type == ethgw::BusType::CanFd);
                transmitter.can[c]->setReceiveFilter(filters[ch.name]);
                fds.push_back({transmitter.can[c]->fd(), POLLIN, 0});
            }
            fdChannel.push_back(c);
            std::cout << "[ethgw] " << ch.name << " (" << ethgw::toString(ch.type) << ") -> "
                      << it->second << "\n";
        }

        // SecOC keys (HSM on the target) and persisted freshness counters.
        secoc::SoftwareCryptoService crypto;
        keym::KeyManager keyManager(config::makeVehicleKeySlots());
        std::unique_ptr<platform::FileWatcher> keyWatcher;
        auto reloadKeys = [&](ethgw::TimePoint t) {
            const auto snapshot = platform::loadKeyStore(keyStore);
            if (!snapshot) throw std::runtime_error("key store " + keyStore + " missing");
            keyManager.restore(*snapshot, t);
            std::cout << "[ethgw] key store " << keyStore << " (re)loaded: " << snapshot->keys.size() << " keys\n";
        };
        if (!keyStore.empty()) {
            keyWatcher = std::make_unique<platform::FileWatcher>(keyStore);
            reloadKeys(ethgw::Clock::now());
        }
        if (!keyFile.empty()) {
            std::cout << "[ethgw] " << platform::loadKeyFile(keyFile, crypto) << " SecOC key(s) loaded\n";
        }
        if (demoKeys) {
            std::cout << "[ethgw] WARNING: built-in SecOC TEST KEYS in use - bench only\n";
            config::provisionDemoSecOcKeys(crypto);
        }
        secoc::ICryptoService* cryptoService = keyStore.empty() ? static_cast<secoc::ICryptoService*>(&crypto)
                                                                : &keyManager;
        ethgw::EthernetGateway gateway(std::move(config), transmitter, cryptoService);
        if (!fvStore.empty()) {
            if (const auto snapshot = platform::loadFreshness(fvStore)) {
                gateway.freshness().restore(*snapshot);
                std::cout << "[ethgw] freshness counters restored from " << fvStore << "\n";
            }
            gateway.freshness().setPersistence([&](const secoc::FreshnessManager::Snapshot& snapshot) {
                if (!platform::saveFreshness(fvStore, snapshot)) {
                    throw std::runtime_error("cannot persist freshness counters to " + fvStore);
                }
            });
        } else {
            std::cout << "[ethgw] WARNING: freshness counters not persisted (no --fv-store) - bench only\n";
        }
        const auto period = std::chrono::milliseconds(periodMs);
        auto now = ethgw::Clock::now();
        gateway.start(now);
        if (!gateway.freshnessMasterActive()) {
            std::cout << "[ethgw] WARNING: FV master inactive (trip counter exhausted) - "
                         "synchronised SecOC PDUs cannot be sent\n";
        }
        auto nextTick = now + period;
        auto nextStats = now + std::chrono::seconds(10);
        auto nextKeyCheck = now + std::chrono::seconds(1);
        std::vector<std::uint8_t> datagram;

        while (g_running) {
            now = ethgw::Clock::now();
            const auto wait =
                std::chrono::duration_cast<std::chrono::milliseconds>(nextTick - now).count();
            const int ready = ::poll(fds.data(), fds.size(), wait > 0 ? static_cast<int>(wait) : 0);
            now = ethgw::Clock::now();
            if (ready > 0) {
                for (std::size_t i = 0; i < fds.size(); ++i) {
                    if (!(fds[i].revents & POLLIN)) continue;
                    const std::size_t c = fdChannel[i];
                    if (transmitter.can[c]) {
                        while (auto frame = transmitter.can[c]->receive()) {
                            gateway.onCanFrame(c, *frame, now);
                        }
                    } else {
                        while (transmitter.udp[c]->receive(datagram)) {
                            gateway.onEthernetDatagram(c, datagram.data(), datagram.size(), now);
                        }
                    }
                }
            }
            if (now >= nextTick) {
                if (keyWatcher) {
                    keyManager.mainFunction(now);
                    if (now >= nextKeyCheck) {
                        nextKeyCheck = now + std::chrono::seconds(1);
                        if (keyWatcher->changed()) {
                            try {
                                reloadKeys(now);  // keys updated / activated over UDS
                            } catch (const std::exception& e) {
                                std::cerr << "[ethgw] keeping current keys: " << e.what() << "\n";
                            }
                        }
                    }
                }
                gateway.mainFunction(now);
                nextTick += period;
                if (nextTick <= now) nextTick = now + period;
            }
            if (now >= nextStats) {
                printStatistics(gateway.statistics());
                if (keyWatcher) {
                    std::cout << "[ethgw] keym rollover verifications=" << keyManager.rolloverVerifications() << "\n";
                }
                nextStats = now + std::chrono::seconds(10);
            }
        }
        printStatistics(gateway.statistics());
    } catch (const ethgw::RoutingConfigError& e) {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
