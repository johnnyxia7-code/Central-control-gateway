// HPC diagnostic gateway process: DoIP (TCP/UDP 13400, TLS 3496) <-> UDS on CAN (ISO-TP).
//
//   ccg_diag_gateway --can PT_CAN=can0 --can CHS_CAN=can1 --can BODY_CAN=can2
//                    [--port 13400] [--broadcast 255.255.255.255]
//                    [--key-store /var/lib/ccg/keys [--demo-keys]] [--doip ADAS=192.168.10.20:13400]
//                    [--tls-cert gw.pem --tls-key gw.key [--tls-ca testers.pem]
//                     [--tls-require-client-cert] [--tls-only] [--tls-port 3496]]
//
// DoIP over TLS (ISO 13400-2:2019): testers connect to the TLS port; with
// --tls-ca their client certificates are verified, and a verified tester may
// use central security activation (0xE0) and the key management routines that
// change keys. --tls-only refuses routing activation on the plain port (0x07).
//
// With --key-store the gateway's own diagnostic address also serves the SecOC
// key management routines (SHE key update, activation, key status); the file
// is the gateway's key store and is followed by ccg_eth_gateway. The gateway
// is also the in-vehicle key master: RoutineControl 31 01 F210 distributes new
// SecOC keys to the ECUs (31 03 F210: results) - to CAN ECUs over ISO-TP and
// to Ethernet ECUs (ADAS) as DoIP client (--doip overrides their endpoints).
// Tester requests to the Ethernet ECUs are routed DoIP-to-DoIP through the
// same client, with the tester's source address.
#include <poll.h>

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/diag/doip_client.hpp"
#include "ccg/keym/key_management_service.hpp"
#include "ccg/keym/key_master.hpp"
#include "doip_sockets.hpp"
#ifdef CCG_HAVE_TLS
#include "doip_tls_server.hpp"
#endif
#include "doip_tcp_connector.hpp"
#include "key_store.hpp"
#include "socketcan_transport.hpp"
#include "system_random.hpp"
#include "vehicle_diag_routing.hpp"
#include "vehicle_key_master.hpp"
#include "vehicle_key_slots.hpp"

namespace {

using namespace ccg;

std::atomic<bool> g_running{true};
void onSignal(int) { g_running = false; }

class LinuxDiagTransport final : public diag::IDiagTransport {
public:
    LinuxDiagTransport(platform::DoipTcpServer& tcp, platform::DoipUdpSocket& udp, std::size_t channels)
        : can(channels), tcp_(tcp), udp_(udp) {}

    // A failed send is detected as a closed socket by the next read.
    void sendTcp(diag::ConnectionId c, const std::vector<std::uint8_t>& d) override {
#ifdef CCG_HAVE_TLS
        if (tls && tls->owns(c)) {
            tls->send(c, d);
            return;
        }
#endif
        tcp_.send(c, d);
    }
    void closeTcp(diag::ConnectionId c) override {
#ifdef CCG_HAVE_TLS
        if (tls && tls->owns(c)) {
            tls->close(c);
            return;
        }
#endif
        tcp_.close(c);
    }
    void sendUdp(const diag::UdpPeer& p, const std::vector<std::uint8_t>& d) override { udp_.sendTo(p, d); }
    void broadcastUdp(const std::vector<std::uint8_t>& d) override { udp_.broadcast(d); }
    bool transmitCan(std::size_t ch, const can::CanFrame& f) override {
        return can[ch] && can[ch]->transmit(f);
    }

    std::vector<std::unique_ptr<platform::SocketCanTransport>> can;
#ifdef CCG_HAVE_TLS
    platform::DoipTlsServer* tls = nullptr;
#endif

private:
    platform::DoipTcpServer& tcp_;
    platform::DoipUdpSocket& udp_;
};

void printStatistics(const diag::DiagStatistics& s) {
    std::cout << "[diag] tcp open/closed=" << s.tcpConnectionsAccepted << "/" << s.tcpConnectionsClosed
              << " activation ok/rej=" << s.routingActivationsAccepted << "/"
              << s.routingActivationsRejected << " | req=" << s.diagRequests
              << " ack=" << s.diagAcks << " nack=" << s.diagNacks
              << " func=" << s.functionalRequests << " local=" << s.localRequests
              << " tls=" << s.tlsConnections << " certified=" << s.authenticatedConnections
              << " | ecuResp=" << s.ecuResponses << " dropped=" << s.responsesDropped
              << " tpTxErr=" << s.isotpTxErrors << " tpRxErr=" << s.isotpRxErrors << "\n";
}

// Prints key management events not printed yet (security log).
void printKeyEvents(const keym::KeyManager& keys, std::uint64_t& seen) {
    const auto& events = keys.events();
    const auto fresh = std::min<std::uint64_t>(keys.eventCount() - seen, events.size());
    for (auto it = events.end() - static_cast<std::ptrdiff_t>(fresh); it != events.end(); ++it) {
        std::cout << "[keym] " << keym::toString(it->kind) << " slot " << int{it->slot} << " counter "
                  << it->counter;
        if (it->error != keym::she::ErrorCode::NoError) std::cout << " " << keym::she::toString(it->error);
        std::cout << "\n";
    }
    seen = keys.eventCount();
}

}  // namespace

int main(int argc, char** argv) {
    std::map<std::string, std::string> canBindings;
    std::uint16_t port = doip::kPort;
    std::string broadcast = "255.255.255.255";
    std::string keyStore;
    bool demoKeys = false;
    std::map<std::string, std::string> doipEndpoints;
    std::string tlsCert, tlsKey, tlsCa;
    bool tlsRequireClientCert = false;
    bool tlsOnly = false;
    std::uint16_t tlsPort = 3496;
    try {
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--demo-keys") {
                demoKeys = true;
                continue;
            }
            if (arg == "--tls-require-client-cert") {
                tlsRequireClientCert = true;
                continue;
            }
            if (arg == "--tls-only") {
                tlsOnly = true;
                continue;
            }
            if (i + 1 >= argc) throw std::invalid_argument("missing value for " + arg);
            const std::string value = argv[++i];
            if (arg == "--can") {
                const auto eq = value.find('=');
                if (eq == std::string::npos) throw std::invalid_argument("expected CHANNEL=IFACE");
                canBindings[value.substr(0, eq)] = value.substr(eq + 1);
            } else if (arg == "--port") {
                port = static_cast<std::uint16_t>(std::stoul(value));
            } else if (arg == "--broadcast") {
                broadcast = value;
            } else if (arg == "--key-store") {
                keyStore = value;
            } else if (arg == "--tls-cert") {
                tlsCert = value;
            } else if (arg == "--tls-key") {
                tlsKey = value;
            } else if (arg == "--tls-ca") {
                tlsCa = value;
            } else if (arg == "--tls-port") {
                tlsPort = static_cast<std::uint16_t>(std::stoul(value));
            } else if (arg == "--doip") {
                const auto eq = value.find('=');
                if (eq == std::string::npos) throw std::invalid_argument("expected ECU=IP:PORT");
                doipEndpoints[value.substr(0, eq)] = value.substr(eq + 1);
            } else {
                throw std::invalid_argument("unknown argument " + arg);
            }
        }
        if (tlsCert.empty() != tlsKey.empty()) throw std::invalid_argument("--tls-cert and --tls-key go together");
        if ((tlsOnly || tlsRequireClientCert || !tlsCa.empty()) && tlsCert.empty()) {
            throw std::invalid_argument("TLS options need --tls-cert and --tls-key");
        }
#ifndef CCG_HAVE_TLS
        if (!tlsCert.empty()) throw std::invalid_argument("built without OpenSSL: no DoIP over TLS");
#endif
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\nusage: " << argv[0]
                  << " --can CHANNEL=IFACE ... [--port 13400] [--broadcast ADDR]"
                     " [--key-store FILE [--demo-keys]] [--doip ECU=IP:PORT]"
                     " [--tls-cert PEM --tls-key PEM [--tls-ca PEM] [--tls-require-client-cert] [--tls-only]"
                     " [--tls-port 3496]]\n";
        return EXIT_FAILURE;
    }

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    std::signal(SIGPIPE, SIG_IGN);  // a tester resetting its TLS socket must not end the process

    try {
        auto config = config::makeVehicleDiagRouting();
        config.entity.requireTls = tlsOnly;
        config.entity.tlsPort = tlsPort;
        platform::DoipTcpServer tcp(port, config.entity.maxTcpConnections);
        platform::DoipUdpSocket udp(port, broadcast);
        LinuxDiagTransport transport(tcp, udp, config.channels.size());
#ifdef CCG_HAVE_TLS
        std::unique_ptr<platform::DoipTlsServer> tls;
        if (!tlsCert.empty()) {
            platform::TlsServerConfig tc;
            tc.certificateFile = tlsCert;
            tc.privateKeyFile = tlsKey;
            tc.caFile = tlsCa;
            tc.requireClientCertificate = tlsRequireClientCert;
            tls = std::make_unique<platform::DoipTlsServer>(tlsPort, config.entity.maxTcpConnections, tc);
            transport.tls = tls.get();
            std::cout << "[diag] DoIP over TLS on TCP " << tlsPort
                      << (tlsCa.empty() ? "" : tlsRequireClientCert ? ", client certificate required"
                                                                    : ", client certificates verified")
                      << (tlsOnly ? ", plain TCP refused for routing activation" : "") << "\n";
        }
#endif

        std::vector<std::pair<int, std::size_t>> canFds;
        for (std::size_t c = 0; c < config.channels.size(); ++c) {
            const auto& ch = config.channels[c];
            const auto it = canBindings.find(ch.name);
            if (it == canBindings.end()) throw std::invalid_argument("channel " + ch.name + " not bound (--can)");
            transport.can[c] = std::make_unique<platform::SocketCanTransport>(it->second, ch.fd);
            std::vector<std::pair<std::uint32_t, bool>> ids;
            for (const auto& ecu : config.ecus) {
                if (ecu.channel == ch.name) ids.emplace_back(ecu.responseId, ecu.extended);
            }
            transport.can[c]->setReceiveFilter(ids);
            canFds.emplace_back(transport.can[c]->fd(), c);
            std::cout << "[diag] " << ch.name << " -> " << it->second << "\n";
        }

        diag::DiagGateway gateway(std::move(config), transport);
        auto now = diag::Clock::now();

        // DoIP client towards the Ethernet ECUs (ADAS): gateway-internal UDS.
        auto doipCfg = config::makeVehicleDoipClient();
        for (auto& ecu : doipCfg.ecus) {
            const auto it = doipEndpoints.find(ecu.name);
            if (it != doipEndpoints.end()) ecu.endpoint = it->second;
            std::cout << "[diag] DoIP ECU " << ecu.name << " at " << ecu.endpoint << "\n";
        }
        platform::DoipTcpConnector doipConnector;
        diag::DoipClient doipClient(doipCfg, doipConnector);
        doipConnector.attach(doipClient);
        gateway.setEthernetRouting(doipClient);  // tester -> ADAS (DoIP-to-DoIP)
        diag::DiagClientRouter diagClients;  // CAN ECUs first, then Ethernet ECUs
        diagClients.add(gateway);
        diagClients.add(doipClient);

        // SecOC key management; the key store file stands in for the HSM key NvM.
        std::unique_ptr<keym::KeyManager> keys;
        std::unique_ptr<keym::KeyManagementService> keyService;
        platform::SystemRandom random;
        std::unique_ptr<keym::KeyMaster> keyMaster;
        std::uint64_t keyEventsSeen = 0;
        auto saveKeys = [&] { return platform::saveKeyStore(keyStore, keys->snapshot(diag::Clock::now())); };
        if (!keyStore.empty()) {
            keys = std::make_unique<keym::KeyManager>(config::makeVehicleKeySlots());
            if (const auto snapshot = platform::loadKeyStore(keyStore)) {
                keys->restore(*snapshot, now);
                std::cout << "[diag] key store " << keyStore << " loaded (" << snapshot->keys.size() << " keys)\n";
            } else if (demoKeys) {
                std::cout << "[diag] WARNING: key store provisioned with TEST KEYS - bench only\n";
                config::provisionDemoKeyStore(*keys, now);
                if (!saveKeys()) throw std::runtime_error("cannot write key store " + keyStore);
            } else {
                throw std::runtime_error("key store " + keyStore + " missing (EOL provisioning or --demo-keys)");
            }
            keys->takePersistRequest();
            keyEventsSeen = keys->eventCount();
            keyService = std::make_unique<keym::KeyManagementService>(*keys, saveKeys, true);
            gateway.addLocalService(*keyService);
            keyMaster = std::make_unique<keym::KeyMaster>(config::makeVehicleKeyMaster(), *keys, diagClients, random);
            keyMaster->setTrace([](const std::string& t) { std::cout << "[keym] " << t << "\n"; });
            gateway.addLocalService(*keyMaster);
        }
        gateway.start(now);
        std::cout << "[diag] DoIP entity listening on TCP/UDP " << port << "\n";

        auto nextTick = now + std::chrono::milliseconds(1);
        auto nextStats = now + std::chrono::seconds(10);
        std::vector<std::uint8_t> buffer;
        while (g_running) {
            std::vector<pollfd> fds = {{tcp.listenFd(), POLLIN, 0}, {udp.fd(), POLLIN, 0}};
            for (const auto& [fd, ch] : canFds) fds.push_back({fd, POLLIN, 0});
            const auto sockets = tcp.sockets();
            for (const auto& s : sockets) fds.push_back({s.fd, POLLIN, 0});
            const std::size_t doipBase = fds.size();
            const auto doipFds = doipConnector.pollFds();
            fds.insert(fds.end(), doipFds.begin(), doipFds.end());
            const std::size_t tlsBase = fds.size();
#ifdef CCG_HAVE_TLS
            if (tls) {
                const auto tlsFds = tls->pollFds();
                fds.insert(fds.end(), tlsFds.begin(), tlsFds.end());
            }
#endif

            now = diag::Clock::now();
            const auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(nextTick - now).count();
            ::poll(fds.data(), fds.size(), wait > 0 ? static_cast<int>(wait) : 0);
            now = diag::Clock::now();

            if (fds[0].revents & POLLIN) {
                for (const auto id : tcp.acceptPending()) gateway.onTcpConnected(id, now);
            }
            if (fds[1].revents & POLLIN) {
                diag::UdpPeer peer;
                while (udp.receive(buffer, peer)) gateway.onUdpDatagram(peer, buffer.data(), buffer.size(), now);
            }
            for (std::size_t i = 0; i < canFds.size(); ++i) {
                if (!(fds[2 + i].revents & POLLIN)) continue;
                const std::size_t ch = canFds[i].second;
                while (auto frame = transport.can[ch]->receive()) gateway.onCanFrame(ch, *frame, now);
            }
            for (std::size_t i = 0; i < sockets.size(); ++i) {
                if (!(fds[2 + canFds.size() + i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
                for (;;) {
                    const auto r = tcp.read(sockets[i].id, buffer);
                    if (r == platform::DoipTcpServer::ReadResult::Data) {
                        gateway.onTcpData(sockets[i].id, buffer.data(), buffer.size(), now);
                    } else {
                        if (r == platform::DoipTcpServer::ReadResult::Closed) {
                            gateway.onTcpClosed(sockets[i].id, now);
                        }
                        break;
                    }
                }
            }
            doipConnector.process(std::vector<pollfd>(fds.begin() + static_cast<std::ptrdiff_t>(doipBase),
                                                      fds.begin() + static_cast<std::ptrdiff_t>(tlsBase)),
                                  now);
#ifdef CCG_HAVE_TLS
            if (tls) {
                tls->process(std::vector<pollfd>(fds.begin() + static_cast<std::ptrdiff_t>(tlsBase), fds.end()), gateway,
                             now);
            }
#endif
            if (now >= nextTick) {
                gateway.mainFunction(now);
                doipClient.mainFunction(now);
                if (keys) {
                    keyMaster->mainFunction(now);
                    keys->mainFunction(now);  // previous keys expire after the grace period
                    if (keys->takePersistRequest() && !saveKeys()) {
                        std::cerr << "[diag] ERROR: cannot persist key store " << keyStore << "\n";
                    }
                    printKeyEvents(*keys, keyEventsSeen);
                }
                nextTick += std::chrono::milliseconds(1);
                if (nextTick <= now) nextTick = now + std::chrono::milliseconds(1);
            }
            if (now >= nextStats) {
                printStatistics(gateway.statistics());
                nextStats = now + std::chrono::seconds(10);
            }
        }
        printStatistics(gateway.statistics());
    } catch (const diag::DiagConfigError& e) {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
