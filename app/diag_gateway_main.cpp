// HPC diagnostic gateway process: DoIP (TCP/UDP 13400) <-> UDS on CAN (ISO-TP).
//
//   ccg_diag_gateway --can PT_CAN=can0 --can CHS_CAN=can1 --can BODY_CAN=can2
//                    [--port 13400] [--broadcast 255.255.255.255]
#include <poll.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "doip_sockets.hpp"
#include "socketcan_transport.hpp"
#include "vehicle_diag_routing.hpp"

namespace {

using namespace ccg;

std::atomic<bool> g_running{true};
void onSignal(int) { g_running = false; }

class LinuxDiagTransport final : public diag::IDiagTransport {
public:
    LinuxDiagTransport(platform::DoipTcpServer& tcp, platform::DoipUdpSocket& udp, std::size_t channels)
        : can(channels), tcp_(tcp), udp_(udp) {}

    // A failed send is detected as a closed socket by the next read.
    void sendTcp(diag::ConnectionId c, const std::vector<std::uint8_t>& d) override { tcp_.send(c, d); }
    void closeTcp(diag::ConnectionId c) override { tcp_.close(c); }
    void sendUdp(const diag::UdpPeer& p, const std::vector<std::uint8_t>& d) override { udp_.sendTo(p, d); }
    void broadcastUdp(const std::vector<std::uint8_t>& d) override { udp_.broadcast(d); }
    bool transmitCan(std::size_t ch, const can::CanFrame& f) override {
        return can[ch] && can[ch]->transmit(f);
    }

    std::vector<std::unique_ptr<platform::SocketCanTransport>> can;

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
              << " | ecuResp=" << s.ecuResponses << " dropped=" << s.responsesDropped
              << " tpTxErr=" << s.isotpTxErrors << " tpRxErr=" << s.isotpRxErrors << "\n";
}

}  // namespace

int main(int argc, char** argv) {
    std::map<std::string, std::string> canBindings;
    std::uint16_t port = doip::kPort;
    std::string broadcast = "255.255.255.255";
    try {
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
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
            } else {
                throw std::invalid_argument("unknown argument " + arg);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\nusage: " << argv[0]
                  << " --can CHANNEL=IFACE ... [--port 13400] [--broadcast ADDR]\n";
        return EXIT_FAILURE;
    }

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    try {
        auto config = config::makeVehicleDiagRouting();
        platform::DoipTcpServer tcp(port, config.entity.maxTcpConnections);
        platform::DoipUdpSocket udp(port, broadcast);
        LinuxDiagTransport transport(tcp, udp, config.channels.size());

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
            if (now >= nextTick) {
                gateway.mainFunction(now);
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
