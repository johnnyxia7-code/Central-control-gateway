// Deterministic bench simulation of the central Ethernet gateway with the
// reference routing table. Runs in virtual time and prints the traffic the
// gateway produces on every channel.
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

#include "ccg/can/signal_codec.hpp"
#include "ccg/e2e/can_e2e.hpp"
#include "ccg/ethgw/ethernet_gateway.hpp"
#include "ccg/ethgw/pdu_header_codec.hpp"
#include "vehicle_eth_gateway_matrix.hpp"

namespace {

using namespace ccg;
using namespace std::chrono_literals;
namespace gw = config::gw;

ethgw::TimePoint g_t0;
ethgw::TimePoint g_now;
int ms() {
    return static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(g_now - g_t0).count());
}

std::string stamp() {
    std::ostringstream os;
    os << "[" << std::setw(4) << ms() << " ms] ";
    return os.str();
}

std::string hexBytes(const std::uint8_t* d, std::size_t n) {
    std::string s;
    char b[4];
    for (std::size_t i = 0; i < n; ++i) {
        std::snprintf(b, sizeof b, "%02X", d[i]);
        s += (i ? " " : "");
        s += b;
    }
    return s;
}

class SimTransmitter final : public ethgw::IGatewayTransmitter {
public:
    explicit SimTransmitter(const ethgw::RoutingConfig& cfg) : cfg_(cfg) {}

    bool transmitCan(std::size_t channel, const can::CanFrame& f) override {
        // The 10 ms wheel-speed forwarding CHS_CAN -> PT_CAN is printed every 50 ms only.
        if (f.id == gw::kEspWheelSpeeds && ms() % 50 != 0) return true;
        std::cout << stamp() << "TX " << std::left << std::setw(9) << cfg_.channels[channel].name
                  << std::right << "0x" << std::hex << std::uppercase << f.id << std::dec
                  << (f.fd ? " FD" : "") << " [" << hexBytes(f.data.data(), f.length) << "]"
                  << describe(channel, f.id, f.data.data()) << "\n";
        return true;
    }

    bool transmitEthernet(std::size_t channel, const std::vector<std::uint8_t>& d) override {
        const auto decoded = ethgw::decodeDatagram(d.data(), d.size());
        std::cout << stamp() << "TX " << std::left << std::setw(9) << cfg_.channels[channel].name
                  << std::right << "UDP datagram " << d.size() << " B, " << decoded.pdus.size()
                  << " PDU(s):";
        for (const auto& p : decoded.pdus) {
            std::cout << " 0x" << std::hex << std::uppercase << p.headerId << std::dec << "("
                      << p.length << ")";
        }
        std::cout << "\n";
        for (const auto& p : decoded.pdus) {
            const auto info = describe(channel, p.headerId, p.data);
            if (!info.empty()) std::cout << "            " << info << "\n";
        }
        return true;
    }

private:
    // Decodes assembled PDUs (those with signals that the gateway writes).
    std::string describe(std::size_t channel, std::uint32_t id, const std::uint8_t* data) const {
        for (const auto& p : cfg_.pdus) {
            if (p.channel != cfg_.channels[channel].name || p.id != id || p.name.rfind("GW_", 0) != 0) {
                continue;
            }
            std::ostringstream os;
            os << "  " << p.name << ":";
            for (const auto& s : p.signals) {
                const auto raw = can::extractRaw(data, s);
                os << " " << s.name.substr(3) << "=";
                if (s.invalidRaw && raw == *s.invalidRaw) {
                    os << "SNA";
                } else {
                    os << can::rawToPhysical(s, raw);
                }
            }
            return os.str();
        }
        return {};
    }

    const ethgw::RoutingConfig& cfg_;
};

class Ecus {
public:
    explicit Ecus(const ethgw::RoutingConfig& cfg) : cfg_(cfg) {}

    can::CanFrame frame(const std::string& name,
                        std::initializer_list<std::pair<const char*, double>> values,
                        bool corruptCrc = false) {
        for (const auto& p : cfg_.pdus) {
            if (p.name != name) continue;
            can::CanFrame f;
            f.id = p.id;
            f.fd = p.fd;
            f.length = static_cast<std::uint8_t>(p.length);
            for (const auto& s : p.signals) {
                can::insertRaw(f.data.data(), s, s.initRaw);
                for (const auto& [n, v] : values) {
                    if (s.name == n) can::insertRaw(f.data.data(), s, can::physicalToRaw(s, v));
                }
            }
            if (p.e2e) {
                auto it = senders_.find(name);
                if (it == senders_.end()) it = senders_.emplace(name, e2e::CanE2ESender(*p.e2e)).first;
                it->second.protect(f.data.data(), f.length);
                if (corruptCrc) f.data[p.e2e->crcByte] ^= 0x5A;
            }
            return f;
        }
        throw std::invalid_argument(name);
    }

private:
    const ethgw::RoutingConfig& cfg_;
    std::map<std::string, e2e::CanE2ESender> senders_;
};

void log(const std::string& text) { std::cout << stamp() << "---- " << text << "\n"; }

}  // namespace

int main() {
    const auto cfg = config::makeVehicleEthGatewayMatrix();
    SimTransmitter tx(cfg);
    Ecus ecus(cfg);
    ethgw::EthernetGateway gateway(cfg, tx);

    g_t0 = g_now = ethgw::TimePoint{} + 1s;
    gateway.start(g_now);

    for (int t = 0; t <= 300; ++t) {
        g_now = g_t0 + std::chrono::milliseconds(t);

        if (t % 10 == 0) {
            const double v = 50.0 + t * 0.02;
            gateway.onCanFrame(gw::kChsCan,
                               ecus.frame("ESP_WheelSpeeds", {{"ESP_WhlSpdFL", v}, {"ESP_WhlSpdFR", v},
                                                              {"ESP_WhlSpdRL", v - 0.25},
                                                              {"ESP_WhlSpdRR", v - 0.25}}),
                               g_now);
        }
        if (t % 20 == 0) {
            const bool corrupt = t >= 200 && t <= 240;
            if (t == 200) log("VCU_DriveState arrives with a corrupted CRC (E2E fault on PT_CAN)");
            gateway.onCanFrame(gw::kPtCan,
                               ecus.frame("VCU_DriveState", {{"VCU_VehSpd", 50.0 + t * 0.02},
                                                             {"VCU_GearPos", 3},
                                                             {"VCU_ReadySts", 1},
                                                             {"VCU_AccelPedal", 18.0}},
                                          corrupt),
                               g_now);
        }
        if (t % 100 == 0) {
            if (t == 100) log("BCM: front door opened, outside temperature 21.5 degC");
            gateway.onCanFrame(gw::kBodyCan,
                               ecus.frame("BCM_Status", {{"BCM_IgnState", 2},
                                                         {"BCM_DoorOpenAny", t >= 100 ? 1.0 : 0.0},
                                                         {"BCM_OutsideTemp", t >= 100 ? 21.5 : 20.0}}),
                               g_now);
        }
        if (t == 50 || t == 150) {
            log("ETH_ADAS: datagram with ADAS_LatCtrlReq + ADAS_HmiInfo + unknown PDU 0x9999");
            std::vector<std::uint8_t> d;
            const std::vector<std::uint8_t> lat = {0x10, 0x27, 0x00, 0x00, 0x01, 0x00, 0x00,
                                                   static_cast<std::uint8_t>(t)};
            const std::vector<std::uint8_t> hmi(32, static_cast<std::uint8_t>(t));
            const std::vector<std::uint8_t> unknown = {0xEE, 0xEE};
            ethgw::appendPdu(d, gw::kAdasLatCtrlReq, lat.data(), lat.size());
            ethgw::appendPdu(d, gw::kAdasHmiInfo, hmi.data(), hmi.size());
            ethgw::appendPdu(d, 0x9999, unknown.data(), unknown.size());
            gateway.onEthernetDatagram(gw::kEthAdas, d.data(), d.size(), g_now);
        }

        gateway.mainFunction(g_now);
    }

    const auto& s = gateway.statistics();
    std::cout << "\nstatistics: canRx=" << s.canFramesReceived << " datagramsRx=" << s.datagramsReceived
              << " unrouted=" << s.unroutedPdus << " e2eErrors=" << s.e2eErrors
              << " forwarded=" << s.pdusForwarded << " signalsRouted=" << s.signalsRouted
              << " assembled=" << s.assembledPdusSent << " canTx=" << s.canFramesSent
              << " datagramsTx=" << s.datagramsSent
              << " maxCollectionDelay=" << s.maxDatagramCollectionDelay.count() << " ms\n";
    return 0;
}
