// Deterministic bench simulation of the diagnostic gateway: a scripted DoIP
// tester talks to simulated UDS ECUs on PT_CAN (CAN FD), CHS_CAN and BODY_CAN,
// and - routed DoIP-to-DoIP - to the ADAS domain controller on ETH_ADAS.
#include <cstdio>
#include <deque>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/diag/doip_client.hpp"
#include "ccg/doip/doip_message.hpp"
#include "doip_ecu.hpp"
#include "doip_link.hpp"
#include "uds_ecu.hpp"
#include "vehicle_diag_routing.hpp"
#include "vehicle_key_master.hpp"

namespace {

using namespace ccg;
using namespace std::chrono_literals;
namespace dg = config::dg;
namespace pt = doip::payload;
using Bytes = std::vector<std::uint8_t>;

diag::TimePoint g_t0;
diag::TimePoint g_now;

std::string stamp() {
    std::ostringstream os;
    os << "[" << std::setw(5) << std::chrono::duration_cast<std::chrono::milliseconds>(g_now - g_t0).count()
       << " ms] ";
    return os.str();
}

std::string hex(const std::uint8_t* d, std::size_t n, std::size_t max = 12) {
    std::ostringstream os;
    os << std::hex << std::uppercase << std::setfill('0');
    for (std::size_t i = 0; i < n && i < max; ++i) os << (i ? " " : "") << std::setw(2) << int{d[i]};
    if (n > max) os << " .. (" << std::dec << n << " B)";
    return os.str();
}

const char* channelName(std::size_t ch) {
    static const char* names[] = {"PT_CAN", "CHS_CAN", "BODY_CAN"};
    return ch < 3 ? names[ch] : "?";
}

// Prints CAN traffic; runs of consecutive frames are summarised.
class CanPrinter {
public:
    void frame(const char* dir, std::size_t ch, const can::CanFrame& f) {
        const bool cf = (f.data[0] >> 4) == 2;
        const auto key = (static_cast<std::uint64_t>(ch) << 32) | f.id;
        if (cf) {
            ++cfRun_[key];
            return;
        }
        flush(key, dir, ch, f.id);
        std::cout << stamp() << dir << " " << std::left << std::setw(8) << channelName(ch) << std::right
                  << " 0x" << std::hex << std::uppercase << f.id << std::dec << (f.fd ? " FD" : "   ")
                  << " [" << hex(f.data.data(), f.length) << "]\n";
    }
    void flushAll() {
        for (auto& [key, n] : cfRun_) {
            if (n > 0) {
                std::cout << stamp() << "         ... " << n << " consecutive frames on 0x" << std::hex
                          << std::uppercase << (key & 0xFFFFFFFF) << std::dec << "\n";
                n = 0;
            }
        }
    }

private:
    void flush(std::uint64_t key, const char*, std::size_t, std::uint32_t) {
        (void)key;
        flushAll();
    }
    std::map<std::uint64_t, std::size_t> cfRun_;
};

CanPrinter g_can;

struct SimTransport final : diag::IDiagTransport {
    std::deque<std::pair<std::size_t, can::CanFrame>> canOut;
    std::vector<Bytes> tcpIn;  // what the tester receives

    void sendTcp(diag::ConnectionId, const Bytes& d) override {
        g_can.flushAll();
        const auto h = doip::decodeHeader(d.data());
        std::cout << stamp() << "DoIP -> tester  " << doip::payloadTypeName(h.type) << " ["
                  << hex(d.data() + doip::kHeaderSize, d.size() - doip::kHeaderSize, 16) << "]\n";
    }
    void closeTcp(diag::ConnectionId) override { std::cout << stamp() << "TCP closed by gateway\n"; }
    void sendUdp(const diag::UdpPeer&, const Bytes& d) override {
        std::cout << stamp() << "UDP -> tester   " << doip::payloadTypeName(doip::decodeHeader(d.data()).type)
                  << " VIN " << std::string(d.begin() + 8, d.begin() + 25) << "\n";
    }
    void broadcastUdp(const Bytes& d) override {
        std::cout << stamp() << "UDP broadcast   " << doip::payloadTypeName(doip::decodeHeader(d.data()).type)
                  << " VIN " << std::string(d.begin() + 8, d.begin() + 25) << "\n";
    }
    bool transmitCan(std::size_t ch, const can::CanFrame& f) override {
        g_can.frame("GW ->", ch, f);
        canOut.emplace_back(ch, f);
        return true;
    }
};

void log(const std::string& text) {
    g_can.flushAll();
    std::cout << stamp() << "---- " << text << "\n";
}

}  // namespace

int main() {
    const auto cfg = config::makeVehicleDiagRouting();
    SimTransport tx;
    diag::DiagGateway gw(cfg, tx);

    // ETH_ADAS: the gateway's DoIP client and the ADAS DoIP entity.
    sim::DoipLink ethernet;
    diag::DoipClient doip(config::makeVehicleDoipClient(), ethernet);
    ethernet.attach(doip);
    gw.setEthernetRouting(doip);
    sim::DoipEcu adas(config::makeAdasDoipEntity(), config::makeEcuKeySlots(dg::kAdas), ethernet.port(dg::kAdasEndpoint));
    ethernet.bind(dg::kAdasEndpoint, adas.entity());  // TLS required by ADAS, modelled by the link

    std::deque<std::pair<std::size_t, can::CanFrame>> ecuOut;
    std::vector<std::pair<std::size_t, std::unique_ptr<sim::UdsEcu>>> ecus;
    for (const auto& r : cfg.ecus) {
        sim::UdsEcu::Config ec;
        ec.name = r.name;
        ec.requestId = r.requestId;
        ec.responseId = r.responseId;
        ec.fd = r.fd;
        ec.partNumber = r.name + "-PN-0123456789";
        if (r.name == "BCM") {
            ec.blockSize = 16;
            ec.stMin = 2;
        }
        const std::size_t ch = *gw.channelIndex(r.channel);
        auto ecu = std::make_unique<sim::UdsEcu>(ec, [&ecuOut, ch](const can::CanFrame& f) {
            g_can.frame("ECU->", ch, f);
            ecuOut.emplace_back(ch, f);
            return true;
        });
        if (r.name == "EPS") ecu->setSilent(true);  // not powered
        ecus.emplace_back(ch, std::move(ecu));
    }

    auto deliver = [&] {
        while (!tx.canOut.empty() || !ecuOut.empty()) {
            while (!tx.canOut.empty()) {
                auto [ch, f] = tx.canOut.front();
                tx.canOut.pop_front();
                for (auto& [ech, e] : ecus) if (ech == ch) e->onFrame(f, g_now);
            }
            while (!ecuOut.empty()) {
                auto [ch, f] = ecuOut.front();
                ecuOut.pop_front();
                gw.onCanFrame(ch, f, g_now);
            }
        }
    };
    const diag::ConnectionId tester = 1;
    auto send = [&](std::uint16_t type, const Bytes& payload) {
        const auto b = doip::encode(doip::kVersion2012, type, payload);
        std::cout << stamp() << "tester -> DoIP  " << doip::payloadTypeName(type) << " ["
                  << hex(payload.data(), payload.size(), 16) << "]\n";
        gw.onTcpData(tester, b.data(), b.size(), g_now);
        deliver();
    };
    auto request = [&](std::uint16_t target, const Bytes& uds) {
        send(pt::kDiagnosticMessage, doip::diagnosticMessagePayload(dg::kTester, target, uds));
    };

    g_t0 = g_now = diag::TimePoint{} + 1s;
    gw.start(g_now);

    adas.entity().start(g_now);
    for (int t = 0; t <= 1900; ++t) {
        g_now = g_t0 + std::chrono::milliseconds(t);
        switch (t) {
            case 10: {
                log("tester: UDP vehicle identification request");
                const auto b = doip::encode(doip::kVersionDefault, pt::kVehicleIdRequest, {});
                gw.onUdpDatagram(diag::UdpPeer{1}, b.data(), b.size(), g_now);
                break;
            }
            case 20:
                log("tester: TCP connect + routing activation (SA 0x0E80)");
                gw.onTcpConnected(tester, g_now);
                send(pt::kRoutingActivationRequest, {0x0E, 0x80, 0x00, 0, 0, 0, 0});
                break;
            case 30:
                log("ReadDataByIdentifier F187 from ESP (0x0020): multi-frame response");
                request(dg::kEsp, {0x22, 0xF1, 0x87});
                break;
            case 60:
                log("functional TesterPresent 3E 80 (0xE400) to every CAN bus and ADAS");
                request(dg::kFunctional, {0x3E, 0x80});
                break;
            case 80:
                log("RoutineControl to BCM (0x0030): response pending, final after 200 ms");
                request(dg::kBcm, {0x31, 0x01, 0xFF, 0x00});
                break;
            case 400: {
                log("TransferData 1026 B to BCM: ECU paces with block size 16, STmin 2 ms");
                Bytes td = {0x36, 0x01};
                for (int i = 0; i < 1024; ++i) td.push_back(static_cast<std::uint8_t>(i));
                request(dg::kBcm, td);
                break;
            }
            case 700: {
                log("TransferData 6002 B to VCU (0x0010): CAN FD frames, escape first frame");
                Bytes td = {0x36, 0x01};
                for (int i = 0; i < 6000; ++i) td.push_back(static_cast<std::uint8_t>(i));
                request(dg::kVcu, td);
                break;
            }
            case 750:
                log("ReadDataByIdentifier to EPS (0x0021), ECU not powered");
                request(dg::kEps, {0x22, 0xF1, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00});
                break;
            case 1760:
                log("gateway itself (0x1001): ReadDataByIdentifier F190");
                request(dg::kGateway, {0x22, 0xF1, 0x90});
                break;
            case 1800:
                log("ADAS (0x1010) on ETH_ADAS: routed DoIP-to-DoIP over TLS (certificate 'adas-dc'), tester address 0x0E80");
                request(dg::kAdas, {0x22, 0xF1, 0x90});
                break;
            case 1820:
                log("ADAS: DiagnosticSessionControl extended over the kept connection");
                request(dg::kAdas, {0x10, 0x03});
                break;
            case 1840:
                log("functional DiagnosticSessionControl default (0xE400): CAN buses and ADAS");
                request(dg::kFunctional, {0x10, 0x01});
                break;
            default:
                break;
        }
        gw.mainFunction(g_now);
        doip.mainFunction(g_now);
        adas.entity().mainFunction(g_now);
        for (auto& [ch, e] : ecus) e->mainFunction(g_now);
        deliver();
        ethernet.pump(g_now);
    }
    g_can.flushAll();

    const auto& s = gw.statistics();
    std::cout << "\nstatistics: requests=" << s.diagRequests << " acks=" << s.diagAcks << " nacks=" << s.diagNacks
              << " functional=" << s.functionalRequests << " local=" << s.localRequests
              << " ecuResponses=" << s.ecuResponses << " ethernet=" << s.ethernetRequests << "/"
              << s.ethernetResponses << " (ADAS TLS connections " << adas.entity().statistics().tlsConnections
              << ") tpTxErrors=" << s.isotpTxErrors
              << " announcements=" << s.announcements << "\n";
    return 0;
}
