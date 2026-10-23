// Deterministic bench simulation of the gateway as in-vehicle SecOC key master:
// the backend starts a key renewal campaign over DoIP; the gateway generates
// the keys and distributes them with the SHE update protocol - over ISO-TP to
// VCU, EPS and BCM on CAN, and as DoIP client to the ADAS domain controller on
// ETH_ADAS. EPS is not powered at first, so its key groups are discarded
// everywhere and renewed in a second campaign. SecOC traffic (both directions
// with ADAS) and the FV sync keep working throughout.
#include <algorithm>
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
#include "ccg/ethgw/ethernet_gateway.hpp"
#include "ccg/ethgw/pdu_header_codec.hpp"
#include "ccg/keym/key_management_service.hpp"
#include "ccg/keym/key_master.hpp"
#include "ccg/secoc/fv_sync.hpp"
#include "doip_ecu.hpp"
#include "doip_link.hpp"
#include "ecu_key_store.hpp"
#include "uds_ecu.hpp"
#include "vehicle_diag_routing.hpp"
#include "vehicle_eth_gateway_matrix.hpp"
#include "vehicle_key_master.hpp"
#include "vehicle_key_slots.hpp"

namespace {

using namespace ccg;
using namespace std::chrono_literals;
using Bytes = std::vector<std::uint8_t>;
namespace dg = config::dg;
namespace gw = config::gw;
namespace pt = doip::payload;
using GroupResult = keym::KeyMaster::GroupResult;

diag::TimePoint g_t0;
diag::TimePoint g_now;

std::string stamp() {
    std::ostringstream os;
    os << "[" << std::setw(4) << std::chrono::duration_cast<std::chrono::milliseconds>(g_now - g_t0).count()
       << " ms] ";
    return os.str();
}

std::string hex(const Bytes& d, std::size_t max = 12) {
    std::ostringstream os;
    os << std::hex << std::uppercase << std::setfill('0');
    for (std::size_t i = 0; i < d.size() && i < max; ++i) os << (i ? " " : "") << std::setw(2) << int{d[i]};
    if (d.size() > max) os << " .. (" << std::dec << d.size() << " B)";
    return os.str();
}

void log(const std::string& text) { std::cout << stamp() << "---- " << text << "\n"; }

std::string ecuName(std::uint16_t a) {
    switch (a) {
        case dg::kVcu: return "VCU";
        case dg::kEps: return "EPS";
        case dg::kBcm: return "BCM";
        case dg::kAdas: return "ADAS";
        default: return "-";
    }
}

// Diagnostic CAN side: gateway <-> simulated ECUs, plus DoIP towards the tester.
struct DiagBus final : diag::IDiagTransport {
    std::deque<std::pair<std::size_t, can::CanFrame>> canOut;
    std::size_t udsFrames = 0;
    Bytes lastUds;
    void sendTcp(diag::ConnectionId, const Bytes& d) override {
        if (doip::decodeHeader(d.data()).type != pt::kDiagnosticMessage) return;
        lastUds.assign(d.begin() + doip::kHeaderSize + 4, d.end());
        std::cout << stamp() << "gateway -> tester [" << hex(lastUds) << "]\n";
    }
    void closeTcp(diag::ConnectionId) override {}
    void sendUdp(const diag::UdpPeer&, const Bytes&) override {}
    void broadcastUdp(const Bytes&) override {}
    bool transmitCan(std::size_t ch, const can::CanFrame& f) override {
        ++udsFrames;
        canOut.emplace_back(ch, f);
        return true;
    }
};

// SecOC side: FV sync messages reach the FV slaves of VCU, EPS and ADAS;
// ETH_ADAS datagrams reach the ADAS domain controller.
struct SecOcBus final : ethgw::IGatewayTransmitter {
    std::function<void(std::size_t, const can::CanFrame&)> onCan;
    std::function<void(std::size_t, const Bytes&)> onEthernet;
    bool transmitCan(std::size_t ch, const can::CanFrame& f) override {
        if (onCan) onCan(ch, f);
        return true;
    }
    bool transmitEthernet(std::size_t ch, const Bytes& d) override {
        if (onEthernet) onEthernet(ch, d);
        return true;
    }
};

}  // namespace

int main() {
    g_t0 = g_now = diag::TimePoint{} + 1s;

    // --- gateway: diagnostic routing, HSM key store, key master, SecOC
    DiagBus diagBus;
    diag::DiagGateway diagGw(config::makeVehicleDiagRouting(), diagBus);
    keym::KeyManager gatewayKeys(config::makeVehicleKeySlots());
    config::provisionDemoKeyStore(gatewayKeys, g_now);
    keym::KeyManagementService keyService(gatewayKeys);
    keym::DeterministicRandom random(config::demoKey(0x77));  // HSM TRNG on the target
    sim::DoipLink ethernet;  // ETH_ADAS (TCP to the ADAS DoIP entity)
    diag::DoipClient doipClient(config::makeVehicleDoipClient(), ethernet);
    ethernet.attach(doipClient);
    diag::DiagClientRouter diagClients;  // CAN ECUs via ISO-TP, Ethernet ECUs via DoIP
    diagClients.add(diagGw);
    diagClients.add(doipClient);
    keym::KeyMaster master(config::makeVehicleKeyMaster(), gatewayKeys, diagClients, random);
    master.setTrace([](const std::string& t) { std::cout << stamp() << t << "\n"; });
    diagGw.addLocalService(keyService);
    diagGw.addLocalService(master);

    auto ethCfg = config::makeVehicleEthGatewayMatrix();
    ethCfg.freshnessSync->message.resetCycle = 500ms;
    SecOcBus secocBus;
    ethgw::EthernetGateway eth(ethCfg, secocBus, &gatewayKeys);

    // --- ECUs on CAN: UDS servers, the key-holding ones with their HSM
    std::deque<std::pair<std::size_t, can::CanFrame>> ecuOut;
    struct EcuOnBus {
        std::size_t channel;
        std::unique_ptr<sim::UdsEcu> ecu;
        std::unique_ptr<sim::EcuKeyStore> hsm;
    };
    std::map<std::uint16_t, EcuOnBus> ecus;
    for (const auto& route : diagGw.config().ecus) {
        sim::UdsEcu::Config ec;
        ec.name = route.name;
        ec.requestId = route.requestId;
        ec.responseId = route.responseId;
        ec.fd = route.fd;
        const std::size_t ch = *diagGw.channelIndex(route.channel);
        EcuOnBus e{ch, std::make_unique<sim::UdsEcu>(ec, [&ecuOut, ch](const can::CanFrame& f) {
                       ecuOut.emplace_back(ch, f);
                       return true;
                   }),
                   nullptr};
        const auto keyEcus = config::keyMasterEcus();
        if (std::find(keyEcus.begin(), keyEcus.end(), route.logicalAddress) != keyEcus.end()) {
            e.hsm = std::make_unique<sim::EcuKeyStore>(config::makeEcuKeySlots(route.logicalAddress));
            config::provisionDemoEcuKeyStore(e.hsm->keys(), g_now);  // plant
            e.hsm->attach(*e.ecu);
        }
        ecus.emplace(route.logicalAddress, std::move(e));
    }
    auto& vcuKeys = ecus.at(dg::kVcu).hsm->keys();
    auto& epsKeys = ecus.at(dg::kEps).hsm->keys();
    ecus.at(dg::kEps).ecu->setSilent(true);  // ignition: EPS not powered yet

    // --- ADAS domain controller on ETH_ADAS: DoIP entity with its HSM
    sim::DoipEcu adas(config::makeAdasDoipEntity(), config::makeEcuKeySlots(dg::kAdas),
                      ethernet.port(dg::kAdasEndpoint));
    ethernet.bind(dg::kAdasEndpoint, adas.entity());
    config::provisionDemoEcuKeyStore(adas.keys(), g_now);  // plant
    auto& adasKeys = adas.keys();

    // --- SecOC in the ECUs, with their HSM keys
    secoc::FreshnessManager vcuFv, epsFv;
    vcuFv.setLayout(ethCfg.freshnessSync->layout);
    epsFv.setLayout(ethCfg.freshnessSync->layout);
    secoc::FreshnessSyncSlave vcuSync(ethCfg.freshnessSync->message, vcuKeys, vcuFv);
    secoc::FreshnessSyncSlave epsSync(ethCfg.freshnessSync->message, epsKeys, epsFv);
    secoc::SecOcProcessor vcuSecOc(vcuKeys, vcuFv);
    secoc::FreshnessManager adasFv;  // ADAS: counter-mode FV on Ethernet + FV slave
    adasFv.setLayout(ethCfg.freshnessSync->layout);
    secoc::FreshnessSyncSlave adasSync(ethCfg.freshnessSync->message, adasKeys, adasFv);
    secoc::SecOcProcessor adasSecOc(adasKeys, adasFv);
    bool epsPowered = false;
    std::map<std::string, std::map<std::string, int>> syncResults;  // ECU -> result -> count
    secocBus.onCan = [&](std::size_t ch, const can::CanFrame& f) {
        if (f.id != gw::kFvSyncCan) return;
        if (ch == gw::kPtCan) ++syncResults["VCU"][secoc::toString(vcuSync.onSyncMessage(f.data.data(), f.length))];
        if (ch == gw::kChsCan && epsPowered) {
            ++syncResults["EPS"][secoc::toString(epsSync.onSyncMessage(f.data.data(), f.length))];
        }
    };
    const secoc::SecOcConfig* powerLimit = nullptr;
    const secoc::SecOcConfig* powerLimitAdas = nullptr;
    const secoc::SecOcConfig* steerRequest = nullptr;
    for (const auto& p : ethCfg.pdus) {
        if (p.name == "VCU_PowerLimit") powerLimit = &*p.secoc;
        if (p.name == "VCU_PowerLimit_ADAS") powerLimitAdas = &*p.secoc;
        if (p.name == "ADAS_SteerTorqueReq") steerRequest = &*p.secoc;
    }
    auto keyGeneration = [](keym::KeyManager& keys, const std::string& keyId) {
        for (const auto& s : keys.status()) {
            if (s.keyId == keyId) return s.counter;
        }
        return 0u;
    };
    secocBus.onEthernet = [&](std::size_t, const Bytes& d) {
        for (const auto& pdu : ethgw::decodeDatagram(d.data(), d.size()).pdus) {
            if (pdu.headerId == gw::kFvSyncEth) {
                ++syncResults["ADAS"][secoc::toString(adasSync.onSyncMessage(pdu.data, pdu.length))];
            } else if (pdu.headerId == gw::kVcuPowerLimitAdas) {
                std::cout << stamp() << "  -> VCU_PowerLimit_ADAS re-authenticated by the gateway (K_GW_ADAS generation "
                          << keyGeneration(gatewayKeys, "K_GW_ADAS") << "): ADAS SecOC "
                          << secoc::toString(adasSecOc.verify(*powerLimitAdas, pdu.data, 12)) << "\n";
            }
        }
    };
    auto adasSendsSteerRequest = [&] {
        const Bytes authentic(8, 0x00);
        const auto secured = adasSecOc.protect(*steerRequest, authentic.data(), authentic.size());
        if (!secured) return;
        Bytes datagram;
        ethgw::appendPdu(datagram, gw::kAdasSteerTorqueReq, secured->data(), secured->size());
        const auto before = eth.statistics().secocVerified;
        eth.onEthernetDatagram(gw::kEthAdas, datagram.data(), datagram.size(), g_now);
        std::cout << stamp() << "ADAS_SteerTorqueReq (ADAS K_ADAS_GW generation "
                  << keyGeneration(adasKeys, "K_ADAS_GW") << ") -> gateway SecOC "
                  << (eth.statistics().secocVerified > before ? "VERIFIED" : "REJECTED") << "\n";
    };
    auto vcuSendsPowerLimit = [&] {
        Bytes authentic(12, 0x00);
        authentic[1] = 0xDC;
        const auto secured = vcuSecOc.protect(*powerLimit, authentic.data(), authentic.size());
        if (!secured) return;
        can::CanFrame f;
        f.id = gw::kVcuPowerLimit;
        f.fd = true;
        f.length = 16;
        std::copy(secured->begin(), secured->end(), f.data.begin());
        const auto before = eth.statistics().secocVerified;
        eth.onCanFrame(gw::kPtCan, f, g_now);
        std::cout << stamp() << "VCU_PowerLimit (VCU key generation "
                  << vcuKeys.status()[1].counter << ") -> gateway SecOC "
                  << (eth.statistics().secocVerified > before ? "VERIFIED" : "REJECTED") << "\n";
    };
    auto printSync = [&] {
        for (const auto& [ecu, counts] : syncResults) {
            std::cout << "            FV sync at " << ecu << ":";
            for (const auto& [result, n] : counts) std::cout << " " << result << " x" << n;
            std::cout << "\n";
        }
        syncResults.clear();
    };

    // --- backend tester over DoIP
    const diag::ConnectionId tester = 1;
    auto send = [&](std::uint16_t type, const Bytes& payload) {
        const auto b = doip::encode(doip::kVersion2012, type, payload);
        diagGw.onTcpData(tester, b.data(), b.size(), g_now);
    };
    auto request = [&](const Bytes& uds) {
        std::cout << stamp() << "tester -> gateway [" << hex(uds) << "]\n";
        send(pt::kDiagnosticMessage, doip::diagnosticMessagePayload(dg::kTester, dg::kGateway, uds));
    };
    auto printResults = [&] {
        const auto& r = diagBus.lastUds;
        if (r.size() < 6 || r[0] != 0x71) return;
        for (std::size_t g = 0; g < r[5]; ++g) {
            const std::uint8_t* e = &r[6 + 8 * g];
            const auto generation = (e[1] << 24) | (e[2] << 16) | (e[3] << 8) | e[4];
            std::cout << "            " << std::left << std::setw(12) << master.config().groups[g].keyId << std::right
                      << toString(static_cast<GroupResult>(e[0]));
            if (generation != 0) std::cout << ", generation " << generation;
            const std::uint16_t failed = static_cast<std::uint16_t>((e[5] << 8) | e[6]);
            if (failed) std::cout << ", failed at " << ecuName(failed);
            std::cout << "\n";
        }
    };

    diagGw.start(g_now);
    adas.entity().start(g_now);
    eth.start(g_now);
    for (int t = 0; t <= 4000; ++t) {
        g_now = g_t0 + std::chrono::milliseconds(t);
        switch (t) {
            case 100:
                log("backend: tester connects over DoIP, extended session");
                diagGw.onTcpConnected(tester, g_now);
                send(pt::kRoutingActivationRequest, {0x0E, 0x80, 0x00, 0, 0, 0, 0});
                request({0x10, 0x03});
                break;
            case 150:
                log("backend: start key renewal campaign for all key groups (31 01 F210)");
                request({0x31, 0x01, 0xF2, 0x10});
                break;
            case 1500:
                log("backend: campaign results (31 03 F210)");
                request({0x10, 0x03});
                request({0x31, 0x03, 0xF2, 0x10});
                printResults();
                printSync();
                break;
            case 1600:
                log("EPS powered up");
                ecus.at(dg::kEps).ecu->setSilent(false);
                epsPowered = true;
                break;
            case 1700:
                log("backend: renew the failed groups K_GW_CHS and K_FV_MASTER (31 01 F210 01 02)");
                request({0x31, 0x01, 0xF2, 0x10, 0x01, 0x02});
                break;
            case 3000:
                log("backend: campaign results (31 03 F210)");
                request({0x10, 0x03});
                request({0x31, 0x03, 0xF2, 0x10});
                printResults();
                break;
            case 4000:
                log("FV sync since the second campaign");
                printSync();
                break;
            default:
                break;
        }
        if (t % 1000 == 50) vcuSendsPowerLimit();
        if (t % 1000 == 60) adasSendsSteerRequest();
        diagGw.mainFunction(g_now);
        doipClient.mainFunction(g_now);
        adas.entity().mainFunction(g_now);
        ethernet.pump(g_now);
        eth.mainFunction(g_now);
        for (auto& [a, e] : ecus) e.ecu->mainFunction(g_now);
        for (int guard = 0; guard < 1000 && (!diagBus.canOut.empty() || !ecuOut.empty()); ++guard) {
            while (!diagBus.canOut.empty()) {
                const auto [ch, f] = diagBus.canOut.front();
                diagBus.canOut.pop_front();
                for (auto& [a, e] : ecus) {
                    if (e.channel == ch) e.ecu->onFrame(f, g_now);
                }
            }
            while (!ecuOut.empty()) {
                const auto [ch, f] = ecuOut.front();
                ecuOut.pop_front();
                diagGw.onCanFrame(ch, f, g_now);
            }
        }
        master.mainFunction(g_now);
        gatewayKeys.mainFunction(g_now);
        ethernet.pump(g_now);
    }

    std::cout << "\nkey generations (gateway / ECUs):\n";
    for (const auto& g : master.config().groups) {
        std::cout << "  " << std::left << std::setw(12) << g.keyId << std::right;
        for (const auto& s : gatewayKeys.status()) {
            if (s.slot == g.gatewaySlot) std::cout << " gateway " << s.counter;
        }
        for (const auto& m : g.ecus) {
            auto& keys = m.ecu == dg::kAdas ? adasKeys : ecus.at(m.ecu).hsm->keys();
            for (const auto& s : keys.status()) {
                if (s.slot == m.slot) std::cout << "  " << ecuName(m.ecu) << " " << s.counter;
            }
        }
        std::cout << "\n";
    }
    const auto& d = doipClient.statistics();
    std::cout << "statistics: UDS CAN frames from the gateway=" << diagBus.udsFrames << " | DoIP client connects="
              << d.connects << " activations=" << d.activations << " requests=" << d.requests
              << " | secoc verified=" << eth.statistics().secocVerified
              << " macFailures=" << eth.statistics().secocMacFailures << "\n";
    return 0;
}
