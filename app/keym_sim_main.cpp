// Deterministic bench simulation of the SecOC key management: the backend key
// server renews the VCU <-> gateway SecOC key over DoIP (SHE memory update
// protocol), activates it, and the gateway keeps verifying the VCU's secured
// PDUs across the rollover. The previous key stops working after the grace period.
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/doip/doip_message.hpp"
#include "ccg/ethgw/ethernet_gateway.hpp"
#include "ccg/keym/key_management_service.hpp"
#include "ccg/keym/key_manager.hpp"
#include "ccg/secoc/fv_sync.hpp"
#include "vehicle_diag_routing.hpp"
#include "vehicle_eth_gateway_matrix.hpp"
#include "vehicle_key_slots.hpp"

namespace {

using namespace ccg;
using namespace std::chrono_literals;
using Bytes = std::vector<std::uint8_t>;
namespace gw = config::gw;
namespace dg = config::dg;
namespace she = keym::she;
namespace pt = doip::payload;

keym::TimePoint g_t0;
keym::TimePoint g_now;

std::string stamp() {
    std::ostringstream os;
    os << "[" << std::setw(4) << std::chrono::duration_cast<std::chrono::milliseconds>(g_now - g_t0).count()
       << " ms] ";
    return os.str();
}

std::string hex(const std::uint8_t* d, std::size_t n, std::size_t max = 16) {
    std::ostringstream os;
    os << std::hex << std::uppercase << std::setfill('0');
    for (std::size_t i = 0; i < n && i < max; ++i) os << (i ? " " : "") << std::setw(2) << int{d[i]};
    if (n > max) os << " .. (" << std::dec << n << " B)";
    return os.str();
}

void log(const std::string& text) { std::cout << stamp() << "---- " << text << "\n"; }

std::string slotName(std::uint8_t slot) {
    if (slot == she::kMasterEcuKey) return "MASTER_ECU_KEY";
    return "KEY_" + std::to_string(slot - she::kKey1 + 1);
}

// Off-board tester side of DoIP: prints the gateway's UDS responses.
struct TesterLink final : diag::IDiagTransport {
    Bytes lastUds;
    void sendTcp(diag::ConnectionId, const Bytes& d) override {
        const auto h = doip::decodeHeader(d.data());
        if (h.type != pt::kDiagnosticMessage) return;
        lastUds.assign(d.begin() + doip::kHeaderSize + 4, d.end());
        std::cout << stamp() << "gateway -> tester UDS [" << hex(lastUds.data(), lastUds.size()) << "]\n";
    }
    void closeTcp(diag::ConnectionId) override {}
    void sendUdp(const diag::UdpPeer&, const Bytes&) override {}
    void broadcastUdp(const Bytes&) override {}
    bool transmitCan(std::size_t, const can::CanFrame&) override { return true; }
};

// CAN/Ethernet side of the gateway: the VCU on PT_CAN follows the FV master.
struct Buses final : ethgw::IGatewayTransmitter {
    secoc::FreshnessSyncSlave* vcuSync = nullptr;
    bool transmitCan(std::size_t channel, const can::CanFrame& f) override {
        if (channel == gw::kPtCan && f.id == gw::kFvSyncCan && vcuSync) vcuSync->onSyncMessage(f.data.data(), f.length);
        return true;
    }
    bool transmitEthernet(std::size_t, const Bytes&) override { return true; }
};

void printKeyStatus(const Bytes& rsp, const keym::KeyManagerConfig& cfg) {
    if (rsp.size() < 4 || rsp[0] != 0x62) return;
    for (std::size_t i = 0; i < rsp[3]; ++i) {
        const std::uint8_t* e = &rsp[4 + 10 * i];
        const auto counter = (e[2] << 24) | (e[3] << 16) | (e[4] << 8) | e[5];
        const auto pending = (e[6] << 24) | (e[7] << 16) | (e[8] << 8) | e[9];
        std::string id;
        for (const auto& s : cfg.slots) {
            if (s.slot == e[0]) id = s.keyId;
        }
        std::cout << "            " << std::left << std::setw(15) << slotName(e[0]) << std::setw(12) << id
                  << std::right << " generation " << counter;
        if (e[1] & keym::uds::kStatusPending) std::cout << ", pending generation " << pending;
        if (e[1] & keym::uds::kStatusPrevious) std::cout << ", previous key in grace period";
        if (e[1] & keym::uds::kStatusWriteProtected) std::cout << ", write-protected";
        std::cout << "\n";
    }
}

}  // namespace

int main() {
    g_t0 = g_now = keym::TimePoint{} + 1s;

    // --- gateway HSM key store (EOL provisioned), grace period shortened for the demo
    auto keyCfg = config::makeVehicleKeySlots();
    keyCfg.gracePeriod = 2s;
    keym::KeyManager keys(keyCfg);
    config::provisionDemoKeyStore(keys, g_now);
    keys.takePersistRequest();

    // --- Ethernet gateway (SecOC + FV master) and diagnostic gateway share the HSM
    auto ethCfg = config::makeVehicleEthGatewayMatrix();
    Buses buses;
    ethgw::EthernetGateway eth(ethCfg, buses, &keys);
    TesterLink testerLink;
    diag::DiagGateway diagGw(config::makeVehicleDiagRouting(), testerLink);
    keym::KeyManagementService keyService(keys, [] {
        std::cout << stamp() << "HSM: key store written to NvM\n";
        return true;
    });
    diagGw.addLocalService(keyService);

    // --- VCU on PT_CAN: SecOC sender of VCU_PowerLimit, FV slave of the gateway
    secoc::SoftwareCryptoService vcuKeys;
    config::provisionDemoSecOcKeys(vcuKeys);
    secoc::FreshnessManager vcuFv;
    vcuFv.setLayout(ethCfg.freshnessSync->layout);
    secoc::FreshnessSyncSlave vcuSync(ethCfg.freshnessSync->message, vcuKeys, vcuFv);
    buses.vcuSync = &vcuSync;
    secoc::SecOcProcessor vcuSecOc(vcuKeys, vcuFv);
    const secoc::SecOcConfig* powerLimit = nullptr;
    for (const auto& p : ethCfg.pdus) {
        if (p.name == "VCU_PowerLimit") powerLimit = &*p.secoc;
    }

    // --- backend key server: owns MASTER_ECU_KEY and generates the new key
    const crypto::Block newVcuKey = {0x5E, 0xC0, 0xC0, 0x4E, 0x77, 0x02, 0x6B, 0x13,
                                     0xA9, 0x41, 0xD2, 0x0F, 0x88, 0x3C, 0x96, 0x21};
    she::Flags macKey;
    macKey.keyUsage = true;
    macKey.wildcard = true;
    auto container = [&](std::uint32_t counter, const crypto::Block& masterKey) {
        const auto r = she::buildUpdate(keyCfg.uid, config::keyslot::kVcuGw, she::kMasterEcuKey, masterKey, newVcuKey,
                                        counter, macKey);
        Bytes uds = {0x31, 0x01, 0xF2, 0x00};
        uds.insert(uds.end(), r.m1.begin(), r.m1.end());
        uds.insert(uds.end(), r.m2.begin(), r.m2.end());
        uds.insert(uds.end(), r.m3.begin(), r.m3.end());
        return uds;
    };

    // Security log of the key manager (IdsM).
    std::uint64_t eventsSeen = keys.eventCount();
    auto printEvents = [&] {
        const auto& events = keys.events();
        const auto fresh = std::min<std::uint64_t>(keys.eventCount() - eventsSeen, events.size());
        for (auto it = events.end() - static_cast<std::ptrdiff_t>(fresh); it != events.end(); ++it) {
            std::cout << stamp() << "keym event: " << keym::toString(it->kind) << " " << slotName(it->slot);
            if (it->counter) std::cout << " generation " << it->counter;
            if (it->error != she::ErrorCode::NoError) std::cout << " " << she::toString(it->error);
            std::cout << "\n";
        }
        eventsSeen = keys.eventCount();
    };

    const diag::ConnectionId tester = 1;
    auto send = [&](std::uint16_t type, const Bytes& payload) {
        const auto b = doip::encode(doip::kVersion2012, type, payload);
        diagGw.onTcpData(tester, b.data(), b.size(), g_now);
    };
    auto request = [&](const Bytes& uds) {
        std::cout << stamp() << "tester -> gateway UDS [" << hex(uds.data(), uds.size()) << "]\n";
        send(pt::kDiagnosticMessage, doip::diagnosticMessagePayload(dg::kTester, dg::kGateway, uds));
        printEvents();
    };

    auto vcuSends = [&](const char* note) {
        Bytes authentic(12);
        authentic[0] = 0x05;  // 150 kW discharge
        authentic[1] = 0xDC;
        authentic[2] = 0x02;  // 60 kW charge
        authentic[3] = 0x58;
        const auto secured = vcuSecOc.protect(*powerLimit, authentic.data(), authentic.size());
        if (!secured) {
            std::cout << stamp() << "VCU: not synchronised yet\n";
            return;
        }
        can::CanFrame f;
        f.id = gw::kVcuPowerLimit;
        f.fd = true;
        f.length = 16;
        std::copy(secured->begin(), secured->end(), f.data.begin());
        const auto before = eth.statistics();
        const auto rollover = keys.rolloverVerifications();
        eth.onCanFrame(gw::kPtCan, f, g_now);
        const auto& after = eth.statistics();
        std::cout << stamp() << "VCU_PowerLimit (" << note << ") -> gateway SecOC: ";
        if (after.secocVerified > before.secocVerified) {
            std::cout << "VERIFIED" << (keys.rolloverVerifications() > rollover ? " with the previous key (rollover)" : "")
                      << ", routed to ETH_ADAS\n";
        } else {
            std::cout << "REJECTED (" << (after.secocMacFailures > before.secocMacFailures ? "MAC failure" : "freshness")
                      << "), security event\n";
        }
    };

    diagGw.start(g_now);
    eth.start(g_now);
    secoc::FreshnessManager leakedFv;
    bool vcuNewKey = false;

    for (int t = 0; t <= 3200; ++t) {
        g_now = g_t0 + std::chrono::milliseconds(t);
        switch (t) {
            case 50:
                log("backend: key renewal campaign for K_VCU_GW (KEY_3) starts, tester connects over DoIP");
                diagGw.onTcpConnected(tester, g_now);
                send(pt::kRoutingActivationRequest, {0x0E, 0x80, 0x00, 0, 0, 0, 0});
                break;
            case 100:
                log("read key status (22 F2 A0)");
                request({0x22, 0xF2, 0xA0});
                printKeyStatus(testerLink.lastUds, keyCfg);
                break;
            case 150:
                log("key update in the default session is refused");
                request(container(2, config::demoMasterEcuKey()));
                break;
            case 200:
                request({0x10, 0x03});
                break;
            case 300:
                log("attacker: forged update container (unknown MASTER_ECU_KEY)");
                request(container(2, config::demoKey(9)));
                break;
            case 350:
                log("attacker: replay of the provisioning generation (counter 1)");
                request(container(1, config::demoMasterEcuKey()));
                break;
            case 400: {
                log("backend: genuine update container M1|M2|M3 for KEY_3, generation 2");
                request(container(2, config::demoMasterEcuKey()));
                const auto proof = she::buildProof(keyCfg.uid, config::keyslot::kVcuGw, she::kMasterEcuKey, newVcuKey, 2);
                Bytes expected(proof.m4.begin(), proof.m4.end());
                expected.insert(expected.end(), proof.m5.begin(), proof.m5.end());
                const Bytes got(testerLink.lastUds.begin() + 5, testerLink.lastUds.end());
                std::cout << "            backend: M4/M5 " << (got == expected ? "verified" : "MISMATCH")
                          << " - gateway holds the new key as pending\n";
                log("backend: VCU (0x0010) receives the same key via its own SHE update (not shown)");
                request({0x22, 0xF2, 0xA0});
                printKeyStatus(testerLink.lastUds, keyCfg);
                break;
            }
            case 700:
                log("backend: all ECUs confirmed - activate the new key generation (31 01 F2 01)");
                request({0x31, 0x01, 0xF2, 0x01});
                leakedFv = vcuFv;  // what an attacker who stole the old key could know
                break;
            case 1100:
                log("VCU switches to the new key 400 ms after the gateway");
                vcuKeys.setKey("K_VCU_GW", newVcuKey);
                vcuNewKey = true;
                break;
            case 2700:
                log("grace period over: the old key is retired");
                break;
            case 3000: {
                log("attacker with the leaked OLD key forges VCU_PowerLimit");
                secoc::SoftwareCryptoService stolen;
                stolen.setKey("K_VCU_GW", config::demoKey(3));
                leakedFv.setTripReset(vcuFv.tripCounter(), vcuFv.resetCounter());
                secoc::SecOcProcessor attacker(stolen, leakedFv);
                for (int i = 0; i < 50; ++i) leakedFv.nextTxSynchronized(powerLimit->dataId, powerLimit->freshnessTxBits);
                Bytes forged(12, 0xFF);  // unlimited power
                const auto secured = attacker.protect(*powerLimit, forged.data(), forged.size());
                can::CanFrame f;
                f.id = gw::kVcuPowerLimit;
                f.fd = true;
                f.length = 16;
                std::copy(secured->begin(), secured->end(), f.data.begin());
                const auto before = eth.statistics().secocMacFailures;
                eth.onCanFrame(gw::kPtCan, f, g_now);
                std::cout << stamp() << "forged PDU -> gateway SecOC: "
                          << (eth.statistics().secocMacFailures > before ? "REJECTED (MAC failure), security event"
                                                                         : "ACCEPTED")
                          << "\n";
                break;
            }
            default:
                break;
        }
        if (t % 200 == 0 && t > 0 && t < 3000) {
            vcuSends(vcuNewKey ? "new key" : "old key");
        }
        keys.mainFunction(g_now);
        eth.mainFunction(g_now);
        diagGw.mainFunction(g_now);
        printEvents();
    }

    const auto& s = eth.statistics();
    std::cout << "\nstatistics: secoc verified=" << s.secocVerified << " macFailures=" << s.secocMacFailures
              << " freshnessFailures=" << s.secocFreshnessFailures << " | keym rolloverVerifications="
              << keys.rolloverVerifications() << " fvSync=" << s.fvSyncMessagesSent << "\n";
    return 0;
}
