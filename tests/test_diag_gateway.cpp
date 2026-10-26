#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/doip/doip_message.hpp"
#include "test_framework.hpp"
#include "uds_ecu.hpp"
#include "vehicle_diag_routing.hpp"

using namespace ccg;
using namespace ccg::diag;
using namespace std::chrono_literals;
namespace dg = ccg::config::dg;
namespace pt = ccg::doip::payload;

namespace {

using Bytes = std::vector<std::uint8_t>;

struct Message {
    std::uint16_t type;
    Bytes payload;
};

Message decode(const Bytes& bytes) {
    const auto h = doip::decodeHeader(bytes.data());
    return {h.type, Bytes(bytes.begin() + doip::kHeaderSize, bytes.end())};
}

struct MockTransport final : IDiagTransport {
    std::map<ConnectionId, std::vector<Message>> tcp;
    std::set<ConnectionId> closed;
    std::vector<std::pair<std::uint64_t, Message>> udp;
    std::vector<Message> broadcasts;
    std::deque<std::pair<std::size_t, can::CanFrame>> canOut;
    std::vector<std::pair<std::size_t, can::CanFrame>> canLog;

    void sendTcp(ConnectionId c, const Bytes& d) override { tcp[c].push_back(decode(d)); }
    void closeTcp(ConnectionId c) override { closed.insert(c); }
    void sendUdp(const UdpPeer& p, const Bytes& d) override { udp.emplace_back(p.token, decode(d)); }
    void broadcastUdp(const Bytes& d) override { broadcasts.push_back(decode(d)); }
    bool transmitCan(std::size_t ch, const can::CanFrame& f) override {
        canOut.emplace_back(ch, f);
        canLog.emplace_back(ch, f);
        return true;
    }
};

struct Fixture {
    DiagRoutingConfig cfg;
    MockTransport tx;
    DiagGateway gw;
    TimePoint now = TimePoint{} + 10s;
    struct EcuOnBus {
        std::size_t channel;
        std::unique_ptr<sim::UdsEcu> ecu;
    };
    std::vector<EcuOnBus> ecus;
    std::deque<std::pair<std::size_t, can::CanFrame>> ecuOut;
    std::uint32_t nextConnection = 1;

    explicit Fixture(DiagRoutingConfig c = config::makeVehicleDiagRouting())
        : cfg(c), gw(std::move(c), tx) {
        for (const auto& route : cfg.ecus) {
            sim::UdsEcu::Config ec;
            ec.name = route.name;
            ec.requestId = route.requestId;
            ec.responseId = route.responseId;
            ec.fd = route.fd;
            ec.partNumber = route.name + "-PN-0123456789";
            const std::size_t channel = *gw.channelIndex(route.channel);
            auto ecu = std::make_unique<sim::UdsEcu>(ec, [this, channel](const can::CanFrame& f) {
                ecuOut.emplace_back(channel, f);
                return true;
            });
            ecus.push_back({channel, std::move(ecu)});
        }
        gw.start(now);
    }

    sim::UdsEcu& ecu(const std::string& name) {
        for (auto& e : ecus) {
            if (e.ecu->config().name == name) return *e.ecu;
        }
        throw std::invalid_argument(name);
    }

    void deliver() {
        for (int guard = 0; guard < 100000 && (!tx.canOut.empty() || !ecuOut.empty()); ++guard) {
            while (!tx.canOut.empty()) {
                const auto [ch, f] = tx.canOut.front();
                tx.canOut.pop_front();
                for (auto& e : ecus) {
                    if (e.channel == ch) e.ecu->onFrame(f, now);
                }
            }
            while (!ecuOut.empty()) {
                const auto [ch, f] = ecuOut.front();
                ecuOut.pop_front();
                gw.onCanFrame(ch, f, now);
            }
        }
    }

    void advance(std::chrono::milliseconds d) {
        deliver();
        for (auto t = 0ms; t < d; t += 1ms) {
            now += 1ms;
            gw.mainFunction(now);
            for (auto& e : ecus) e.ecu->mainFunction(now);
            deliver();
        }
    }

    // --- tester side helpers
    ConnectionId connect() {
        const ConnectionId c = nextConnection++;
        gw.onTcpConnected(c, now);
        return c;
    }

    void send(ConnectionId c, std::uint16_t type, const Bytes& payload) {
        const auto bytes = doip::encode(doip::kVersion2012, type, payload);
        gw.onTcpData(c, bytes.data(), bytes.size(), now);
        deliver();
    }

    void activate(ConnectionId c, std::uint16_t tester = dg::kTester, std::uint8_t type = 0x00) {
        send(c, pt::kRoutingActivationRequest,
             {static_cast<std::uint8_t>(tester >> 8), static_cast<std::uint8_t>(tester), type, 0, 0, 0, 0});
    }

    ConnectionId activeTester(std::uint16_t tester = dg::kTester) {
        const auto c = connect();
        activate(c, tester);
        return c;
    }

    void request(ConnectionId c, std::uint16_t target, const Bytes& uds,
                 std::uint16_t tester = dg::kTester) {
        send(c, pt::kDiagnosticMessage, doip::diagnosticMessagePayload(tester, target, uds));
    }

    std::vector<Message> received(ConnectionId c, std::uint16_t type) const {
        std::vector<Message> out;
        const auto it = tx.tcp.find(c);
        if (it == tx.tcp.end()) return out;
        for (const auto& m : it->second) {
            if (m.type == type) out.push_back(m);
        }
        return out;
    }

    // UDS responses (payload after SA/TA) from `source` to the tester on connection c.
    std::vector<Bytes> responses(ConnectionId c, std::uint16_t source) const {
        std::vector<Bytes> out;
        for (const auto& m : received(c, pt::kDiagnosticMessage)) {
            if (doip::readU16(m.payload.data()) == source) {
                out.emplace_back(m.payload.begin() + 4, m.payload.end());
            }
        }
        return out;
    }

    std::uint8_t activationCode(ConnectionId c) const {
        const auto msgs = received(c, pt::kRoutingActivationResponse);
        return msgs.empty() ? 0xFF : msgs.back().payload.at(4);
    }
};

Bytes pattern(std::size_t n) {
    Bytes b(n);
    for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::uint8_t>(i);
    return b;
}

bool contains(const std::vector<std::string>& errors, const std::string& needle) {
    for (const auto& e : errors) {
        if (e.find(needle) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

// ---------------------------------------------------------------- configuration

TEST_CASE("diag config: reference routing table is consistent") {
    const auto errors = validateDiagConfig(config::makeVehicleDiagRouting());
    for (const auto& e : errors) std::cerr << "    " << e << "\n";
    CHECK(errors.empty());
}

TEST_CASE("diag config: address and identifier conflicts are rejected") {
    auto cfg = config::makeVehicleDiagRouting();
    cfg.entity.vin = "SHORT";
    cfg.ecus[1].logicalAddress = cfg.ecus[0].logicalAddress;
    cfg.ecus[2].logicalAddress = 0x0E10;          // tester range
    cfg.ecus[3].responseId = cfg.ecus[2].responseId;
    cfg.ecus[4].fd = true;                        // BODY_CAN is classic
    cfg.ecus[0].channel = "LIN1";
    cfg.ecus[1].maxRequestLength = 9000;          // above the DoIP limit
    const auto errors = validateDiagConfig(cfg);
    CHECK(contains(errors, "VIN must have 17 characters"));
    CHECK(contains(errors, "ECU 'BMS': logical address 0x10 already used"));
    CHECK(contains(errors, "ECU 'ESP': logical address 0xE10 is in the tester range"));
    CHECK(contains(errors, "ECU 'EPS': CAN ID 0x728 already used on CHS_CAN"));
    CHECK(contains(errors, "ECU 'BCM': CAN FD ISO-TP on classic channel BODY_CAN"));
    CHECK(contains(errors, "ECU 'VCU': unknown channel 'LIN1'"));
    CHECK(contains(errors, "ECU 'BMS': maxRequestLength must be 1..maxDiagnosticMessageSize"));
}

// ------------------------------------------------------------------------ UDP

TEST_CASE("diag udp: vehicle announcements after start-up") {
    Fixture f;
    f.advance(1ms);
    CHECK_EQ(f.tx.broadcasts.size(), 1U);
    f.advance(1200ms);
    REQUIRE(f.tx.broadcasts.size() == 3);  // A_DoIP_Announce_Num, 500 ms apart
    const auto& a = f.tx.broadcasts[0];
    CHECK_EQ(a.type, pt::kVehicleAnnouncement);
    CHECK(std::string(a.payload.begin(), a.payload.begin() + 17) == "WCCG0HPC0RT000001");
    CHECK_EQ(doip::readU16(a.payload.data() + 17), dg::kGateway);
}

TEST_CASE("diag udp: vehicle identification, entity status, power mode, errors") {
    Fixture f;
    auto udp = [&](std::uint8_t version, std::uint16_t type, const Bytes& payload) {
        const auto b = doip::encode(version, type, payload);
        f.gw.onUdpDatagram(UdpPeer{7}, b.data(), b.size(), f.now);
    };
    udp(doip::kVersionDefault, pt::kVehicleIdRequest, {});
    REQUIRE(f.tx.udp.size() == 1);
    CHECK_EQ(f.tx.udp[0].first, 7U);
    CHECK_EQ(f.tx.udp[0].second.type, pt::kVehicleAnnouncement);

    udp(doip::kVersion2012, pt::kVehicleIdRequestEid, {9, 9, 9, 9, 9, 9});  // other entity
    CHECK_EQ(f.tx.udp.size(), 1U);
    const std::string vin = "WCCG0HPC0RT000001";
    udp(doip::kVersion2012, pt::kVehicleIdRequestVin, Bytes(vin.begin(), vin.end()));
    CHECK_EQ(f.tx.udp.size(), 2U);

    udp(doip::kVersion2012, pt::kEntityStatusRequest, {});
    const auto& status = f.tx.udp.back().second;
    REQUIRE(status.type == pt::kEntityStatusResponse);
    CHECK_EQ(status.payload[0], 0x00);  // node type gateway
    CHECK_EQ(status.payload[1], 2);     // max sockets
    CHECK_EQ(doip::readU16(status.payload.data() + 5), 8196);  // max data size (low 16 bit)

    udp(doip::kVersion2012, pt::kPowerModeRequest, {});
    CHECK_EQ(f.tx.udp.back().second.payload.at(0), 0x01);

    udp(doip::kVersion2012, 0x1234, {});
    CHECK_EQ(f.tx.udp.back().second.type, pt::kGenericNack);
    CHECK_EQ(f.tx.udp.back().second.payload.at(0), 0x01);  // unknown payload type

    auto bad = doip::encode(doip::kVersion2012, pt::kVehicleIdRequest, {});
    bad[1] = 0x00;
    f.gw.onUdpDatagram(UdpPeer{7}, bad.data(), bad.size(), f.now);
    CHECK_EQ(f.tx.udp.back().second.payload.at(0), 0x00);  // incorrect pattern

    udp(doip::kVersionDefault, pt::kEntityStatusRequest, {});  // 0xFF only for VIR
    CHECK_EQ(f.tx.udp.back().second.payload.at(0), 0x00);

    udp(doip::kVersion2012, pt::kVehicleIdRequestEid, {1, 2});
    CHECK_EQ(f.tx.udp.back().second.payload.at(0), 0x04);  // invalid payload length
}

// ----------------------------------------------------------- routing activation

TEST_CASE("diag tcp: routing activation success and rejections") {
    Fixture f;
    const auto ok = f.activeTester();
    CHECK_EQ(f.activationCode(ok), 0x10);
    const auto ra = f.received(ok, pt::kRoutingActivationResponse).at(0).payload;
    CHECK_EQ(doip::readU16(ra.data()), dg::kTester);
    CHECK_EQ(doip::readU16(ra.data() + 2), dg::kGateway);
    CHECK(f.gw.isRoutingActive(ok));

    const auto unknown = f.connect();
    f.activate(unknown, 0x0100);
    CHECK_EQ(f.activationCode(unknown), 0x00);
    CHECK(f.tx.closed.count(unknown));

    const auto security = f.connect();
    f.activate(security, 0x0E81, 0xE0);  // central security needs TLS (ISO 13400-2:2019)
    CHECK_EQ(f.activationCode(security), 0x07);
    CHECK(f.tx.closed.count(security));

    const auto oem = f.connect();
    f.activate(oem, 0x0E81, 0x02);
    CHECK_EQ(f.activationCode(oem), 0x06);
    CHECK(f.tx.closed.count(oem));

    f.activate(ok, 0x0E99);  // other SA on an active socket
    CHECK_EQ(f.activationCode(ok), 0x02);
    CHECK(f.tx.closed.count(ok));
}

TEST_CASE("diag tcp: diagnostic message before routing activation is refused") {
    Fixture f;
    const auto c = f.connect();
    f.request(c, dg::kEsp, {0x3E, 0x00});
    const auto nack = f.received(c, pt::kDiagnosticNack);
    REQUIRE(nack.size() == 1);
    CHECK_EQ(nack[0].payload.at(4), 0x02);  // invalid source address
    CHECK(f.tx.closed.count(c));
    CHECK(f.tx.canLog.empty());
}

TEST_CASE("diag tcp: all sockets in use - alive check decides") {
    Fixture f;
    const auto t1 = f.activeTester(0x0E80);
    const auto t2 = f.activeTester(0x0E81);
    const auto t3 = f.connect();
    f.activate(t3, 0x0E82);
    CHECK_EQ(f.received(t1, pt::kAliveCheckRequest).size(), 1U);
    CHECK_EQ(f.received(t2, pt::kAliveCheckRequest).size(), 1U);
    f.send(t1, pt::kAliveCheckResponse, {0x0E, 0x80});
    f.send(t2, pt::kAliveCheckResponse, {0x0E, 0x81});
    CHECK_EQ(f.activationCode(t3), 0x01);  // both alive: no free socket
    CHECK(f.tx.closed.count(t3));

    const auto t4 = f.connect();
    f.activate(t4, 0x0E83);
    f.send(t1, pt::kAliveCheckResponse, {0x0E, 0x80});  // t2 stays silent
    f.advance(499ms);
    CHECK_EQ(f.activationCode(t4), 0xFF);  // still waiting
    f.advance(1ms);
    CHECK(f.tx.closed.count(t2));
    CHECK_EQ(f.activationCode(t4), 0x10);
    CHECK(f.gw.isRoutingActive(t4));
}

TEST_CASE("diag tcp: source address already active on another socket") {
    Fixture f;
    const auto old = f.activeTester();
    const auto again = f.connect();
    f.activate(again);
    f.send(old, pt::kAliveCheckResponse, {0x0E, 0x80});
    CHECK_EQ(f.activationCode(again), 0x03);
    CHECK(f.tx.closed.count(again));

    const auto reconnect = f.connect();  // the old socket is dead this time
    f.activate(reconnect);
    f.advance(500ms);
    CHECK(f.tx.closed.count(old));
    CHECK_EQ(f.activationCode(reconnect), 0x10);
}

TEST_CASE("diag tcp: inactivity timers") {
    Fixture f;
    const auto idle = f.connect();
    const auto active = f.activeTester();
    f.advance(2000ms);
    CHECK(f.tx.closed.count(idle));      // no routing activation within 2 s
    CHECK(!f.tx.closed.count(active));
    f.advance(298000ms);
    CHECK(f.tx.closed.count(active));    // 5 min without traffic
}

TEST_CASE("diag tcp: header errors") {
    Fixture f;
    const auto c = f.activeTester();
    f.send(c, 0x7777, {});
    CHECK_EQ(f.received(c, pt::kGenericNack).back().payload.at(0), 0x01);  // unknown type
    CHECK(!f.tx.closed.count(c));

    f.send(c, pt::kDiagnosticMessage, doip::diagnosticMessagePayload(dg::kTester, dg::kEsp, Bytes(9000, 0x36)));
    CHECK_EQ(f.received(c, pt::kGenericNack).back().payload.at(0), 0x02);  // too large
    f.request(c, dg::kGateway, {0x3E, 0x00});                               // stream still in sync
    CHECK_EQ(f.responses(c, dg::kGateway).size(), 1U);

    f.send(c, pt::kRoutingActivationRequest, {0x0E, 0x80, 0x00});
    CHECK_EQ(f.received(c, pt::kGenericNack).back().payload.at(0), 0x04);  // invalid length
    CHECK(f.tx.closed.count(c));

    const auto d = f.activeTester(0x0E81);
    const Bytes garbage = {0x05, 0x05, 0x80, 0x01, 0, 0, 0, 0};
    f.gw.onTcpData(d, garbage.data(), garbage.size(), f.now);
    CHECK_EQ(f.received(d, pt::kGenericNack).back().payload.at(0), 0x00);  // incorrect pattern
    CHECK(f.tx.closed.count(d));
}

// ------------------------------------------------------------- physical routing

TEST_CASE("diag routing: single frame request, multi-frame response") {
    Fixture f;
    const auto c = f.activeTester();
    f.request(c, dg::kEsp, {0x22, 0xF1, 0x90});

    REQUIRE(!f.tx.canLog.empty());
    const auto& [ch, req] = f.tx.canLog[0];
    CHECK_EQ(ch, dg::kChsCan);
    CHECK_EQ(req.id, 0x720U);
    const Bytes sf = {0x03, 0x22, 0xF1, 0x90, 0xCC, 0xCC, 0xCC, 0xCC};
    CHECK(Bytes(req.data.begin(), req.data.begin() + 8) == sf);

    const auto acks = f.received(c, pt::kDiagnosticAck);
    REQUIRE(acks.size() == 1);
    CHECK_EQ(doip::readU16(acks[0].payload.data()), dg::kEsp);
    CHECK_EQ(doip::readU16(acks[0].payload.data() + 2), dg::kTester);
    CHECK_EQ(acks[0].payload.at(4), 0x00);

    f.advance(5ms);
    const auto resp = f.responses(c, dg::kEsp);
    REQUIRE(resp.size() == 1);  // 20 bytes: FF + CFs, gateway sent the FC on 0x720
    const std::string vin = "WCCG0HPC0RT000001";
    Bytes expected = {0x62, 0xF1, 0x90};
    expected.insert(expected.end(), vin.begin(), vin.end());
    CHECK(resp[0] == expected);
    bool fcSent = false;
    for (const auto& [chan, frame] : f.tx.canLog) {
        if (frame.id == 0x720 && frame.data[0] == 0x30) fcSent = true;
    }
    CHECK(fcSent);
}

TEST_CASE("diag routing: response pending (NRC 0x78) is forwarded, then the final response") {
    Fixture f;
    const auto c = f.activeTester();
    f.request(c, dg::kBcm, {0x31, 0x01, 0xFF, 0x00});
    f.advance(10ms);
    auto resp = f.responses(c, dg::kBcm);
    REQUIRE(resp.size() == 1);
    CHECK(resp[0] == (Bytes{0x7F, 0x31, 0x78}));
    f.advance(200ms);
    resp = f.responses(c, dg::kBcm);
    REQUIRE(resp.size() == 2);
    CHECK(resp[1] == (Bytes{0x71, 0x01, 0xFF, 0x00}));
}

TEST_CASE("diag routing: multi-frame request paced by the ECU, ACK after delivery") {
    Fixture f;
    for (auto& e : f.ecus) {  // BCM as a slow receiver: block size 8, STmin 2 ms
        if (e.ecu->config().name != "BCM") continue;
        auto ec = e.ecu->config();
        ec.blockSize = 8;
        ec.stMin = 2;
        e.ecu = std::make_unique<sim::UdsEcu>(ec, [&f](const can::CanFrame& fr) {
            f.ecuOut.emplace_back(dg::kBodyCan, fr);
            return true;
        });
    }
    const auto c = f.activeTester();
    Bytes transfer = {0x36, 0x01};
    const auto block = pattern(1000);
    transfer.insert(transfer.end(), block.begin(), block.end());
    f.request(c, dg::kBcm, transfer);
    CHECK(f.received(c, pt::kDiagnosticAck).empty());  // not delivered yet

    f.advance(400ms);
    REQUIRE(f.received(c, pt::kDiagnosticAck).size() == 1);
    REQUIRE(f.ecu("BCM").requests().size() == 1);
    CHECK(f.ecu("BCM").requests()[0] == transfer);
    const auto resp = f.responses(c, dg::kBcm);
    REQUIRE(resp.size() == 1);
    CHECK(resp[0] == (Bytes{0x76, 0x01}));

    std::size_t cf = 0;
    for (const auto& [ch, frame] : f.tx.canLog) {
        if (frame.id == 0x740 && (frame.data[0] >> 4) == 2) ++cf;
    }
    CHECK_EQ(cf, 143U);  // (1002 - 6) / 7 -> 143 consecutive frames  // (1002 - 6) / 7 = 142.3 -> 143 consecutive frames
}

TEST_CASE("diag routing: CAN FD ISO-TP with escape first frame to the VCU") {
    Fixture f;
    const auto c = f.activeTester();
    Bytes transfer = {0x36, 0x01};
    const auto block = pattern(5000);
    transfer.insert(transfer.end(), block.begin(), block.end());
    f.request(c, dg::kVcu, transfer);
    f.advance(20ms);
    REQUIRE(f.ecu("VCU").requests().size() == 1);
    CHECK(f.ecu("VCU").requests()[0] == transfer);
    CHECK_EQ(f.received(c, pt::kDiagnosticAck).size(), 1U);
    const auto& ff = f.tx.canLog.at(0).second;
    CHECK(ff.fd);
    CHECK_EQ(ff.data[0], 0x10);
    CHECK_EQ(ff.data[1], 0x00);  // escape: 32-bit length follows
}

TEST_CASE("diag routing: unreachable ECU, unknown target and busy channel") {
    Fixture f;
    const auto c = f.activeTester();
    f.ecu("EPS").setSilent(true);
    f.request(c, dg::kEps, {0x22, 0xF1, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    f.advance(999ms);
    CHECK(f.received(c, pt::kDiagnosticNack).empty());
    f.advance(1ms);
    auto nack = f.received(c, pt::kDiagnosticNack);
    REQUIRE(nack.size() == 1);
    CHECK_EQ(doip::readU16(nack[0].payload.data()), dg::kEps);
    CHECK_EQ(nack[0].payload.at(4), 0x08);  // transport protocol error (no FC)
    CHECK_EQ(f.gw.statistics().isotpTxErrors, 1U);

    f.request(c, 0x0777, {0x3E, 0x00});
    CHECK_EQ(f.received(c, pt::kDiagnosticNack).back().payload.at(4), 0x03);  // unknown target

    f.request(c, dg::kBms, pattern(5000));  // classic CAN ECU: no escape first frame
    CHECK_EQ(f.received(c, pt::kDiagnosticNack).back().payload.at(4), 0x04);  // too large

    f.request(c, dg::kEps, pattern(30));  // multi-frame, waits for FC
    f.request(c, dg::kEps, {0x3E, 0x00});
    CHECK_EQ(f.received(c, pt::kDiagnosticNack).back().payload.at(4), 0x08);  // channel busy
}

TEST_CASE("diag routing: responses after the tester left are dropped") {
    Fixture f;
    const auto c = f.activeTester();
    f.request(c, dg::kBcm, {0x31, 0x01, 0xFF, 0x00});
    f.advance(10ms);
    f.gw.onTcpClosed(c, f.now);
    f.advance(200ms);
    CHECK_EQ(f.gw.statistics().responsesDropped, 1U);
}

// ------------------------------------------------------------ functional routing

TEST_CASE("diag routing: functional TesterPresent reaches every bus, no response") {
    Fixture f;
    const auto c = f.activeTester();
    f.request(c, dg::kFunctional, {0x3E, 0x80});
    const auto acks = f.received(c, pt::kDiagnosticAck);
    REQUIRE(acks.size() == 1);
    CHECK_EQ(doip::readU16(acks[0].payload.data()), dg::kFunctional);
    std::set<std::size_t> channels;
    for (const auto& [ch, frame] : f.tx.canLog) {
        CHECK_EQ(frame.id, 0x7DFU);
        CHECK(!frame.fd);
        channels.insert(ch);
    }
    CHECK_EQ(channels.size(), 3U);
    f.advance(10ms);
    CHECK(f.received(c, pt::kDiagnosticMessage).empty());
    for (auto& e : f.ecus) CHECK_EQ(e.ecu->requests().size(), 1U);
}

TEST_CASE("diag routing: functional request collects the answers of all ECUs") {
    Fixture f;
    const auto c = f.activeTester();
    f.request(c, dg::kFunctional, {0x22, 0xF1, 0x90});
    f.advance(10ms);
    const auto all = f.received(c, pt::kDiagnosticMessage);
    CHECK_EQ(all.size(), 6U);  // 5 ECUs + the gateway itself
    for (const auto source : {dg::kVcu, dg::kBms, dg::kEsp, dg::kEps, dg::kBcm, dg::kGateway}) {
        CHECK_EQ(f.responses(c, source).size(), 1U);
    }
    f.request(c, dg::kFunctional, pattern(8));
    CHECK_EQ(f.received(c, pt::kDiagnosticNack).back().payload.at(4), 0x04);  // not a single frame
}

// ------------------------------------------------------------- gateway services

TEST_CASE("diag local: UDS services of the gateway and S3 timeout") {
    Fixture f;
    const auto c = f.activeTester();
    f.request(c, dg::kGateway, {0x10, 0x03});
    CHECK(f.responses(c, dg::kGateway).back() == (Bytes{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4}));
    f.request(c, dg::kGateway, {0x22, 0xF1, 0x86});
    CHECK(f.responses(c, dg::kGateway).back() == (Bytes{0x62, 0xF1, 0x86, 0x03}));
    f.request(c, dg::kGateway, {0x3E, 0x00});
    CHECK(f.responses(c, dg::kGateway).back() == (Bytes{0x7E, 0x00}));
    f.request(c, dg::kGateway, {0x22, 0x12, 0x34});
    CHECK(f.responses(c, dg::kGateway).back() == (Bytes{0x7F, 0x22, 0x31}));
    f.request(c, dg::kGateway, {0x31, 0x01, 0x02, 0x03});  // no such routine
    CHECK(f.responses(c, dg::kGateway).back() == (Bytes{0x7F, 0x31, 0x31}));
    f.request(c, dg::kGateway, {0x2E, 0xF1, 0x90, 0x00});
    CHECK(f.responses(c, dg::kGateway).back() == (Bytes{0x7F, 0x2E, 0x11}));
    CHECK(f.tx.canLog.empty());  // nothing reached the CAN buses

    f.advance(5000ms);  // S3 server timeout
    f.request(c, dg::kGateway, {0x22, 0xF1, 0x86});
    CHECK(f.responses(c, dg::kGateway).back() == (Bytes{0x62, 0xF1, 0x86, 0x01}));
}

TEST_CASE("diag tcp: DoIP message split over several TCP segments") {
    Fixture f;
    const auto c = f.activeTester();
    const auto bytes = doip::encode(doip::kVersion2012, pt::kDiagnosticMessage,
                                    doip::diagnosticMessagePayload(dg::kTester, dg::kGateway, {0x3E, 0x00}));
    for (const auto b : bytes) f.gw.onTcpData(c, &b, 1, f.now);
    CHECK_EQ(f.responses(c, dg::kGateway).size(), 1U);
}

TEST_CASE("diag routing: unauthenticated key controls never reach CAN") {
    for (const auto& security : {ConnectionSecurity{}, ConnectionSecurity{true, false, ""},
                                  ConnectionSecurity{true, true, "workshop"}}) {
        for (const auto target : {dg::kVcu, dg::kBcm, dg::kFunctional}) {
            for (const std::uint8_t rid : {0x01, 0x02, 0x10}) {
                Fixture f;
                f.gw.onTcpConnected(1, f.now, security);
                f.activate(1);
                f.request(1, target, {0x31, 0x81, 0xF2, rid});
                if (target == dg::kFunctional) {
                    CHECK(f.tx.canLog.empty());
                    CHECK(f.responses(1, target).empty());
                } else if (security.clientAuthenticated) {
                    CHECK(!f.tx.canLog.empty());
                } else {
                    CHECK(f.tx.canLog.empty());
                    const auto replies = f.responses(1, target);
                    REQUIRE(replies.size() == 1u);
                    CHECK(replies[0] == (Bytes{0x7F, 0x31, 0x33}));
                }
            }
        }
    }
}

TEST_CASE("diag routing: functional traffic cannot interfere with an internal exchange") {
    Fixture f;
    const auto tester = f.activeTester();
    f.ecu("BCM").setSilent(true);
    std::optional<Bytes> internal;
    f.gw.request(dg::kBcm, {0x22, 0xF1, 0x90}, f.now,
                 [&](ClientResult result, Bytes reply) {
                     CHECK(result == ClientResult::Ok);
                     internal = std::move(reply);
                 });
    const auto frames = f.tx.canLog.size();
    f.request(tester, dg::kFunctional, {0x3E, 0x00});
    CHECK_EQ(f.tx.canLog.size(), frames); // refusal must precede every broadcast
    REQUIRE(!f.received(tester, pt::kDiagnosticNack).empty());
    CHECK_EQ(f.received(tester, pt::kDiagnosticNack).back().payload.at(4), 0x08);
    auto response = [&](const Bytes& uds) {
        const auto frame = isotp::makeSingleFrame(0x748, false, false, 0xCC, uds.data(), uds.size());
        REQUIRE(frame.has_value());
        f.gw.onCanFrame(dg::kBodyCan, *frame, f.now);
    };
    response({0x7E, 0x00});       // different service
    response({0x62, 0xF1, 0x87}); // same service, different DID
    response({0x7F, 0x31, 0x78}); // pending response for a different service
    CHECK(!internal.has_value());
    response({0x62, 0xF1, 0x90, 0x42});
    REQUIRE(internal.has_value());
    CHECK(*internal == (Bytes{0x62, 0xF1, 0x90, 0x42}));
    CHECK_EQ(f.gw.statistics().responsesDropped, 3u);
    f.request(tester, dg::kFunctional, {0x3E, 0x00});
    CHECK(f.tx.canLog.size() > frames);
}

TEST_CASE("diag routing: ownership lasts until reply even after request delivery") {
    Fixture f;
    const auto tester = f.activeTester();
    // Functional requests also reserve the ECU before an internal client can start.
    f.request(tester, dg::kFunctional, {0x22, 0xF1, 0x90});
    std::optional<ClientResult> result;
    f.gw.request(dg::kBcm, {0x3E, 0x00}, f.now, [&](ClientResult r, Bytes) { result = r; });
    CHECK(result == ClientResult::Busy);
    f.advance(10ms);
    result.reset();
    f.gw.request(dg::kBcm, {0x3E, 0x00}, f.now, [&](ClientResult r, Bytes) { result = r; });
    f.advance(10ms);
    CHECK(result == ClientResult::Ok);

    f.ecu("BCM").setHandler([](const Bytes&, bool) {
        return sim::UdsEcu::Responses{{0ms, {0x7F, 0x31, 0x78}}, {2000ms, {0x71, 0x01, 0xFF, 0x00}}};
    });
    f.request(tester, dg::kBcm, {0x31, 0x01, 0xFF, 0x00});
    f.advance(1100ms); // pending extended P2; request TX has long completed
    const auto frames = f.tx.canLog.size();
    f.request(tester, dg::kFunctional, {0x3E, 0x00});
    CHECK_EQ(f.tx.canLog.size(), frames);
    f.gw.request(dg::kBcm, {0x3E, 0x00}, f.now, [&](ClientResult r, Bytes) { result = r; });
    CHECK(result == ClientResult::Busy);
    f.advance(1000ms);
    const auto replies = f.responses(tester, dg::kBcm);
    CHECK(replies.back() == (Bytes{0x71, 0x01, 0xFF, 0x00}));
}

TEST_CASE("diag routing: unanswered requests release ownership at timeout") {
    Fixture f;
    const auto tester = f.activeTester();
    f.ecu("BCM").setSilent(true);
    f.request(tester, dg::kBcm, {0x3E, 0x80});
    std::optional<ClientResult> result;
    f.gw.request(dg::kBcm, {0x22, 0xF1, 0x90}, f.now, [&](ClientResult r, Bytes) { result = r; });
    CHECK(result == ClientResult::Busy);
    f.advance(1001ms);
    f.ecu("BCM").setSilent(false);
    result.reset();
    f.gw.request(dg::kBcm, {0x22, 0xF1, 0x90}, f.now, [&](ClientResult r, Bytes) { result = r; });
    f.advance(10ms);
    CHECK(result == ClientResult::Ok);
}
