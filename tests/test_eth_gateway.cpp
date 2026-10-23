#include <map>
#include <string>
#include <utility>
#include <vector>

#include "ccg/can/signal_codec.hpp"
#include "ccg/e2e/can_e2e.hpp"
#include "ccg/ethgw/ethernet_gateway.hpp"
#include "ccg/ethgw/pdu_header_codec.hpp"
#include "test_framework.hpp"
#include "vehicle_eth_gateway_matrix.hpp"

using namespace ccg;
using namespace ccg::ethgw;
using namespace std::chrono_literals;
namespace gw = ccg::config::gw;

namespace {

using Bytes = std::vector<std::uint8_t>;

struct MockTransmitter final : IGatewayTransmitter {
    struct CanTx {
        std::size_t channel;
        can::CanFrame frame;
    };
    struct EthTx {
        std::size_t channel;
        Bytes datagram;
    };
    std::vector<CanTx> can;
    std::vector<EthTx> eth;

    bool transmitCan(std::size_t channel, const can::CanFrame& frame) override {
        can.push_back({channel, frame});
        return true;
    }
    bool transmitEthernet(std::size_t channel, const Bytes& datagram) override {
        eth.push_back({channel, datagram});
        return true;
    }

    std::vector<can::CanFrame> canFrames(std::size_t channel, std::uint32_t id) const {
        std::vector<can::CanFrame> out;
        for (const auto& c : can) {
            if (c.channel == channel && c.frame.id == id) out.push_back(c.frame);
        }
        return out;
    }
    std::vector<Bytes> datagrams(std::size_t channel) const {
        std::vector<Bytes> out;
        for (const auto& e : eth) {
            if (e.channel == channel) out.push_back(e.datagram);
        }
        return out;
    }
    // Every contained PDU with this header ID sent on the channel.
    std::vector<Bytes> ethPdus(std::size_t channel, std::uint32_t headerId) const {
        std::vector<Bytes> out;
        for (const auto& d : datagrams(channel)) {
            for (const auto& p : decodeDatagram(d.data(), d.size()).pdus) {
                if (p.headerId == headerId) out.emplace_back(p.data, p.data + p.length);
            }
        }
        return out;
    }
};

struct Fixture {
    RoutingConfig cfg;
    MockTransmitter tx;
    EthernetGateway gw;
    TimePoint now = TimePoint{} + 10s;
    std::map<std::string, e2e::CanE2ESender> senders;

    explicit Fixture(RoutingConfig c = config::makeVehicleEthGatewayMatrix())
        : cfg(c), gw(std::move(c), tx) {
        gw.start(now);
    }

    void advance(Milliseconds duration) {
        for (Milliseconds t{0}; t < duration; t += 1ms) {
            now += 1ms;
            gw.mainFunction(now);
        }
    }

    const PduDefinition& def(const std::string& name) const {
        for (const auto& p : cfg.pdus) {
            if (p.name == name) return p;
        }
        throw std::invalid_argument(name);
    }

    const can::SignalSpec& spec(const std::string& pdu, const std::string& signal) const {
        for (const auto& s : def(pdu).signals) {
            if (s.name == signal) return s;
        }
        throw std::invalid_argument(signal);
    }

    // Frame as sent by the source ECU (E2E protected where configured).
    can::CanFrame frame(const std::string& name,
                        const std::vector<std::pair<std::string, double>>& physical,
                        const std::vector<std::pair<std::string, std::uint64_t>>& raw = {},
                        bool corruptCrc = false) {
        const auto& p = def(name);
        can::CanFrame f;
        f.id = p.id;
        f.fd = p.fd;
        f.length = static_cast<std::uint8_t>(p.length);
        for (const auto& s : p.signals) {
            can::insertRaw(f.data.data(), s, s.initRaw);
            for (const auto& [n, v] : physical) {
                if (n == s.name) can::insertRaw(f.data.data(), s, can::physicalToRaw(s, v));
            }
            for (const auto& [n, v] : raw) {
                if (n == s.name) can::insertRaw(f.data.data(), s, v);
            }
        }
        if (p.e2e) {
            auto it = senders.find(name);
            if (it == senders.end()) it = senders.emplace(name, e2e::CanE2ESender(*p.e2e)).first;
            it->second.protect(f.data.data(), f.length);
            if (corruptCrc) f.data[p.e2e->crcByte] ^= 0xFF;
        }
        return f;
    }

    void rx(const std::string& name, const std::vector<std::pair<std::string, double>>& physical,
            const std::vector<std::pair<std::string, std::uint64_t>>& raw = {},
            bool corruptCrc = false) {
        gw.onCanFrame(*gw.channelIndex(def(name).channel), frame(name, physical, raw, corruptCrc),
                      now);
    }

    std::uint64_t raw(const std::string& pdu, const std::string& signal) const {
        return *gw.assembledSignalRaw(pdu, signal);
    }

    std::uint64_t field(const std::string& pdu, const std::string& signal,
                        const std::uint8_t* data) const {
        return can::extractRaw(data, spec(pdu, signal));
    }
};

Bytes datagram(const std::vector<std::pair<std::uint32_t, Bytes>>& pdus) {
    Bytes out;
    for (const auto& [id, payload] : pdus) appendPdu(out, id, payload.data(), payload.size());
    return out;
}

PduDefinition* findPdu(RoutingConfig& cfg, const std::string& name) {
    for (auto& p : cfg.pdus) {
        if (p.name == name) return &p;
    }
    return nullptr;
}

bool contains(const std::vector<std::string>& errors, const std::string& needle) {
    for (const auto& e : errors) {
        if (e.find(needle) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

// -------------------------------------------------------------- configuration

TEST_CASE("ethgw config: reference routing table is consistent") {
    const auto errors = validateRoutingConfig(config::makeVehicleEthGatewayMatrix());
    for (const auto& e : errors) std::cerr << "    " << e << "\n";
    CHECK(errors.empty());
}

TEST_CASE("ethgw config: routing loops, double writers and bad conversions are rejected") {
    auto cfg = config::makeVehicleEthGatewayMatrix();
    cfg.pduRoutes.push_back({"loop", "ESP_WheelSpeeds_ADAS", {"ADAS_HmiInfo_IVI"}});
    cfg.pduRoutes.push_back({"dup", "ADAS_HmiInfo", {"ESP_WheelSpeeds_PT"}});
    cfg.signalRoutes.push_back({{"BCM_Status", "BCM_HazardSts"},
                                {"GW_BodyInfo", "GW_DoorOpenAny"},
                                Conversion::Raw, Substitution::InitValue, true});
    cfg.signalRoutes.push_back({{"VCU_DriveState", "VCU_VehSpd"},
                                {"GW_BodyInfo", "GW_IgnState"},
                                Conversion::Raw, Substitution::InitValue, true});
    cfg.signalRoutes.push_back({{"VCU_DriveState", "VCU_DrvMode"},
                                {"GW_VehicleState", "Missing"},
                                Conversion::Raw, Substitution::InitValue, true});
    const auto errors = validateRoutingConfig(cfg);
    CHECK(contains(errors, "PDU 'ESP_WheelSpeeds_ADAS' is both received and transmitted"));
    CHECK(contains(errors, "PDU 'ESP_WheelSpeeds_PT' is the target of more than one PDU route"));
    CHECK(contains(errors, "GW_BodyInfo.GW_DoorOpenAny: target signal written by more than one route"));
    CHECK(contains(errors, "GW_BodyInfo.GW_IgnState: raw copy needs equal length"));
    CHECK(contains(errors, "GW_VehicleState.Missing: unknown target signal"));
}

TEST_CASE("ethgw config: bus constraints and routing roles") {
    auto cfg = config::makeVehicleEthGatewayMatrix();
    findPdu(cfg, "ADAS_LatCtrlReq_CHS")->fd = true;                       // FD on classic CAN
    findPdu(cfg, "ADAS_HmiInfo_IVI")->length = 1400;                      // > datagram size
    findPdu(cfg, "ESP_WheelSpeeds_PT")->length = 4;                       // shorter than source
    findPdu(cfg, "VCU_DriveState_ADAS")->e2e = e2e::CanE2EConfig{};       // routed unchanged
    findPdu(cfg, "GW_BodyInfo")->id = gw::kVcuDriveState;                 // ID clash on PT_CAN
    findPdu(cfg, "GW_VehicleState")->txMode = TxMode::Cyclic;
    findPdu(cfg, "GW_VehicleState")->cycleTime = Milliseconds{0};
    cfg.signalRoutes[2].substitution = Substitution::InvalidValue;        // GW_ReadySts has none
    const auto errors = validateRoutingConfig(cfg);
    CHECK(contains(errors, "PDU 'ADAS_LatCtrlReq_CHS': CAN FD frame on classic CAN channel"));
    CHECK(contains(errors, "PDU 'ADAS_HmiInfo_IVI': length 1400 not possible on ETH_IVI"));
    CHECK(contains(errors, "target 'ESP_WheelSpeeds_PT' (4 bytes) shorter than source"));
    CHECK(contains(errors, "target 'VCU_DriveState_ADAS' has E2E protection"));
    CHECK(contains(errors, "PDU 'GW_BodyInfo': identifier 0x120 already used on PT_CAN"));
    CHECK(contains(errors, "PDU 'GW_VehicleState': cyclic transmission needs a cycle time"));
    CHECK(contains(errors, "substitution InvalidValue but target has no invalid value"));
}

TEST_CASE("ethgw config: invalid table throws on construction") {
    auto cfg = config::makeVehicleEthGatewayMatrix();
    cfg.pduRoutes[0].source = "Nope";
    MockTransmitter tx;
    bool thrown = false;
    try {
        EthernetGateway g(cfg, tx);
    } catch (const RoutingConfigError& e) {
        thrown = true;
        CHECK_EQ(e.errors().size(), 1U);
    }
    CHECK(thrown);
}

// ------------------------------------------------------------ message routing

TEST_CASE("ethgw: CAN frame fan-out to CAN and Ethernet (frame assembly in datagram)") {
    Fixture f;
    f.rx("ESP_WheelSpeeds", {{"ESP_WhlSpdFL", 50.0}, {"ESP_WhlSpdRR", 51.0}});

    const auto pt = f.tx.canFrames(gw::kPtCan, gw::kEspWheelSpeeds);
    REQUIRE(pt.size() == 1);  // CAN -> CAN: forwarded at once
    CHECK(!pt[0].fd);
    CHECK_EQ(pt[0].length, 8);
    CHECK_EQ(f.field("ESP_WheelSpeeds", "ESP_WhlSpdFL", pt[0].data.data()), 1600U);

    CHECK(f.tx.datagrams(gw::kEthAdas).empty());  // collected for 5 ms
    f.advance(4ms);
    CHECK(f.tx.datagrams(gw::kEthAdas).empty());
    f.advance(1ms);
    const auto pdus = f.tx.ethPdus(gw::kEthAdas, gw::kEspWheelSpeeds);
    REQUIRE(pdus.size() == 1);
    CHECK(Bytes(pt[0].data.begin(), pt[0].data.begin() + 8) == pdus[0]);
    CHECK_EQ(f.gw.statistics().pdusForwarded, 2U);
    CHECK(f.gw.statistics().maxDatagramCollectionDelay == 5ms);
}

TEST_CASE("ethgw: PDUs from several buses share one Ethernet datagram") {
    Fixture f;
    f.rx("ESP_WheelSpeeds", {{"ESP_WhlSpdFL", 10.0}});
    f.advance(2ms);
    f.rx("VCU_DriveState", {{"VCU_VehSpd", 30.0}});
    f.advance(3ms);

    const auto adas = f.tx.datagrams(gw::kEthAdas);
    REQUIRE(adas.size() == 1);
    const auto decoded = decodeDatagram(adas[0].data(), adas[0].size());
    REQUIRE(decoded.pdus.size() == 2);
    CHECK_EQ(decoded.pdus[0].headerId, gw::kEspWheelSpeeds);
    CHECK_EQ(decoded.pdus[1].headerId, gw::kVcuDriveState);
    CHECK_EQ(decoded.pdus[1].length, 16U);
    CHECK_EQ(adas[0].size(), 2 * kPduHeaderSize + 8 + 16);

    CHECK(f.tx.datagrams(gw::kEthIvi).empty());  // ETH_IVI collects for 10 ms
    f.advance(7ms);
    CHECK_EQ(f.tx.ethPdus(gw::kEthIvi, gw::kVcuDriveState).size(), 1U);
}

TEST_CASE("ethgw: datagram size limit and urgent PDUs flush the container") {
    auto cfg = config::makeVehicleEthGatewayMatrix();
    cfg.channels[gw::kEthAdas].maxDatagramSize = 30;  // room for ESP (16) but not ESP + VCU (40)
    findPdu(cfg, "ADAS_HmiInfo")->length = 16;        // keep every ETH_ADAS PDU within 30 bytes
    findPdu(cfg, "ADAS_HmiInfo_IVI")->length = 16;
    Fixture f(cfg);
    f.rx("ESP_WheelSpeeds", {});
    CHECK(f.tx.datagrams(gw::kEthAdas).empty());
    f.rx("VCU_DriveState", {});
    REQUIRE(f.tx.datagrams(gw::kEthAdas).size() == 1);  // ESP flushed before VCU is added
    CHECK_EQ(f.tx.datagrams(gw::kEthAdas)[0].size(), 16U);
    f.advance(5ms);
    CHECK_EQ(f.tx.datagrams(gw::kEthAdas).size(), 2U);

    auto urgentCfg = config::makeVehicleEthGatewayMatrix();
    findPdu(urgentCfg, "ESP_WheelSpeeds_ADAS")->urgent = true;
    Fixture u(urgentCfg);
    u.rx("ESP_WheelSpeeds", {});
    CHECK_EQ(u.tx.datagrams(gw::kEthAdas).size(), 1U);  // no collection delay
}

TEST_CASE("ethgw: datagram decomposition routes PDUs to CAN (ID translation) and Ethernet") {
    Fixture f;
    const Bytes latCtrl = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    const Bytes hmi(32, 0x77);
    const auto d = datagram({{gw::kAdasLatCtrlReq, latCtrl}, {gw::kAdasHmiInfo, hmi}, {0x9999, {1, 2}}});
    f.gw.onEthernetDatagram(gw::kEthAdas, d.data(), d.size(), f.now);

    const auto chs = f.tx.canFrames(gw::kChsCan, gw::kChsLatCtrlReq);
    REQUIRE(chs.size() == 1);
    CHECK(Bytes(chs[0].data.begin(), chs[0].data.begin() + 8) == latCtrl);
    CHECK_EQ(f.gw.statistics().unroutedPdus, 1U);
    CHECK_EQ(f.gw.statistics().pdusReceived, 2U);

    f.advance(10ms);
    const auto ivi = f.tx.ethPdus(gw::kEthIvi, gw::kAdasHmiInfo);
    REQUIRE(ivi.size() == 1);
    CHECK(ivi[0] == hmi);
}

TEST_CASE("ethgw: malformed datagrams and short PDUs") {
    Fixture f;
    auto d = datagram({{gw::kAdasLatCtrlReq, Bytes(8, 0x11)}});
    d.insert(d.end(), {0x00, 0x00, 0x10});  // truncated second header
    f.gw.onEthernetDatagram(gw::kEthAdas, d.data(), d.size(), f.now);
    CHECK_EQ(f.gw.statistics().malformedDatagrams, 1U);
    CHECK_EQ(f.tx.canFrames(gw::kChsCan, gw::kChsLatCtrlReq).size(), 1U);  // first PDU still routed

    const auto shortPdu = datagram({{gw::kAdasLatCtrlReq, Bytes(4, 0x22)}});
    f.gw.onEthernetDatagram(gw::kEthAdas, shortPdu.data(), shortPdu.size(), f.now);
    CHECK_EQ(f.gw.statistics().lengthErrors, 1U);
    CHECK_EQ(f.tx.canFrames(gw::kChsCan, gw::kChsLatCtrlReq).size(), 1U);

    // A CAN frame given to an Ethernet channel (or an unknown channel) is ignored.
    f.gw.onCanFrame(gw::kEthAdas, f.frame("ESP_WheelSpeeds", {}), f.now);
    f.gw.onCanFrame(42, f.frame("ESP_WheelSpeeds", {}), f.now);
    CHECK_EQ(f.gw.statistics().canFramesReceived, 0U);
}

TEST_CASE("ethgw: classic frame routed into a longer CAN FD frame is padded") {
    auto cfg = config::makeVehicleEthGatewayMatrix();
    auto* pt = findPdu(cfg, "ESP_WheelSpeeds_PT");
    pt->fd = true;
    pt->length = 12;
    pt->padding = 0xCC;
    Fixture f(cfg);
    f.rx("ESP_WheelSpeeds", {{"ESP_WhlSpdFL", 1.0}});
    const auto frames = f.tx.canFrames(gw::kPtCan, gw::kEspWheelSpeeds);
    REQUIRE(frames.size() == 1);
    CHECK(frames[0].fd);
    CHECK_EQ(frames[0].length, 12);
    for (std::size_t i = 8; i < 12; ++i) CHECK_EQ(frames[0].data[i], 0xCC);
}

// ------------------------------------------- signal routing and frame assembly

TEST_CASE("ethgw: frame assembly from two buses with rescaling and E2E") {
    Fixture f;
    f.rx("VCU_DriveState", {{"VCU_VehSpd", 88.88}, {"VCU_GearPos", 3}, {"VCU_ReadySts", 1}});
    auto out = f.tx.canFrames(gw::kChsCan, gw::kGwVehicleState);
    REQUIRE(out.size() == 1);  // CyclicAndOnChange: sent on change
    const auto* d = out[0].data.data();
    CHECK_EQ(f.field("GW_VehicleState", "GW_VehSpd", d), 889U);  // 0.01 km/h -> 0.1 km/h
    CHECK_EQ(f.field("GW_VehicleState", "GW_GearPos", d), 3U);
    CHECK_EQ(f.field("GW_VehicleState", "GW_ReadySts", d), 1U);
    CHECK_EQ(f.field("GW_VehicleState", "GW_IgnState", d), 0U);   // BCM not yet received

    e2e::CanE2EReceiver checker(*f.def("GW_VehicleState").e2e);
    CHECK(checker.check(d, 8) == e2e::CheckStatus::Ok);

    f.rx("BCM_Status", {{"BCM_IgnState", 2}});
    CHECK_EQ(f.tx.canFrames(gw::kChsCan, gw::kGwVehicleState).size(), 1U);  // 10 ms MDT
    f.advance(10ms);
    out = f.tx.canFrames(gw::kChsCan, gw::kGwVehicleState);
    REQUIRE(out.size() == 2);
    CHECK_EQ(f.field("GW_VehicleState", "GW_IgnState", out[1].data.data()), 2U);
    CHECK_EQ(f.field("GW_VehicleState", "GW_VehSpd", out[1].data.data()), 889U);
    CHECK(checker.check(out[1].data.data(), 8) == e2e::CheckStatus::Ok);
}

TEST_CASE("ethgw: unchanged and non-triggering signals wait for the cycle") {
    Fixture f;
    f.rx("VCU_DriveState", {{"VCU_VehSpd", 50.0}, {"VCU_GearPos", 3}});
    f.rx("BCM_Status", {{"BCM_IgnState", 2}, {"BCM_OutsideTemp", 10.0}});
    f.advance(20ms);
    const std::size_t before = f.tx.canFrames(gw::kChsCan, gw::kGwVehicleState).size();

    f.rx("VCU_DriveState", {{"VCU_VehSpd", 50.0}, {"VCU_GearPos", 3}});      // same values
    f.rx("BCM_Status", {{"BCM_IgnState", 2}, {"BCM_OutsideTemp", 25.5}});    // temp only
    f.advance(1ms);
    CHECK_EQ(f.tx.canFrames(gw::kChsCan, gw::kGwVehicleState).size(), before);
    CHECK_EQ(f.raw("GW_VehicleState", "GW_OutsideTemp"), 131U);  // (25.5 + 40) / 0.5

    f.advance(80ms);  // cyclic frame at t0 + 100 ms carries the new temperature
    const auto out = f.tx.canFrames(gw::kChsCan, gw::kGwVehicleState);
    REQUIRE(out.size() == before + 1);
    CHECK_EQ(f.field("GW_VehicleState", "GW_OutsideTemp", out.back().data.data()), 131U);
}

TEST_CASE("ethgw: frame decomposition feeds several assembled PDUs") {
    Fixture f;
    f.rx("BCM_Status", {{"BCM_IgnState", 2}, {"BCM_DoorOpenAny", 1}, {"BCM_HazardSts", 1}});
    const auto body = f.tx.canFrames(gw::kPtCan, gw::kGwBodyInfo);
    REQUIRE(body.size() == 1);
    CHECK_EQ(f.field("GW_BodyInfo", "GW_IgnState", body[0].data.data()), 2U);
    CHECK_EQ(f.field("GW_BodyInfo", "GW_DoorOpenAny", body[0].data.data()), 1U);
    CHECK_EQ(f.field("GW_BodyInfo", "GW_HazardSts", body[0].data.data()), 1U);
    CHECK_EQ(f.tx.canFrames(gw::kChsCan, gw::kGwVehicleState).size(), 1U);
    CHECK_EQ(f.raw("GW_ADAS_VehicleInfo", "GW_IgnState"), 2U);
    CHECK_EQ(f.gw.statistics().signalsRouted, 6U);
}

TEST_CASE("ethgw: minimum delay time between assembled frames") {
    Fixture f;
    f.rx("BCM_Status", {{"BCM_DoorOpenAny", 1}});
    f.advance(5ms);
    f.rx("BCM_Status", {{"BCM_DoorOpenAny", 0}});
    CHECK_EQ(f.tx.canFrames(gw::kPtCan, gw::kGwBodyInfo).size(), 1U);
    f.advance(14ms);
    CHECK_EQ(f.tx.canFrames(gw::kPtCan, gw::kGwBodyInfo).size(), 1U);
    f.advance(1ms);  // 20 ms after the first frame
    const auto body = f.tx.canFrames(gw::kPtCan, gw::kGwBodyInfo);
    REQUIRE(body.size() == 2);
    CHECK_EQ(f.field("GW_BodyInfo", "GW_DoorOpenAny", body[1].data.data()), 0U);
}

TEST_CASE("ethgw: cyclic Ethernet PDU assembled from three CAN buses") {
    Fixture f;
    f.rx("ESP_WheelSpeeds", {{"ESP_WhlSpdFL", 100.0}, {"ESP_WhlSpdFR", 100.5},
                             {"ESP_WhlSpdRL", 99.75}, {"ESP_WhlSpdRR", 100.25}});
    f.rx("VCU_DriveState", {{"VCU_VehSpd", 100.12}, {"VCU_GearPos", 3}, {"VCU_AccelPedal", 20.0}});
    f.rx("BCM_Status", {{"BCM_IgnState", 2}});
    f.advance(25ms);  // cycle 20 ms + 5 ms datagram collection

    const auto pdus = f.tx.ethPdus(gw::kEthAdas, gw::kGwAdasVehicleInfo);
    REQUIRE(pdus.size() == 1);
    REQUIRE(pdus[0].size() == 16);
    const auto* d = pdus[0].data();
    CHECK_EQ(f.field("GW_ADAS_VehicleInfo", "GW_WhlSpdFL", d), 10000U);
    CHECK_EQ(f.field("GW_ADAS_VehicleInfo", "GW_WhlSpdFR", d), 10050U);
    CHECK_EQ(f.field("GW_ADAS_VehicleInfo", "GW_WhlSpdRL", d), 9975U);
    CHECK_EQ(f.field("GW_ADAS_VehicleInfo", "GW_VehSpd", d), 10012U);
    CHECK_EQ(f.field("GW_ADAS_VehicleInfo", "GW_GearPos", d), 3U);
    CHECK_EQ(f.field("GW_ADAS_VehicleInfo", "GW_IgnState", d), 2U);
    CHECK_EQ(f.field("GW_ADAS_VehicleInfo", "GW_AccelPedal", d), 50U);
}

TEST_CASE("ethgw: source timeout applies the substitution values") {
    Fixture f;
    f.rx("VCU_DriveState", {{"VCU_VehSpd", 60.0}, {"VCU_GearPos", 3}, {"VCU_ReadySts", 1}});
    f.advance(99ms);
    CHECK_EQ(f.raw("GW_VehicleState", "GW_VehSpd"), 600U);
    f.advance(1ms);
    CHECK_EQ(f.raw("GW_VehicleState", "GW_VehSpd"), 0xFFFU);  // InvalidValue
    CHECK_EQ(f.raw("GW_VehicleState", "GW_GearPos"), 0xFU);   // InvalidValue
    CHECK_EQ(f.raw("GW_VehicleState", "GW_ReadySts"), 0U);    // InitValue
    CHECK_EQ(f.raw("GW_ADAS_VehicleInfo", "GW_VehSpd"), 0xFFFFU);
    const auto out = f.tx.canFrames(gw::kChsCan, gw::kGwVehicleState);
    REQUIRE(!out.empty());
    CHECK_EQ(f.field("GW_VehicleState", "GW_VehSpd", out.back().data.data()), 0xFFFU);

    f.rx("VCU_DriveState", {{"VCU_VehSpd", 61.0}, {"VCU_GearPos", 3}});
    CHECK_EQ(f.raw("GW_VehicleState", "GW_VehSpd"), 610U);  // recovered
}

TEST_CASE("ethgw: invalid source value is propagated as invalid") {
    Fixture f;
    f.rx("VCU_DriveState", {}, {{"VCU_VehSpd", 0xFFFF}, {"VCU_GearPos", 0xF}});
    CHECK_EQ(f.raw("GW_VehicleState", "GW_VehSpd"), 0xFFFU);
    CHECK_EQ(f.raw("GW_VehicleState", "GW_GearPos"), 0xFU);
    CHECK_EQ(f.raw("GW_ADAS_VehicleInfo", "GW_VehSpd"), 0xFFFFU);
}

TEST_CASE("ethgw: E2E fault blocks signal routing but not message routing") {
    Fixture f;
    f.rx("VCU_DriveState", {{"VCU_VehSpd", 40.0}});
    CHECK_EQ(f.raw("GW_VehicleState", "GW_VehSpd"), 400U);
    f.advance(10ms);

    f.rx("VCU_DriveState", {{"VCU_VehSpd", 120.0}}, {}, true);
    f.rx("VCU_DriveState", {{"VCU_VehSpd", 120.0}}, {}, true);
    CHECK_EQ(f.raw("GW_VehicleState", "GW_VehSpd"), 400U);  // corrupted data not used
    f.rx("VCU_DriveState", {{"VCU_VehSpd", 120.0}}, {}, true);
    CHECK_EQ(f.raw("GW_VehicleState", "GW_VehSpd"), 0xFFFU);  // debounced fault
    CHECK_EQ(f.gw.statistics().e2eErrors, 3U);

    // Message routing is end-to-end transparent: all four frames went to ETH_ADAS / ETH_IVI.
    f.advance(10ms);
    CHECK_EQ(f.tx.ethPdus(gw::kEthAdas, gw::kVcuDriveState).size(), 4U);
    CHECK_EQ(f.tx.ethPdus(gw::kEthIvi, gw::kVcuDriveState).size(), 4U);

    const auto repeated = f.frame("VCU_DriveState", {{"VCU_VehSpd", 41.0}});
    f.gw.onCanFrame(gw::kPtCan, repeated, f.now);  // resynchronises (counter jump)
    f.gw.onCanFrame(gw::kPtCan, repeated, f.now);  // same counter again
    CHECK_EQ(f.gw.statistics().e2eRepeated, 1U);
    f.rx("VCU_DriveState", {{"VCU_VehSpd", 42.0}});
    CHECK_EQ(f.raw("GW_VehicleState", "GW_VehSpd"), 420U);
}
