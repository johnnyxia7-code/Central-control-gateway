#include <deque>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/diag/doip_client.hpp"
#include "ccg/doip/doip_message.hpp"
#include "doip_ecu.hpp"
#include "doip_link.hpp"
#include "test_framework.hpp"
#include "uds_ecu.hpp"
#include "vehicle_diag_routing.hpp"
#include "vehicle_key_master.hpp"

using namespace ccg;
using namespace std::chrono_literals;
using Bytes = std::vector<std::uint8_t>;
namespace dg = config::dg;
namespace pt = doip::payload;

namespace {

struct Message {
    std::uint16_t type;
    Bytes payload;
};

struct TesterSide final : diag::IDiagTransport {
    std::vector<Message> tcp;
    std::deque<std::pair<std::size_t, can::CanFrame>> canOut;
    bool closed = false;
    void sendTcp(diag::ConnectionId, const Bytes& d) override {
        tcp.push_back({doip::decodeHeader(d.data()).type, Bytes(d.begin() + doip::kHeaderSize, d.end())});
    }
    void closeTcp(diag::ConnectionId) override { closed = true; }
    void sendUdp(const diag::UdpPeer&, const Bytes&) override {}
    void broadcastUdp(const Bytes&) override {}
    bool transmitCan(std::size_t ch, const can::CanFrame& f) override {
        canOut.emplace_back(ch, f);
        return true;
    }
};

// Tester -> gateway (DoIP) -> ADAS (DoIP) and CAN ECUs (ISO-TP).
struct Routing {
    diag::TimePoint now = diag::TimePoint{} + 100s;
    TesterSide tester;
    diag::DiagGateway gw{config::makeVehicleDiagRouting(), tester};
    sim::DoipLink ethernet;
    diag::DoipClient doip{config::makeVehicleDoipClient(), ethernet};
    std::unique_ptr<sim::DoipEcu> adas;
    std::vector<std::pair<std::size_t, std::unique_ptr<sim::UdsEcu>>> canEcus;
    std::deque<std::pair<std::size_t, can::CanFrame>> ecuOut;

    explicit Routing(diag::DiagRoutingConfig adasEntity = config::makeAdasDoipEntity(),
                     const diag::ConnectionSecurity& security = {}) {
        ethernet.attach(doip);
        gw.setEthernetRouting(doip);
        adas = std::make_unique<sim::DoipEcu>(std::move(adasEntity), config::makeEcuKeySlots(dg::kAdas),
                                              ethernet.port(dg::kAdasEndpoint));
        ethernet.bind(dg::kAdasEndpoint, adas->entity());
        for (const auto& route : gw.config().ecus) {
            sim::UdsEcu::Config ec;
            ec.name = route.name;
            ec.requestId = route.requestId;
            ec.responseId = route.responseId;
            ec.fd = route.fd;
            const std::size_t ch = *gw.channelIndex(route.channel);
            canEcus.emplace_back(ch, std::make_unique<sim::UdsEcu>(ec, [this, ch](const can::CanFrame& f) {
                                     ecuOut.emplace_back(ch, f);
                                     return true;
                                 }));
        }
        gw.start(now);
        adas->entity().start(now);
        gw.onTcpConnected(1, now, security);
        send(pt::kRoutingActivationRequest, {0x0E, 0x80, 0x00, 0, 0, 0, 0});
    }

    void send(std::uint16_t type, const Bytes& payload) {
        const auto b = doip::encode(doip::kVersion2012, type, payload);
        gw.onTcpData(1, b.data(), b.size(), now);
    }
    void request(std::uint16_t target, const Bytes& uds) {
        tester.tcp.clear();
        send(pt::kDiagnosticMessage, doip::diagnosticMessagePayload(dg::kTester, target, uds));
    }
    void run(std::chrono::milliseconds d) {
        for (auto t = 0ms; t < d; t += 1ms) {
            now += 1ms;
            gw.mainFunction(now);
            doip.mainFunction(now);
            adas->entity().mainFunction(now);
            for (auto& [ch, e] : canEcus) e->mainFunction(now);
            for (int guard = 0; guard < 1000 && (!tester.canOut.empty() || !ecuOut.empty()); ++guard) {
                while (!tester.canOut.empty()) {
                    const auto [ch, f] = tester.canOut.front();
                    tester.canOut.pop_front();
                    for (auto& [ech, e] : canEcus) {
                        if (ech == ch) e->onFrame(f, now);
                    }
                }
                while (!ecuOut.empty()) {
                    const auto [ch, f] = ecuOut.front();
                    ecuOut.pop_front();
                    gw.onCanFrame(ch, f, now);
                }
            }
            ethernet.pump(now);
        }
    }
    // Messages of `type` to the tester whose source address is `from`.
    std::vector<Bytes> fromSource(std::uint16_t type, std::uint16_t from) const {
        std::vector<Bytes> out;
        for (const auto& m : tester.tcp) {
            if (m.type == type && m.payload.size() >= 4 && doip::readU16(m.payload.data()) == from) {
                out.push_back(m.payload);
            }
        }
        return out;
    }
    std::vector<Bytes> responses(std::uint16_t from) const {
        std::vector<Bytes> out;
        for (const auto& p : fromSource(pt::kDiagnosticMessage, from)) out.emplace_back(p.begin() + 4, p.end());
        return out;
    }
};

}  // namespace

TEST_CASE("doip routing: tester reads the ADAS ECU through the gateway") {
    Routing r;
    r.request(dg::kAdas, {0x22, 0xF1, 0x90});
    CHECK(r.tester.tcp.empty());  // ACK only once ADAS acknowledged
    r.run(5ms);
    const auto acks = r.fromSource(pt::kDiagnosticAck, dg::kAdas);
    REQUIRE(acks.size() == 1u);
    CHECK_EQ(doip::readU16(acks[0].data() + 2), dg::kTester);
    const auto rsp = r.responses(dg::kAdas);
    REQUIRE(rsp.size() == 1u);
    const std::string vin = config::makeAdasDoipEntity().entity.vin;
    Bytes expected = {0x62, 0xF1, 0x90};
    expected.insert(expected.end(), vin.begin(), vin.end());
    CHECK(rsp[0] == expected);
    // ACK before the response
    CHECK_EQ(r.tester.tcp.front().type, pt::kDiagnosticAck);

    // ADAS saw the tester's own address (activation and message).
    const auto& toAdas = r.ethernet.received(dg::kAdasEndpoint);
    REQUIRE(toAdas.size() == 2u);
    CHECK_EQ(doip::decodeHeader(toAdas[0].data()).type, pt::kRoutingActivationRequest);
    CHECK_EQ(doip::readU16(toAdas[0].data() + doip::kHeaderSize), dg::kTester);
    CHECK_EQ(doip::readU16(toAdas[1].data() + doip::kHeaderSize), dg::kTester);
    CHECK_EQ(doip::readU16(toAdas[1].data() + doip::kHeaderSize + 2), dg::kAdas);
    CHECK(r.doip.routingActive(dg::kAdas, dg::kTester));
    CHECK_EQ(r.gw.statistics().ethernetRequests, 1u);
    CHECK_EQ(r.gw.statistics().ethernetResponses, 1u);

    // The connection is kept: the next request needs no new routing activation.
    r.request(dg::kAdas, {0x10, 0x03});
    r.run(5ms);
    CHECK(r.responses(dg::kAdas).at(0) == (Bytes{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4}));
    CHECK_EQ(r.doip.statistics().activations, 1u);
}

TEST_CASE("doip routing: tester and key master use separate connections to ADAS") {
    Routing r;
    std::optional<std::pair<diag::ClientResult, Bytes>> internal;
    r.request(dg::kAdas, {0x22, 0xF1, 0x90});
    r.doip.request(dg::kAdas, {0x22, 0xF2, 0xA1}, r.now,
                   [&](diag::ClientResult res, Bytes d) { internal.emplace(res, std::move(d)); });
    r.run(5ms);
    REQUIRE(internal.has_value());
    CHECK(internal->first == diag::ClientResult::Ok);
    CHECK_EQ(internal->second.at(0), 0x62);
    CHECK_EQ(r.responses(dg::kAdas).size(), 1u);  // the tester gets only its own answer
    CHECK(r.doip.routingActive(dg::kAdas, dg::kTester));
    CHECK(r.doip.routingActive(dg::kAdas, dg::kInternalTester));
    CHECK_EQ(r.doip.openConnections(), 2u);
    CHECK_EQ(r.adas->entity().openConnections(), 2u);
}

TEST_CASE("doip routing: unreachable ADAS or refused activation give NACK 0x06 to the tester") {
    {
        Routing r;
        r.ethernet.setReachable(dg::kAdasEndpoint, false);
        r.request(dg::kAdas, {0x22, 0xF1, 0x90});
        r.run(5ms);
        const auto nacks = r.fromSource(pt::kDiagnosticNack, dg::kAdas);
        REQUIRE(nacks.size() == 1u);
        CHECK_EQ(nacks[0].at(4), static_cast<std::uint8_t>(doip::DiagNack::TargetUnreachable));
    }
    {
        auto entity = config::makeAdasDoipEntity();
        entity.entity.testerAddressMin = 0x0F00;  // ADAS accepts in-vehicle testers only
        Routing r(entity);
        r.request(dg::kAdas, {0x22, 0xF1, 0x90});
        r.run(5ms);
        const auto nacks = r.fromSource(pt::kDiagnosticNack, dg::kAdas);
        REQUIRE(nacks.size() == 1u);
        CHECK_EQ(nacks[0].at(4), static_cast<std::uint8_t>(doip::DiagNack::TargetUnreachable));
        CHECK_EQ(r.doip.statistics().activationFailures, 1u);
    }
    {
        Routing r;  // unknown addresses are still refused by the gateway itself
        r.request(0x1099, {0x22, 0xF1, 0x90});
        const auto nacks = r.fromSource(pt::kDiagnosticNack, 0x1099);
        REQUIRE(nacks.size() == 1u);
        CHECK_EQ(nacks[0].at(4), static_cast<std::uint8_t>(doip::DiagNack::UnknownTargetAddress));
    }
}

TEST_CASE("doip routing: functional requests reach the CAN ECUs and ADAS") {
    Routing r;
    r.request(dg::kFunctional, {0x10, 0x03});
    r.run(50ms);
    CHECK_EQ(r.fromSource(pt::kDiagnosticAck, dg::kFunctional).size(), 1u);  // one ACK, from the gateway
    CHECK(r.fromSource(pt::kDiagnosticNack, dg::kAdas).empty());
    CHECK_EQ(r.responses(dg::kVcu).size(), 1u);
    CHECK_EQ(r.responses(dg::kBcm).size(), 1u);
    const auto adas = r.responses(dg::kAdas);
    REQUIRE(adas.size() == 1u);
    CHECK(adas[0] == (Bytes{0x50, 0x03, 0x00, 0x32, 0x01, 0xF4}));
    // ADAS got the request on the functional address
    const auto& toAdas = r.ethernet.received(dg::kAdasEndpoint);
    CHECK_EQ(doip::readU16(toAdas.back().data() + doip::kHeaderSize + 2), dg::kFunctional);
}

TEST_CASE("doip routing: the tester leaves, its ADAS connection is closed") {
    Routing r;
    r.request(dg::kAdas, {0x3E, 0x00});
    r.run(5ms);
    CHECK_EQ(r.adas->entity().openConnections(), 1u);
    r.gw.onTcpClosed(1, r.now);
    r.run(5ms);
    CHECK_EQ(r.doip.openConnections(), 0u);
    CHECK_EQ(r.adas->entity().openConnections(), 0u);
}

// --------------------------------------------------------------- DoIP over TLS to ADAS

TEST_CASE("doip routing: the gateway reaches ADAS over TLS with its vehicle certificate") {
    Routing r;
    r.request(dg::kAdas, {0x22, 0xF1, 0x90});
    std::optional<diag::ClientResult> internal;
    r.doip.request(dg::kAdas, {0x3E, 0x00}, r.now, [&](diag::ClientResult res, Bytes) { internal = res; });
    r.run(5ms);
    CHECK_EQ(r.responses(dg::kAdas).size(), 1u);
    CHECK(internal == std::optional<diag::ClientResult>(diag::ClientResult::Ok));
    // ADAS (TLS required) sees two TLS connections authenticated by the gateway's certificate.
    CHECK_EQ(r.adas->entity().statistics().tlsConnections, 2u);
    CHECK_EQ(r.adas->entity().statistics().authenticatedConnections, 2u);
    CHECK_EQ(r.adas->entity().statistics().routingActivationsAccepted, 2u);
}

TEST_CASE("doip routing: ADAS certificate problems stop the connection") {
    struct Case {
        sim::DoipLink::TlsServer server;
        sim::DoipLink::TlsClient client;
    };
    sim::DoipLink::TlsClient noCertificate;
    noCertificate.present = false;
    const std::vector<Case> cases = {
        {{true, "ivi-head-unit", true, false}, {}},  // certificate names another ECU
        {{true, "", false, false}, {}},              // not signed by the vehicle CA
        {{false, "", true, false}, {}},              // the endpoint offers no TLS
        {{true, "", true, true}, noCertificate},     // ADAS wants the gateway's certificate
    };
    for (const auto& c : cases) {
        Routing r;
        r.ethernet.setTls(dg::kAdasEndpoint, c.server);
        r.ethernet.setClientCertificate(c.client);
        r.request(dg::kAdas, {0x22, 0xF1, 0x90});
        std::optional<diag::ClientResult> internal;
        r.doip.request(dg::kAdas, {0x3E, 0x00}, r.now, [&](diag::ClientResult res, Bytes) { internal = res; });
        r.run(5ms);
        const auto nacks = r.fromSource(pt::kDiagnosticNack, dg::kAdas);
        REQUIRE(nacks.size() == 1u);
        CHECK_EQ(nacks[0].at(4), static_cast<std::uint8_t>(doip::DiagNack::TargetUnreachable));
        CHECK(internal == std::optional<diag::ClientResult>(diag::ClientResult::TransportError));
        CHECK_EQ(r.ethernet.tlsHandshakeFailures(), 2u);
        CHECK_EQ(r.adas->entity().statistics().tcpConnectionsAccepted, 0u);  // nothing reached ADAS
    }
}

TEST_CASE("doip routing: a plain route to an ADAS that requires TLS is refused with 0x07") {
    auto cfg = config::makeVehicleDoipClient();
    cfg.ecus[0].tls = false;
    TesterSide tester;
    diag::DiagGateway gw(config::makeVehicleDiagRouting(), tester);
    sim::DoipLink ethernet;
    diag::DoipClient doip(cfg, ethernet);
    ethernet.attach(doip);
    sim::DoipEcu adas(config::makeAdasDoipEntity(), config::makeEcuKeySlots(dg::kAdas), ethernet.port(dg::kAdasEndpoint));
    ethernet.bind(dg::kAdasEndpoint, adas.entity());
    diag::TimePoint now = diag::TimePoint{} + 1s;
    std::optional<diag::ClientResult> result;
    doip.request(dg::kAdas, {0x3E, 0x00}, now, [&](diag::ClientResult res, Bytes) { result = res; });
    for (int i = 0; i < 5; ++i) ethernet.pump(now);
    CHECK(result == std::optional<diag::ClientResult>(diag::ClientResult::TransportError));
    CHECK_EQ(doip.statistics().activationFailures, 1u);
    CHECK_EQ(adas.entity().statistics().routingActivationsRejected, 1u);
}

TEST_CASE("doip routing: key activation and discard preserve tester authorization") {
    for (const auto& security : {diag::ConnectionSecurity{}, diag::ConnectionSecurity{true, false, ""},
                                  diag::ConnectionSecurity{true, true, "workshop"}}) {
        for (const std::uint8_t rid : {0x01, 0x02}) {
            for (const std::uint8_t sub : {0x01, 0x81}) {
                Routing r(config::makeAdasDoipEntity(), security);
                config::provisionDemoEcuKeyStore(r.adas->keys(), r.now);
                keym::she::Flags flags;
                flags.keyUsage = true;
                REQUIRE(r.adas->keys().stageInternal(keym::she::kKey1, crypto::Block{42}, 2, flags, r.now) ==
                        keym::she::ErrorCode::NoError);
                r.request(dg::kAdas, {0x10, 0x03});
                r.run(5ms);
                r.request(dg::kAdas, {0x31, sub, 0xF2, rid});
                r.run(5ms);
                CHECK(r.adas->keys().hasPending() == !security.clientAuthenticated);
                const auto replies = r.responses(dg::kAdas);
                if (!security.clientAuthenticated) {
                    REQUIRE(replies.size() == 1u);
                    CHECK(replies[0] == (Bytes{0x7F, 0x31, 0x33}));
                    CHECK_EQ(r.gw.statistics().ethernetRequests, 1u); // only session control was forwarded
                } else if (sub == 0x01) {
                    REQUIRE(replies.size() == 1u);
                    CHECK(replies[0] == (Bytes{0x71, 0x01, 0xF2, rid, 0x01}));
                } else {
                    CHECK(replies.empty()); // suppressPositiveResponse never bypasses authorization
                }
            }
        }
    }
}
