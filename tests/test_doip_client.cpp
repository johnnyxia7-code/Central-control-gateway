#include <memory>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/diag/doip_client.hpp"
#include "ccg/doip/doip_message.hpp"
#include "doip_ecu.hpp"
#include "doip_link.hpp"
#include "test_framework.hpp"
#include "vehicle_diag_routing.hpp"
#include "vehicle_key_master.hpp"

using namespace ccg;
using namespace std::chrono_literals;
using Bytes = std::vector<std::uint8_t>;
namespace dg = config::dg;
namespace pt = doip::payload;
using diag::ClientResult;

namespace {

// Scripted network: records what the client sends, the test plays the entity.
struct ScriptedNet final : diag::IDoipConnector {
    std::vector<std::pair<diag::ConnectionId, diag::DoipTarget>> connects;
    std::vector<std::pair<std::uint16_t, Bytes>> sent;  // DoIP payload type, payload
    std::vector<diag::ConnectionId> closed;
    void connect(diag::ConnectionId id, const diag::DoipTarget& target) override { connects.emplace_back(id, target); }
    void send(diag::ConnectionId, const Bytes& d) override {
        sent.emplace_back(doip::decodeHeader(d.data()).type, Bytes(d.begin() + doip::kHeaderSize, d.end()));
    }
    void close(diag::ConnectionId id) override { closed.push_back(id); }
};

struct Scripted {
    ScriptedNet net;
    diag::DoipClient client{config::makeVehicleDoipClient(), net};
    diag::TimePoint now = diag::TimePoint{} + 10s;
    std::vector<std::pair<ClientResult, Bytes>> results;

    diag::IDiagClient::Callback collect() {
        return [this](ClientResult r, Bytes d) { results.emplace_back(r, std::move(d)); };
    }
    void fromEntity(std::uint16_t type, const Bytes& payload) {
        const auto b = doip::encode(doip::kVersion2012, type, payload);
        client.onData(1, b.data(), b.size(), now);
    }
    void advance(std::chrono::milliseconds d) {
        for (auto t = 0ms; t < d; t += 1ms) {
            now += 1ms;
            client.mainFunction(now);
        }
    }
    // Connect and activate routing for the request already queued.
    void activate() {
        client.onConnected(1, now);
        fromEntity(pt::kRoutingActivationResponse,
                   doip::routingActivationResponsePayload(dg::kInternalTester, dg::kAdas, doip::ActivationCode::Success));
    }
    Bytes response(const Bytes& uds) { return doip::diagnosticMessagePayload(dg::kAdas, dg::kInternalTester, uds); }
    Bytes ack() { return doip::diagnosticAckPayload(dg::kAdas, dg::kInternalTester, 0x00); }
};

}  // namespace

TEST_CASE("doip client: config validation") {
    CHECK(diag::validateDoipClientConfig(config::makeVehicleDoipClient()).empty());
    auto c = config::makeVehicleDoipClient();
    c.sourceAddress = 0x1001;  // not a tester address
    c.ecus.push_back({"ADAS2", dg::kAdas, "", false, ""});
    c.ecus.push_back({"X", 0x0E80, "10.0.0.1:3496", true, ""});  // tester range, TLS without server name
    CHECK_EQ(diag::validateDoipClientConfig(c).size(), 5u);
}

TEST_CASE("doip client: connect, routing activation, request and response") {
    Scripted s;
    CHECK(s.client.reaches(dg::kAdas));
    CHECK(!s.client.reaches(dg::kVcu));
    s.client.request(dg::kAdas, {0x22, 0xF2, 0xA1}, s.now, s.collect());
    REQUIRE(s.net.connects.size() == 1u);
    CHECK(s.net.connects[0].second.endpoint == std::string(dg::kAdasEndpoint));
    CHECK(s.net.connects[0].second.tls);
    CHECK(s.net.connects[0].second.serverName == std::string(dg::kAdasServerName));
    CHECK(s.net.sent.empty());  // nothing before the TCP connection is up

    s.client.onConnected(1, s.now);
    REQUIRE(s.net.sent.size() == 1u);
    CHECK_EQ(s.net.sent[0].first, pt::kRoutingActivationRequest);
    CHECK(s.net.sent[0].second == (Bytes{0x0F, 0x00, 0x00, 0, 0, 0, 0}));
    s.fromEntity(pt::kRoutingActivationResponse,
                 doip::routingActivationResponsePayload(dg::kInternalTester, dg::kAdas, doip::ActivationCode::Success));
    CHECK(s.client.routingActive(dg::kAdas));
    REQUIRE(s.net.sent.size() == 2u);
    CHECK_EQ(s.net.sent[1].first, pt::kDiagnosticMessage);
    CHECK(s.net.sent[1].second == (Bytes{0x0F, 0x00, 0x10, 0x10, 0x22, 0xF2, 0xA1}));

    s.fromEntity(pt::kDiagnosticAck, s.ack());
    // a response for another tester is ignored
    s.fromEntity(pt::kDiagnosticMessage, doip::diagnosticMessagePayload(dg::kAdas, 0x0E80, {0x62}));
    CHECK(s.results.empty());
    s.fromEntity(pt::kDiagnosticMessage, s.response({0x62, 0xF2, 0xA1, 0x01}));
    REQUIRE(s.results.size() == 1u);
    CHECK(s.results[0].first == ClientResult::Ok);
    CHECK(s.results[0].second == (Bytes{0x62, 0xF2, 0xA1, 0x01}));

    // The connection stays: the next request goes out at once.
    s.client.request(dg::kAdas, {0x3E, 0x00}, s.now, s.collect());
    CHECK_EQ(s.net.connects.size(), 1u);
    CHECK_EQ(s.net.sent.size(), 3u);
    CHECK_EQ(s.client.statistics().activations, 1u);
}

TEST_CASE("doip client: busy, unknown target, response pending and P2 timeout") {
    Scripted s;
    s.client.request(0x2000, {0x3E, 0x00}, s.now, s.collect());
    REQUIRE(s.results.size() == 1u);
    CHECK(s.results[0].first == ClientResult::UnknownTarget);

    s.client.request(dg::kAdas, {0x31, 0x01, 0xF2, 0x00}, s.now, s.collect());
    s.client.request(dg::kAdas, {0x3E, 0x00}, s.now, s.collect());
    REQUIRE(s.results.size() == 2u);
    CHECK(s.results[1].first == ClientResult::Busy);
    s.activate();
    s.fromEntity(pt::kDiagnosticAck, s.ack());
    s.advance(900ms);
    s.fromEntity(pt::kDiagnosticMessage, s.response({0x7F, 0x31, 0x78}));  // response pending
    s.advance(5000ms);
    CHECK_EQ(s.results.size(), 2u);  // P2* = 5.5 s
    s.fromEntity(pt::kDiagnosticMessage, s.response({0x71, 0x01, 0xF2, 0x00, 0x00}));
    REQUIRE(s.results.size() == 3u);
    CHECK(s.results[2].first == ClientResult::Ok);

    // ACK but no response within P2: timeout, connection kept.
    s.client.request(dg::kAdas, {0x3E, 0x00}, s.now, s.collect());
    s.fromEntity(pt::kDiagnosticAck, s.ack());
    s.advance(1001ms);
    REQUIRE(s.results.size() == 4u);
    CHECK(s.results[3].first == ClientResult::Timeout);
    CHECK(s.client.routingActive(dg::kAdas));

    // No ACK within A_DoIP_Ctrl: the connection is dropped.
    s.client.request(dg::kAdas, {0x3E, 0x00}, s.now, s.collect());
    s.advance(2001ms);
    REQUIRE(s.results.size() == 5u);
    CHECK(s.results[4].first == ClientResult::Timeout);
    CHECK(!s.client.routingActive(dg::kAdas));
    CHECK_EQ(s.net.closed.size(), 1u);
}

TEST_CASE("doip client: NACK, refused activation, generic NACK and lost connection") {
    Scripted s;
    s.client.request(dg::kAdas, {0x3E, 0x00}, s.now, s.collect());
    s.activate();
    s.fromEntity(pt::kDiagnosticNack, doip::diagnosticAckPayload(dg::kAdas, dg::kInternalTester, 0x03));
    REQUIRE(s.results.size() == 1u);
    CHECK(s.results[0].first == ClientResult::TransportError);
    CHECK(s.client.routingActive(dg::kAdas));  // a NACK does not end the connection

    // Alive check from the entity is answered with our source address.
    s.fromEntity(pt::kAliveCheckRequest, {});
    CHECK_EQ(s.net.sent.back().first, pt::kAliveCheckResponse);
    CHECK(s.net.sent.back().second == (Bytes{0x0F, 0x00}));

    // Generic header NACK: the stream is broken, connection closed.
    s.client.request(dg::kAdas, {0x3E, 0x00}, s.now, s.collect());
    s.fromEntity(pt::kGenericNack, {0x04});
    REQUIRE(s.results.size() == 2u);
    CHECK(s.results[1].first == ClientResult::TransportError);
    CHECK(!s.client.routingActive(dg::kAdas));

    // Reconnect; the entity refuses the routing activation.
    s.client.request(dg::kAdas, {0x3E, 0x00}, s.now, s.collect());
    CHECK_EQ(s.net.connects.size(), 2u);
    s.client.onConnected(1, s.now);
    s.fromEntity(pt::kRoutingActivationResponse,
                 doip::routingActivationResponsePayload(dg::kInternalTester, dg::kAdas,
                                                        doip::ActivationCode::UnknownSourceAddress));
    REQUIRE(s.results.size() == 3u);
    CHECK(s.results[2].first == ClientResult::TransportError);
    CHECK_EQ(s.client.statistics().activationFailures, 1u);

    // Connection refused / lost.
    s.client.request(dg::kAdas, {0x3E, 0x00}, s.now, s.collect());
    s.client.onClosed(1, s.now);
    REQUIRE(s.results.size() == 4u);
    CHECK(s.results[3].first == ClientResult::TransportError);
    CHECK_EQ(s.client.statistics().connectFailures, 1u);

    // No TCP connection within the connect timeout.
    s.client.request(dg::kAdas, {0x3E, 0x00}, s.now, s.collect());
    s.advance(2001ms);
    REQUIRE(s.results.size() == 5u);
    CHECK(s.results[4].first == ClientResult::Timeout);
}

TEST_CASE("doip client: UDS with the simulated ADAS DoIP entity") {
    sim::DoipLink link;
    diag::DoipClient client(config::makeVehicleDoipClient(), link);
    link.attach(client);
    auto entityCfg = config::makeAdasDoipEntity();
    entityCfg.entity.maxTcpConnections = 1;
    entityCfg.entity.generalInactivity = 3s;
    sim::DoipEcu adas(entityCfg, config::makeEcuKeySlots(dg::kAdas), link.port(dg::kAdasEndpoint));
    link.bind(dg::kAdasEndpoint, adas.entity());
    diag::TimePoint now = diag::TimePoint{} + 10s;
    adas.entity().start(now);
    std::vector<std::pair<ClientResult, Bytes>> results;
    auto collect = [&](ClientResult r, Bytes d) { results.emplace_back(r, std::move(d)); };
    auto run = [&](std::chrono::milliseconds d) {
        for (auto t = 0ms; t < d; t += 1ms) {
            now += 1ms;
            client.mainFunction(now);
            adas.entity().mainFunction(now);
            link.pump(now);
        }
    };

    client.request(dg::kAdas, {0x22, 0xF2, 0xA1}, now, collect);
    run(10ms);
    REQUIRE(results.size() == 1u);
    CHECK(results[0].first == ClientResult::Ok);
    Bytes uid = {0x62, 0xF2, 0xA1};
    uid.insert(uid.end(), adas.keys().config().uid.begin(), adas.keys().config().uid.end());
    CHECK(results[0].second == uid);
    client.request(dg::kAdas, {0x31, 0x01, 0xF2, 0x01}, now, collect);  // default session
    run(10ms);
    REQUIRE(results.size() == 2u);
    CHECK(results[1].second == (Bytes{0x7F, 0x31, 0x7F}));

    // Another tester (also on TLS) wants the only socket: the entity alive-checks us, we answer.
    adas.entity().onTcpConnected(7, now, diag::ConnectionSecurity{true, false, ""});
    const auto ra = doip::encode(doip::kVersion2012, pt::kRoutingActivationRequest, {0x0E, 0x80, 0x00, 0, 0, 0, 0});
    adas.entity().onTcpData(7, ra.data(), ra.size(), now);
    run(600ms);
    CHECK_EQ(client.statistics().aliveChecksAnswered, 1u);
    CHECK(client.routingActive(dg::kAdas));
    const auto& foreign = link.foreign(dg::kAdasEndpoint)[7];
    REQUIRE(!foreign.empty());
    CHECK_EQ(foreign.back()[doip::kHeaderSize + 4], static_cast<std::uint8_t>(doip::ActivationCode::NoFreeSocket));
    adas.entity().onTcpClosed(7, now);

    // The entity closes the idle connection; the next request reconnects.
    run(3100ms);
    CHECK(!client.routingActive(dg::kAdas));
    client.request(dg::kAdas, {0x3E, 0x00}, now, collect);
    run(10ms);
    REQUIRE(results.size() == 3u);
    CHECK(results[2].first == ClientResult::Ok);
    CHECK(results[2].second == (Bytes{0x7E, 0x00}));
    CHECK_EQ(client.statistics().connects, 2u);
}

TEST_CASE("doip client: routed tester requests (pass-through source, ACK, NRC 0x78, NACK, busy)") {
    Scripted s;
    std::vector<std::optional<doip::DiagNack>> delivered;
    std::vector<Bytes> responses;
    auto handlers = [&] {
        diag::DoipClient::RouteHandlers h;
        h.delivered = [&](std::optional<doip::DiagNack> n) { delivered.push_back(n); };
        h.response = [&](Bytes d) { responses.push_back(std::move(d)); };
        return h;
    };
    constexpr std::uint16_t kTester = 0x0E80;
    s.client.route(kTester, dg::kAdas, dg::kAdas, {0x31, 0x01, 0xFF, 0x00}, s.now, handlers());
    REQUIRE(s.net.connects.size() == 1u);
    s.client.onConnected(1, s.now);
    CHECK(s.net.sent.back().second == (Bytes{0x0E, 0x80, 0x00, 0, 0, 0, 0}));  // activation as the tester
    auto fromEntity = [&](std::uint16_t type, const Bytes& payload) {
        const auto b = doip::encode(doip::kVersion2012, type, payload);
        s.client.onData(1, b.data(), b.size(), s.now);
    };
    fromEntity(pt::kRoutingActivationResponse,
               doip::routingActivationResponsePayload(kTester, dg::kAdas, doip::ActivationCode::Success));
    CHECK(s.net.sent.back().second == (Bytes{0x0E, 0x80, 0x10, 0x10, 0x31, 0x01, 0xFF, 0x00}));
    CHECK(s.client.routingActive(dg::kAdas, kTester));
    CHECK(!s.client.routingActive(dg::kAdas));  // the internal connection is a different one

    fromEntity(pt::kDiagnosticAck, doip::diagnosticAckPayload(dg::kAdas, kTester, 0x00));
    REQUIRE(delivered.size() == 1u);
    CHECK(!delivered[0].has_value());
    // Pending and final response are both forwarded; the tester runs its own P2 timers.
    fromEntity(pt::kDiagnosticMessage, doip::diagnosticMessagePayload(dg::kAdas, kTester, {0x7F, 0x31, 0x78}));
    s.advance(6000ms);
    fromEntity(pt::kDiagnosticMessage, doip::diagnosticMessagePayload(dg::kAdas, kTester, {0x71, 0x01, 0xFF, 0x00}));
    REQUIRE(responses.size() == 2u);
    CHECK(responses[0] == (Bytes{0x7F, 0x31, 0x78}));
    CHECK(responses[1] == (Bytes{0x71, 0x01, 0xFF, 0x00}));

    // Busy until the entity acknowledged; a NACK is passed through with its code.
    s.client.route(kTester, dg::kAdas, dg::kAdas, {0x22, 0x12, 0x34}, s.now, handlers());
    s.client.route(kTester, dg::kAdas, dg::kAdas, {0x3E, 0x00}, s.now, handlers());
    REQUIRE(delivered.size() == 2u);
    CHECK(delivered[1] == std::optional<doip::DiagNack>(doip::DiagNack::TransportProtocolError));
    fromEntity(pt::kDiagnosticNack, doip::diagnosticAckPayload(dg::kAdas, kTester, 0x04));
    REQUIRE(delivered.size() == 3u);
    CHECK(delivered[2] == std::optional<doip::DiagNack>(doip::DiagNack::MessageTooLarge));

    // No ACK within A_DoIP_Ctrl: NACK "target unreachable", connection dropped.
    s.client.route(kTester, dg::kAdas, dg::kAdas, {0x3E, 0x00}, s.now, handlers());
    s.advance(2001ms);
    REQUIRE(delivered.size() == 4u);
    CHECK(delivered[3] == std::optional<doip::DiagNack>(doip::DiagNack::TargetUnreachable));
    CHECK(!s.client.routingActive(dg::kAdas, kTester));

    // Unknown ECU
    s.client.route(kTester, 0x2222, 0x2222, {0x3E, 0x00}, s.now, handlers());
    CHECK(delivered.back() == std::optional<doip::DiagNack>(doip::DiagNack::UnknownTargetAddress));
}

TEST_CASE("doip client: closeSource ends a tester's connections, not the gateway's own") {
    Scripted s;
    diag::DoipClient::RouteHandlers h;
    h.delivered = [](std::optional<doip::DiagNack>) {};
    h.response = [](Bytes) {};
    s.client.request(dg::kAdas, {0x3E, 0x00}, s.now, s.collect());   // connection 1 (0x0F00)
    s.client.route(0x0E80, dg::kAdas, dg::kAdas, {0x3E, 0x00}, s.now, h);  // connection 2
    REQUIRE(s.net.connects.size() == 2u);
    s.client.onConnected(1, s.now);
    s.client.onConnected(2, s.now);
    CHECK_EQ(s.client.openConnections(), 2u);
    s.client.closeSource(0x0E80);
    CHECK_EQ(s.client.openConnections(), 1u);
    REQUIRE(s.net.closed.size() == 1u);
    CHECK_EQ(s.net.closed[0], 2u);
    s.client.closeSource(dg::kInternalTester);  // never closes the gateway's own connection
    CHECK_EQ(s.client.openConnections(), 1u);
}
