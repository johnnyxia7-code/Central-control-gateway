// DoIP over TLS, transport independent part: what the gateway does with the
// connection security reported by the TLS layer (ISO 13400-2:2019).
#include <optional>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/doip/doip_message.hpp"
#include "ccg/keym/key_management_service.hpp"
#include "test_framework.hpp"
#include "vehicle_diag_routing.hpp"
#include "vehicle_key_slots.hpp"

using namespace ccg;
using namespace std::chrono_literals;
using Bytes = std::vector<std::uint8_t>;
namespace dg = config::dg;
namespace pt = doip::payload;

namespace {

struct Capture final : diag::IDiagTransport {
    std::vector<std::pair<diag::ConnectionId, Bytes>> tcp;
    std::vector<diag::ConnectionId> closed;
    void sendTcp(diag::ConnectionId c, const Bytes& d) override { tcp.emplace_back(c, d); }
    void closeTcp(diag::ConnectionId c) override { closed.push_back(c); }
    void sendUdp(const diag::UdpPeer&, const Bytes&) override {}
    void broadcastUdp(const Bytes&) override {}
    bool transmitCan(std::size_t, const can::CanFrame&) override { return true; }
};

// Records the request context the gateway hands to its local services.
struct ContextProbe final : diag::ILocalServiceHandler {
    std::optional<diag::LocalRequestContext> last;
    std::optional<Bytes> handle(const Bytes& request, const diag::LocalRequestContext& context) override {
        if (request.size() == 3 && request[0] == 0x22 && request[1] == 0xFD && request[2] == 0x01) {
            last = context;
            return Bytes{0x62, 0xFD, 0x01};
        }
        return std::nullopt;
    }
};

struct Gateway {
    Capture tx;
    diag::DiagGateway gw;
    diag::TimePoint now = diag::TimePoint{} + 10s;
    ContextProbe probe;

    explicit Gateway(bool requireTls = false) : gw(config(requireTls), tx) {
        gw.addLocalService(probe);
        gw.start(now);
    }
    static diag::DiagRoutingConfig config(bool requireTls) {
        auto c = config::makeVehicleDiagRouting();
        c.entity.requireTls = requireTls;
        return c;
    }
    void send(diag::ConnectionId id, std::uint16_t type, const Bytes& payload) {
        const auto b = doip::encode(doip::kVersion2012, type, payload);
        gw.onTcpData(id, b.data(), b.size(), now);
    }
    // Connects and activates; returns the routing activation response code.
    std::uint8_t activate(diag::ConnectionId id, const diag::ConnectionSecurity& security, std::uint8_t type,
                          std::uint16_t tester = dg::kTester) {
        gw.onTcpConnected(id, now, security);
        tx.tcp.clear();
        send(id, pt::kRoutingActivationRequest,
             {static_cast<std::uint8_t>(tester >> 8), static_cast<std::uint8_t>(tester), type, 0, 0, 0, 0});
        for (const auto& [c, m] : tx.tcp) {
            if (c == id && doip::decodeHeader(m.data()).type == pt::kRoutingActivationResponse) {
                return m[doip::kHeaderSize + 4];
            }
        }
        return 0xFF;
    }
    Bytes uds(diag::ConnectionId id, std::uint16_t target, const Bytes& request, std::uint16_t tester = dg::kTester) {
        tx.tcp.clear();
        send(id, pt::kDiagnosticMessage, doip::diagnosticMessagePayload(tester, target, request));
        for (const auto& [c, m] : tx.tcp) {
            if (c == id && doip::decodeHeader(m.data()).type == pt::kDiagnosticMessage) {
                return Bytes(m.begin() + doip::kHeaderSize + 4, m.end());
            }
        }
        return {};
    }
};

const diag::ConnectionSecurity kPlain{};
const diag::ConnectionSecurity kTlsAnonymous{true, false, ""};
const diag::ConnectionSecurity kTlsCertified{true, true, "workshop-tester-17"};

}  // namespace

TEST_CASE("doip tls: plain TCP is refused with 0x07 when TLS is required") {
    Gateway g(true);
    CHECK_EQ(g.activate(1, kPlain, diag::kActivationDefault), 0x07);
    CHECK(!g.tx.closed.empty() && g.tx.closed.back() == 1u);
    CHECK_EQ(g.activate(2, kTlsAnonymous, diag::kActivationDefault), 0x10);
    CHECK(g.gw.isRoutingActive(2));
    CHECK_EQ(g.gw.statistics().tlsConnections, 1u);
}

TEST_CASE("doip tls: central security activation needs TLS and a verified client certificate") {
    Gateway g;
    CHECK_EQ(g.activate(1, kPlain, diag::kActivationCentralSecurity), 0x07);
    CHECK_EQ(g.activate(2, kTlsAnonymous, diag::kActivationCentralSecurity, 0x0E81), 0x04);
    CHECK_EQ(g.activate(3, kTlsCertified, diag::kActivationCentralSecurity, 0x0E82), 0x10);
    CHECK_EQ(g.activate(4, kPlain, diag::kActivationDefault, 0x0E83), 0x10);  // TLS optional by default
    // "authenticated" without TLS is not believed
    CHECK_EQ(g.activate(5, diag::ConnectionSecurity{false, true, "x"}, diag::kActivationCentralSecurity, 0x0E84),
             0x07);
    CHECK_EQ(g.gw.statistics().authenticatedConnections, 1u);
}

TEST_CASE("doip tls: local services see whether the tester is authenticated") {
    Gateway g;
    REQUIRE(g.activate(1, kTlsCertified, diag::kActivationDefault) == 0x10);
    CHECK(g.uds(1, dg::kGateway, {0x22, 0xFD, 0x01}) == (Bytes{0x62, 0xFD, 0x01}));
    REQUIRE(g.probe.last.has_value());
    CHECK(g.probe.last->tls && g.probe.last->authenticated);

    REQUIRE(g.activate(2, kTlsAnonymous, diag::kActivationDefault, 0x0E81) == 0x10);
    g.uds(2, dg::kGateway, {0x22, 0xFD, 0x01}, 0x0E81);
    CHECK(g.probe.last->tls && !g.probe.last->authenticated);

    g.gw.onTcpClosed(1, g.now);  // two TCP_DATA sockets in the reference configuration
    REQUIRE(g.activate(3, kPlain, diag::kActivationDefault, 0x0E82) == 0x10);
    g.uds(3, dg::kFunctional, {0x22, 0xFD, 0x01}, 0x0E82);  // functional requests too
    CHECK(g.probe.last->functional && !g.probe.last->tls && !g.probe.last->authenticated);
}

TEST_CASE("doip tls: activating or discarding keys needs a certificate-authenticated tester") {
    Gateway g;
    keym::KeyManager keys(config::makeVehicleKeySlots());
    config::provisionDemoKeyStore(keys, g.now);
    keym::KeyManagementService service(keys, {}, true);
    g.gw.addLocalService(service);
    keym::she::Flags flags;
    flags.keyUsage = true;
    REQUIRE(keys.stageInternal(config::keyslot::kVcuGw, crypto::Block{1}, 2, flags, g.now) ==
            keym::she::ErrorCode::NoError);

    REQUIRE(g.activate(1, kTlsAnonymous, diag::kActivationDefault) == 0x10);
    g.uds(1, dg::kGateway, {0x10, 0x03});
    CHECK(g.uds(1, dg::kGateway, {0x31, 0x01, 0xF2, 0x01}) == (Bytes{0x7F, 0x31, 0x33}));
    CHECK(keys.hasPending());
    // Reading the key status stays open to every tester.
    CHECK_EQ(g.uds(1, dg::kGateway, {0x22, 0xF2, 0xA0}).at(0), 0x62);

    REQUIRE(g.activate(2, kTlsCertified, diag::kActivationCentralSecurity, 0x0E81) == 0x10);
    CHECK(g.uds(2, dg::kGateway, {0x31, 0x01, 0xF2, 0x01}, 0x0E81) == (Bytes{0x71, 0x01, 0xF2, 0x01, 0x01}));
    CHECK(!keys.hasPending());
}
