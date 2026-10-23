#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ccg/diag/diag_gateway.hpp"
#include "ccg/diag/doip_client.hpp"

// In-memory vehicle Ethernet for tests and simulation: TCP connections from
// the gateway's DoIP client to simulated DoIP entities. Events are queued and
// delivered by pump(), like frames on a real network.
//
// TLS routes are modelled by their outcome (the real handshake is tested
// with OpenSSL on loopback): the handshake fails if the entity has no TLS,
// its certificate is untrusted or names another identity, or it requires a
// client certificate the gateway does not present; otherwise the entity sees
// a TLS connection, authenticated if the gateway's certificate is trusted.
namespace ccg::sim {

class DoipLink final : public diag::IDoipConnector {
public:
    // Transport for the simulated entity listening at `endpoint`; pass it to
    // the entity's constructor, then bind() the entity.
    diag::IDiagTransport& port(const std::string& endpoint);
    void bind(const std::string& endpoint, diag::DiagGateway& entity);
    void attach(diag::DoipClient& client) { client_ = &client; }

    void setReachable(const std::string& endpoint, bool reachable) { entities_[endpoint].reachable = reachable; }

    struct TlsServer {
        bool enabled = true;           // the entity offers TLS
        std::string certificateName;   // identity in its certificate (empty: what the client expects)
        bool trusted = true;           // signed by the vehicle CA
        bool requireClientCertificate = false;
    };
    void setTls(const std::string& endpoint, const TlsServer& tls) { entities_[endpoint].tls = tls; }
    struct TlsClient {
        bool present = true;           // the gateway presents its vehicle certificate
        bool trusted = true;
        std::string name = "ccg-gateway";
    };
    void setClientCertificate(const TlsClient& client) { client_cert_ = client; }
    std::uint64_t tlsHandshakeFailures() const { return tlsFailures_; }
    void setMuted(const std::string& endpoint, bool muted) { entities_[endpoint].muted = muted; }

    // diag::IDoipConnector
    void connect(diag::ConnectionId id, const diag::DoipTarget& target) override;
    void send(diag::ConnectionId id, const std::vector<std::uint8_t>& data) override;
    void close(diag::ConnectionId id) override;

    void pump(diag::TimePoint now);

    // Traffic of entity connections that are not the gateway's (opened by a test).
    std::map<diag::ConnectionId, std::vector<std::vector<std::uint8_t>>>& foreign(const std::string& endpoint) {
        return entities_[endpoint].foreign;
    }
    std::uint64_t bytesToEntities() const { return bytesToEntities_; }
    // DoIP messages the gateway sent to the entity (header included).
    const std::vector<std::vector<std::uint8_t>>& received(const std::string& endpoint) {
        return entities_[endpoint].received;
    }

private:
    struct Port final : diag::IDiagTransport {
        DoipLink* link = nullptr;
        std::string endpoint;
        void sendTcp(diag::ConnectionId c, const std::vector<std::uint8_t>& d) override;
        void closeTcp(diag::ConnectionId c) override;
        void sendUdp(const diag::UdpPeer&, const std::vector<std::uint8_t>&) override {}
        void broadcastUdp(const std::vector<std::uint8_t>&) override {}
        bool transmitCan(std::size_t, const can::CanFrame&) override { return false; }
    };
    struct Entity {
        std::unique_ptr<Port> port;
        diag::DiagGateway* gateway = nullptr;
        bool reachable = true;
        bool muted = false;
        TlsServer tls;
        std::map<diag::ConnectionId, diag::ConnectionId> clientOf;  // entity connection -> client id
        std::map<diag::ConnectionId, std::vector<std::vector<std::uint8_t>>> foreign;
        std::vector<std::vector<std::uint8_t>> received;
    };
    struct Event {
        enum class Kind : std::uint8_t { Connect, ToEntity, ToClient, CloseByClient, CloseByEntity } kind;
        diag::ConnectionId client = 0;
        std::string endpoint;
        std::vector<std::uint8_t> data;
        bool tls = false;
        std::string serverName;
    };

    diag::DoipClient* client_ = nullptr;
    std::map<std::string, Entity> entities_;
    std::map<diag::ConnectionId, std::pair<std::string, diag::ConnectionId>> routes_;  // client id -> entity conn
    std::deque<Event> events_;
    diag::ConnectionId nextEntityConnection_ = 100;
    std::uint64_t bytesToEntities_ = 0;
    TlsClient client_cert_;
    std::uint64_t tlsFailures_ = 0;
};

}  // namespace ccg::sim
