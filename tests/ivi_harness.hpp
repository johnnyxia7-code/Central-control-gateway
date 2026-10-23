#pragma once

// In-process HPC <-> IVI harness: the real S2SGateway (HPC) on one side, the
// IVI VehicleClient on the other, connected by a loopback "SOME/IP stack".

#include <deque>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "ccg/can/signal_codec.hpp"
#include "ccg/e2e/can_e2e.hpp"
#include "ccg/ivi/vehicle_client.hpp"
#include "ccg/s2s/s2s_gateway.hpp"
#include "vehicle_s2s_matrix.hpp"

namespace ccg::test {

using namespace std::chrono_literals;

struct HarnessCan final : s2s::ICanTransmitter {
    std::vector<can::CanFrame> frames;
    bool transmit(const can::CanFrame& f) override {
        frames.push_back(f);
        return true;
    }
};

// Client side of the loopback: queues requests until the harness pumps them.
struct LoopbackClientTransport final : ivi::IClientTransport {
    std::vector<std::uint16_t> requested;
    std::deque<someip::Message> outbox;
    std::uint16_t session = 0;
    bool accept = true;

    void requestService(const ivi::ServiceDescriptor& s) override { requested.push_back(s.serviceId); }
    std::optional<std::uint16_t> send(std::uint16_t, const someip::Message& request) override {
        if (!accept) return std::nullopt;
        someip::Message m = request;
        m.header.clientId = 0x1234;
        m.header.sessionId = someip::nextSessionId(session);
        outbox.push_back(m);
        return m.header.sessionId;
    }
};

// HPC side of the loopback: every notification goes to the single IVI subscriber.
struct LoopbackServerBinding final : s2s::ISomeIpBinding {
    std::deque<someip::Message> toClient;
    std::vector<s2s::ServiceInstance> offered;

    void offerService(const s2s::ServiceInstance& s) override { offered.push_back(s); }
    void notify(std::uint16_t, std::uint16_t, std::uint16_t, const someip::Message& m) override {
        toClient.push_back(m);
    }
    void sendTo(const s2s::Peer&, const someip::Message& m) override { toClient.push_back(m); }
};

struct IviHarness {
    s2s::GatewayConfig cfg = config::makeVehicleS2SMatrix();
    HarnessCan can;
    LoopbackServerBinding server;
    s2s::S2SGateway gw{cfg, can, server};
    LoopbackClientTransport transport;
    ivi::VehicleClient client;
    s2s::TimePoint now = s2s::TimePoint{} + 10s;
    std::map<std::string, e2e::CanE2ESender> senders;

    explicit IviHarness(ivi::ClientOptions options = {}) : client(transport, options) {
        gw.start(now);
        client.start();
    }

    void offerAll() {
        for (const auto& s : server.offered) {
            client.onAvailability(s.serviceId, s.instanceId, true, now);
        }
    }

    // Delivers queued messages in both directions until nothing is left.
    void pump() {
        while (!transport.outbox.empty() || !server.toClient.empty()) {
            while (!transport.outbox.empty()) {
                auto m = transport.outbox.front();
                transport.outbox.pop_front();
                gw.onSomeIpRequest(m, s2s::RequestContext{config::ids::kInstance, s2s::Peer{1}}, now);
            }
            while (!server.toClient.empty()) {
                auto m = server.toClient.front();
                server.toClient.pop_front();
                client.onMessage(m, now);
            }
        }
    }

    void advance(std::chrono::milliseconds duration) {
        for (std::chrono::milliseconds t{0}; t < duration; t += 5ms) {
            now += 5ms;
            gw.mainFunction(now);
            client.mainFunction(now);
            pump();
        }
    }

    void rx(const std::string& name, const std::vector<std::pair<std::string, double>>& physical,
            const std::vector<std::pair<std::string, std::uint64_t>>& raw = {}) {
        for (const auto& m : cfg.rxMessages) {
            if (m.name != name) continue;
            can::CanFrame f;
            f.id = m.canId;
            f.length = m.length;
            for (const auto& s : m.signals) {
                for (const auto& [n, v] : physical) {
                    if (n == s.name) can::insertRaw(f.data.data(), s, can::physicalToRaw(s, v));
                }
                for (const auto& [n, v] : raw) {
                    if (n == s.name) can::insertRaw(f.data.data(), s, v);
                }
            }
            if (m.e2e) {
                auto it = senders.find(name);
                if (it == senders.end()) it = senders.emplace(name, e2e::CanE2ESender(*m.e2e)).first;
                it->second.protect(f.data.data(), f.length);
            }
            gw.onCanFrame(f, now);
            pump();
            return;
        }
    }

    std::optional<double> txSignal(const std::string& message, const std::string& signal) const {
        for (const auto& m : cfg.txMessages) {
            if (m.name != message) continue;
            for (auto it = can.frames.rbegin(); it != can.frames.rend(); ++it) {
                if (it->id != m.canId) continue;
                for (const auto& s : m.signals) {
                    if (s.name == signal) {
                        return can::rawToPhysical(s, can::extractRaw(it->data.data(), s));
                    }
                }
            }
        }
        return std::nullopt;
    }
};

}  // namespace ccg::test
