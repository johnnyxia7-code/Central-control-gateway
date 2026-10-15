// Deterministic bench simulation of the S2S gateway with the reference vehicle
// matrix. Runs in virtual time without any hardware and prints the SOME/IP and
// CAN traffic produced by the gateway.
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

#include "ccg/can/signal_codec.hpp"
#include "ccg/e2e/can_e2e.hpp"
#include "ccg/s2s/s2s_gateway.hpp"
#include "vehicle_s2s_matrix.hpp"

namespace {

using namespace ccg;
using namespace std::chrono_literals;
namespace ids = config::ids;

s2s::TimePoint g_t0;
s2s::TimePoint g_now;

std::string stamp() {
    std::ostringstream os;
    os << "[" << std::setw(5)
       << std::chrono::duration_cast<std::chrono::milliseconds>(g_now - g_t0).count() << " ms] ";
    return os.str();
}

std::string decodeElements(const s2s::EventMapping& ev, const std::vector<std::uint8_t>& payload) {
    std::ostringstream os;
    someip::PayloadReader r(payload);
    for (const auto& el : ev.elements) {
        const auto v = s2s::readValue(r, el.type);
        os << el.name << "=" << (v ? *v : 0.0);
        if (ev.appendStatus) {
            std::uint8_t st = 0;
            r.readU8(st);
            if (st != 0) os << "(" << s2s::toString(static_cast<s2s::SignalStatus>(st)) << ")";
        }
        os << " ";
    }
    return os.str();
}

class SimCan final : public s2s::ICanTransmitter {
public:
    explicit SimCan(const s2s::GatewayConfig& cfg) : cfg_(cfg) {}
    bool transmit(const can::CanFrame& f) override {
        std::cout << stamp() << "CAN TX  0x" << std::hex << std::uppercase << f.id << std::dec
                  << " [";
        for (int i = 0; i < f.length; ++i) {
            char b[4];
            std::snprintf(b, sizeof b, "%02X", f.data[static_cast<std::size_t>(i)]);
            std::cout << (i ? " " : "") << b;
        }
        std::cout << "]";
        for (const auto& m : cfg_.txMessages) {
            if (m.canId != f.id) continue;
            std::cout << "  " << m.name << ":";
            for (const auto& s : m.signals) {
                std::cout << " " << s.name << "="
                          << can::rawToPhysical(s, can::extractRaw(f.data.data(), s));
            }
        }
        std::cout << "\n";
        return true;
    }

private:
    const s2s::GatewayConfig& cfg_;
};

class SimSomeIp final : public s2s::ISomeIpBinding {
public:
    explicit SimSomeIp(const s2s::GatewayConfig& cfg) : cfg_(cfg) {}
    void offerService(const s2s::ServiceInstance& s) override {
        std::cout << stamp() << "SD OFFER " << s.name << " 0x" << std::hex << s.serviceId
                  << "/0x" << s.instanceId << std::dec << "\n";
    }
    void notify(std::uint16_t svc, std::uint16_t, std::uint16_t,
                const someip::Message& m) override {
        const auto* ev = find(svc, m.header.methodId);
        // Cyclic events (20 ms) are printed every 100 ms or when a status changes.
        if (ev && ev->updateMode == s2s::UpdateMode::Cyclic) {
            const std::string statuses = statusSignature(*ev, m.payload);
            const bool changed = statuses != lastStatuses_[ev];
            lastStatuses_[ev] = statuses;
            if (!changed && m.header.sessionId % 5 != 0) {
                return;
            }
        }
        print("NOTIFY  ", m, ev);
    }
    void sendTo(const s2s::Peer&, const someip::Message& m) override {
        const auto* ev = m.header.messageType == someip::MessageType::Response
                             ? findByGetter(m.header.serviceId, m.header.methodId)
                             : find(m.header.serviceId, m.header.methodId);
        print("UNICAST ", m, ev);
    }

private:
    static std::string statusSignature(const s2s::EventMapping& ev,
                                       const std::vector<std::uint8_t>& payload) {
        std::string sig;
        someip::PayloadReader r(payload);
        for (const auto& el : ev.elements) {
            s2s::readValue(r, el.type);
            std::uint8_t st = 0;
            if (ev.appendStatus) r.readU8(st);
            sig.push_back(static_cast<char>('0' + st));
        }
        return sig;
    }

    const s2s::EventMapping* find(std::uint16_t svc, std::uint16_t id) const {
        for (const auto& e : cfg_.events) {
            if (e.serviceId == svc && e.eventId == id) return &e;
        }
        return nullptr;
    }
    const s2s::EventMapping* findByGetter(std::uint16_t svc, std::uint16_t id) const {
        for (const auto& e : cfg_.events) {
            if (e.serviceId == svc && e.getterMethodId && *e.getterMethodId == id) return &e;
        }
        return nullptr;
    }
    void print(const char* what, const someip::Message& m, const s2s::EventMapping* ev) const {
        std::cout << stamp() << what << std::hex << std::uppercase << "0x" << m.header.serviceId
                  << ".0x" << m.header.methodId << std::dec << " "
                  << someip::toString(m.header.messageType) << " "
                  << someip::toString(m.header.returnCode) << " session=" << m.header.sessionId;
        if (ev && !m.payload.empty()) {
            std::cout << "  " << ev->name << ": " << decodeElements(*ev, m.payload);
        }
        std::cout << "\n";
    }
    const s2s::GatewayConfig& cfg_;
    std::map<const s2s::EventMapping*, std::string> lastStatuses_;
};

// Builds Rx frames as the ECUs on the bus would send them (including E2E).
class EcuSimulator {
public:
    explicit EcuSimulator(const s2s::GatewayConfig& cfg) : cfg_(cfg) {}

    can::CanFrame frame(const std::string& message,
                        std::initializer_list<std::pair<const char*, double>> physical,
                        bool corruptCrc = false) {
        for (const auto& m : cfg_.rxMessages) {
            if (m.name != message) continue;
            can::CanFrame f;
            f.id = m.canId;
            f.length = m.length;
            for (const auto& [name, value] : physical) {
                for (const auto& s : m.signals) {
                    if (s.name == name) {
                        can::insertRaw(f.data.data(), s, can::physicalToRaw(s, value));
                    }
                }
            }
            if (m.e2e) {
                auto it = senders_.find(message);
                if (it == senders_.end()) {
                    it = senders_.emplace(message, e2e::CanE2ESender(*m.e2e)).first;
                }
                it->second.protect(f.data.data(), f.length);
                if (corruptCrc) f.data[m.e2e->crcByte] ^= 0x5A;
            }
            return f;
        }
        throw std::invalid_argument("unknown message " + message);
    }

private:
    const s2s::GatewayConfig& cfg_;
    std::map<std::string, e2e::CanE2ESender> senders_;
};

someip::Message request(std::uint16_t svc, std::uint16_t method, someip::MessageType type,
                        std::uint16_t session, std::vector<std::uint8_t> payload = {}) {
    someip::Message m;
    m.header.serviceId = svc;
    m.header.methodId = method;
    m.header.clientId = 0x0101;
    m.header.sessionId = session;
    m.header.interfaceVersion = 1;
    m.header.messageType = type;
    m.payload = std::move(payload);
    return m;
}

void log(const std::string& text) { std::cout << stamp() << "----  " << text << "\n"; }

}  // namespace

int main() {
    const auto cfg = config::makeVehicleS2SMatrix();
    SimCan can(cfg);
    SimSomeIp someip(cfg);
    EcuSimulator ecus(cfg);
    s2s::S2SGateway gw(cfg, can, someip);

    g_t0 = g_now = s2s::TimePoint{} + 1s;
    gw.start(g_now);
    const s2s::RequestContext client{ids::kInstance, s2s::Peer{0x7F000001'7595ULL}};
    gw.onSubscribe(ids::kBodyService, ids::kInstance, ids::kEgDoors, client.peer, g_now);

    std::uint16_t session = 0;
    for (int t = 0; t <= 1500; t += 5) {
        g_now = g_t0 + std::chrono::milliseconds(t);

        // --- ECUs on the CAN side
        if (t % 10 == 0) {
            const bool corrupt = t >= 900 && t < 930;
            if (t == 900) log("ESP starts sending frames with a corrupted CRC");
            gw.onCanFrame(ecus.frame("ESP_VehicleSpeed",
                                     {{"ESP_VehSpd", t * 0.036}, {"ESP_LongAccel", 1.0},
                                      {"ESP_YawRate", 0.0}},
                                     corrupt),
                          g_now);
            double angle = t < 200 ? 0.0 : (t < 400 ? 15.0 : -30.5);
            if (t >= 600) angle = t < 610 ? 45.0 : 46.0;  // two changes within 20 ms
            gw.onCanFrame(ecus.frame("EPS_SteeringAngle",
                                     {{"EPS_SteerWhlAng", angle}, {"EPS_SteerWhlSpd", 0.0}}),
                          g_now);
        }
        if (t % 100 == 0) {
            gw.onCanFrame(ecus.frame("BCM_DoorStatus", {{"BCM_DoorFLSts", t >= 300 ? 2.0 : 0.0},
                                                        {"BCM_CentralLockSts", t >= 600 ? 1.0 : 0.0}}),
                          g_now);
            if (t <= 700) {
                gw.onCanFrame(ecus.frame("BMS_PackStatus", {{"BMS_SoC", 80.5 - t * 0.001},
                                                            {"BMS_PackVolt", 400.2},
                                                            {"BMS_PackCurr", -12.5}}),
                              g_now);
            }
            if (t == 700) log("BMS goes silent (timeout 500 ms)");
        }

        // --- SOME/IP clients
        if (t == 500) {
            log("client: BodyService.SetCentralLock(request=1 LOCK)");
            gw.onSomeIpRequest(request(ids::kBodyService, ids::kMtdSetCentralLock,
                                       someip::MessageType::Request, ++session, {0x01}),
                               client, g_now);
        }
        if (t == 520) {
            log("client: BodyService.SetCentralLock(request=3) -> out of range");
            gw.onSomeIpRequest(request(ids::kBodyService, ids::kMtdSetCentralLock,
                                       someip::MessageType::Request, ++session, {0x03}),
                               client, g_now);
        }
        if (t == 550) {
            log("client: BodyService.DoorStatus getter");
            gw.onSomeIpRequest(request(ids::kBodyService, ids::kGetDoorStatus,
                                       someip::MessageType::Request, ++session),
                               client, g_now);
        }
        if (t == 800) {
            log("client: ClimateService.SetCabinClimate(22.5 degC, fan 3)");
            someip::PayloadWriter w;
            w.writeF32(22.5F);
            w.writeU8(3);
            gw.onSomeIpRequest(request(ids::kClimateService, ids::kMtdSetCabinClimate,
                                       someip::MessageType::Request, ++session, w.take()),
                               client, g_now);
        }
        if (t == 1000) {
            log("client: BodyService.OpenTrunk(true) fire&forget");
            gw.onSomeIpRequest(request(ids::kBodyService, ids::kMtdOpenTrunk,
                                       someip::MessageType::RequestNoReturn, ++session, {0x01}),
                               client, g_now);
        }

        gw.mainFunction(g_now);
    }

    const auto& s = gw.statistics();
    std::cout << "\nstatistics: rxAccepted=" << s.canRxAccepted << " e2eCrcErrors=" << s.e2eCrcErrors
              << " rxTimeouts=" << s.rxTimeouts << " notifications=" << s.notificationsSent
              << " requests=" << s.requestsReceived << " responses=" << s.responsesSent
              << " errors=" << s.errorResponsesSent << " canTx=" << s.canTxFrames << "\n";
    return 0;
}
