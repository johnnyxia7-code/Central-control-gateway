#include "doip_link.hpp"

#include <memory>

namespace ccg::sim {

diag::IDiagTransport& DoipLink::port(const std::string& endpoint) {
    auto& e = entities_[endpoint];
    if (!e.port) {
        e.port = std::make_unique<Port>();
        e.port->link = this;
        e.port->endpoint = endpoint;
    }
    return *e.port;
}

void DoipLink::bind(const std::string& endpoint, diag::DiagGateway& entity) { entities_[endpoint].gateway = &entity; }

void DoipLink::connect(diag::ConnectionId id, const diag::DoipTarget& target) {
    events_.push_back({Event::Kind::Connect, id, target.endpoint, {}, target.tls, target.serverName});
}

void DoipLink::send(diag::ConnectionId id, const std::vector<std::uint8_t>& data) {
    events_.push_back({Event::Kind::ToEntity, id, {}, data, false, {}});
}

void DoipLink::close(diag::ConnectionId id) { events_.push_back({Event::Kind::CloseByClient, id, {}, {}, false, {}}); }

void DoipLink::Port::sendTcp(diag::ConnectionId c, const std::vector<std::uint8_t>& d) {
    auto& e = link->entities_[endpoint];
    const auto it = e.clientOf.find(c);
    if (it == e.clientOf.end()) {
        e.foreign[c].push_back(d);
        return;
    }
    if (!e.muted) link->events_.push_back({Event::Kind::ToClient, it->second, endpoint, d, false, {}});
}

void DoipLink::Port::closeTcp(diag::ConnectionId c) {
    auto& e = link->entities_[endpoint];
    const auto it = e.clientOf.find(c);
    if (it == e.clientOf.end()) return;
    link->events_.push_back({Event::Kind::CloseByEntity, it->second, endpoint, {}, false, {}});
}

void DoipLink::pump(diag::TimePoint now) {
    for (int guard = 0; guard < 100000 && !events_.empty(); ++guard) {
        Event ev = std::move(events_.front());
        events_.pop_front();
        switch (ev.kind) {
            case Event::Kind::Connect: {
                auto& e = entities_[ev.endpoint];
                if (!e.reachable || !e.gateway) {
                    if (client_) client_->onClosed(ev.client, now);  // connection refused
                    break;
                }
                diag::ConnectionSecurity security;
                if (ev.tls) {
                    const bool serverOk = e.tls.enabled && e.tls.trusted &&
                                          (e.tls.certificateName.empty() || e.tls.certificateName == ev.serverName);
                    const bool clientOk = !e.tls.requireClientCertificate || (client_cert_.present && client_cert_.trusted);
                    if (!serverOk || !clientOk) {
                        ++tlsFailures_;
                        if (client_) client_->onClosed(ev.client, now);  // handshake failed
                        break;
                    }
                    security.tls = true;
                    security.clientAuthenticated = client_cert_.present && client_cert_.trusted;
                    security.peer = client_cert_.present ? client_cert_.name : "";
                }
                const auto conn = nextEntityConnection_++;
                e.clientOf[conn] = ev.client;
                routes_[ev.client] = {ev.endpoint, conn};
                e.gateway->onTcpConnected(conn, now, security);
                if (client_) client_->onConnected(ev.client, now);
                break;
            }
            case Event::Kind::ToEntity: {
                const auto it = routes_.find(ev.client);
                if (it == routes_.end()) break;
                auto& e = entities_[it->second.first];
                bytesToEntities_ += ev.data.size();
                e.received.push_back(ev.data);
                if (e.gateway && !e.muted) e.gateway->onTcpData(it->second.second, ev.data.data(), ev.data.size(), now);
                break;
            }
            case Event::Kind::ToClient:
                if (client_ && routes_.count(ev.client)) client_->onData(ev.client, ev.data.data(), ev.data.size(), now);
                break;
            case Event::Kind::CloseByClient: {
                const auto it = routes_.find(ev.client);
                if (it == routes_.end()) break;
                auto& e = entities_[it->second.first];
                e.clientOf.erase(it->second.second);
                if (e.gateway) e.gateway->onTcpClosed(it->second.second, now);
                routes_.erase(it);
                break;
            }
            case Event::Kind::CloseByEntity: {
                const auto it = routes_.find(ev.client);
                if (it == routes_.end()) break;
                entities_[it->second.first].clientOf.erase(it->second.second);
                routes_.erase(it);
                if (client_) client_->onClosed(ev.client, now);
                break;
            }
        }
    }
}

}  // namespace ccg::sim
