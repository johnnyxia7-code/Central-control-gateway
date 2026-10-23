#include "ccg/diag/doip_client.hpp"

#include <set>

namespace ccg::diag {

namespace pt = doip::payload;

std::vector<std::string> validateDoipClientConfig(const DoipClientConfig& c) {
    std::vector<std::string> errors;
    if (c.sourceAddress < 0x0E00 || c.sourceAddress > 0x0FFF) {
        errors.push_back("DoIP client: source address must be a tester address (0x0E00..0x0FFF)");
    }
    if (c.protocolVersion != doip::kVersion2012 && c.protocolVersion != doip::kVersion2019) {
        errors.push_back("DoIP client: protocol version must be 0x02 or 0x03");
    }
    if (c.maxMessageSize < 8) errors.push_back("DoIP client: maxMessageSize must be >= 8");
    std::set<std::uint16_t> addresses;
    for (const auto& r : c.ecus) {
        if (!addresses.insert(r.logicalAddress).second) {
            errors.push_back("DoIP ECU '" + r.name + "': logical address used twice");
        }
        if (r.endpoint.empty()) errors.push_back("DoIP ECU '" + r.name + "': endpoint missing");
        if (r.tls && r.serverName.empty()) {
            errors.push_back("DoIP ECU '" + r.name + "': TLS needs the expected server name");
        }
        if (r.logicalAddress >= 0x0E00 && r.logicalAddress <= 0x0FFF) {
            errors.push_back("DoIP ECU '" + r.name + "': logical address is in the tester range");
        }
    }
    return errors;
}

DoipClient::DoipClient(DoipClientConfig config, IDoipConnector& connector)
    : config_(std::move(config)), connector_(connector) {
    auto errors = validateDoipClientConfig(config_);
    if (!errors.empty()) throw DiagConfigError(std::move(errors));
}

std::optional<std::size_t> DoipClient::routeOf(std::uint16_t target) const {
    for (std::size_t i = 0; i < config_.ecus.size(); ++i) {
        if (config_.ecus[i].logicalAddress == target) return i;
    }
    return std::nullopt;
}

bool DoipClient::reaches(std::uint16_t target) const { return routeOf(target).has_value(); }

const DoipClient::Connection* DoipClient::find(std::size_t route, std::uint16_t source) const {
    for (const auto& [id, c] : connections_) {
        if (c.route == route && c.source == source) return &c;
    }
    return nullptr;
}

ConnectionId DoipClient::connectionFor(std::size_t route, std::uint16_t source) {
    for (const auto& [id, c] : connections_) {
        if (c.route == route && c.source == source) return id;
    }
    const ConnectionId id = nextId_++;
    connections_.emplace(id, Connection(route, source, config_.maxMessageSize + 4));  // SA + TA + UDS
    return id;
}

bool DoipClient::routingActive(std::uint16_t target, std::uint16_t source) const {
    const auto route = routeOf(target);
    const Connection* c = route ? find(*route, source) : nullptr;
    return c && c->state == State::Active;
}

std::size_t DoipClient::openConnections() const {
    std::size_t n = 0;
    for (const auto& [id, c] : connections_) n += c.state != State::Closed;
    return n;
}

void DoipClient::request(std::uint16_t target, std::vector<std::uint8_t> uds, TimePoint now, Callback callback) {
    const auto route = routeOf(target);
    if (!route) {
        callback(ClientResult::UnknownTarget, {});
        return;
    }
    const ConnectionId id = connectionFor(*route, config_.sourceAddress);
    auto& c = connections_.at(id);
    if (c.pending || c.routed) {
        callback(ClientResult::Busy, {});
        return;
    }
    ++stats_.requests;
    c.pending = Pending{std::move(uds), std::move(callback), false, false};
    open(id, now);
}

void DoipClient::route(std::uint16_t source, std::uint16_t ecu, std::uint16_t targetOnWire,
                       std::vector<std::uint8_t> uds, TimePoint now, RouteHandlers handlers) {
    const auto route = routeOf(ecu);
    if (!route) {
        handlers.delivered(doip::DiagNack::UnknownTargetAddress);
        return;
    }
    const ConnectionId id = connectionFor(*route, source);
    auto& c = connections_.at(id);
    if (c.pending || c.routed) {
        handlers.delivered(doip::DiagNack::TransportProtocolError);  // previous request not yet acknowledged
        return;
    }
    ++stats_.routedRequests;
    c.routed = Routed{targetOnWire, std::move(uds), std::move(handlers), false};
    open(id, now);
}

void DoipClient::closeSource(std::uint16_t source) {
    for (auto it = connections_.begin(); it != connections_.end();) {
        if (it->second.source != source || source == config_.sourceAddress) {
            ++it;
            continue;
        }
        if (it->second.state != State::Closed) connector_.close(it->first);
        it = connections_.erase(it);  // pending routed request and sink are dropped silently
    }
}

void DoipClient::open(ConnectionId id, TimePoint now) {
    auto& c = connections_.at(id);
    switch (c.state) {
        case State::Active:
            flush(id, now);
            break;
        case State::Closed:
            c.state = State::Connecting;
            c.stream = doip::StreamReassembler(config_.maxMessageSize + 4);
            c.deadline = now + config_.connectTimeout;
            ++stats_.connects;
            {
                const auto& route = config_.ecus[c.route];
                connector_.connect(id, DoipTarget{route.endpoint, route.tls, route.serverName});
            }
            break;
        case State::Connecting:
        case State::Activating:
            break;  // sent once routing is active
    }
}

void DoipClient::flush(ConnectionId id, TimePoint now) {
    auto& c = connections_.at(id);
    const std::uint16_t entity = config_.ecus[c.route].logicalAddress;
    if (c.pending && !c.pending->sent) {
        send(id, pt::kDiagnosticMessage, doip::diagnosticMessagePayload(c.source, entity, c.pending->uds));
        c.pending->sent = true;
        c.deadline = now + config_.ctrlTimeout;  // diagnostic ACK
    } else if (c.routed && !c.routed->sent) {
        send(id, pt::kDiagnosticMessage, doip::diagnosticMessagePayload(c.source, c.routed->targetOnWire, c.routed->uds));
        c.routed->sent = true;
        c.sink = c.routed->handlers.response;
        c.deadline = now + config_.ctrlTimeout;
    }
}

void DoipClient::onConnected(ConnectionId id, TimePoint now) {
    const auto it = connections_.find(id);
    if (it == connections_.end() || it->second.state != State::Connecting) return;
    auto& c = it->second;
    c.state = State::Activating;
    c.deadline = now + config_.ctrlTimeout;
    send(id, pt::kRoutingActivationRequest,
         {static_cast<std::uint8_t>(c.source >> 8), static_cast<std::uint8_t>(c.source), config_.activationType, 0, 0, 0,
          0});
}

void DoipClient::onData(ConnectionId id, const std::uint8_t* data, std::size_t length, TimePoint now) {
    auto it = connections_.find(id);
    if (it == connections_.end()) return;
    it->second.stream.feed(data, length);
    for (;;) {
        it = connections_.find(id);
        if (it == connections_.end() || it->second.state == State::Closed) break;
        auto item = it->second.stream.next();
        if (!item) break;
        handle(id, *item, now);
    }
}

void DoipClient::handle(ConnectionId id, const doip::StreamReassembler::Item& item, TimePoint now) {
    auto& c = connections_.at(id);
    if (item.kind != doip::StreamReassembler::Kind::Message) {
        drop(id, ClientResult::TransportError);  // the entity's stream cannot be trusted any more
        return;
    }
    const auto& p = item.payload;
    const std::uint16_t entity = config_.ecus[c.route].logicalAddress;
    switch (item.header.type) {
        case pt::kRoutingActivationResponse: {
            if (c.state != State::Activating || p.size() < 9) return;
            if (p[4] != static_cast<std::uint8_t>(doip::ActivationCode::Success)) {
                ++stats_.activationFailures;
                drop(id, ClientResult::TransportError);
                return;
            }
            ++stats_.activations;
            c.state = State::Active;
            flush(id, now);
            return;
        }
        case pt::kAliveCheckRequest:
            ++stats_.aliveChecksAnswered;
            send(id, pt::kAliveCheckResponse, {static_cast<std::uint8_t>(c.source >> 8), static_cast<std::uint8_t>(c.source)});
            return;
        case pt::kDiagnosticAck:
        case pt::kDiagnosticNack: {
            if (p.size() < 5 || doip::readU16(p.data() + 2) != c.source) return;
            const bool ack = item.header.type == pt::kDiagnosticAck;
            const std::uint16_t from = doip::readU16(p.data());
            if (c.pending && c.pending->sent && !c.pending->acked && from == entity) {
                if (ack) {
                    c.pending->acked = true;
                    c.deadline = now + config_.p2;
                } else {
                    ++stats_.nacks;
                    complete(id, ClientResult::TransportError, {});
                }
            } else if (c.routed && c.routed->sent && from == c.routed->targetOnWire) {
                if (!ack) ++stats_.nacks;
                deliver(id, ack ? std::nullopt : std::optional<doip::DiagNack>(static_cast<doip::DiagNack>(p[4])));
            }
            return;
        }
        case pt::kDiagnosticMessage: {
            if (p.size() < 5 || doip::readU16(p.data() + 2) != c.source) return;
            std::vector<std::uint8_t> uds(p.begin() + 4, p.end());
            if (c.pending && c.pending->sent) {
                if (doip::readU16(p.data()) != entity) return;
                if (uds.size() == 3 && uds[0] == 0x7F && uds[2] == 0x78) {
                    c.pending->acked = true;
                    c.deadline = now + config_.p2Star;  // response pending
                    return;
                }
                ++stats_.responses;
                complete(id, ClientResult::Ok, std::move(uds));
            } else if (c.sink) {
                ++stats_.routedResponses;
                c.sink(std::move(uds));  // transparent: the tester runs its own P2 timers
            }
            return;
        }
        case pt::kGenericNack:
            drop(id, ClientResult::TransportError);
            return;
        default:
            return;
    }
}

void DoipClient::send(ConnectionId id, std::uint16_t type, const std::vector<std::uint8_t>& payload) {
    connector_.send(id, doip::encode(config_.protocolVersion, type, payload));
}

void DoipClient::onClosed(ConnectionId id, TimePoint) {
    const auto it = connections_.find(id);
    if (it == connections_.end()) return;
    auto& c = it->second;
    if (c.state == State::Connecting) ++stats_.connectFailures;
    c.state = State::Closed;
    c.sink = nullptr;
    if (c.pending) complete(id, ClientResult::TransportError, {});
    if (connections_.count(id) && connections_.at(id).routed) deliver(id, doip::DiagNack::TargetUnreachable);
}

void DoipClient::drop(ConnectionId id, ClientResult result) {
    auto& c = connections_.at(id);
    if (c.state != State::Closed) connector_.close(id);
    c.state = State::Closed;
    c.sink = nullptr;
    if (c.pending) complete(id, result, {});
    if (connections_.count(id) && connections_.at(id).routed) deliver(id, doip::DiagNack::TargetUnreachable);
}

void DoipClient::complete(ConnectionId id, ClientResult result, std::vector<std::uint8_t> response) {
    auto& c = connections_.at(id);
    auto callback = std::move(c.pending->callback);
    c.pending.reset();
    callback(result, std::move(response));
}

void DoipClient::deliver(ConnectionId id, std::optional<doip::DiagNack> nack) {
    auto& c = connections_.at(id);
    auto delivered = std::move(c.routed->handlers.delivered);
    c.routed.reset();
    delivered(nack);
}

void DoipClient::mainFunction(TimePoint now) {
    std::vector<ConnectionId> due;
    for (const auto& [id, c] : connections_) {
        if (now >= c.deadline && c.state != State::Closed) due.push_back(id);
    }
    for (const auto id : due) {
        const auto it = connections_.find(id);
        if (it == connections_.end()) continue;
        auto& c = it->second;
        switch (c.state) {
            case State::Connecting:
                ++stats_.connectFailures;
                drop(id, ClientResult::Timeout);
                break;
            case State::Activating:
                ++stats_.activationFailures;
                drop(id, ClientResult::Timeout);
                break;
            case State::Active:
                if ((c.pending && c.pending->sent && !c.pending->acked) || (c.routed && c.routed->sent)) {
                    // No ACK: the entity is not processing our messages - start over.
                    ++stats_.timeouts;
                    drop(id, ClientResult::Timeout);
                } else if (c.pending && c.pending->sent) {
                    ++stats_.timeouts;
                    complete(id, ClientResult::Timeout, {});
                }
                break;
            case State::Closed:
                break;
        }
    }
}

}  // namespace ccg::diag
