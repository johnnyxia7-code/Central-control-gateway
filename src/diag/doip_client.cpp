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
    for (std::size_t i = 0; i < config_.ecus.size(); ++i) {
        connections_.emplace_back(config_.maxMessageSize + 4);  // SA + TA + UDS
    }
}

std::optional<std::size_t> DoipClient::routeOf(std::uint16_t target) const {
    for (std::size_t i = 0; i < config_.ecus.size(); ++i) {
        if (config_.ecus[i].logicalAddress == target) return i;
    }
    return std::nullopt;
}

bool DoipClient::reaches(std::uint16_t target) const { return routeOf(target).has_value(); }

bool DoipClient::routingActive(std::uint16_t target) const {
    const auto i = routeOf(target);
    return i && connections_[*i].state == State::Active;
}

void DoipClient::request(std::uint16_t target, std::vector<std::uint8_t> uds, TimePoint now, Callback callback) {
    const auto index = routeOf(target);
    if (!index) {
        callback(ClientResult::UnknownTarget, {});
        return;
    }
    auto& c = connections_[*index];
    if (c.pending) {
        callback(ClientResult::Busy, {});
        return;
    }
    ++stats_.requests;
    c.pending = Pending{std::move(uds), std::move(callback), false, false};
    switch (c.state) {
        case State::Active:
            sendPending(*index, now);
            break;
        case State::Closed:
            c.state = State::Connecting;
            c.stream = doip::StreamReassembler(config_.maxMessageSize + 4);
            c.deadline = now + config_.connectTimeout;
            ++stats_.connects;
            connector_.connect(static_cast<ConnectionId>(*index + 1), config_.ecus[*index].endpoint);
            break;
        case State::Connecting:
        case State::Activating:
            break;  // sent once routing is active
    }
}

void DoipClient::onConnected(ConnectionId id, TimePoint now) {
    if (id == 0 || id > connections_.size()) return;
    auto& c = connections_[id - 1];
    if (c.state != State::Connecting) return;
    c.state = State::Activating;
    c.deadline = now + config_.ctrlTimeout;
    send(id - 1, pt::kRoutingActivationRequest,
         {static_cast<std::uint8_t>(config_.sourceAddress >> 8), static_cast<std::uint8_t>(config_.sourceAddress),
          config_.activationType, 0, 0, 0, 0});
}

void DoipClient::onData(ConnectionId id, const std::uint8_t* data, std::size_t length, TimePoint now) {
    if (id == 0 || id > connections_.size()) return;
    const std::size_t index = id - 1;
    connections_[index].stream.feed(data, length);
    while (connections_[index].state != State::Closed) {
        auto item = connections_[index].stream.next();
        if (!item) break;
        handle(index, *item, now);
    }
}

void DoipClient::handle(std::size_t index, const doip::StreamReassembler::Item& item, TimePoint now) {
    auto& c = connections_[index];
    if (item.kind != doip::StreamReassembler::Kind::Message) {
        drop(index, ClientResult::TransportError);  // the entity's stream cannot be trusted any more
        return;
    }
    const auto& p = item.payload;
    const std::uint16_t entity = config_.ecus[index].logicalAddress;
    switch (item.header.type) {
        case pt::kRoutingActivationResponse: {
            if (c.state != State::Activating || p.size() < 9) return;
            if (p[4] != static_cast<std::uint8_t>(doip::ActivationCode::Success)) {
                ++stats_.activationFailures;
                drop(index, ClientResult::TransportError);
                return;
            }
            ++stats_.activations;
            c.state = State::Active;
            if (c.pending) sendPending(index, now);
            return;
        }
        case pt::kAliveCheckRequest:
            ++stats_.aliveChecksAnswered;
            send(index, pt::kAliveCheckResponse,
                 {static_cast<std::uint8_t>(config_.sourceAddress >> 8), static_cast<std::uint8_t>(config_.sourceAddress)});
            return;
        case pt::kDiagnosticAck:
            if (c.pending && c.pending->sent && !c.pending->acked && p.size() >= 5 && doip::readU16(p.data()) == entity) {
                c.pending->acked = true;
                c.deadline = now + config_.p2;
            }
            return;
        case pt::kDiagnosticNack:
            if (c.pending && c.pending->sent && p.size() >= 5 && doip::readU16(p.data()) == entity) {
                ++stats_.nacks;
                complete(index, ClientResult::TransportError, {});
            }
            return;
        case pt::kDiagnosticMessage: {
            if (!c.pending || !c.pending->sent || p.size() < 5 || doip::readU16(p.data()) != entity ||
                doip::readU16(p.data() + 2) != config_.sourceAddress) {
                return;  // not for the open request
            }
            std::vector<std::uint8_t> uds(p.begin() + 4, p.end());
            if (uds.size() == 3 && uds[0] == 0x7F && uds[2] == 0x78) {
                c.pending->acked = true;
                c.deadline = now + config_.p2Star;  // response pending
                return;
            }
            ++stats_.responses;
            complete(index, ClientResult::Ok, std::move(uds));
            return;
        }
        case pt::kGenericNack:
            drop(index, ClientResult::TransportError);
            return;
        default:
            return;
    }
}

void DoipClient::sendPending(std::size_t index, TimePoint now) {
    auto& c = connections_[index];
    send(index, pt::kDiagnosticMessage,
         doip::diagnosticMessagePayload(config_.sourceAddress, config_.ecus[index].logicalAddress, c.pending->uds));
    c.pending->sent = true;
    c.deadline = now + config_.ctrlTimeout;  // diagnostic ACK
}

void DoipClient::send(std::size_t index, std::uint16_t type, const std::vector<std::uint8_t>& payload) {
    connector_.send(static_cast<ConnectionId>(index + 1), doip::encode(config_.protocolVersion, type, payload));
}

void DoipClient::onClosed(ConnectionId id, TimePoint) {
    if (id == 0 || id > connections_.size()) return;
    auto& c = connections_[id - 1];
    if (c.state == State::Connecting) ++stats_.connectFailures;
    c.state = State::Closed;
    if (c.pending) complete(id - 1, ClientResult::TransportError, {});
}

void DoipClient::drop(std::size_t index, ClientResult result) {
    auto& c = connections_[index];
    if (c.state != State::Closed) connector_.close(static_cast<ConnectionId>(index + 1));
    c.state = State::Closed;
    if (c.pending) complete(index, result, {});
}

void DoipClient::complete(std::size_t index, ClientResult result, std::vector<std::uint8_t> response) {
    auto callback = std::move(connections_[index].pending->callback);
    connections_[index].pending.reset();
    callback(result, std::move(response));
}

void DoipClient::mainFunction(TimePoint now) {
    for (std::size_t i = 0; i < connections_.size(); ++i) {
        auto& c = connections_[i];
        if (now < c.deadline) continue;
        switch (c.state) {
            case State::Connecting:
                ++stats_.connectFailures;
                drop(i, ClientResult::Timeout);
                break;
            case State::Activating:
                ++stats_.activationFailures;
                drop(i, ClientResult::Timeout);
                break;
            case State::Active:
                if (c.pending && c.pending->sent) {
                    ++stats_.timeouts;
                    // No ACK: the entity is not processing our messages - start over.
                    if (!c.pending->acked) {
                        drop(i, ClientResult::Timeout);
                    } else {
                        complete(i, ClientResult::Timeout, {});
                    }
                }
                break;
            case State::Closed:
                break;
        }
    }
}

}  // namespace ccg::diag
