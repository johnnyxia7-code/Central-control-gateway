#include "ccg/diag/diag_gateway.hpp"

#include <algorithm>
#include <sstream>

#include "ccg/diag/doip_client.hpp"

namespace ccg::diag {

namespace {

using doip::ActivationCode;
using doip::DiagNack;
using doip::HeaderNack;
namespace pt = doip::payload;

constexpr std::chrono::milliseconds kS3Server{5000};  // UDS session timeout of the gateway
// Internal client timing: P2 includes the ISO-TP transfer of request and response.
constexpr std::chrono::milliseconds kP2Client{1000};
constexpr std::chrono::milliseconds kP2StarClient{5500};

std::uint64_t rxKey(std::size_t channel, std::uint32_t id, bool extended) {
    return (static_cast<std::uint64_t>(channel) << 33) | (static_cast<std::uint64_t>(extended) << 32) |
           id;
}

std::string joinErrors(const std::vector<std::string>& errors) {
    std::ostringstream os;
    os << "invalid diagnostic routing configuration (" << errors.size() << " error(s))";
    for (const auto& e : errors) os << "\n  - " << e;
    return os.str();
}

}  // namespace

const char* toString(ClientResult result) {
    switch (result) {
        case ClientResult::Ok: return "OK";
        case ClientResult::Busy: return "BUSY";
        case ClientResult::UnknownTarget: return "UNKNOWN_TARGET";
        case ClientResult::TransportError: return "TRANSPORT_ERROR";
        case ClientResult::Timeout: return "TIMEOUT";
    }
    return "UNKNOWN";
}

DiagConfigError::DiagConfigError(std::vector<std::string> errors)
    : std::runtime_error(joinErrors(errors)), errors_(std::move(errors)) {}

DiagGateway::DiagGateway(DiagRoutingConfig config, IDiagTransport& transport)
    : config_(std::move(config)), transport_(transport) {
    auto errors = validateDiagConfig(config_);
    if (!errors.empty()) {
        throw DiagConfigError(std::move(errors));
    }
    // Largest DoIP payload we accept: a diagnostic message (SA + TA + UDS data)
    // or a routing activation request with OEM data.
    maxTcpPayload_ = std::max<std::size_t>(config_.entity.maxDiagnosticMessageSize + 4, 11);

    for (std::size_t c = 0; c < config_.channels.size(); ++c) {
        channelByName_[config_.channels[c].name] = c;
    }
    ecus_.resize(config_.ecus.size());
    for (std::size_t i = 0; i < config_.ecus.size(); ++i) {
        const auto& route = config_.ecus[i];
        auto& ecu = ecus_[i];
        ecu.channel = channelByName_.at(route.channel);

        isotp::Config tp;
        tp.txId = route.requestId;
        tp.rxId = route.responseId;
        tp.extended = route.extended;
        tp.fd = route.fd;
        tp.padding = config_.channels[ecu.channel].padding;
        tp.blockSize = route.blockSize;
        tp.stMin = route.stMin;
        tp.nBs = route.nBs;
        tp.nCr = route.nCr;
        tp.maxRxLength = config_.entity.maxDiagnosticMessageSize;

        isotp::Callbacks cb;
        const std::size_t channel = ecu.channel;
        cb.transmit = [this, channel](const can::CanFrame& f) {
            return transport_.transmitCan(channel, f);
        };
        cb.txDone = [this, i](isotp::Result r) { onEcuTxDone(i, r); };
        cb.rxDone = [this, i](std::vector<std::uint8_t>&& d) { onEcuResponse(i, std::move(d)); };
        cb.rxError = [this](isotp::Result) { ++stats_.isotpRxErrors; };
        ecu.tp = std::make_unique<isotp::Channel>(tp, std::move(cb));

        ecuByRxId_[rxKey(ecu.channel, route.responseId, route.extended)] = i;
        ecuByAddress_[route.logicalAddress] = i;
    }
}

void DiagGateway::start(TimePoint now) {
    announcementsLeft_ = config_.entity.announceCount;
    nextAnnouncement_ = now;
    localSessionActivity_ = now;
}

std::optional<std::size_t> DiagGateway::channelIndex(const std::string& name) const {
    const auto it = channelByName_.find(name);
    if (it == channelByName_.end()) return std::nullopt;
    return it->second;
}

bool DiagGateway::isRoutingActive(ConnectionId connection) const {
    const auto it = connections_.find(connection);
    return it != connections_.end() && it->second.registered;
}

bool DiagGateway::isTester(std::uint16_t address) const {
    return address >= config_.entity.testerAddressMin && address <= config_.entity.testerAddressMax;
}

doip::EntityIdentity DiagGateway::identity() const {
    return {config_.entity.vin, config_.entity.logicalAddress, config_.entity.eid,
            config_.entity.gid};
}

// ---------------------------------------------------------------------------
// Sending helpers
// ---------------------------------------------------------------------------

void DiagGateway::sendTcp(ConnectionId id, std::uint16_t type,
                          const std::vector<std::uint8_t>& payload) {
    const auto it = connections_.find(id);
    if (it == connections_.end()) return;
    transport_.sendTcp(id, doip::encode(it->second.version, type, payload));
}

void DiagGateway::sendHeaderNack(ConnectionId id, HeaderNack code) {
    ++stats_.headerNacks;
    sendTcp(id, pt::kGenericNack, {static_cast<std::uint8_t>(code)});
}

void DiagGateway::sendDiagAck(const Requester& req, std::uint16_t source) {
    ++stats_.diagAcks;
    sendTcp(req.connection, pt::kDiagnosticAck, doip::diagnosticAckPayload(source, req.tester, 0x00));
}

void DiagGateway::sendDiagNack(const Requester& req, std::uint16_t source, DiagNack code) {
    ++stats_.diagNacks;
    sendTcp(req.connection, pt::kDiagnosticNack,
            doip::diagnosticAckPayload(source, req.tester, static_cast<std::uint8_t>(code)));
}

void DiagGateway::sendDiagMessage(const Requester& req, std::uint16_t source,
                                  const std::vector<std::uint8_t>& data) {
    sendTcp(req.connection, pt::kDiagnosticMessage,
            doip::diagnosticMessagePayload(source, req.tester, data));
}

void DiagGateway::sendUdp(const UdpPeer& peer, std::uint8_t version, std::uint16_t type,
                          const std::vector<std::uint8_t>& payload) {
    transport_.sendUdp(peer, doip::encode(version, type, payload));
}

// ---------------------------------------------------------------------------
// UDP: vehicle identification, entity status, power mode
// ---------------------------------------------------------------------------

void DiagGateway::onUdpDatagram(const UdpPeer& peer, const std::uint8_t* data, std::size_t length,
                                TimePoint) {
    const std::uint8_t version = config_.entity.protocolVersion;
    auto nack = [&](HeaderNack code) {
        ++stats_.headerNacks;
        sendUdp(peer, version, pt::kGenericNack, {static_cast<std::uint8_t>(code)});
    };
    if (length < doip::kHeaderSize) {
        return;  // not even a header: silently discarded
    }
    if (!doip::isValidPattern(data)) {
        nack(HeaderNack::IncorrectPattern);
        return;
    }
    const auto header = doip::decodeHeader(data);
    const bool vehicleIdRequest = header.type == pt::kVehicleIdRequest ||
                                  header.type == pt::kVehicleIdRequestEid ||
                                  header.type == pt::kVehicleIdRequestVin;
    if (header.version == doip::kVersionDefault && !vehicleIdRequest) {
        nack(HeaderNack::IncorrectPattern);
        return;
    }
    if (header.length != length - doip::kHeaderSize) {
        nack(HeaderNack::InvalidPayloadLength);
        return;
    }
    const std::uint8_t* p = data + doip::kHeaderSize;
    const auto& e = config_.entity;

    auto announce = [&] {
        ++stats_.vehicleIdResponses;
        sendUdp(peer, version, pt::kVehicleAnnouncement, doip::vehicleAnnouncementPayload(identity()));
    };

    switch (header.type) {
        case pt::kVehicleIdRequest:
            if (header.length != 0) return nack(HeaderNack::InvalidPayloadLength);
            announce();
            return;
        case pt::kVehicleIdRequestEid:
            if (header.length != 6) return nack(HeaderNack::InvalidPayloadLength);
            if (std::equal(e.eid.begin(), e.eid.end(), p)) announce();
            return;
        case pt::kVehicleIdRequestVin:
            if (header.length != 17) return nack(HeaderNack::InvalidPayloadLength);
            if (std::equal(e.vin.begin(), e.vin.end(), p)) announce();
            return;
        case pt::kEntityStatusRequest:
            if (header.length != 0) return nack(HeaderNack::InvalidPayloadLength);
            sendUdp(peer, version, pt::kEntityStatusResponse,
                    doip::entityStatusPayload(0x00, e.maxTcpConnections,
                                              static_cast<std::uint8_t>(connections_.size()),
                                              static_cast<std::uint32_t>(maxTcpPayload_)));
            return;
        case pt::kPowerModeRequest:
            if (header.length != 0) return nack(HeaderNack::InvalidPayloadLength);
            sendUdp(peer, version, pt::kPowerModeResponse, {0x01});  // ready
            return;
        default:
            nack(HeaderNack::UnknownPayloadType);
            return;
    }
}

// ---------------------------------------------------------------------------
// TCP: connections, routing activation, diagnostic messages
// ---------------------------------------------------------------------------

void DiagGateway::onTcpConnected(ConnectionId id, TimePoint now) {
    Connection c(maxTcpPayload_);
    c.connectedAt = now;
    c.lastActivity = now;
    c.version = config_.entity.protocolVersion;
    connections_.erase(id);
    connections_.emplace(id, std::move(c));
    ++stats_.tcpConnectionsAccepted;
}

void DiagGateway::onTcpClosed(ConnectionId id, TimePoint) { closeConnection(id, false); }

void DiagGateway::closeConnection(ConnectionId id, bool notifyTransport) {
    const auto it = connections_.find(id);
    if (it == connections_.end()) {
        return;
    }
    if (ethernet_ && it->second.registered) {
        ethernet_->closeSource(it->second.tester);  // its connections to the Ethernet ECUs end too
    }
    connections_.erase(it);
    ++stats_.tcpConnectionsClosed;
    if (notifyTransport) {
        transport_.closeTcp(id);
    }
    if (pending_) {
        if (pending_->connection == id) {
            pending_.reset();
        } else if (pending_->waiting.erase(id) > 0) {
            pending_->anyGone = true;
            evaluatePendingActivation();
        }
    }
}

void DiagGateway::onTcpData(ConnectionId id, const std::uint8_t* data, std::size_t length,
                            TimePoint now) {
    auto it = connections_.find(id);
    if (it == connections_.end()) {
        return;
    }
    it->second.lastActivity = now;
    it->second.stream.feed(data, length);
    for (;;) {
        it = connections_.find(id);
        if (it == connections_.end()) return;  // closed while handling a message
        auto item = it->second.stream.next();
        if (!item) return;
        switch (item->kind) {
            case doip::StreamReassembler::Kind::IncorrectPattern:
                sendHeaderNack(id, HeaderNack::IncorrectPattern);
                closeConnection(id, true);
                return;
            case doip::StreamReassembler::Kind::TooLarge:
                sendHeaderNack(id, HeaderNack::MessageTooLarge);
                break;
            case doip::StreamReassembler::Kind::Message:
                handleTcpMessage(id, *item, now);
                break;
        }
    }
}

void DiagGateway::handleTcpMessage(ConnectionId id, const doip::StreamReassembler::Item& item,
                                   TimePoint now) {
    auto& c = connections_.at(id);
    c.version = item.header.version;
    const auto& payload = item.payload;
    auto invalidLength = [&] {
        sendHeaderNack(id, HeaderNack::InvalidPayloadLength);
        closeConnection(id, true);
    };

    switch (item.header.type) {
        case pt::kRoutingActivationRequest:
            if (payload.size() != 7 && payload.size() != 11) return invalidLength();
            handleRoutingActivation(id, payload, now);
            return;
        case pt::kAliveCheckResponse:
            if (payload.size() != 2) return invalidLength();
            handleAliveCheckResponse(id);
            return;
        case pt::kDiagnosticMessage:
            if (payload.size() < 5) return invalidLength();
            handleDiagnosticMessage(id, payload, now);
            return;
        case pt::kEntityStatusRequest:
            if (!payload.empty()) return invalidLength();
            sendTcp(id, pt::kEntityStatusResponse,
                    doip::entityStatusPayload(0x00, config_.entity.maxTcpConnections,
                                              static_cast<std::uint8_t>(connections_.size()),
                                              static_cast<std::uint32_t>(maxTcpPayload_)));
            return;
        case pt::kPowerModeRequest:
            if (!payload.empty()) return invalidLength();
            sendTcp(id, pt::kPowerModeResponse, {0x01});
            return;
        default:
            sendHeaderNack(id, HeaderNack::UnknownPayloadType);
            return;
    }
}

void DiagGateway::handleRoutingActivation(ConnectionId id, const std::vector<std::uint8_t>& payload,
                                          TimePoint now) {
    const std::uint16_t tester = doip::readU16(payload.data());
    const std::uint8_t activationType = payload[2];
    auto& c = connections_.at(id);
    auto respond = [&](ActivationCode code) {
        sendTcp(id, pt::kRoutingActivationResponse,
                doip::routingActivationResponsePayload(tester, config_.entity.logicalAddress, code));
    };
    auto reject = [&](ActivationCode code) {
        respond(code);
        ++stats_.routingActivationsRejected;
        closeConnection(id, true);
    };

    if (!isTester(tester)) return reject(ActivationCode::UnknownSourceAddress);
    if (activationType != 0x00 && activationType != 0x01) {
        return reject(ActivationCode::UnsupportedActivationType);  // 0xE0 central security etc.
    }
    if (c.registered) {
        if (c.tester != tester) return reject(ActivationCode::SourceAddressMismatch);
        ++stats_.routingActivationsAccepted;
        return respond(ActivationCode::Success);  // repeated activation on the same socket
    }
    if (pending_) {
        return reject(ActivationCode::NoFreeSocket);  // one activation handshake at a time
    }

    // Source address already active on another socket: probe that socket first.
    for (const auto& [otherId, other] : connections_) {
        if (otherId != id && other.registered && other.tester == tester) {
            pending_ = PendingActivation{id, tester, true, {otherId}, false,
                                         now + config_.entity.aliveCheckTimeout};
            sendAliveCheck(otherId);
            return;
        }
    }

    // All sockets in use: probe every registered socket.
    std::set<ConnectionId> registered;
    for (const auto& [otherId, other] : connections_) {
        if (other.registered) registered.insert(otherId);
    }
    if (registered.size() >= config_.entity.maxTcpConnections) {
        pending_ = PendingActivation{id, tester, false, registered, false,
                                     now + config_.entity.aliveCheckTimeout};
        for (const auto otherId : registered) sendAliveCheck(otherId);
        return;
    }

    c.registered = true;
    c.tester = tester;
    ++stats_.routingActivationsAccepted;
    respond(ActivationCode::Success);
}

void DiagGateway::sendAliveCheck(ConnectionId id) {
    ++stats_.aliveChecksSent;
    sendTcp(id, pt::kAliveCheckRequest, {});
}

void DiagGateway::handleAliveCheckResponse(ConnectionId id) {
    if (pending_ && pending_->waiting.erase(id) > 0) {
        evaluatePendingActivation();
    }
}

void DiagGateway::evaluatePendingActivation() {
    if (!pending_) return;
    if (pending_->anyGone) {
        finishActivation(true, ActivationCode::Success);
    } else if (pending_->waiting.empty()) {
        finishActivation(false, pending_->sourceInUse ? ActivationCode::SourceAddressInUse
                                                      : ActivationCode::NoFreeSocket);
    }
}

void DiagGateway::finishActivation(bool accept, ActivationCode rejectCode) {
    const PendingActivation p = *pending_;
    pending_.reset();
    const auto it = connections_.find(p.connection);
    if (it == connections_.end()) return;
    const ActivationCode code = accept ? ActivationCode::Success : rejectCode;
    sendTcp(p.connection, pt::kRoutingActivationResponse,
            doip::routingActivationResponsePayload(p.tester, config_.entity.logicalAddress, code));
    if (accept) {
        it->second.registered = true;
        it->second.tester = p.tester;
        ++stats_.routingActivationsAccepted;
    } else {
        ++stats_.routingActivationsRejected;
        closeConnection(p.connection, true);
    }
}

void DiagGateway::handleDiagnosticMessage(ConnectionId id, const std::vector<std::uint8_t>& payload,
                                          TimePoint now) {
    const std::uint16_t source = doip::readU16(payload.data());
    const std::uint16_t target = doip::readU16(payload.data() + 2);
    const auto& c = connections_.at(id);
    const Requester req{id, source};

    if (!c.registered || c.tester != source) {
        sendDiagNack(req, target, DiagNack::InvalidSourceAddress);
        closeConnection(id, true);
        return;
    }
    ++stats_.diagRequests;
    std::vector<std::uint8_t> data(payload.begin() + 4, payload.end());

    if (target == config_.entity.logicalAddress) {
        ++stats_.localRequests;
        sendDiagAck(req, target);
        if (auto response = localService(data, false, now)) {
            sendDiagMessage(req, target, *response);
        }
        return;
    }
    if (target == config_.entity.functionalAddress) {
        handleFunctionalRequest(req, data, now);
        return;
    }
    const auto it = ecuByAddress_.find(target);
    if (it == ecuByAddress_.end()) {
        if (ethernet_ && ethernet_->reaches(target)) {
            routeToEthernet(req, target, target, std::move(data), false, now);
            return;  // ACK / NACK once the entity has answered
        }
        sendDiagNack(req, target, DiagNack::UnknownTargetAddress);
        return;
    }
    auto& ecu = ecus_[it->second];
    if (data.size() > config_.ecus[it->second].maxRequestLength) {
        sendDiagNack(req, target, DiagNack::MessageTooLarge);
        return;
    }
    if (ecu.awaitingAck || ecu.tp->txBusy() || ecu.internal) {
        // previous request still on the bus, or the gateway itself talks to the ECU
        sendDiagNack(req, target, DiagNack::TransportProtocolError);
        return;
    }
    ecu.awaitingAck = req;
    ecu.responseOwner = req;
    if (!ecu.tp->transmit(std::move(data), now)) {
        ecu.awaitingAck.reset();
        sendDiagNack(req, target, DiagNack::TransportProtocolError);
    }
    // The ACK follows from onEcuTxDone() once ISO-TP has delivered the request.
}

void DiagGateway::handleFunctionalRequest(const Requester& req,
                                          const std::vector<std::uint8_t>& data, TimePoint now) {
    // Functional requests must fit a single frame on every channel (classic SF).
    if (data.size() > isotp::maxSingleFrameLength(false)) {
        sendDiagNack(req, config_.entity.functionalAddress, DiagNack::MessageTooLarge);
        return;
    }
    ++stats_.functionalRequests;
    sendDiagAck(req, config_.entity.functionalAddress);
    for (std::size_t c = 0; c < config_.channels.size(); ++c) {
        const auto& ch = config_.channels[c];
        const auto frame = isotp::makeSingleFrame(ch.functionalRequestId, false, false, ch.padding,
                                                  data.data(), data.size());
        if (!transport_.transmitCan(c, *frame)) {
            ++stats_.isotpTxErrors;
        }
    }
    for (auto& ecu : ecus_) {
        ecu.responseOwner = req;  // every ECU may answer
    }
    if (ethernet_) {
        for (const auto& ecu : ethernet_->config().ecus) {
            routeToEthernet(req, ecu.logicalAddress, config_.entity.functionalAddress, data, true, now);
        }
    }
    if (auto response = localService(data, true, now)) {
        sendDiagMessage(req, config_.entity.logicalAddress, *response);
    }
}

// Minimal UDS server of the gateway itself (its own logical address).
std::optional<std::vector<std::uint8_t>> DiagGateway::localService(
    const std::vector<std::uint8_t>& request, bool functional, TimePoint now) {
    const std::uint8_t sid = request[0];
    localSessionActivity_ = now;
    auto negative = [&](std::uint8_t nrc) -> std::optional<std::vector<std::uint8_t>> {
        // ISO 14229-1: no NRC 0x11/0x12/0x31/0x7E/0x7F on functional requests.
        if (functional && (nrc == 0x11 || nrc == 0x12 || nrc == 0x31 || nrc == 0x7E || nrc == 0x7F)) {
            return std::nullopt;
        }
        return std::vector<std::uint8_t>{0x7F, sid, nrc};
    };

    for (auto* handler : localHandlers_) {
        auto response = handler->handle(request, LocalRequestContext{localSession_, functional, now});
        if (!response) continue;
        if (response->empty()) return std::nullopt;
        if (response->size() == 3 && (*response)[0] == 0x7F) return negative((*response)[2]);
        return response;
    }

    switch (sid) {
        case 0x10: {  // DiagnosticSessionControl
            if (request.size() != 2) return negative(0x13);
            const std::uint8_t session = request[1] & 0x7F;
            if (session != 0x01 && session != 0x03) return negative(0x12);
            localSession_ = session;
            if (request[1] & 0x80) return std::nullopt;
            return std::vector<std::uint8_t>{0x50, session, 0x00, 0x32, 0x01, 0xF4};  // P2 50 ms, P2* 5 s
        }
        case 0x3E: {  // TesterPresent
            if (request.size() != 2) return negative(0x13);
            if ((request[1] & 0x7F) != 0x00) return negative(0x12);
            if (request[1] & 0x80) return std::nullopt;
            return std::vector<std::uint8_t>{0x7E, 0x00};
        }
        case 0x22: {  // ReadDataByIdentifier (one DID)
            if (request.size() != 3) return negative(0x13);
            const std::uint16_t did = static_cast<std::uint16_t>((request[1] << 8) | request[2]);
            std::vector<std::uint8_t> out = {0x62, request[1], request[2]};
            switch (did) {
                case 0xF190: out.insert(out.end(), config_.entity.vin.begin(), config_.entity.vin.end()); break;
                case 0xF186: out.push_back(localSession_); break;
                case 0xF18C: {
                    static const std::string serial = "CCG-HPC-000001";
                    out.insert(out.end(), serial.begin(), serial.end());
                    break;
                }
                default: return negative(0x31);
            }
            return out;
        }
        case 0x31:  // RoutineControl: routines are provided by local service handlers
            return negative(request.size() < 4 ? 0x13 : 0x31);
        default:
            return negative(0x11);
    }
}

// ---------------------------------------------------------------------------
// CAN side
// ---------------------------------------------------------------------------

void DiagGateway::onCanFrame(std::size_t channel, const can::CanFrame& frame, TimePoint now) {
    now_ = now;
    const auto it = ecuByRxId_.find(rxKey(channel, frame.id, frame.extended));
    if (it != ecuByRxId_.end()) {
        ecus_[it->second].tp->onFrame(frame, now);
    }
}

void DiagGateway::onEcuTxDone(std::size_t index, isotp::Result result) {
    auto& ecu = ecus_[index];
    if (ecu.internal && !ecu.awaitingAck) {
        if (result != isotp::Result::Ok) {
            ++stats_.isotpTxErrors;
            finishInternal(index, ClientResult::TransportError, {});
        }
        return;
    }
    const auto req = ecu.awaitingAck;
    ecu.awaitingAck.reset();
    if (!req) return;
    const std::uint16_t source = config_.ecus[index].logicalAddress;
    if (result == isotp::Result::Ok) {
        sendDiagAck(*req, source);
    } else {
        ++stats_.isotpTxErrors;
        sendDiagNack(*req, source, DiagNack::TransportProtocolError);
    }
}

void DiagGateway::onEcuResponse(std::size_t index, std::vector<std::uint8_t>&& data) {
    ++stats_.ecuResponses;
    if (auto& internal = ecus_[index].internal) {
        if (data.size() == 3 && data[0] == 0x7F && data[2] == 0x78) {
            internal->deadline = now_ + kP2StarClient;  // response pending
            return;
        }
        finishInternal(index, ClientResult::Ok, std::move(data));
        return;
    }
    const auto& owner = ecus_[index].responseOwner;
    const auto it = owner ? connections_.find(owner->connection) : connections_.end();
    if (it == connections_.end() || !it->second.registered || it->second.tester != owner->tester) {
        ++stats_.responsesDropped;  // tester gone or never asked
        return;
    }
    sendDiagMessage(*owner, config_.ecus[index].logicalAddress, data);
}

// ---------------------------------------------------------------------------
// DoIP-to-DoIP routing (Ethernet ECUs)
// ---------------------------------------------------------------------------

bool DiagGateway::testerConnected(const Requester& req) const {
    const auto it = connections_.find(req.connection);
    return it != connections_.end() && it->second.registered && it->second.tester == req.tester;
}

void DiagGateway::routeToEthernet(const Requester& req, std::uint16_t ecu, std::uint16_t targetOnWire,
                                  std::vector<std::uint8_t> data, bool functional, TimePoint now) {
    ++stats_.ethernetRequests;
    DoipClient::RouteHandlers handlers;
    handlers.delivered = [this, req, ecu, functional](std::optional<DiagNack> nack) {
        // A functional request was acknowledged by the gateway already.
        if (functional || !testerConnected(req)) return;
        if (nack) {
            sendDiagNack(req, ecu, *nack);
        } else {
            sendDiagAck(req, ecu);
        }
    };
    handlers.response = [this, req, ecu](std::vector<std::uint8_t> uds) {
        if (!testerConnected(req)) {
            ++stats_.responsesDropped;
            return;
        }
        ++stats_.ethernetResponses;
        sendDiagMessage(req, ecu, uds);
    };
    ethernet_->route(req.tester, ecu, targetOnWire, std::move(data), now, std::move(handlers));
}

// ---------------------------------------------------------------------------
// Gateway-internal diagnostic client
// ---------------------------------------------------------------------------

void DiagGateway::request(std::uint16_t target, std::vector<std::uint8_t> uds, TimePoint now,
                          Callback callback) {
    now_ = now;
    const auto it = ecuByAddress_.find(target);
    if (it == ecuByAddress_.end()) {
        callback(ClientResult::UnknownTarget, {});
        return;
    }
    auto& ecu = ecus_[it->second];
    if (ecu.awaitingAck || ecu.tp->txBusy() || ecu.internal) {
        callback(ClientResult::Busy, {});
        return;
    }
    ecu.internal = InternalRequest{std::move(callback), now + kP2Client};
    ecu.responseOwner.reset();  // a tester's late responses must not reach the client
    if (!ecu.tp->transmit(std::move(uds), now)) {
        finishInternal(it->second, ClientResult::TransportError, {});
    }
}

void DiagGateway::finishInternal(std::size_t index, ClientResult result, std::vector<std::uint8_t> response) {
    auto callback = std::move(ecus_[index].internal->callback);
    ecus_[index].internal.reset();
    callback(result, std::move(response));
}

// ---------------------------------------------------------------------------
// Periodic processing
// ---------------------------------------------------------------------------

void DiagGateway::mainFunction(TimePoint now) {
    now_ = now;
    // Vehicle announcements after start-up.
    if (announcementsLeft_ > 0 && now >= nextAnnouncement_) {
        --announcementsLeft_;
        ++stats_.announcements;
        transport_.broadcastUdp(doip::encode(config_.entity.protocolVersion, pt::kVehicleAnnouncement,
                                             doip::vehicleAnnouncementPayload(identity())));
        nextAnnouncement_ = now + config_.entity.announceInterval;
    }

    // Alive check timeout: silent sockets are closed, the new tester gets the socket.
    if (pending_ && now >= pending_->deadline) {
        const auto dead = pending_->waiting;
        pending_->waiting.clear();
        pending_->anyGone = true;
        for (const auto id : dead) closeConnection(id, true);
        evaluatePendingActivation();
    }

    // TCP inactivity timers.
    std::vector<ConnectionId> expired;
    for (const auto& [id, c] : connections_) {
        if (!c.registered && now - c.connectedAt >= config_.entity.initialInactivity) {
            expired.push_back(id);
        } else if (c.registered && now - c.lastActivity >= config_.entity.generalInactivity) {
            expired.push_back(id);
        }
    }
    for (const auto id : expired) closeConnection(id, true);

    // Gateway's own UDS session falls back to the default session (S3 timeout).
    if (localSession_ != 0x01 && now - localSessionActivity_ >= kS3Server) {
        localSession_ = 0x01;
    }

    for (std::size_t i = 0; i < ecus_.size(); ++i) {
        ecus_[i].tp->mainFunction(now);
        if (ecus_[i].internal && now >= ecus_[i].internal->deadline) {
            finishInternal(i, ClientResult::Timeout, {});
        }
    }
}

}  // namespace ccg::diag
