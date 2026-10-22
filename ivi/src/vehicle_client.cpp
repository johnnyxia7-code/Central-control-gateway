#include "ccg/ivi/vehicle_client.hpp"

#include "vehicle_s2s_matrix.hpp"

namespace ccg::ivi {

namespace ids = config::ids;
using someip::MessageType;
using someip::ReturnCode;

const std::vector<ServiceDescriptor>& hpcServices() {
    static const std::vector<ServiceDescriptor> services = {
        {"VehicleMotionService",
         ids::kVehicleMotionService,
         ids::kInstance,
         1,
         0,
         {{ids::kEvtVehicleDynamics, ids::kEgDynamics, false, std::nullopt},
          {ids::kFldSteeringWheel, ids::kEgSteering, true, ids::kGetSteeringWheel}}},
        {"BodyService",
         ids::kBodyService,
         ids::kInstance,
         1,
         0,
         {{ids::kFldDoorStatus, ids::kEgDoors, true, ids::kGetDoorStatus}}},
        {"EnergyService",
         ids::kEnergyService,
         ids::kInstance,
         1,
         0,
         {{ids::kFldBatteryStatus, ids::kEgBattery, true, ids::kGetBatteryStatus}}},
        {"ClimateService", ids::kClimateService, ids::kInstance, 1, 0, {}},
    };
    return services;
}

const char* toString(CallStatus status) {
    switch (status) {
        case CallStatus::Ok: return "OK";
        case CallStatus::NotAvailable: return "NOT_AVAILABLE";
        case CallStatus::SendFailed: return "SEND_FAILED";
        case CallStatus::Timeout: return "TIMEOUT";
        case CallStatus::Error: return "ERROR";
    }
    return "?";
}

VehicleClient::VehicleClient(IClientTransport& transport, ClientOptions options)
    : transport_(transport), options_(options) {
    for (const auto& svc : hpcServices()) {
        available_[svc.serviceId] = false;
    }
}

void VehicleClient::setListener(IVehicleListener* listener) {
    std::lock_guard<std::mutex> lock(mutex_);
    listener_ = listener;
}

void VehicleClient::start() {
    for (const auto& svc : hpcServices()) {
        transport_.requestService(svc);
    }
}

const ServiceDescriptor* VehicleClient::findService(std::uint16_t serviceId) const {
    for (const auto& svc : hpcServices()) {
        if (svc.serviceId == serviceId) return &svc;
    }
    return nullptr;
}

void VehicleClient::run(Deferred& deferred) {
    for (auto& fn : deferred) fn();
    deferred.clear();
}

void VehicleClient::onAvailability(std::uint16_t serviceId, std::uint16_t instanceId,
                                   bool available, TimePoint now) {
    const auto* svc = findService(serviceId);
    if (!svc || svc->instanceId != instanceId) return;

    Deferred deferred;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (available_[serviceId] == available) return;
        available_[serviceId] = available;
        auto* listener = listener_;
        if (listener) {
            deferred.push_back([listener, serviceId, available] {
                listener->onServiceAvailability(serviceId, available);
            });
        }
        if (!available) {
            // Cached values are no longer backed by the HPC; outstanding calls fail now.
            switch (serviceId) {
                case ids::kVehicleMotionService:
                    dynamics_.reset();
                    steering_.reset();
                    break;
                case ids::kBodyService: doors_.reset(); break;
                case ids::kEnergyService: battery_.reset(); break;
                default: break;
            }
            for (auto it = pending_.begin(); it != pending_.end();) {
                if (std::get<0>(it->first) == serviceId) {
                    auto handler = std::move(it->second.handler);
                    deferred.push_back([handler] {
                        handler(CallResult{CallStatus::NotAvailable, ReturnCode::NotReachable},
                                nullptr);
                    });
                    it = pending_.erase(it);
                } else {
                    ++it;
                }
            }
        } else if (options_.refreshFieldsOnAvailable) {
            for (const auto& ev : svc->events) {
                if (!ev.getterId) continue;
                const auto eventId = ev.eventId;
                call(serviceId, *ev.getterId, false, {},
                     [this, serviceId, eventId](const CallResult& r, const someip::Message* m) {
                         if (!r.ok() || !m) return;
                         Deferred inner;
                         {
                             std::lock_guard<std::mutex> innerLock(mutex_);
                             applyEvent(serviceId, eventId, m->payload, inner);
                         }
                         run(inner);
                     },
                     now, deferred);
            }
        }
    }
    run(deferred);
}

void VehicleClient::applyEvent(std::uint16_t serviceId, std::uint16_t eventId,
                               const std::vector<std::uint8_t>& payload, Deferred& deferred) {
    auto* listener = listener_;
    auto update = [&](auto& cache, const auto& decoded, auto notifyFn) {
        if (!decoded) {
            ++stats_.malformed;
            return;
        }
        ++stats_.notifications;
        cache = *decoded;
        if (listener) {
            deferred.push_back([listener, value = *decoded, notifyFn] { (listener->*notifyFn)(value); });
        }
    };

    if (serviceId == ids::kVehicleMotionService && eventId == ids::kEvtVehicleDynamics) {
        update(dynamics_, decodeVehicleDynamics(payload), &IVehicleListener::onVehicleDynamics);
    } else if (serviceId == ids::kVehicleMotionService && eventId == ids::kFldSteeringWheel) {
        update(steering_, decodeSteeringWheel(payload), &IVehicleListener::onSteeringWheel);
    } else if (serviceId == ids::kBodyService && eventId == ids::kFldDoorStatus) {
        update(doors_, decodeDoorStatus(payload), &IVehicleListener::onDoorStatus);
    } else if (serviceId == ids::kEnergyService && eventId == ids::kFldBatteryStatus) {
        update(battery_, decodeBatteryStatus(payload), &IVehicleListener::onBatteryStatus);
    } else {
        ++stats_.unexpected;
    }
}

void VehicleClient::onMessage(const someip::Message& message, TimePoint) {
    const auto& h = message.header;
    Deferred deferred;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto* svc = findService(h.serviceId);
        if (!svc) {
            ++stats_.unexpected;
            return;
        }
        if (h.protocolVersion != someip::kProtocolVersion ||
            h.interfaceVersion != svc->majorVersion) {
            ++stats_.malformed;
            return;
        }
        if (h.messageType == MessageType::Notification) {
            if (!available_[h.serviceId]) {
                ++stats_.unexpected;  // e.g. still queued in the stack after a StopOffer
                return;
            }
            applyEvent(h.serviceId, h.methodId, message.payload, deferred);
        } else if (h.messageType == MessageType::Response || h.messageType == MessageType::Error) {
            const auto it = pending_.find({h.serviceId, h.methodId, h.sessionId});
            if (it == pending_.end()) {
                ++stats_.unexpected;  // late response after timeout, or not ours
                return;
            }
            auto handler = std::move(it->second.handler);
            pending_.erase(it);
            CallResult result;
            if (h.messageType == MessageType::Error || h.returnCode != ReturnCode::Ok) {
                ++stats_.errors;
                result = {CallStatus::Error, h.returnCode};
            } else {
                ++stats_.responses;
            }
            deferred.push_back([handler, result, message] { handler(result, &message); });
        } else {
            ++stats_.unexpected;
        }
    }
    run(deferred);
}

void VehicleClient::mainFunction(TimePoint now) {
    Deferred deferred;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (now >= it->second.deadline) {
                ++stats_.timeouts;
                auto handler = std::move(it->second.handler);
                deferred.push_back([handler] {
                    handler(CallResult{CallStatus::Timeout, ReturnCode::Timeout}, nullptr);
                });
                it = pending_.erase(it);
            } else {
                ++it;
            }
        }
    }
    run(deferred);
}

void VehicleClient::call(std::uint16_t serviceId, std::uint16_t methodId, bool fireAndForget,
                         std::vector<std::uint8_t> payload, ResponseHandler handler,
                         TimePoint now, Deferred& deferred) {
    auto fail = [&](CallStatus status, ReturnCode code) {
        if (handler) {
            deferred.push_back([handler, status, code] { handler(CallResult{status, code}, nullptr); });
        }
    };
    const auto* svc = findService(serviceId);
    if (!svc || !available_[serviceId]) {
        return fail(CallStatus::NotAvailable, ReturnCode::NotReachable);
    }

    someip::Message request;
    request.header.serviceId = serviceId;
    request.header.methodId = methodId;
    request.header.interfaceVersion = svc->majorVersion;
    request.header.messageType = fireAndForget ? MessageType::RequestNoReturn : MessageType::Request;
    request.payload = std::move(payload);

    // The transport is called with the lock held so that a response cannot
    // overtake the registration of its pending entry.
    const auto session = transport_.send(svc->instanceId, request);
    if (!session) {
        return fail(CallStatus::SendFailed, ReturnCode::NotOk);
    }
    ++stats_.requestsSent;
    if (fireAndForget) {
        if (handler) deferred.push_back([handler] { handler(CallResult{}, nullptr); });
        return;
    }
    auto& entry = pending_[{serviceId, methodId, *session}];
    if (entry.handler) {
        // Session wrapped around onto an outstanding request (65535 calls in flight).
        auto old = std::move(entry.handler);
        deferred.push_back([old] { old(CallResult{CallStatus::Timeout, ReturnCode::Timeout}, nullptr); });
    }
    entry = Pending{now + options_.requestTimeout, std::move(handler)};
}

void VehicleClient::setCentralLock(LockRequest request, CallCallback done, TimePoint now) {
    Deferred deferred;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        call(ids::kBodyService, ids::kMtdSetCentralLock, false, encodeSetCentralLock(request),
             [done](const CallResult& r, const someip::Message*) {
                 if (done) done(r);
             },
             now, deferred);
    }
    run(deferred);
}

bool VehicleClient::openTrunk(TimePoint now) {
    Deferred deferred;
    bool sent = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        call(ids::kBodyService, ids::kMtdOpenTrunk, true, encodeOpenTrunk(true),
             [&sent](const CallResult& r, const someip::Message*) { sent = r.ok(); }, now,
             deferred);
    }
    run(deferred);
    return sent;
}

void VehicleClient::setCabinClimate(const CabinClimateRequest& request, CallCallback done,
                                    TimePoint now) {
    Deferred deferred;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        call(ids::kClimateService, ids::kMtdSetCabinClimate, false,
             encodeSetCabinClimate(request),
             [done](const CallResult& r, const someip::Message*) {
                 if (done) done(r);
             },
             now, deferred);
    }
    run(deferred);
}

bool VehicleClient::isAvailable(std::uint16_t serviceId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = available_.find(serviceId);
    return it != available_.end() && it->second;
}

std::optional<VehicleDynamics> VehicleClient::vehicleDynamics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dynamics_;
}

std::optional<SteeringWheel> VehicleClient::steeringWheel() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return steering_;
}

std::optional<DoorStatus> VehicleClient::doorStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return doors_;
}

std::optional<BatteryStatus> VehicleClient::batteryStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return battery_;
}

ClientStatistics VehicleClient::statistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

}  // namespace ccg::ivi
