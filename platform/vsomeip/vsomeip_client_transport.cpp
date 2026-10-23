#include "vsomeip_client_transport.hpp"

#include <set>

#include "vsomeip_message.hpp"

namespace ccg::platform {

VsomeipClientTransport::VsomeipClientTransport(std::string applicationName)
    : name_(std::move(applicationName)) {}

VsomeipClientTransport::~VsomeipClientTransport() { stop(); }

bool VsomeipClientTransport::init() {
    app_ = vsomeip::runtime::get()->create_application(name_);
    if (!app_ || !app_->init()) {
        app_.reset();
        return false;
    }
    app_->register_message_handler(
        vsomeip::ANY_SERVICE, vsomeip::ANY_INSTANCE, vsomeip::ANY_METHOD,
        [this](const std::shared_ptr<vsomeip::message>& m) {
            if (auto* client = client_.load()) {
                client->onMessage(vsomeip_adapter::fromVsomeip(*m), ivi::Clock::now());
            }
        });
    return true;
}

void VsomeipClientTransport::start() {
    if (!app_ || thread_.joinable()) return;
    thread_ = std::thread([app = app_] { app->start(); });
}

void VsomeipClientTransport::stop() {
    if (!app_) return;
    if (thread_.joinable()) {
        app_->stop();
        thread_.join();
    }
}

void VsomeipClientTransport::requestService(const ivi::ServiceDescriptor& service) {
    if (!app_) return;
    const auto svc = service.serviceId;
    const auto inst = service.instanceId;
    app_->register_availability_handler(
        svc, inst,
        [this](vsomeip::service_t s, vsomeip::instance_t i, bool available) {
            if (auto* client = client_.load()) {
                client->onAvailability(s, i, available, ivi::Clock::now());
            }
        },
        service.majorVersion, vsomeip::ANY_MINOR);
    app_->request_service(svc, inst, service.majorVersion, vsomeip::ANY_MINOR);

    std::set<vsomeip::eventgroup_t> groups;
    for (const auto& ev : service.events) {
        app_->request_event(svc, inst, ev.eventId, {ev.eventgroupId},
                            ev.isField ? vsomeip::event_type_e::ET_FIELD
                                       : vsomeip::event_type_e::ET_EVENT);
        groups.insert(ev.eventgroupId);
    }
    // vsomeip keeps the subscriptions and renews them whenever the service is
    // (re-)offered, so subscribing once at start-up is sufficient.
    for (const auto eg : groups) {
        app_->subscribe(svc, inst, eg, service.majorVersion);
    }
}

std::optional<std::uint16_t> VsomeipClientTransport::send(std::uint16_t instanceId,
                                                          const someip::Message& request) {
    if (!app_) return std::nullopt;
    const auto& h = request.header;
    auto m = vsomeip::runtime::get()->create_request(false);  // UDP
    m->set_service(h.serviceId);
    m->set_instance(instanceId);
    m->set_method(h.methodId);
    m->set_interface_version(h.interfaceVersion);
    m->set_message_type(h.messageType == someip::MessageType::RequestNoReturn
                            ? vsomeip::message_type_e::MT_REQUEST_NO_RETURN
                            : vsomeip::message_type_e::MT_REQUEST);
    m->set_payload(vsomeip_adapter::toPayload(request.payload));
    app_->send(m);  // assigns client and session ID
    return m->get_session();
}

}  // namespace ccg::platform
