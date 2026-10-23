#include "vsomeip_server_binding.hpp"

#include <sys/eventfd.h>
#include <unistd.h>

#include <cerrno>
#include <set>
#include <system_error>
#include <tuple>

#include "vsomeip_message.hpp"

namespace ccg::platform {

namespace {

// Peer tokens: requests use a running number, subscribers carry their vsomeip
// client ID (and the instance) with the top bit set.
constexpr std::uint64_t kSubscriberFlag = 1ULL << 63;
constexpr std::size_t kMaxPendingRequests = 256;

s2s::Peer subscriberPeer(std::uint16_t instance, vsomeip::client_t client) {
    return s2s::Peer{kSubscriberFlag | (static_cast<std::uint64_t>(instance) << 16) | client};
}

}  // namespace

VsomeipServerBinding::VsomeipServerBinding(std::string applicationName)
    : name_(std::move(applicationName)) {
    eventFd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (eventFd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "eventfd");
    }
}

VsomeipServerBinding::~VsomeipServerBinding() {
    stop();
    ::close(eventFd_);
}

bool VsomeipServerBinding::init(const s2s::GatewayConfig& config) {
    app_ = vsomeip::runtime::get()->create_application(name_);
    if (!app_ || !app_->init()) {
        app_.reset();
        return false;
    }

    std::set<std::tuple<std::uint16_t, std::uint16_t, std::uint16_t>> eventgroups;
    for (const auto& ev : config.events) {
        // The gateway decides when to send (on-change, cyclic, debounce): no
        // vsomeip cycle, and notify() forces unchanged payloads out. Note that
        // update_on_change must stay true, otherwise vsomeip only sends on its
        // own cycle (i.e. never, apart from initial field values).
        app_->offer_event(ev.serviceId, ev.instanceId, ev.eventId, {ev.eventgroupId},
                          ev.isField ? vsomeip::event_type_e::ET_FIELD
                                     : vsomeip::event_type_e::ET_EVENT,
                          std::chrono::milliseconds::zero(), false, true, nullptr,
                          vsomeip::reliability_type_e::RT_UNRELIABLE);
        eventgroups.insert({ev.serviceId, ev.instanceId, ev.eventgroupId});
    }

    for (const auto& svc : config.services) {
        app_->register_message_handler(
            svc.serviceId, svc.instanceId, vsomeip::ANY_METHOD,
            [this](const std::shared_ptr<vsomeip::message>& m) {
                Inbound in;
                in.kind = Inbound::Kind::Request;
                in.message = vsomeip_adapter::fromVsomeip(*m);
                in.context.instanceId = m->get_instance();
                if (m->get_message_type() == vsomeip::message_type_e::MT_REQUEST) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    const auto token = nextToken_++;
                    in.context.peer = s2s::Peer{token};
                    pendingRequests_.emplace(token, m);
                    while (pendingRequests_.size() > kMaxPendingRequests) {
                        pendingRequests_.erase(pendingRequests_.begin());
                        ++droppedResponses_;
                    }
                }
                enqueue(std::move(in));
            });
    }

    for (const auto& [svc, inst, eg] : eventgroups) {
        app_->register_subscription_handler(
            svc, inst, eg,
            [this, svc = svc, inst = inst, eg = eg](vsomeip::client_t client,
                                                   const vsomeip_sec_client_t*,
                                                   const std::string&, bool subscribed) {
                if (subscribed) {
                    Inbound in;
                    in.kind = Inbound::Kind::Subscribe;
                    in.serviceId = svc;
                    in.eventgroupId = eg;
                    in.context = {inst, subscriberPeer(inst, client)};
                    enqueue(std::move(in));
                }
                return true;  // access control is configured in the vsomeip security policy
            });
    }
    return true;
}

void VsomeipServerBinding::start() {
    if (!app_ || thread_.joinable()) return;
    thread_ = std::thread([app = app_] { app->start(); });
}

void VsomeipServerBinding::stop() {
    if (app_ && thread_.joinable()) {
        app_->stop();
        thread_.join();
    }
}

void VsomeipServerBinding::enqueue(Inbound inbound) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        inbox_.push_back(std::move(inbound));
    }
    const std::uint64_t one = 1;
    (void)!::write(eventFd_, &one, sizeof one);
}

std::vector<VsomeipServerBinding::Inbound> VsomeipServerBinding::receive() {
    std::uint64_t count = 0;
    (void)!::read(eventFd_, &count, sizeof count);
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Inbound> out;
    out.swap(inbox_);
    return out;
}

void VsomeipServerBinding::offerService(const s2s::ServiceInstance& service) {
    if (app_) {
        app_->offer_service(service.serviceId, service.instanceId, service.majorVersion,
                            service.minorVersion);
    }
}

void VsomeipServerBinding::notify(std::uint16_t serviceId, std::uint16_t instanceId,
                                  std::uint16_t, const someip::Message& message) {
    if (app_) {
        app_->notify(serviceId, instanceId, message.header.methodId,
                     vsomeip_adapter::toPayload(message.payload), true);
    }
}

void VsomeipServerBinding::sendTo(const s2s::Peer& peer, const someip::Message& message) {
    if (!app_) return;
    if (peer.token & kSubscriberFlag) {
        // Initial value of a field for a new subscriber.
        const auto instance = static_cast<std::uint16_t>(peer.token >> 16);
        const auto client = static_cast<vsomeip::client_t>(peer.token & 0xFFFFU);
        app_->notify_one(message.header.serviceId, instance, message.header.methodId,
                         vsomeip_adapter::toPayload(message.payload), client, true);
        return;
    }

    std::shared_ptr<vsomeip::message> request;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = pendingRequests_.find(peer.token);
        if (it == pendingRequests_.end()) {
            ++droppedResponses_;
            return;
        }
        request = it->second;
        pendingRequests_.erase(it);
    }
    auto response = vsomeip::runtime::get()->create_response(request);
    if (message.header.messageType == someip::MessageType::Error) {
        response->set_message_type(vsomeip::message_type_e::MT_ERROR);
    }
    response->set_return_code(static_cast<vsomeip::return_code_e>(message.header.returnCode));
    response->set_payload(vsomeip_adapter::toPayload(message.payload));
    app_->send(response);
}

std::uint64_t VsomeipServerBinding::droppedResponses() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return droppedResponses_;
}

}  // namespace ccg::platform
