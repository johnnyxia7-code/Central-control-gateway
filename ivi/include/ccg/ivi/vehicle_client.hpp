#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <tuple>
#include <vector>

#include "ccg/ivi/vehicle_services.hpp"
#include "ccg/someip/someip_message.hpp"

// IVI-side proxy of the HPC S2S services.
//
//   Android VHAL / apps  <-->  VehicleClient  <-->  IClientTransport (vsomeip)  <-->  HPC
//
// VehicleClient is independent of the SOME/IP stack: the transport finds the
// services, subscribes the eventgroups and forwards availability changes and
// received messages. Unlike the HPC gateway core, the client is thread safe,
// because on Android the stack delivers on its dispatcher threads while the
// VHAL calls in on binder threads. Listener and call callbacks are invoked
// without the internal lock held, so they may call back into the client.
namespace ccg::ivi {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

struct EventDescriptor {
    std::uint16_t eventId = 0;
    std::uint16_t eventgroupId = 0;
    bool isField = false;
    std::optional<std::uint16_t> getterId;
};

struct ServiceDescriptor {
    const char* name = "";
    std::uint16_t serviceId = 0;
    std::uint16_t instanceId = 0;
    std::uint8_t majorVersion = 1;
    std::uint32_t minorVersion = 0;
    std::vector<EventDescriptor> events;
};

// The service instances consumed from the HPC (IDs from config/vehicle_s2s_matrix.hpp).
const std::vector<ServiceDescriptor>& hpcServices();

class IClientTransport {
public:
    virtual ~IClientTransport() = default;
    // Find the service instance and subscribe all its eventgroups. Availability
    // and messages are reported through VehicleClient::onAvailability / onMessage.
    virtual void requestService(const ServiceDescriptor& service) = 0;
    // Sends a REQUEST or REQUEST_NO_RETURN. Returns the session ID the stack put
    // into the header (the key to match the response), nullopt if not sent.
    // Called with the client lock held: must not call back into the client
    // synchronously (responses arrive later on the stack's own thread).
    virtual std::optional<std::uint16_t> send(std::uint16_t instanceId,
                                              const someip::Message& request) = 0;
};

class IVehicleListener {
public:
    virtual ~IVehicleListener() = default;
    virtual void onServiceAvailability(std::uint16_t /*serviceId*/, bool /*available*/) {}
    virtual void onVehicleDynamics(const VehicleDynamics&) {}
    virtual void onSteeringWheel(const SteeringWheel&) {}
    virtual void onDoorStatus(const DoorStatus&) {}
    virtual void onBatteryStatus(const BatteryStatus&) {}
};

enum class CallStatus : std::uint8_t {
    Ok,
    NotAvailable,  // service not (yet) offered by the HPC
    SendFailed,    // the stack refused the request
    Timeout,       // no response within ClientOptions::requestTimeout
    Error,         // HPC answered with an ERROR message, see returnCode
};

const char* toString(CallStatus status);

struct CallResult {
    CallStatus status = CallStatus::Ok;
    someip::ReturnCode returnCode = someip::ReturnCode::Ok;
    bool ok() const { return status == CallStatus::Ok; }
};

using CallCallback = std::function<void(const CallResult&)>;

struct ClientOptions {
    std::chrono::milliseconds requestTimeout{500};
    // Read every field with its getter when its service becomes available. This
    // makes the client independent of the initial event (e.g. HPC without SD).
    bool refreshFieldsOnAvailable = true;
};

struct ClientStatistics {
    std::uint64_t notifications = 0;
    std::uint64_t malformed = 0;  // payload or header not matching the interface
    std::uint64_t unexpected = 0; // unknown event, response without pending request
    std::uint64_t requestsSent = 0;
    std::uint64_t responses = 0;
    std::uint64_t errors = 0;
    std::uint64_t timeouts = 0;
};

class VehicleClient {
public:
    explicit VehicleClient(IClientTransport& transport, ClientOptions options = {});
    VehicleClient(const VehicleClient&) = delete;
    VehicleClient& operator=(const VehicleClient&) = delete;

    // The listener must outlive the client (or be reset with nullptr first).
    void setListener(IVehicleListener* listener);

    // Requests all HPC services from the transport.
    void start();

    // --- transport upcalls (any thread) ---
    void onAvailability(std::uint16_t serviceId, std::uint16_t instanceId, bool available,
                        TimePoint now);
    void onMessage(const someip::Message& message, TimePoint now);

    // Request supervision; call periodically (100 ms is plenty).
    void mainFunction(TimePoint now);

    // --- BodyService ---
    void setCentralLock(LockRequest request, CallCallback done, TimePoint now);
    // Fire & forget: true when the request was handed to the stack.
    bool openTrunk(TimePoint now);

    // --- ClimateService ---
    void setCabinClimate(const CabinClimateRequest& request, CallCallback done, TimePoint now);

    // --- cached state ---
    bool isAvailable(std::uint16_t serviceId) const;
    std::optional<VehicleDynamics> vehicleDynamics() const;
    std::optional<SteeringWheel> steeringWheel() const;
    std::optional<DoorStatus> doorStatus() const;
    std::optional<BatteryStatus> batteryStatus() const;
    ClientStatistics statistics() const;

private:
    using Deferred = std::vector<std::function<void()>>;
    using ResponseHandler = std::function<void(const CallResult&, const someip::Message*)>;

    struct Pending {
        TimePoint deadline;
        ResponseHandler handler;
    };
    using PendingKey = std::tuple<std::uint16_t, std::uint16_t, std::uint16_t>;  // svc, method, session

    const ServiceDescriptor* findService(std::uint16_t serviceId) const;
    void call(std::uint16_t serviceId, std::uint16_t methodId, bool fireAndForget,
              std::vector<std::uint8_t> payload, ResponseHandler handler, TimePoint now,
              Deferred& deferred);
    void applyEvent(std::uint16_t serviceId, std::uint16_t eventId,
                    const std::vector<std::uint8_t>& payload, Deferred& deferred);
    static void run(Deferred& deferred);

    IClientTransport& transport_;
    const ClientOptions options_;

    mutable std::mutex mutex_;
    IVehicleListener* listener_ = nullptr;
    std::map<std::uint16_t, bool> available_;
    std::map<PendingKey, Pending> pending_;
    std::optional<VehicleDynamics> dynamics_;
    std::optional<SteeringWheel> steering_;
    std::optional<DoorStatus> doors_;
    std::optional<BatteryStatus> battery_;
    ClientStatistics stats_;
};

}  // namespace ccg::ivi
