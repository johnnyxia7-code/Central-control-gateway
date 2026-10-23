#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>

#include <vsomeip/vsomeip.hpp>

#include "ccg/ivi/vehicle_client.hpp"

namespace ccg::platform {

// IVI side: ivi::IClientTransport on top of a vsomeip application.
//
// Service discovery, subscriptions and the local routing manager connection
// are handled by vsomeip according to the JSON configuration
// (VSOMEIP_CONFIGURATION, see android/vendor/ccg/someip/config).
// Availability changes and messages are forwarded to the VehicleClient on the
// vsomeip dispatcher thread.
class VsomeipClientTransport final : public ivi::IClientTransport {
public:
    explicit VsomeipClientTransport(std::string applicationName);
    ~VsomeipClientTransport() override;
    VsomeipClientTransport(const VsomeipClientTransport&) = delete;
    VsomeipClientTransport& operator=(const VsomeipClientTransport&) = delete;

    // Creates and initialises the vsomeip application; false on configuration errors.
    bool init();
    // Upcall target; set before start().
    void setClient(ivi::VehicleClient* client) { client_ = client; }
    // Runs the vsomeip application on its own thread.
    void start();
    void stop();

    void requestService(const ivi::ServiceDescriptor& service) override;
    std::optional<std::uint16_t> send(std::uint16_t instanceId,
                                      const someip::Message& request) override;

private:
    std::string name_;
    std::shared_ptr<vsomeip::application> app_;
    std::atomic<ivi::VehicleClient*> client_{nullptr};
    std::thread thread_;
};

}  // namespace ccg::platform
