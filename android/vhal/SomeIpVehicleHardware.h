#pragma once

#include <IVehicleHardware.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ccg/ivi/vehicle_client.hpp"
#include "ccg/ivi/vehicle_property_bridge.hpp"
#include "vsomeip_client_transport.hpp"

namespace ccg::android_vhal {

namespace aidlvhal = ::aidl::android::hardware::automotive::vehicle;
using ::android::hardware::automotive::vehicle::DumpResult;
using ::android::hardware::automotive::vehicle::IVehicleHardware;

// IVehicleHardware backend of the AOSP reference DefaultVehicleHal: properties
// come from the HPC S2S services over SOME/IP (vsomeip), see
// ivi/include/ccg/ivi/vehicle_property_bridge.hpp for the mapping.
//
// Continuous properties (speed, steering angle, battery) are served from the
// cache through getValues(); DefaultVehicleHal polls them at the subscribed
// sample rate. On-change properties are pushed with the property change callback.
class SomeIpVehicleHardware final : public IVehicleHardware {
public:
    explicit SomeIpVehicleHardware(std::string vsomeipApplication = "ccg_vhal",
                                   ccg::ivi::vhal::BridgeOptions options = {});
    ~SomeIpVehicleHardware() override;

    std::vector<aidlvhal::VehiclePropConfig> getAllPropertyConfigs() const override;
    aidlvhal::StatusCode setValues(std::shared_ptr<const SetValuesCallback> callback,
                                   const std::vector<aidlvhal::SetValueRequest>& requests) override;
    aidlvhal::StatusCode getValues(std::shared_ptr<const GetValuesCallback> callback,
                                   const std::vector<aidlvhal::GetValueRequest>& requests) const override;
    DumpResult dump(const std::vector<std::string>& options) override;
    aidlvhal::StatusCode checkHealth() override;
    void registerOnPropertyChangeEvent(std::unique_ptr<const PropertyChangeCallback> callback) override;
    void registerOnPropertySetErrorEvent(
            std::unique_ptr<const PropertySetErrorCallback> callback) override;

private:
    void onPropertyChange(std::vector<ccg::ivi::vhal::PropertyValue> values);

    ccg::platform::VsomeipClientTransport mTransport;
    ccg::ivi::VehicleClient mClient;
    ccg::ivi::vhal::VehiclePropertyBridge mBridge;
    std::vector<aidlvhal::VehiclePropConfig> mConfigs;
    bool mStackReady = false;

    std::mutex mCallbackLock;
    std::shared_ptr<const PropertyChangeCallback> mOnChange;
    std::shared_ptr<const PropertySetErrorCallback> mOnSetError;

    std::atomic<bool> mRunning{true};
    std::thread mSupervision;
};

}  // namespace ccg::android_vhal
