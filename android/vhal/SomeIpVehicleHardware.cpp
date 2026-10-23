#define LOG_TAG "ccg_vhal"

#include "SomeIpVehicleHardware.h"

#include <android-base/stringprintf.h>
#include <utils/Log.h>
#include <utils/SystemClock.h>

#include <chrono>

namespace ccg::android_vhal {

namespace bridge = ::ccg::ivi::vhal;
using ::android::base::StringAppendF;

namespace {

aidlvhal::VehiclePropValue toAidl(const bridge::PropertyValue& v) {
    aidlvhal::VehiclePropValue out;
    out.timestamp = v.timestampNs;
    out.areaId = v.areaId;
    out.prop = v.prop;
    out.status = static_cast<aidlvhal::VehiclePropertyStatus>(v.status);
    out.value.int32Values = v.int32Values;
    out.value.floatValues = v.floatValues;
    return out;
}

bridge::PropertyValue fromAidl(const aidlvhal::VehiclePropValue& v) {
    bridge::PropertyValue out;
    out.prop = v.prop;
    out.areaId = v.areaId;
    out.timestampNs = v.timestamp;
    out.status = static_cast<bridge::PropertyStatus>(v.status);
    out.int32Values = v.value.int32Values;
    out.floatValues = v.value.floatValues;
    return out;
}

aidlvhal::VehiclePropConfig toAidl(const bridge::PropertyConfig& c) {
    aidlvhal::VehiclePropConfig out;
    out.prop = c.prop;
    out.access = static_cast<aidlvhal::VehiclePropertyAccess>(c.access);
    out.changeMode = static_cast<aidlvhal::VehiclePropertyChangeMode>(c.changeMode);
    out.configArray = c.configArray;
    out.minSampleRate = c.minSampleRate;
    out.maxSampleRate = c.maxSampleRate;
    for (const auto& a : c.areaConfigs) {
        aidlvhal::VehicleAreaConfig area;
        area.areaId = a.areaId;
        area.minInt32Value = a.minInt32Value;
        area.maxInt32Value = a.maxInt32Value;
        area.minFloatValue = a.minFloatValue;
        area.maxFloatValue = a.maxFloatValue;
        // Per-area access (Android 14+): only the trunk of DOOR_POS is writable.
        area.access = static_cast<aidlvhal::VehiclePropertyAccess>(a.access);
        out.areaConfigs.push_back(area);
    }
    return out;
}

bool isContinuous(const std::vector<aidlvhal::VehiclePropConfig>& configs, int32_t prop) {
    for (const auto& c : configs) {
        if (c.prop == prop) return c.changeMode == aidlvhal::VehiclePropertyChangeMode::CONTINUOUS;
    }
    return false;
}

}  // namespace

SomeIpVehicleHardware::SomeIpVehicleHardware(std::string vsomeipApplication,
                                             bridge::BridgeOptions options)
    : mTransport(std::move(vsomeipApplication)),
      mClient(mTransport),
      mBridge(mClient, options, [] { return ::android::elapsedRealtimeNano(); }) {
    for (const auto& c : mBridge.propertyConfigs()) mConfigs.push_back(toAidl(c));

    mClient.setListener(&mBridge);
    mBridge.setChangeCallback(
            [this](std::vector<bridge::PropertyValue> values) { onPropertyChange(std::move(values)); });

    // vsomeip reads VSOMEIP_CONFIGURATION / VSOMEIP_APPLICATION_NAME from the init
    // environment and connects to ccg_someipd (vendor.ccg.someipd) through
    // /dev/socket/someip; it retries until the routing manager is up.
    mStackReady = mTransport.init();
    if (!mStackReady) {
        ALOGE("vsomeip initialisation failed: all properties stay NOT_AVAILABLE");
    } else {
        mTransport.setClient(&mClient);
        mClient.start();
        mTransport.start();
    }
    mSupervision = std::thread([this] {
        while (mRunning) {
            mClient.mainFunction(ccg::ivi::Clock::now());
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
}

SomeIpVehicleHardware::~SomeIpVehicleHardware() {
    mRunning = false;
    if (mSupervision.joinable()) mSupervision.join();
    mClient.setListener(nullptr);
    mTransport.setClient(nullptr);
    mTransport.stop();
}

std::vector<aidlvhal::VehiclePropConfig> SomeIpVehicleHardware::getAllPropertyConfigs() const {
    return mConfigs;
}

aidlvhal::StatusCode SomeIpVehicleHardware::getValues(
        std::shared_ptr<const GetValuesCallback> callback,
        const std::vector<aidlvhal::GetValueRequest>& requests) const {
    std::vector<aidlvhal::GetValueResult> results;
    results.reserve(requests.size());
    for (const auto& request : requests) {
        const auto [status, value] = mBridge.get(request.prop.prop, request.prop.areaId);
        aidlvhal::GetValueResult result;
        result.requestId = request.requestId;
        result.status = static_cast<aidlvhal::StatusCode>(status);
        if (status == bridge::StatusCode::Ok) result.prop = toAidl(value);
        results.push_back(std::move(result));
    }
    (*callback)(std::move(results));
    return aidlvhal::StatusCode::OK;
}

aidlvhal::StatusCode SomeIpVehicleHardware::setValues(
        std::shared_ptr<const SetValuesCallback> callback,
        const std::vector<aidlvhal::SetValueRequest>& requests) {
    // Results are delivered per request as the HPC answers (DefaultVehicleHal
    // matches them by requestId and applies its own timeout).
    for (const auto& request : requests) {
        const int64_t requestId = request.requestId;
        mBridge.set(fromAidl(request.value), [callback, requestId](bridge::StatusCode status) {
            aidlvhal::SetValueResult result;
            result.requestId = requestId;
            result.status = static_cast<aidlvhal::StatusCode>(status);
            (*callback)({result});
        });
    }
    return aidlvhal::StatusCode::OK;
}

void SomeIpVehicleHardware::onPropertyChange(std::vector<bridge::PropertyValue> values) {
    std::shared_ptr<const PropertyChangeCallback> callback;
    {
        std::lock_guard<std::mutex> lock(mCallbackLock);
        callback = mOnChange;
    }
    if (!callback) return;
    std::vector<aidlvhal::VehiclePropValue> events;
    for (const auto& v : values) {
        // Continuous values reach subscribers through DefaultVehicleHal's
        // polling at the requested sample rate; pushing every 20 ms update as
        // well would exceed it. Status changes are pushed nevertheless.
        if (isContinuous(mConfigs, v.prop) && v.status == bridge::PropertyStatus::Available) {
            continue;
        }
        events.push_back(toAidl(v));
    }
    if (!events.empty()) (*callback)(std::move(events));
}

void SomeIpVehicleHardware::registerOnPropertyChangeEvent(
        std::unique_ptr<const PropertyChangeCallback> callback) {
    std::lock_guard<std::mutex> lock(mCallbackLock);
    mOnChange = std::move(callback);
}

void SomeIpVehicleHardware::registerOnPropertySetErrorEvent(
        std::unique_ptr<const PropertySetErrorCallback> callback) {
    // Write errors are reported synchronously through the setValues results.
    std::lock_guard<std::mutex> lock(mCallbackLock);
    mOnSetError = std::move(callback);
}

aidlvhal::StatusCode SomeIpVehicleHardware::checkHealth() {
    return mStackReady ? aidlvhal::StatusCode::OK : aidlvhal::StatusCode::INTERNAL_ERROR;
}

DumpResult SomeIpVehicleHardware::dump(const std::vector<std::string>& /*options*/) {
    std::string out = "SOME/IP vehicle hardware (HPC S2S services)\n";
    for (const auto& svc : ccg::ivi::hpcServices()) {
        StringAppendF(&out, "  %-22s 0x%04X/0x%04X v%u: %s\n", svc.name, svc.serviceId,
                      svc.instanceId, svc.majorVersion,
                      mClient.isAvailable(svc.serviceId) ? "available" : "NOT available");
    }
    const auto s = mClient.statistics();
    StringAppendF(&out,
                  "  notifications=%llu malformed=%llu unexpected=%llu requests=%llu "
                  "responses=%llu errors=%llu timeouts=%llu\n",
                  static_cast<unsigned long long>(s.notifications),
                  static_cast<unsigned long long>(s.malformed),
                  static_cast<unsigned long long>(s.unexpected),
                  static_cast<unsigned long long>(s.requestsSent),
                  static_cast<unsigned long long>(s.responses),
                  static_cast<unsigned long long>(s.errors),
                  static_cast<unsigned long long>(s.timeouts));
    for (const auto& c : mConfigs) {
        for (const auto& a : c.areaConfigs) {
            const auto [status, v] = mBridge.get(c.prop, a.areaId);
            StringAppendF(&out, "  %s[0x%X]: %s", bridge::propertyName(c.prop), a.areaId,
                          bridge::toString(status));
            for (const auto i : v.int32Values) StringAppendF(&out, " %d", i);
            for (const auto f : v.floatValues) StringAppendF(&out, " %f", f);
            out += "\n";
        }
    }
    DumpResult result;
    result.callerShouldDumpState = true;
    result.buffer = std::move(out);
    return result;
}

}  // namespace ccg::android_vhal
