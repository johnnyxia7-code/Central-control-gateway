// Vehicle HAL service of the IVI controller: AOSP DefaultVehicleHal on top of
// the SOME/IP backend (HPC S2S services). Mirrors the reference
// hardware/interfaces/automotive/vehicle/aidl/impl/vhal/src/VehicleService.cpp.
#define LOG_TAG "ccg_vhal"

#include <DefaultVehicleHal.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <utils/Log.h>

#include "SomeIpVehicleHardware.h"

using ::android::hardware::automotive::vehicle::DefaultVehicleHal;
using ::ccg::android_vhal::SomeIpVehicleHardware;

int main(int /*argc*/, char* /*argv*/[]) {
    ALOGI("Starting thread pool...");
    if (!ABinderProcess_setThreadPoolMaxThreadCount(4)) {
        ALOGE("%s", "failed to set thread pool max thread count");
        return 1;
    }
    ABinderProcess_startThreadPool();

    auto hardware = std::make_unique<SomeIpVehicleHardware>();
    std::shared_ptr<DefaultVehicleHal> vhal =
            ::ndk::SharedRefBase::make<DefaultVehicleHal>(std::move(hardware));

    ALOGI("Registering as service...");
    const binder_exception_t err = AServiceManager_addService(
            vhal->asBinder().get(), "android.hardware.automotive.vehicle.IVehicle/default");
    if (err != EX_NONE) {
        ALOGE("failed to register android.hardware.automotive.vehicle service, exception: %d", err);
        return 1;
    }

    ALOGI("Vehicle Service Ready (SOME/IP backend)");
    ABinderProcess_joinThreadPool();
    ALOGI("Vehicle Service Exiting");
    return 0;
}
