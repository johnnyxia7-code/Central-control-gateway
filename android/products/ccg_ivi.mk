# IVI controller: vsomeip port and SOME/IP Vehicle HAL.
#
# In the device makefile:
#   $(call inherit-product, vendor/ccg/central-control-gateway/android/products/ccg_ivi.mk)
# and remove the reference VHAL (FakeVehicleHardware), e.g.
#   android.hardware.automotive.vehicle@V3-default-service
# from PRODUCT_PACKAGES (device/generic/car/common/car.mk on the AOSP car targets).

PRODUCT_PACKAGES += \
    android.hardware.automotive.vehicle-ccg-service \
    ccg_someipd \
    ccg_vsomeip_ivi.json \
    libvsomeip3 \
    libvsomeip_cfg \
    libvsomeip_sd \
    CcgIviConnectivityOverlay

PRODUCT_PACKAGES_DEBUG += \
    ccg_ivi_vehicle_client \
    ccg_s2s_ivi_tests
