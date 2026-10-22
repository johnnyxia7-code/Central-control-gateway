cmake_minimum_required(VERSION 3.16)
project(central_control_gateway VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(CCG_BUILD_TESTS "Build unit tests" ON)
option(CCG_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
set(CCG_WITH_VSOMEIP "AUTO" CACHE STRING "Build the vsomeip bindings (ON, OFF, AUTO = if vsomeip3 is found)")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

function(ccg_warnings target)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
  if(CCG_WARNINGS_AS_ERRORS)
    target_compile_options(${target} PRIVATE -Werror)
  endif()
endfunction()

# --- portable S2S core (no OS dependencies) ---------------------------------
add_library(ccg_s2s
  src/can/signal_codec.cpp
  src/e2e/can_e2e.cpp
  src/someip/someip_message.cpp
  src/s2s/data_type.cpp
  src/s2s/s2s_config_validator.cpp
  src/s2s/s2s_gateway.cpp
)
target_include_directories(ccg_s2s PUBLIC include)
ccg_warnings(ccg_s2s)

# --- reference vehicle matrix ------------------------------------------------
add_library(ccg_vehicle_matrix config/vehicle_s2s_matrix.cpp)
target_include_directories(ccg_vehicle_matrix PUBLIC config)
target_link_libraries(ccg_vehicle_matrix PUBLIC ccg_s2s)
ccg_warnings(ccg_vehicle_matrix)

# --- IVI client side (portable, consumed by the Android VHAL bridge) --------
add_library(ccg_ivi
  ivi/src/vehicle_services.cpp
  ivi/src/vehicle_client.cpp
  ivi/src/vehicle_property_bridge.cpp
)
target_include_directories(ccg_ivi PUBLIC ivi/include)
target_link_libraries(ccg_ivi PUBLIC ccg_s2s PRIVATE ccg_vehicle_matrix)
ccg_warnings(ccg_ivi)

# --- bench simulation (virtual time, no hardware) ----------------------------
add_executable(ccg_s2s_sim app/s2s_sim_main.cpp)
target_link_libraries(ccg_s2s_sim PRIVATE ccg_vehicle_matrix)
ccg_warnings(ccg_s2s_sim)

# --- Linux gateway process (SocketCAN + SOME/IP over UDP) --------------------
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_library(ccg_platform_linux
    platform/linux/socketcan_transport.cpp
    platform/linux/someip_udp_binding.cpp
    platform/linux/network_setup.cpp
  )
  target_include_directories(ccg_platform_linux PUBLIC platform/linux)
  target_link_libraries(ccg_platform_linux PUBLIC ccg_s2s)
  ccg_warnings(ccg_platform_linux)

  add_executable(ccg_s2s_gateway app/s2s_gateway_main.cpp)
  target_link_libraries(ccg_s2s_gateway PRIVATE ccg_platform_linux ccg_vehicle_matrix)
  ccg_warnings(ccg_s2s_gateway)

  # --- vsomeip bindings: HPC gateway with SOME/IP-SD, IVI vehicle client -------
  if(CCG_WITH_VSOMEIP STREQUAL "AUTO")
    find_package(vsomeip3 CONFIG QUIET)
  elseif(CCG_WITH_VSOMEIP)
    find_package(vsomeip3 CONFIG REQUIRED)
  endif()
  if(vsomeip3_FOUND)
    message(STATUS "vsomeip3 ${vsomeip3_VERSION}: building vsomeip bindings")
    add_library(ccg_platform_vsomeip
      platform/vsomeip/vsomeip_server_binding.cpp
      platform/vsomeip/vsomeip_client_transport.cpp
    )
    target_include_directories(ccg_platform_vsomeip PUBLIC platform/vsomeip)
    target_link_libraries(ccg_platform_vsomeip PUBLIC ccg_s2s ccg_ivi vsomeip3)
    ccg_warnings(ccg_platform_vsomeip)

    add_executable(ccg_s2s_gateway_vsomeip app/s2s_gateway_vsomeip_main.cpp)
    target_link_libraries(ccg_s2s_gateway_vsomeip PRIVATE ccg_platform_vsomeip ccg_platform_linux
                                                          ccg_vehicle_matrix)
    ccg_warnings(ccg_s2s_gateway_vsomeip)

    add_executable(ccg_hpc_vsomeip_bench app/hpc_vsomeip_bench_main.cpp)
    target_link_libraries(ccg_hpc_vsomeip_bench PRIVATE ccg_platform_vsomeip ccg_vehicle_matrix)
    ccg_warnings(ccg_hpc_vsomeip_bench)

    add_executable(ccg_someipd app/someipd_main.cpp)
    target_link_libraries(ccg_someipd PRIVATE ccg_platform_linux vsomeip3)
    ccg_warnings(ccg_someipd)

    add_executable(ccg_ivi_vehicle_client app/ivi_vehicle_client_main.cpp)
    target_link_libraries(ccg_ivi_vehicle_client PRIVATE ccg_platform_vsomeip ccg_vehicle_matrix)
    ccg_warnings(ccg_ivi_vehicle_client)
  endif()
endif()

# --- tests --------------------------------------------------------------------
if(CCG_BUILD_TESTS)
  enable_testing()
  add_executable(ccg_s2s_tests
    tests/test_main.cpp
    tests/test_signal_codec.cpp
    tests/test_e2e.cpp
    tests/test_someip.cpp
    tests/test_config_validator.cpp
    tests/test_s2s_gateway.cpp
    tests/test_ivi_client.cpp
    tests/test_ivi_vhal_bridge.cpp
  )
  target_link_libraries(ccg_s2s_tests PRIVATE ccg_vehicle_matrix ccg_ivi)
  if(TARGET ccg_platform_linux)
    target_sources(ccg_s2s_tests PRIVATE tests/test_someip_udp_binding.cpp
                                         tests/test_network_setup.cpp)
    target_link_libraries(ccg_s2s_tests PRIVATE ccg_platform_linux)
  endif()
  ccg_warnings(ccg_s2s_tests)
  add_test(NAME ccg_s2s_tests COMMAND ccg_s2s_tests)
endif()
