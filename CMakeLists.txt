cmake_minimum_required(VERSION 3.16)
project(central_control_gateway VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(CCG_BUILD_TESTS "Build unit tests" ON)
option(CCG_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

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
  src/can/signal_layout.cpp
  src/e2e/can_e2e.cpp
  src/someip/someip_message.cpp
  src/s2s/data_type.cpp
  src/s2s/s2s_config_validator.cpp
  src/s2s/s2s_gateway.cpp
)
target_include_directories(ccg_s2s PUBLIC include)
ccg_warnings(ccg_s2s)

# --- Ethernet gateway: message/signal routing, frame (de)composition ---------
add_library(ccg_ethgw
  src/ethgw/pdu_header_codec.cpp
  src/ethgw/routing_config_validator.cpp
  src/ethgw/ethernet_gateway.cpp
)
target_include_directories(ccg_ethgw PUBLIC include)
target_link_libraries(ccg_ethgw PUBLIC ccg_s2s ccg_secoc)
ccg_warnings(ccg_ethgw)

# --- diagnostic routing: DoIP <-> UDS on CAN (ISO-TP) -------------------------
add_library(ccg_diag
  src/isotp/isotp_channel.cpp
  src/doip/doip_message.cpp
  src/diag/diag_config_validator.cpp
  src/diag/diag_gateway.cpp
  src/diag/doip_client.cpp
)
target_include_directories(ccg_diag PUBLIC include)
target_link_libraries(ccg_diag PUBLIC ccg_s2s)
ccg_warnings(ccg_diag)

# --- SecOC: AES-128-CMAC authentication, freshness management ---------------
add_library(ccg_secoc
  src/crypto/aes_cmac.cpp
  src/secoc/secoc.cpp
  src/secoc/fv_sync.cpp
)
target_include_directories(ccg_secoc PUBLIC include)
ccg_warnings(ccg_secoc)

# --- SecOC key management: SHE key update protocol, key slots, rollover -------
add_library(ccg_keym
  src/keym/she.cpp
  src/keym/key_manager.cpp
  src/keym/key_management_service.cpp
  src/keym/key_master.cpp
)
target_include_directories(ccg_keym PUBLIC include)
target_link_libraries(ccg_keym PUBLIC ccg_secoc ccg_diag)
ccg_warnings(ccg_keym)

# --- reference vehicle matrices ----------------------------------------------
add_library(ccg_vehicle_matrix
  config/vehicle_s2s_matrix.cpp
  config/vehicle_eth_gateway_matrix.cpp
  config/vehicle_diag_routing.cpp
  config/vehicle_key_slots.cpp
  config/vehicle_key_master.cpp
)
target_include_directories(ccg_vehicle_matrix PUBLIC config)
target_link_libraries(ccg_vehicle_matrix PUBLIC ccg_s2s ccg_ethgw ccg_diag ccg_keym)
ccg_warnings(ccg_vehicle_matrix)

# --- simulated ECUs for tests and bench simulations --------------------------
add_library(ccg_sim sim/uds_ecu.cpp sim/ecu_key_store.cpp sim/doip_link.cpp)
target_include_directories(ccg_sim PUBLIC sim)
target_link_libraries(ccg_sim PUBLIC ccg_diag ccg_keym)
ccg_warnings(ccg_sim)

# --- bench simulation (virtual time, no hardware) ----------------------------
add_executable(ccg_s2s_sim app/s2s_sim_main.cpp)
target_link_libraries(ccg_s2s_sim PRIVATE ccg_vehicle_matrix)
ccg_warnings(ccg_s2s_sim)

add_executable(ccg_eth_gw_sim app/eth_gw_sim_main.cpp)
target_link_libraries(ccg_eth_gw_sim PRIVATE ccg_vehicle_matrix)
ccg_warnings(ccg_eth_gw_sim)

add_executable(ccg_diag_sim app/diag_sim_main.cpp)
target_link_libraries(ccg_diag_sim PRIVATE ccg_vehicle_matrix ccg_sim)
ccg_warnings(ccg_diag_sim)

add_executable(ccg_keym_sim app/keym_sim_main.cpp)
target_link_libraries(ccg_keym_sim PRIVATE ccg_vehicle_matrix)
ccg_warnings(ccg_keym_sim)

add_executable(ccg_key_master_sim app/key_master_sim_main.cpp)
target_link_libraries(ccg_key_master_sim PRIVATE ccg_vehicle_matrix ccg_sim)
ccg_warnings(ccg_key_master_sim)

# --- backend key server tool (builds SHE M1..M3, checks M4/M5) ---------------
add_executable(ccg_key_tool app/key_tool_main.cpp)
target_link_libraries(ccg_key_tool PRIVATE ccg_keym)
ccg_warnings(ccg_key_tool)

# OpenSSL 3 (optional): DoIP over TLS in the Linux diagnostic gateway, and a
# test-only cross-check of the software AES-CMAC.
find_package(OpenSSL 3 QUIET)

# --- Linux gateway process (SocketCAN + SOME/IP over UDP) --------------------
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_library(ccg_platform_linux
    platform/linux/socketcan_transport.cpp
    platform/linux/someip_udp_binding.cpp
    platform/linux/udp_socket.cpp
    platform/linux/doip_sockets.cpp
    platform/linux/secoc_storage.cpp
    platform/linux/key_store.cpp
    platform/linux/system_random.cpp
    platform/linux/doip_tcp_connector.cpp
    platform/linux/crl_fetcher.cpp
  )
  target_include_directories(ccg_platform_linux PUBLIC platform/linux)
  find_package(Threads REQUIRED)  # CRL downloads run on a worker thread
  target_link_libraries(ccg_platform_linux PUBLIC ccg_s2s ccg_diag ccg_secoc ccg_keym Threads::Threads)
  if(OpenSSL_FOUND)
    target_sources(ccg_platform_linux PRIVATE platform/linux/doip_tls_server.cpp platform/linux/tls_revocation.cpp
                                               platform/linux/tls_ocsp.cpp)
    target_link_libraries(ccg_platform_linux PUBLIC OpenSSL::SSL)
    target_compile_definitions(ccg_platform_linux PUBLIC CCG_HAVE_TLS=1)
  endif()
  ccg_warnings(ccg_platform_linux)

  add_executable(ccg_s2s_gateway app/s2s_gateway_main.cpp)
  target_link_libraries(ccg_s2s_gateway PRIVATE ccg_platform_linux ccg_vehicle_matrix)
  ccg_warnings(ccg_s2s_gateway)

  add_executable(ccg_eth_gateway app/eth_gateway_main.cpp)
  target_link_libraries(ccg_eth_gateway PRIVATE ccg_platform_linux ccg_vehicle_matrix)
  ccg_warnings(ccg_eth_gateway)

  add_executable(ccg_diag_gateway app/diag_gateway_main.cpp)
  target_link_libraries(ccg_diag_gateway PRIVATE ccg_platform_linux ccg_vehicle_matrix)
  ccg_warnings(ccg_diag_gateway)
endif()

# --- tests --------------------------------------------------------------------
if(CCG_BUILD_TESTS)
  enable_testing()
  add_executable(ccg_tests
    tests/test_main.cpp
    tests/test_signal_codec.cpp
    tests/test_e2e.cpp
    tests/test_someip.cpp
    tests/test_config_validator.cpp
    tests/test_s2s_gateway.cpp
    tests/test_pdu_header_codec.cpp
    tests/test_eth_gateway.cpp
    tests/test_isotp.cpp
    tests/test_doip_message.cpp
    tests/test_diag_gateway.cpp
    tests/test_aes_cmac.cpp
    tests/test_secoc.cpp
    tests/test_fv_sync.cpp
    tests/test_she.cpp
    tests/test_key_manager.cpp
    tests/test_key_master.cpp
    tests/test_doip_client.cpp
    tests/test_doip_routing.cpp
    tests/test_doip_tls.cpp
  )
  target_link_libraries(ccg_tests PRIVATE ccg_vehicle_matrix ccg_sim ccg_secoc)
  if(TARGET ccg_platform_linux)
    target_sources(ccg_tests PRIVATE tests/test_someip_udp_binding.cpp tests/test_udp_socket.cpp
                                     tests/test_doip_sockets.cpp tests/test_secoc_storage.cpp
                                     tests/test_key_store.cpp tests/test_crl_fetcher_linux.cpp)
    target_link_libraries(ccg_tests PRIVATE ccg_platform_linux)
  endif()
  if(OpenSSL_FOUND)  # test-only cross-check of the software AES-CMAC
    target_sources(ccg_tests PRIVATE tests/test_cmac_openssl.cpp)
    target_link_libraries(ccg_tests PRIVATE OpenSSL::Crypto)
    if(TARGET ccg_platform_linux)
      target_sources(ccg_tests PRIVATE tests/test_doip_tls_linux.cpp)
    endif()
  endif()
  ccg_warnings(ccg_tests)
  add_test(NAME ccg_tests COMMAND ccg_tests)
endif()
