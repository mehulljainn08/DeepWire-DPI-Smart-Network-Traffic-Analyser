cmake_minimum_required(VERSION 3.10)
project(DeepWireEngine)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
enable_testing()

# --- Find libpcap ---
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Install with: sudo apt-get install libpcap-dev")
endif()

message(STATUS "Found libpcap: ${PCAP_LIBRARY}")

# --- Include paths ---
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/common
    ${PCAP_INCLUDE_DIR}
)

# --- Ingress Handler Service ---
# Responsible for raw pcap capture and Ethernet/IP/TCP header stripping
add_executable(ingress_service
    src/ingress_handler/main.cpp
)
target_link_libraries(ingress_service ${PCAP_LIBRARY})

# --- Flow State Service ---
# Responsible for 5-tuple TCP session tracking and stream reassembly
add_executable(state_service
    src/flow_state/main.cpp
)
target_link_libraries(state_service ${PCAP_LIBRARY})

# --- Protocol Inspection Service ---
# Responsible for Layer 7 TLS/SNI Deep Packet Inspection
add_executable(inspec_service
    src/protocol_inspec/main.cpp
)
target_link_libraries(inspec_service ${PCAP_LIBRARY})

# --- IPC Bridge Service ---
# Responsible for thread-safe queue consumption and Unix Domain Socket IPC
add_executable(ipc_service
    src/ipc_bridge/main.cpp
)
target_link_libraries(ipc_service ${PCAP_LIBRARY} pthread)

# --- Unit Tests ---
add_executable(test_ingress_handler
    tests/test_ingress_handler.cpp
)
target_link_libraries(test_ingress_handler ${PCAP_LIBRARY})
add_test(NAME test_ingress_handler COMMAND test_ingress_handler)

add_executable(test_flow_state
    tests/test_flow_state.cpp
)
add_test(NAME test_flow_state COMMAND test_flow_state)

add_executable(test_protocol_inspec
    tests/test_protocol_inspec.cpp
)
add_test(NAME test_protocol_inspec COMMAND test_protocol_inspec)

add_executable(test_ipc_bridge
    tests/test_ipc_bridge.cpp
)
add_test(NAME test_ipc_bridge COMMAND test_ipc_bridge)
