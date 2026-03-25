cmake_minimum_required(VERSION 3.10)
project(DeepWireEngine)

set(CMAKE_CXX_STANDARD 17)
find_package(PCAP REQUIRED)

include_directories(include/common ${PCAP_INCLUDE_DIRS})

# Ingress Handler: Responsible for the raw capture and IP/TCP header stripping
add_executable(ingress_service src/ingress_handler/main.cpp)
target_link_libraries(ingress_service ${PCAP_LIBRARIES})

# Flow State: Responsible for the 5-tuple tracking and session management
add_executable(state_service src/flow_state/main.cpp)
target_link_libraries(state_service ${PCAP_LIBRARIES})

# Protocol Inspec: Responsible for the Layer 7 TLS SNI extraction
add_executable(inspec_service src/protocol_inspec/main.cpp)
target_link_libraries(inspec_service ${PCAP_LIBRARIES})