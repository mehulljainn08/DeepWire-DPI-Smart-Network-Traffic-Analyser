// ============================================================================
// DeepWire DPI — Flow State Service
// ============================================================================
// Track TCP connections using 5-tuple hash maps and reassemble streams.
// Refer to flow_data.h for FlowKey, FlowKeyHash, and ParsedPacket structs.
//
// Build: cd engine && mkdir build && cd build && cmake .. && make
// Run:   ./state_service
// ============================================================================

#include <iostream>
#include <unordered_map>
#include "../common/flow_data.h"

int main()
{
    std::cout << "=== DeepWire DPI — Flow State Service ===" << std::endl;

    // TODO: Your implementation goes here

    return 0;
}
