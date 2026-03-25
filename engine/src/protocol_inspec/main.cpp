// ============================================================================
// DeepWire DPI — Protocol Inspection Service (TLS/SNI Extractor)
// ============================================================================
// Inspect TCP payloads for TLS Client Hello and extract SNI domains.
// Refer to flow_data.h for the FlowEvent struct you need to populate.
//
// Build: cd engine && mkdir build && cd build && cmake .. && make
// Run:   ./inspec_service
// ============================================================================

#include <iostream>
#include <cstdint>
#include <string>
#include <optional>
#include "flow_data.h"

int main()
{
    std::cout << "=== DeepWire DPI — Protocol Inspector ===" << std::endl;

    // TODO: Your implementation goes here

    return 0;
}
