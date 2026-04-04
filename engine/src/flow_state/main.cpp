// ============================================================================
// DeepWire DPI — Flow State Service
// ============================================================================
// Track TCP connections using 5-tuple hash maps and reassemble streams.
// Refer to flow_data.h for FlowKey, FlowKeyHash, and ParsedPacket structs.
//
// Build: cd engine && mkdir build && cd build && cmake .. && make
// Run:   ./state_service
// ============================================================================

#include "../common/flow_data.h"
#include <iostream>
#include <unordered_map>
#include "flow_state_logic.h"
using namespace std;
int main() {

  // TODO: Your implementation goes here

deepwire::ParsedPacket pkt;

deepwire::FlowStatus status=deepwire::derive_status(pkt);
deepwire::FlowKey key=deepwire::make_flow_key(pkt);

  return 0;
}
