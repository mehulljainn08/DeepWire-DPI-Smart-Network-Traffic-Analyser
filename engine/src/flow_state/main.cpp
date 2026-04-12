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
#include "flow_state_logic.h"
#include <iostream>

using namespace std;

// ============================================================================
// Single definition of the session table.
// The header (flow_state_logic.h) declares it as `extern`; we define it here.
// ============================================================================
std::unordered_map<deepwire::FlowKey, deepwire::FlowRecord, deepwire::FlowKeyHash>
    session_table;

#ifndef UNIT_TEST
int main() {
  cout << "=== DeepWire DPI — Flow State Service ===" << endl;

  // TODO: Your implementation goes here
  // In the final architecture this service will receive ParsedPacket
  // structs over IPC (Unix Domain Socket / shared memory) from the
  // Ingress Handler, rather than processing them in-process.

  return 0;
}
#endif