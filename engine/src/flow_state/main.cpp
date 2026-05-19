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

using namespace deepwire::flow_state;
std::unordered_map<deepwire::FlowKey, deepwire::FlowRecord, deepwire::FlowKeyHash> session_table;


#ifndef UNIT_TEST
int main() {

  // TODO: Your implementation goes here



  return 0;
}
#endif