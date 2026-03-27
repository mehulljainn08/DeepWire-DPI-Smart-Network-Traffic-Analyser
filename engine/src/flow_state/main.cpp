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
using namespace std;
int main() {
  cout << "=== DeepWire DPI — Flow State Service ===" << endl;

  // TODO: Your implementation goes here

  return 0;
}
