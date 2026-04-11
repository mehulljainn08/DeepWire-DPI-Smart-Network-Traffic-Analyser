#pragma once

#include "../common/flow_data.h"

namespace deepwire::flow_state {

inline deepwire::FlowKey make_flow_key(const deepwire::ParsedPacket& packet) {
  // TODO: Extract the 5-tuple from the `packet` and return it as a FlowKey struct.
  // The 5-tuple consists of: src_ip, dest_ip, src_port, dest_port, and protocol.
  return {}; // Placeholder return
}

inline deepwire::FlowStatus derive_status(const deepwire::ParsedPacket& packet) {
  // TODO: Determine the lifecycle status of this TCP packet based on its flags.
  // 1. If it's a finish/reset packet (FIN or RST), the connection is closing. Return CLOSED.
  // 2. If it's a synchronization packet (SYN) without an ACK, it's a brand new connection request. Return NEW_FLOW.
  // 3. Otherwise, it belongs to an ongoing data transfer. Return EXISTING_FLOW.
  
  return deepwire::FlowStatus::NEW_FLOW; // Placeholder return
}

}  // namespace deepwire::flow_state
