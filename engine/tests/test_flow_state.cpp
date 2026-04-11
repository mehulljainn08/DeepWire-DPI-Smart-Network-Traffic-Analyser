#include "../src/common/flow_data.h"
#include "../src/flow_state/flow_state_logic.h"

#include <cassert>
#include <unordered_map>

int main() {
  deepwire::ParsedPacket syn_packet{
      "192.168.1.10", "93.184.216.34", 49152, 443, "TCP", true, false,
      false,          false,           1,     0,   nullptr, 0, 1710000000};

  auto key = deepwire::flow_state::make_flow_key(syn_packet);
  assert(key.src_ip == "192.168.1.10");
  assert(key.dest_port == 443);
  assert(deepwire::flow_state::derive_status(syn_packet) ==
         deepwire::FlowStatus::NEW_FLOW);

  std::unordered_map<deepwire::FlowKey, deepwire::FlowStatus,
                     deepwire::FlowKeyHash>
      flows;
  flows[key] = deepwire::flow_state::derive_status(syn_packet);
  assert(flows[key] == deepwire::FlowStatus::NEW_FLOW);

  deepwire::ParsedPacket ack_packet = syn_packet;
  ack_packet.flag_syn = false;
  ack_packet.flag_ack = true;
  assert(deepwire::flow_state::derive_status(ack_packet) ==
         deepwire::FlowStatus::EXISTING_FLOW);

  deepwire::ParsedPacket fin_packet = syn_packet;
  fin_packet.flag_syn = false;
  fin_packet.flag_fin = true;
  assert(deepwire::flow_state::derive_status(fin_packet) ==
         deepwire::FlowStatus::CLOSED);

  return 0;
}

