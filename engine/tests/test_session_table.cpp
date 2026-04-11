#include "../src/common/flow_data.h"
#include "../src/flow_state/flow_state_logic.h"

#define UNIT_TEST
#include "../src/flow_state/main.cpp"

#include <cassert>
#include <iostream>

using namespace deepwire::flow_state;

int main() {
    session_table.clear();

    // SYN packet -> NEW_FLOW
    deepwire::ParsedPacket syn_pkt{
        "192.168.1.10", "93.184.216.34",
        49152, 443, "TCP",
        true, false, false, false,
        1, 0, nullptr, 0, 1710000000
    };

    process_packet_state(syn_pkt);

    assert(session_table.size() == 1);

    auto key = make_flow_key(syn_pkt);
    auto it1 = session_table.find(key);
    assert(it1 != session_table.end());
    assert(it1->second.status == deepwire::FlowStatus::NEW_FLOW);

    // ACK packet -> EXISTING_FLOW
    deepwire::ParsedPacket ack_pkt = syn_pkt;
    ack_pkt.flag_syn = false;
    ack_pkt.flag_ack = true;
    ack_pkt.flag_fin = false;
    ack_pkt.flag_rst = false;

    process_packet_state(ack_pkt);

    assert(session_table.size() == 1);

    auto it2 = session_table.find(key);
    assert(it2 != session_table.end());
    assert(it2->second.status == deepwire::FlowStatus::EXISTING_FLOW);

    // FIN packet -> CLOSED
    deepwire::ParsedPacket fin_pkt = syn_pkt;
    fin_pkt.flag_syn = false;
    fin_pkt.flag_ack = false;
    fin_pkt.flag_fin = true;
    fin_pkt.flag_rst = false;

    process_packet_state(fin_pkt);

    assert(session_table.size() == 0);

    std::cout << "Session table test passed!\n";
    return 0;
}