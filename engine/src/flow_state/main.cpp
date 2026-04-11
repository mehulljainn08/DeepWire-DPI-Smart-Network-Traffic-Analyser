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

void process_packet_state(const deepwire::ParsedPacket& pkt){
  deepwire::FlowKey key=make_flow_key(pkt);
  deepwire::FlowStatus status=derive_status(pkt);  

  if(status==deepwire::FlowStatus::NEW_FLOW){// if the pkt has new flow then we have to create
    //a key,value in session_table through .insert({key,value})

    deepwire::FlowRecord record{};
    //transfer the 5-tuple from pkt to record and set sni_domain to "" 
    //and status to flowstatus::status

     record.src_ip = pkt.src_ip;
        record.dest_ip = pkt.dest_ip;
        record.src_port = pkt.src_port;
        record.dest_port = pkt.dest_port;
        record.protocol = pkt.protocol;
        record.sni_domain = "";
        record.status = status;

    session_table.insert({key,record});
    cout << "NEW_FLOW inserted\n";
  }

  else if(status==deepwire::FlowStatus::EXISTING_FLOW){
    //if the pkt has existing flow then we have to update the status of that key 
    //in session_table through .find(key) and then update the status

    auto it=session_table.find(key);

    if(it!=session_table.end()){
      it->second.status = status;
      cout << "EXISTING_FLOW found and updated\n";
    }
    else
    cout << "EXISTING_FLOW not found\n";
  }

  else if (status == deepwire::FlowStatus::CLOSED)
  //if the pkt has closed flow then we have to erase that key from session_table 
  //through .erase(key)
    {
        session_table.erase(key);
        cout << "CLOSED flow erase key\n";
    }

}
#ifndef UNIT_TEST
int main() {

  // TODO: Your implementation goes here



  return 0;
}
#endif