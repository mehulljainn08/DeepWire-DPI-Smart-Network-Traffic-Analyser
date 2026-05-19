#pragma once
#include <unordered_map>
#include <iostream>
#include <ctime>
#include "../common/flow_data.h"
#include <iostream>
#include <unordered_map>

// ============================================================================
// Session table — declared here, defined in exactly ONE .cpp file
// (flow_state/main.cpp) to avoid ODR / multiple-definition linker errors.
// ============================================================================
extern std::unordered_map<deepwire::FlowKey, deepwire::FlowRecord,
                          deepwire::FlowKeyHash>
    session_table;

namespace deepwire::flow_state {

  extern std::unordered_map<
    deepwire::FlowKey,
    deepwire::FlowRecord,
    deepwire::FlowKeyHash
> session_table;


inline deepwire::FlowKey make_flow_key(const deepwire::ParsedPacket& packet) {
  // TODO: Extract the 5-tuple from the `packet` and return it as a FlowKey struct.
  // The 5-tuple consists of: src_ip, dest_ip, src_port, dest_port, and protocol.
  deepwire::FlowKey key;
  key.protocol = packet.protocol;

  // Canonicalize: smaller IP (or smaller port on tie) always goes in src
  bool swap = (packet.src_ip > packet.dest_ip) ||
              (packet.src_ip == packet.dest_ip &&
               packet.src_port > packet.dest_port);

  if (swap) {
    key.src_ip    = packet.dest_ip;
    key.dest_ip   = packet.src_ip;
    key.src_port  = packet.dest_port;
    key.dest_port = packet.src_port;
  } else {
    key.src_ip    = packet.src_ip;
    key.dest_ip   = packet.dest_ip;
    key.src_port  = packet.src_port;
    key.dest_port = packet.dest_port;
  }
  return key;
}

// --------------------------------------------------------------------------
// derive_status — Classify the packet's role in the TCP lifecycle.
// --------------------------------------------------------------------------
inline deepwire::FlowStatus
derive_status(const deepwire::ParsedPacket &packet) {
  // FIN or RST → connection is tearing down
  if (packet.flag_fin || packet.flag_rst)
    return deepwire::FlowStatus::CLOSED;

  // SYN without ACK → brand-new connection request
  if (packet.flag_syn && !packet.flag_ack)
    return deepwire::FlowStatus::NEW_FLOW;

  // Everything else → ongoing data transfer
  return deepwire::FlowStatus::EXISTING_FLOW;
}

// --------------------------------------------------------------------------
// process_packet_state — Update the session table based on the packet.
// --------------------------------------------------------------------------
inline void process_packet_state(const deepwire::ParsedPacket &pkt) {
  deepwire::FlowKey key = make_flow_key(pkt);
  deepwire::FlowStatus status = derive_status(pkt);

  if (status == deepwire::FlowStatus::NEW_FLOW) {
    deepwire::FlowRecord record{};
    record.src_ip    = pkt.src_ip;
    record.dest_ip   = pkt.dest_ip;
    record.src_port  = pkt.src_port;
    record.dest_port = pkt.dest_port;
    record.protocol  = pkt.protocol;
    record.sni_domain = "";
    record.status    = status;

    session_table.insert({key, record});
    std::cout << "[FlowState] NEW_FLOW inserted: "
              << pkt.src_ip << ":" << pkt.src_port << " -> "
              << pkt.dest_ip << ":" << pkt.dest_port << "\n";
  }

  else if (status == deepwire::FlowStatus::EXISTING_FLOW) {
    auto it = session_table.find(key);
    if (it != session_table.end()) {
      it->second.status = status;
    } else {
      // SYN-ACK or mid-stream join — create the record anyway
      deepwire::FlowRecord record{};
      record.src_ip    = pkt.src_ip;
      record.dest_ip   = pkt.dest_ip;
      record.src_port  = pkt.src_port;
      record.dest_port = pkt.dest_port;
      record.protocol  = pkt.protocol;
      record.sni_domain = "";
      record.status    = status;
      session_table.insert({key, record});
      std::cout << "[FlowState] Mid-stream flow inserted: "
                << pkt.src_ip << ":" << pkt.src_port << " -> "
                << pkt.dest_ip << ":" << pkt.dest_port << "\n";
    }
  }

  else if (status == deepwire::FlowStatus::CLOSED) {
    auto erased = session_table.erase(key);
    if (erased) {
      std::cout << "[FlowState] CLOSED flow erased: "
                << pkt.src_ip << ":" << pkt.src_port << " -> "
                << pkt.dest_ip << ":" << pkt.dest_port << "\n";
    }
  }
}

inline void process_packet_state(const deepwire::ParsedPacket& pkt){
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
        record.last_seen = pkt.timestamp;

    session_table.insert({key,record});
    std::cout << "NEW_FLOW inserted\n";
  }

  else if(status==deepwire::FlowStatus::EXISTING_FLOW){
    //if the pkt has existing flow then we have to update the status of that key 
    //in session_table through .find(key) and then update the status

    auto it=session_table.find(key);

    if(it!=session_table.end()){
      it->second.status = status;
      it->second.last_seen = pkt.timestamp; // update last seen time
      std::cout << "EXISTING_FLOW found and updated\n";
    }
    else
    std::cout << "EXISTING_FLOW not found\n";
  }

  else if (status == deepwire::FlowStatus::CLOSED)
  //if the pkt has closed flow then we have to erase that key from session_table 
  //through .erase(key)
    {
        session_table.erase(key);
        std::cout << "CLOSED flow erase key\n";
    }

}

inline void sweep_stale_connections(){
  std::time_t now=std::time(nullptr); // get current time
  auto it=session_table.begin();
  while(it!=session_table.end()){ // iterate through session_table
    if(now-it->second.last_seen>30)
    {  
      std::cout<< "Flow Timeout: Evicted silent connection.\n";
      it=session_table.erase(it); // erase the key and move to next key without losing the iterator
    }
    else 
    it++;
  }
}

}  // namespace deepwire::flow_state
