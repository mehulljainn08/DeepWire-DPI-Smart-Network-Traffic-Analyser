#pragma once
#include "../common/flow_data.h"
namespace deepwire {

FlowKey make_flow_key(const ParsedPacket &pkt)
{
  FlowKey key;
key.src_ip = pkt.src_ip;
key.dest_ip = pkt.dest_ip;
key.src_port = pkt.src_port;
key.dest_port = pkt.dest_port;
key.protocol = pkt.protocol;
return key;
}

FlowStatus derive_status(const ParsedPacket &pkt)
{
  FlowStatus status;
  // SYN- start tcp connection
// ack- response to syn
// fin- end tcp connection
// rst- reset tcp connection
if(pkt.flag_syn && !pkt.flag_ack)
status=FlowStatus::NEW_FLOW; // syn=1 and ack=0

else if(pkt.flag_fin || pkt.flag_rst) //fin=1 and rst=1
status=FlowStatus::CLOSED;

else
status=FlowStatus::EXISTING_FLOW; // ack=1

return status;
}
}
