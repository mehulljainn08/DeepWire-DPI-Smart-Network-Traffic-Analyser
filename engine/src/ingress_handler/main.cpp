// ============================================================================
// DeepWire DPI — Ingress Handler Service
// ============================================================================
// Capture raw network packets using libpcap and parse L2-L4 headers.
// Refer to flow_data.h for the ParsedPacket struct you need to populate.
//
// Build: cd engine && mkdir build && cd build && cmake .. && make
// Run:   sudo ./ingress_service
// ============================================================================

#include <iostream>
#include <pcap/pcap.h>
#include "../common/flow_data.h"

int main()
{
    std::cout << "=== DeepWire DPI — Ingress Handler ===" << std::endl;

    // TODO: Your implementation goes here

    return 0;
}
