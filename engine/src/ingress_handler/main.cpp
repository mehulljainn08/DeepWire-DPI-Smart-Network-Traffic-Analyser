// ============================================================================
// DeepWire DPI — Ingress Handler Service
// ============================================================================
// Capture raw network packets using libpcap, compile and attach a Berkeley
// Packet Filter (BPF) to intercept only target traffic at the kernel level,
// and parse L2-L4 headers.
// Refer to flow_data.h for the ParsedPacket struct you need to populate.
//
// Build: cd engine && mkdir build && cd build && cmake .. && make
// Run:   sudo ./ingress_service
// ============================================================================

#include <iostream>
#include <cstring>
#include <pcap/pcap.h>
#include "../common/flow_data.h"

// ============================================================================
// BPF Filter Configuration
// ============================================================================
// A Berkeley Packet Filter (BPF) is compiled and loaded into the OS kernel
// so that ONLY matching packets are copied to userspace.  This is critical
// for performance: without it, every single frame on the wire would be
// handed to our process, incurring unnecessary context-switch and copy costs.
//
// The filter string below captures only TCP traffic destined for port 443
// (HTTPS/TLS), which is the traffic we need for SNI extraction.
// Adjust this string to widen or narrow the capture scope.
// ============================================================================
static const char* BPF_FILTER_EXPRESSION = "tcp port 443";

// ----------------------------------------------------------------------------
// compile_and_attach_bpf — Compiles a BPF expression and attaches it to a
//                          live pcap handle so the kernel drops non-matching
//                          packets before they ever reach userspace.
//
// @param handle   Active pcap handle obtained from pcap_open_live().
// @param filter   BPF filter expression string (tcpdump syntax).
// @param net      Network address of the capture interface (from pcap_lookupnet).
// @return         0 on success, -1 on error (messages printed to stderr).
// ----------------------------------------------------------------------------
int compile_and_attach_bpf(pcap_t* handle, const char* filter, bpf_u_int32 net)
{
    struct bpf_program compiled_filter;

    // pcap_compile() translates the human-readable filter string into
    // BPF bytecode that the kernel can execute on every incoming frame.
    if (pcap_compile(handle, &compiled_filter, filter, 1 /* optimize */, net) == -1) {
        std::cerr << "[Ingress] BPF compile error: " << pcap_geterr(handle) << std::endl;
        return -1;
    }

    // pcap_setfilter() loads the compiled BPF program into the kernel.
    // From this point on, only packets matching our filter are delivered.
    if (pcap_setfilter(handle, &compiled_filter) == -1) {
        std::cerr << "[Ingress] BPF attach error: " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&compiled_filter);
        return -1;
    }

    pcap_freecode(&compiled_filter);
    std::cout << "[Ingress] BPF filter attached: \"" << filter << "\"" << std::endl;
    return 0;
}

int main()
{
    std::cout << "=== DeepWire DPI — Ingress Handler ===" << std::endl;

    // TODO: Your implementation goes here
    //
    // Recommended flow:
    //   1. pcap_lookupdev()  — find the default network interface
    //   2. pcap_lookupnet()  — get the network address & mask (needed for BPF)
    //   3. pcap_open_live()  — open the interface in promiscuous mode
    //   4. compile_and_attach_bpf(handle, BPF_FILTER_EXPRESSION, net)
    //   5. pcap_loop()       — start the capture loop with a packet callback
    //   6. In the callback, strip Ethernet → IPv4 → TCP headers and populate
    //      a deepwire::ParsedPacket struct for downstream consumers.

    return 0;
}
