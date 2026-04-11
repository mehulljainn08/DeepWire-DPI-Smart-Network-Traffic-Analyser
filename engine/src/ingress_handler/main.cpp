
// DeepWire DPI — Ingress Handler Service
// Capture raw network packets using libpcap, compile and attach a Berkeley
// Packet Filter (BPF) to intercept only target traffic at the kernel level,
// and parse L2-L4 headers.
// Refer to flow_data.h for the ParsedPacket struct you need to populate.
//
// Build: cd engine && mkdir build && cd build && cmake .. && make
// Run:   sudo ./ingress_service
// ============================================================================

#include "../common/flow_data.h"
#include <cstring>
#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
using namespace std;

void packet_handler(u_char *args,
                    const struct pcap_pkthdr *header,
                    const u_char *packet) {

    // Ethernet Header 
    struct ether_header *eth = (struct ether_header *)packet;

    // Only IPv4
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // IP Header 
    struct ip *ip_hdr =
        (struct ip *)((u_char *)eth + sizeof(struct ether_header));

    // Only TCP
    if (ip_hdr->ip_p != IPPROTO_TCP) {
        return;
    }

    int ip_header_len = ip_hdr->ip_hl * 4;

    // TCP Header 
    struct tcphdr *tcp_hdr =
        (struct tcphdr *)((u_char *)ip_hdr + ip_header_len);

    //  Extract fields 
    string src_ip = inet_ntoa(ip_hdr->ip_src);
    string dst_ip = inet_ntoa(ip_hdr->ip_dst);

    uint16_t src_port = ntohs(tcp_hdr->th_sport);
    uint16_t dst_port = ntohs(tcp_hdr->th_dport);

    // Output 
    cout << "Target TCP packet captured! "
         << "Source IP: " << src_ip
         << ", Dest Port: " << dst_port
         << endl;
}
// BPF Filter Configuration

// A Berkeley Packet Filter (BPF) is compiled and loaded into the OS kernel
// so that ONLY matching packets are copied to userspace.  This is critical
// for performance: without it, every single frame on the wire would be
// handed to our process, incurring unnecessary context-switch and copy costs.
//
// The filter string below captures only TCP traffic destined for port 443
// (HTTPS/TLS), which is the traffic we need for SNI extraction.
// Adjust this string to widen or narrow the capture scope.
// ============================================================================
static const char *BPF_FILTER_EXPRESSION = "tcp port 443";

// ----------------------------------------------------------------------------
// compile_and_attach_bpf — Compiles a BPF expression and attaches it to a
//                          live pcap handle so the kernel drops non-matching
//                          packets before they ever reach userspace.
//
// @return         0 on success, -1 on error (messages printed to stderr).
// ----------------------------------------------------------------------------
int compile_and_attach_bpf(pcap_t *handle, const char *filter,
                           bpf_u_int32 net) {
  // TODO: Implement Berkeley Packet Filter (BPF) logic here.
  // 1. Declare a `struct bpf_program`.
  // 2. Use `pcap_compile()` to compile the string `filter` into bytecode.
  // 3. Check for compilation errors and print `pcap_geterr(handle)` if it fails.
  // 4. Use `pcap_setfilter()` to load the compiled bytecode into the kernel.
  // 5. Use `pcap_freecode()` to free the bytecode from memory when done.
  // 6. Return 0 on success, or -1 on failure.
  if (!handle || !filter) {
        cout << "Invalid" << endl;
        return -1;
    }

    struct bpf_program bpf_prog;

    // Compiling the BPF filter string into bytecode
    if (pcap_compile(handle, &bpf_prog, filter, 1, net) < 0) {
        cout << "BPF failed: " << pcap_geterr(handle) << endl;
        return -1;
    }

    // Attaching the compiled filter to the pcap handle
    if (pcap_setfilter(handle, &bpf_prog) < 0) {
        cout << "Setting BPF filter failed: " << pcap_geterr(handle) << endl;
        pcap_freecode(&bpf_prog);
        return -1;
    }

    // Setting the memory free
    pcap_freecode(&bpf_prog);

  return 0; // Placeholder return value
}

int main() {
  cout << "=== DeepWire DPI — Ingress Handler ===" << endl;

  // TODO: Your implementation goes here
  //
  // Recommended flow:
  //   1. pcap_lookupdev()  — find the default network interface
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        cout << errbuf << endl;
        return 1;
    } else {
        cout << "Using device: " << dev << endl;
    }
  //   2. pcap_lookupnet()  — get the network address & mask (needed for BPF)
    bpf_u_int32 net;
    bpf_u_int32 mask;

    if (pcap_lookupnet(dev, &net, &mask, errbuf) < 0) {
        cout << errbuf << endl;
        net = 0;
        mask = PCAP_NETMASK_UNKNOWN;
    }
  //   3. pcap_open_live()  — open the interface in promiscuous mode
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
      cerr << "Open failed: " << errbuf << endl;
      return 1;
  }
  //   4. compile_and_attach_bpf(handle, BPF_FILTER_EXPRESSION, net)
  if (compile_and_attach_bpf(handle, BPF_FILTER_EXPRESSION, mask) < 0) {
    cout<< "BPF attach failed" << endl;
    return 1;
  }
  cout<<"Success"<<endl;
  //   5. pcap_loop()       — start the capture loop with a packet callback
  pcap_loop(handle, 0, packet_handler, NULL); // 0 -> capture all packets

  //   6. In the callback, strip Ethernet → IPv4 → TCP headers and populate
  //      a deepwire::ParsedPacket struct for downstream consumers.

  return 0;
}
