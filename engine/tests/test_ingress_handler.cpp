#include "../src/common/flow_data.h"
#include "../src/ingress_handler/parser_utils.h"

#include <cassert>
#include <cstdint>

int main() {
  std::uint8_t payload[] = {0x16, 0x03, 0x01};
  deepwire::ParsedPacket https_packet{
      "10.0.0.1", "142.250.190.46", 53000, 443, "TCP", false, true,
      false,      false,            1000,  2000, payload,
      sizeof(payload), 1710000000};

  assert(deepwire::ingress::is_target_tls_packet(https_packet));
  assert(deepwire::ingress::has_payload(https_packet));
  assert(deepwire::ingress::payload_length_hint(https_packet) == 3);

  deepwire::ParsedPacket dns_packet = https_packet;
  dns_packet.dest_port = 53;
  dns_packet.payload = nullptr;
  dns_packet.payload_len = 0;

  assert(!deepwire::ingress::is_target_tls_packet(dns_packet));
  assert(!deepwire::ingress::has_payload(dns_packet));

  return 0;
}
