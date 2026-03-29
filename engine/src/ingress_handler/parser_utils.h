#pragma once

#include "../common/flow_data.h"

#include <cstdint>

namespace deepwire::ingress {

inline bool is_target_tls_packet(const deepwire::ParsedPacket& packet) {
  return packet.protocol == "TCP" && packet.dest_port == 443;
}

inline bool has_payload(const deepwire::ParsedPacket& packet) {
  return packet.payload != nullptr && packet.payload_len > 0;
}

inline uint16_t payload_length_hint(const deepwire::ParsedPacket& packet) {
  return static_cast<uint16_t>(packet.payload_len);
}

}  // namespace deepwire::ingress
