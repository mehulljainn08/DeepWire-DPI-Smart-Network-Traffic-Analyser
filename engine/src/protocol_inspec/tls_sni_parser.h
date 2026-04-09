#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>



namespace deepwire::protocol_inspec {

inline std::optional<std::string> extract_sni(const uint8_t* data,
                                              std::size_t len) {
  // TODO: Implement Deep Packet Inspection (DPI) to extract the SNI Domain.
  // 
  // 1. Verify this is a valid TLS handshake by checking data[0] == 0x16 
  //    (Handshake) and ensuring length bounds.
  // 2. Safely traverse the variable-length TLS header structures to find
  //    the Extensions block.
  // 3. Loop through Extensions looking for type 0x0000 (Server Name).
  // 4. Safely extract the plaintext domain name string and return it.
  // 
  // WARNING: You are parsing RAW pointers. Use strict bounds checking!
  // If `offset + amount > len`, return std::nullopt immediately.

  // 1. Check if pointer is null 
  if (data == nullptr) {
    return std::nullopt;
  }

  // 2. Check minimum length (TLS Header needs at least 5 bytes) 
  if (len < 5) {
    return std::nullopt;
  }

  // 3. Check TLS handshake type (0x16)
  if (data[0] != 0x16) {
    return std::nullopt;
  }

  // Read TLS record length (data[3] high byte , data[4] low byte)
  uint16_t record_len = (data[3] << 8) | data[4];

  //Bounds check (to prevent segmentation fault - don't read beyond memory)
  if(5 + record_len > len) return std::nullopt;

  //Jump to handshake Layer (tls header = 5bytes )
  const uint8_t* current = data + 5;

  //Before accessing mem , checking pointer is still inside valid buffer or not
  if(current >= data + len) return std::nullopt;

  if(current[0] == 0x01){
    return std::make_optional<std::string>("CLIENT_HELLO_FOUND");
  }

  return std::nullopt; // Placeholder return value
}

}  // namespace deepwire::protocol_inspec
