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

  // if(current[0] == 0x01){
  //   return std::make_optional<std::string>("CLIENT_HELLO_FOUND");
  // }

  if(current[0] != 0x01){
    return std::nullopt;
  }

  // Create endpoint for safety.
  const uint8_t* const end = data + len;

  // Handshake header must be present.
  if (current + 4 > end) {
    return std::nullopt;
  }

  if (current[0] != 0x01) {
    return std::nullopt;
  }

  uint32_t handshake_len = (static_cast<uint32_t>(current[1]) << 16) |
                           (static_cast<uint32_t>(current[2]) << 8) |
                           static_cast<uint32_t>(current[3]);
  current += 4;

  const uint8_t* const record_end = data + 5 + record_len;
  const uint8_t* const handshake_end = current + handshake_len;
  if (handshake_end > record_end || handshake_end > end) {
    return std::nullopt;
  }

  // Skip fixed ClientHello fields: version(2) + random(32).
  if (current + 34 > handshake_end) {
    return std::nullopt;
  }
  current += 34;

  // Session ID.
  if (current + 1 > handshake_end) {
    return std::nullopt;
  }
  uint8_t session_len = current[0];
  current += 1;
  if (current + session_len > handshake_end) {
    return std::nullopt;
  }
  current += session_len;

  // Cipher suites.
  if (current + 2 > handshake_end) {
    return std::nullopt;
  }
  uint16_t cipher_len = (static_cast<uint16_t>(current[0]) << 8) |
                        static_cast<uint16_t>(current[1]);
  current += 2;
  if (current + cipher_len > handshake_end) {
    return std::nullopt;
  }
  current += cipher_len;

  // Compression methods.
  if (current + 1 > handshake_end) {
    return std::nullopt;
  }
  uint8_t comp_len = current[0];
  current += 1;
  if (current + comp_len > handshake_end) {
    return std::nullopt;
  }
  current += comp_len;

  // Extensions may be absent.
  if (current == handshake_end) {
    return std::nullopt;
  }

  if (current + 2 > handshake_end) {
    return std::nullopt;
  }
  uint16_t extensions_len = (static_cast<uint16_t>(current[0]) << 8) |
                            static_cast<uint16_t>(current[1]);
  current += 2;
  const uint8_t* const extensions_end = current + extensions_len;
  if (extensions_end > handshake_end) {
    return std::nullopt;
  }

  while (current + 4 <= extensions_end) {
    uint16_t ext_type = (static_cast<uint16_t>(current[0]) << 8) |
                        static_cast<uint16_t>(current[1]);
    uint16_t ext_len = (static_cast<uint16_t>(current[2]) << 8) |
                       static_cast<uint16_t>(current[3]);
    current += 4;

    if (current + ext_len > extensions_end) {
      return std::nullopt;
    }

    if (ext_type == 0x0000) {
      if (current + 2 > extensions_end) {
        return std::nullopt;
      }
      uint16_t name_list_len = (static_cast<uint16_t>(current[0]) << 8) |
                               static_cast<uint16_t>(current[1]);
      current += 2;
      const uint8_t* const name_list_end = current + name_list_len;
      if (name_list_end > extensions_end) {
        return std::nullopt;
      }

      while (current + 3 <= name_list_end) {
        uint8_t name_type = current[0];
        uint16_t name_len = (static_cast<uint16_t>(current[1]) << 8) |
                            static_cast<uint16_t>(current[2]);
        current += 3;

        if (current + name_len > name_list_end) {
          return std::nullopt;
        }

        if (name_type == 0x00) {
          return std::make_optional<std::string>(
              reinterpret_cast<const char*>(current), name_len);
        }

        current += name_len;
      }

      return std::nullopt;
    }

    current += ext_len;
  }

  return std::nullopt;
}

}  // namespace deepwire::protocol_inspec
