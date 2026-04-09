#include "../src/protocol_inspec/tls_sni_parser.h"
#include <cassert>
#include <vector>
#include <string>

int main() {

  // Test 1: invalid record type (not 0x16)
  const std::vector<unsigned char> invalid_record = {
      0x15, 0x03, 0x03, 0x00, 0x00};
  auto missing = deepwire::protocol_inspec::extract_sni(
      invalid_record.data(), invalid_record.size());
  assert(!missing.has_value());

  // Test 2: dangerously short array
  const std::vector<unsigned char> short_record = {
      0x16, 0x00, 0x00};
  auto missing_short = deepwire::protocol_inspec::extract_sni(
      short_record.data(), short_record.size());
  assert(!missing_short.has_value());

  // Test 3: null pointer
  auto missing_null =
      deepwire::protocol_inspec::extract_sni(nullptr, 10);
  assert(!missing_null.has_value());

  // Test 4: VALID TLS CLIENT HELLO
  const std::vector<unsigned char> client_hello = {
      0x16,       // TLS Handshake
      0x03, 0x01, // Version
      0x00, 0x01, // Length = 1 byte
      0x01        // Handshake Type = Client Hello
  };

  auto result = deepwire::protocol_inspec::extract_sni(
      client_hello.data(), client_hello.size());

  assert(result.has_value());
  assert(result.value() == "CLIENT_HELLO_FOUND");

  return 0;
}