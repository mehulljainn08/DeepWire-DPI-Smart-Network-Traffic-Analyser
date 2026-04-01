#include "../src/protocol_inspec/tls_sni_parser.h"
#include <cassert>
#include <vector>

int main() {
  // test 1 invalid record type (not 0x16)
  const std::vector<unsigned char> invalid_record = {0x15, 0x03, 0x03, 0x00,
                                                     0x00};
  auto missing = deepwire::protocol_inspec::extract_sni(invalid_record.data(),
                                                        invalid_record.size());
  assert(!missing.has_value());

  // test 2 dangerously short array (3 bytes) with correct handshake type
  const std::vector<unsigned char> short_record = {0x16, 0x00, 0x00};
  auto missing_short = deepwire::protocol_inspec::extract_sni(
      short_record.data(), short_record.size());
  assert(!missing_short.has_value());

  // test 3 null pointer
  auto missing_null = deepwire::protocol_inspec::extract_sni(nullptr, 10);
  assert(!missing_null.has_value());

  return 0;
}
