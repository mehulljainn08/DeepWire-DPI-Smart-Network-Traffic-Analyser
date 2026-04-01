#include "../src/protocol_inspec/tls_sni_parser.h"

#include <cassert>
#include <vector>

int main() {
  std::vector<unsigned char> client_hello = {
      0x16, 0x03, 0x01, 0x00, 0x3c, 0x01, 0x00, 0x00, 0x38, 0x03, 0x03};
  client_hello.insert(client_hello.end(), 32, 0x00);
  client_hello.insert(client_hello.end(),
                      {0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x0d,
                       0x00, 0x00, 0x00, 0x09, 0x00, 0x07, 0x00, 0x00, 0x04,
                       0x74, 0x65, 0x73, 0x74});

  //auto sni = deepwire::protocol_inspec::extract_sni(client_hello.data(),
                                                    // client_hello.size());
  // assert(sni.has_value());
  // assert(sni.value() == "test");

  const std::vector<unsigned char> invalid_record = {0x15, 0x03, 0x03, 0x00,
                                                     0x00};
  auto missing = deepwire::protocol_inspec::extract_sni(invalid_record.data(),
                                                        invalid_record.size());
  assert(!missing.has_value());

  return 0;
}
