#include <cassert>
#include "../src/protocol_inspec/tls_sni_parser.h"

int main() {
    uint8_t data[3] = {0x16, 0x00, 0x00};

    auto result = deepwire::protocol_inspec::extract_sni(data, 3);

    assert(result == std::nullopt);

    return 0;
}
