#include "../src/common/flow_data.h"
#include "../src/ipc_bridge/json_serializer.h"

#include <cassert>
#include <string>

int main() {
  deepwire::FlowEvent event{1710000000, "10.0.0.10", 51515, "142.250.190.46",
                            443,        "TCP",       "youtube.com",
                            "",         "BLOCKED"};

  std::string json = deepwire::ipc_bridge::to_json_line(event);

  assert(json.find("\"timestamp\":1710000000") != std::string::npos);
  assert(json.find("\"src_ip\":\"10.0.0.10\"") != std::string::npos);
  assert(json.find("\"sni_domain\":\"youtube.com\"") != std::string::npos);
  assert(json.find("\"status\":\"BLOCKED\"") != std::string::npos);
  assert(!json.empty() && json.back() == '\n');

  return 0;
}
