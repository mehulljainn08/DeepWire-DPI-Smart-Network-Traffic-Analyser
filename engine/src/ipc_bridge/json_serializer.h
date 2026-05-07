#pragma once

#include "../common/flow_data.h"

#include <sstream>
#include <string>

namespace deepwire::ipc_bridge {

inline std::string escape_json(const std::string& input) {
  std::ostringstream escaped;
  for (char ch : input) {
    switch (ch) {
      case '\\':
        escaped << "\\\\";
        break;
      case '"':
        escaped << "\\\"";
        break;
      case '\n':
        escaped << "\\n";
        break;
      default:
        escaped << ch;
        break;
    }
  }
  return escaped.str();
}

inline std::string to_json_line(const deepwire::FlowEvent& event) {
  std::ostringstream json;
  json << "{"
       << "\"timestamp\":" << event.timestamp << ","
       << "\"src_ip\":\"" << escape_json(event.src_ip) << "\","
       << "\"src_port\":" << event.src_port << ","
       << "\"dest_ip\":\"" << escape_json(event.dest_ip) << "\","
       << "\"dest_port\":" << event.dest_port << ","
       << "\"protocol\":\"" << escape_json(event.protocol) << "\","
       << "\"sni_domain\":\"" << escape_json(event.sni_domain) << "\","
       << "\"status\":\"" << escape_json(event.status) << "\""
       << "}\n";
  return json.str();
}

}  // namespace deepwire::ipc_bridge
