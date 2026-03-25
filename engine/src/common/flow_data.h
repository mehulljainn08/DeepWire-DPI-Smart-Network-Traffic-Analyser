#ifndef DEEPWIRE_FLOW_DATA_H
#define DEEPWIRE_FLOW_DATA_H

#include <cstdint>
#include <string>
#include <ctime>

namespace deepwire {

// ============================================================================
// FlowKey: Uniquely identifies a TCP/UDP flow (the "5-tuple")
// ============================================================================
struct FlowKey {
    std::string src_ip;
    std::string dest_ip;
    uint16_t    src_port;
    uint16_t    dest_port;
    std::string protocol;  // "TCP" or "UDP"

    bool operator==(const FlowKey& other) const {
        return src_ip    == other.src_ip
            && dest_ip   == other.dest_ip
            && src_port  == other.src_port
            && dest_port == other.dest_port
            && protocol  == other.protocol;
    }
};

// Hash function for FlowKey (needed for std::unordered_map)
struct FlowKeyHash {
    std::size_t operator()(const FlowKey& key) const {
        // FNV-1a inspired hash combining
        std::size_t h = 14695981039346656037ULL;
        auto combine = [&](std::size_t val) {
            h ^= val;
            h *= 1099511628211ULL;
        };
        combine(std::hash<std::string>{}(key.src_ip));
        combine(std::hash<std::string>{}(key.dest_ip));
        combine(std::hash<uint16_t>{}(key.src_port));
        combine(std::hash<uint16_t>{}(key.dest_port));
        combine(std::hash<std::string>{}(key.protocol));
        return h;
    }
};

// ============================================================================
// ParsedPacket: Output of the Ingress Handler → Input to Flow State
// ============================================================================
struct ParsedPacket {
    std::string src_ip;
    std::string dest_ip;
    uint16_t    src_port;
    uint16_t    dest_port;
    std::string protocol;       // "TCP" or "UDP"

    // TCP flags
    bool flag_syn;
    bool flag_ack;
    bool flag_fin;
    bool flag_rst;

    // TCP sequence tracking
    uint32_t seq_num;
    uint32_t ack_num;

    // Raw payload after TCP header (for TLS inspection)
    const uint8_t* payload;
    size_t         payload_len;

    // Metadata
    std::time_t    timestamp;
};

// ============================================================================
// FlowEvent: Output of the full pipeline → Sent to Go Control Plane via IPC
// This matches the JSON contract in contracts/flow_event.json
// ============================================================================
struct FlowEvent {
    std::time_t timestamp;
    std::string src_ip;
    uint16_t    src_port;
    std::string dest_ip;
    uint16_t    dest_port;
    std::string protocol;
    std::string sni_domain;     // Extracted by Protocol Inspector (empty if not found)
    std::string country_code;   // 2-letter ISO country code resolved via Geo-IP (empty if unresolved)
    std::string status;         // "NEW_FLOW", "ACTIVE", "CLOSED", "BLOCKED"
};

} // namespace deepwire

#endif // DEEPWIRE_FLOW_DATA_H
