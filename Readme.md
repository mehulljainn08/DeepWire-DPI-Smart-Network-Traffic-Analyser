# DeepWire DPI: Smart Network Traffic Analyser

![C++](https://img.shields.io/badge/C++-17-blue.svg)
![Go](https://img.shields.io/badge/Go-1.21-00ADD8.svg)
![CMake](https://img.shields.io/badge/CMake-3.10+-brightgreen.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)

**DeepWire DPI** is a high-performance, polyglot network traffic analyzer and dynamic firewall enforcer. Operating at the bare-metal level, it intercepts raw network frames, reconstructs TCP streams, and utilizes Deep Packet Inspection (DPI) to extract plaintext Server Name Indication (SNI) domains from TLS handshakes. 

By separating the memory-intensive packet sniffing from the concurrent rule matching, DeepWire provides real-time, OS-level network enforcement without bottlenecking system performance.

---

## 🏗️ Polyglot Architecture

DeepWire utilizes an Inter-Process Communication (IPC) architecture to bridge low-level system memory with high-level concurrent routing.

1. **The Core Engine (`/engine` - C++):** Built with `libpcap`, this daemon binds to the network interface card in promiscuous mode. It is divided into isolated services: handling raw ingress, tracking stateful TCP flows via optimized hash maps, and executing custom pointer algorithms to extract SNI domains from Layer 7 TLS payloads safely.
2. **The IPC Bridge (`/contracts`):** Extracted flow data is serialized into strict JSON contracts and streamed over a local Unix Domain Socket or TCP port, fully decoupling the engine from the firewall logic.
3. **The Control Plane (`/control-plane` - Go):** A highly concurrent worker pool that ingests the IPC stream. It matches incoming domains against a dynamic rule engine in real-time and executes OS-level syscalls (`iptables` / Windows Firewall) to instantly drop blacklisted connections.

---

## 📜 IPC Data Contract

The C++ engine and Go control plane communicate strictly via the following shared JSON schema:

```json
{
  "timestamp": 1740538920,
  "src_ip": "192.168.1.15",
  "src_port": 54322,
  "dest_ip": "142.250.190.46",
  "dest_port": 443,
  "protocol": "TCP",
  "sni_domain": "youtube.com",
  "status": "NEW_FLOW"
}
```

---

## 📂 Repository Structure

```text
deepwire-dpi/
├── engine/                       # C++ libpcap packet sniffer and DPI engine
│   ├── src/
│   │   ├── common/               # Shared structs and headers (e.g., flow_data.h)
│   │   ├── ingress_handler/      # L2/L3 Packet capture and header stripping
│   │   ├── flow_state/           # L4 Session tracking and Hash Maps
│   │   └── protocol_inspec/      # L7 TLS/SNI Deep Packet Inspection
│   ├── include/                  # Public headers
│   └── CMakeLists.txt            # Multi-executable CMake build configuration
├── control-plane/                # Go concurrent listener and firewall enforcer
│   └── main.go                   # Goroutine worker pool and OS exec logic
├── contracts/                    # Shared data schemas (JSON/Protobuf)
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites

- **C++ Engine:** `cmake` (3.10+), `make`, and `libpcap` development headers (`sudo apt-get install libpcap-dev`).
- **Go Control Plane:** Go 1.21+ installed.
- **Permissions:** Root/Administrator access is strictly required to bind to the network interface and execute firewall commands.

### 1. Build the C++ Engine Services

The CMake configuration is designed to build the isolated C++ services independently for concurrent development.

```bash
cd engine
mkdir build && cd build
cmake ..
make
```
*(This will output ingress_service, state_service, and inspec_service executables).*

### 2. Run the Go Control Plane

Open a new terminal session and start the concurrent listener:

```bash
cd control-plane
go run main.go
```

### 3. Initialize the Capture Services

Return to your C++ terminal and execute the required engine service with elevated privileges. (Example: starting the ingress router):

```bash
sudo ./ingress_service
```

---

## 🛠️ Team Workflow & Service Ownership

This project operates on strict architectural boundaries. Development is compartmentalized to ensure memory safety and prevent cross-module regressions.

- **Ingress Handler (C++):** Responsible for raw pcap ingestion, verifying Ethernet/IPv4/IPv6 integrity, and correctly calculating variable-length L3/L4 headers.
- **Flow State (C++):** Responsible for 5-tuple TCP session tracking, hash collision mitigation, and connection garbage collection to prevent OOM errors during traffic spikes.
- **Protocol Inspection (C++):** Responsible for safe pointer arithmetic through variable-length TLS extensions to extract plaintext domain names without triggering segmentation faults.
- **Control Plane (Go):** Responsible for goroutine orchestration, race-condition prevention during rule matching, IPC socket management, and safe execution of OS-level firewall drops.