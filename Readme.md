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

1. **The Core Engine (`/engine` - C++):** Built with `libpcap`, this daemon binds to the network interface card in promiscuous mode. It strips Layer 2-4 headers, manages TCP flow states via highly optimized hash maps, and executes custom pointer algorithms to extract SNI domains from Layer 7 TLS payloads safely.
2. **The IPC Bridge (`/contracts`):** Extracted flow data is serialized into strict JSON contracts and streamed over a local Unix Domain Socket or TCP port, fully decoupling the engine from the firewall logic.
3. **The Control Plane (`/control-plane` - Go):** A highly concurrent worker pool that ingests the IPC stream. It matches incoming domains against a dynamic rule engine in real-time and executes OS-level syscalls (`iptables` / Windows Firewall) to instantly drop blacklisted connections.

---

## 📜 IPC Data Contract

The C++ engine and Go control plane communicate strictly via the following JSON schema:

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

📂 Repository Structure
Plaintext
deepwire-dpi/
├── engine/                 # C++ libpcap packet sniffer and DPI engine
│   ├── src/                # Core C++ source files (pointer parsing, state map)
│   ├── include/            # Header files
│   └── CMakeLists.txt      # C++ build configuration
├── control-plane/          # Go concurrent listener and firewall enforcer
│   └── main.go             # Goroutine worker pool and OS exec logic
├── contracts/              # Shared data schemas (JSON/Protobuf)
└── README.md

🚀 Quick Start
Prerequisites

C++ Engine: cmake (3.10+), make, and libpcap development headers (sudo apt-get install libpcap-dev).

Go Control Plane: Go 1.21+ installed.

Permissions: Root/Administrator access is strictly required to bind to the network interface and execute firewall commands.

1. Build the C++ Engine

Bash
cd engine
mkdir build && cd build
cmake ..
make
2. Run the Go Control Plane

Open a new terminal session and start the listener:

Bash
cd control-plane
go run main.go
3. Initialize the Capture Engine

Return to your C++ terminal and execute the engine with elevated privileges:

Bash
sudo ./engine_node
🛠️ Development & Sprints
This project operates on strict architectural boundaries:

Engine Team (C++): Responsible for memory safety, pointer arithmetic bounds checking, and preventing memory leaks during high-throughput packet bursts.

Control Plane Team (Go): Responsible for goroutine orchestration, race-condition prevention during rule matching, and safe execution of OS-level firewall drops.

