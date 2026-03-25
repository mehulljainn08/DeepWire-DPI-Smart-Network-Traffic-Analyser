# DeepWire DPI: Smart Network Traffic Analyser

![C++](https://img.shields.io/badge/C++-17-blue.svg)
![Go](https://img.shields.io/badge/Go-1.21-00ADD8.svg)
![CMake](https://img.shields.io/badge/CMake-3.10+-brightgreen.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)

---

## 🚀 Overview

**DeepWire DPI** is a high-performance, polyglot network traffic analyzer and dynamic firewall enforcer.

Traditional firewalls operate primarily at IP/port levels and struggle with encrypted traffic. DeepWire bridges this gap by performing **Deep Packet Inspection (DPI)** on TLS handshakes to extract **Server Name Indication (SNI)** domains in real-time—enabling domain-level blocking **without decrypting traffic**.

It operates close to the OS networking stack, combining **low-level packet processing (C++)** with **high-concurrency rule enforcement (Go)**.

---

## 🧠 Key Features

- 🔍 Real-time TLS SNI extraction without decryption  
- ⚡ High-performance packet parsing using `libpcap` (C++)  
- 🔄 TCP stream reconstruction with flow tracking  
- 🚀 Concurrent rule matching using Go worker pools  
- 🛡️ Dynamic OS-level firewall enforcement (`iptables` / Windows Firewall)  
- 🔌 Decoupled architecture via IPC (Unix Socket / TCP)  
- 🧱 Modular and extensible design  

---

## 🏗️ Architecture

DeepWire follows a **polyglot, decoupled architecture**:

### 1. Core Engine (`/engine` - C++)
- Captures raw packets using `libpcap`
- Operates in promiscuous mode
- Parses Layer 2–4 headers
- Reconstructs TCP streams using flow state maps
- Extracts SNI from TLS handshake payloads using pointer-safe parsing

### 2. IPC Bridge (`/contracts`)
- Serializes extracted data into strict JSON contracts
- Streams data via Unix Domain Socket or TCP
- Fully decouples packet processing from control logic

### 3. Control Plane (`/control-plane` - Go)
- Consumes IPC stream
- Uses goroutine worker pool for concurrent processing
- Matches domains against rule engine
- Executes OS-level firewall commands to drop traffic

---

## 🔄 Example Flow

1. User initiates connection to `youtube.com`
2. TLS handshake packet is captured
3. Engine extracts SNI → `"youtube.com"`
4. JSON event sent to Go control plane
5. Rule engine checks blacklist
6. Match found → firewall rule injected
7. Connection dropped in real-time

---

## 📜 IPC Data Contract

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
deepwire-dpi/
├── engine/                 # C++ DPI engine (libpcap, TCP reassembly)
│   ├── src/
│   ├── include/
│   └── CMakeLists.txt
├── control-plane/          # Go rule engine & firewall enforcer
│   └── main.go
├── contracts/              # Shared IPC schemas
└── README.md


⚙️ Tech Stack
	•	Languages: C++ (17), Go (1.21)
	•	Networking: libpcap, TCP/IP
	•	Concurrency: Goroutines, worker pools
	•	IPC: Unix Domain Sockets / TCP
	•	System Integration: iptables, Windows Firewall
	•	Build Tools: CMake


⚖️ Design Decisions
	•	C++ for Engine: Fine-grained memory control and high-performance packet parsing
	•	Go for Control Plane: Efficient concurrency and simplicity in rule handling
	•	IPC-based Communication: Loose coupling, modularity, and fault isolation
	•	SNI-based DPI: Enables domain filtering without TLS decryption

⚡ Performance (Planned / Measurable)
	•	Packet throughput: High-throughput (target: 100K+ packets/sec)
	•	Low-latency enforcement: Near real-time (< few ms)
	•	Efficient memory usage via optimized flow tracking

(To be benchmarked and optimized further)

🚀 Quick Start

Prerequisites
	•	C++ Engine:
	•	cmake (3.10+)
	•	make
	•	libpcap-dev

sudo apt-get install libpcap-dev


	•	Go Control Plane:
	•	Go 1.21+
	•	Permissions:
	•	Root/Admin required

1. Build the C++ Engine

cd engine
mkdir build && cd build
cmake ..
make

2. Run the Control Plane
cd control-plane
go run main.go

3. Start the Engine
sudo ./engine_node



🛠️ Development Guidelines

Engine Team (C++)
	•	Ensure memory safety and bounds checking
	•	Optimize pointer arithmetic and parsing
	•	Prevent memory leaks under high throughput

Control Plane Team (Go)
	•	Handle concurrency and race conditions
	•	Optimize worker pool throughput
	•	Ensure safe execution of firewall commands

⸻

🔮 Future Enhancements
	•	HTTP/2 and QUIC inspection support
	•	AI-based domain classification
	•	Web dashboard for rule management
	•	Redis-based rule caching
	•	eBPF integration for kernel-level performance
	•	Kubernetes deployment

⸻

🧠 Technical Highlights
	•	Implemented TCP stream reassembly using flow-based state tracking
	•	Designed IPC pipeline for cross-language communication
	•	Built concurrent rule engine using goroutines
	•	Integrated real-time firewall enforcement at OS level

⸻

📌 Use Cases
	•	Enterprise network monitoring
	•	Parental control systems
	•	Malware and phishing domain blocking
	•	Network policy enforcement in organizations

⸻

