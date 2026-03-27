# DeepWire DPI: Smart Network Traffic Analyser

![C++](https://img.shields.io/badge/C++-17-blue.svg)
![Go](https://img.shields.io/badge/Go-1.21-00ADD8.svg)
![CMake](https://img.shields.io/badge/CMake-3.10+-brightgreen.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)

**DeepWire DPI** is a high-performance, polyglot network traffic analyzer and dynamic firewall enforcer. Operating at the bare-metal level, it intercepts raw network frames, reconstructs TCP streams, and utilizes Deep Packet Inspection (DPI) to extract plaintext Server Name Indication (SNI) domains from TLS handshakes.

By separating the memory-intensive packet sniffing from the concurrent rule matching, DeepWire provides real-time, OS-level network enforcement without bottlenecking system performance.

---

## 🧭 What Does This Actually Do? 

Think of your internet connection like a busy highway where thousands of cars (data packets) pass through every second. Each car is headed somewhere — YouTube, a banking site, a game server — and most of the time, you have no idea what's driving through your network or where it's going.

**DeepWire sits at the entrance of that highway and reads every car's destination sign in real time.**

Here's what that means in practice:

- 🔍 **It can see where your traffic is going** — even for encrypted connections (like HTTPS websites). It doesn't read *what* you're sending, but it can tell *who* you're talking to (e.g., "this device just connected to `youtube.com`").

- 🌍 **It can block traffic from entire countries** — If you only want your server to accept connections from India and the US, DeepWire can automatically drop any packet arriving from anywhere else, in real time.

- 🚨 **It detects and stops attacks automatically** — If something or someone starts hammering your network with thousands of fake connection requests per second (a common attack called a SYN Flood), DeepWire notices the abnormal pattern and blocks the attacker — before your server even feels the strain.

- 🔥 **It enforces rules without slowing you down** — Blocking decisions happen in the background, so legitimate traffic (your real users) never experiences added delay.

**Who is this for?** System administrators, homelab enthusiasts, security researchers, or anyone running a server who wants full visibility and control over what enters and leaves their network — without relying on a black-box commercial firewall.

---

## ✨ Key Features

* **Bare-Metal Deep Packet Inspection:** Extracts plaintext SNI domains from encrypted TLS handshakes by safely navigating variable-length Layer 7 extensions.
* **Kernel-Level BPF Filtering:** Utilizes strict Berkeley Packet Filters at the OS Kernel level to only intercept target traffic (e.g., HTTPS), ensuring near-zero idle CPU consumption.
* **Dynamic Geo-IP Firewall:** Integrates with MaxMind databases to provide real-time, sub-millisecond packet dropping based on nation-state geographic origin.
* **Statistical Heuristics (IPS):** Features a sliding-window rate limiter in the control plane to automatically detect and mitigate Layer 4 attacks (e.g., SYN Floods and port scans).
* **Asynchronous Enforcement:** Executes out-of-band OS firewall drops (`iptables` / Windows Firewall) to kill unauthorized connections without introducing latency to legitimate network traffic.

---

## 🏗️ Polyglot Architecture

DeepWire utilizes an Inter-Process Communication (IPC) architecture to bridge low-level system memory with high-level concurrent routing.

1. **The Core Engine (`/engine` - C++):** Built with `libpcap`, this daemon binds to the network interface card in promiscuous mode. It is divided into 4 isolated services: handling raw ingress, tracking stateful TCP flows via optimized hash maps, executing custom pointer algorithms to extract SNI domains, and bridging the data to the control plane via IPC.
2. **The IPC Bridge (`/engine/src/ipc_bridge` + `/contracts`):** Reads from a thread-safe queue, serializes `FlowEvent` records into strict JSON contracts (matching `/contracts/flow_event.json`), and streams them over a local Unix Domain Socket, fully decoupling the engine from the firewall logic.
3. **The Control Plane (`/control-plane` - Go):** A highly concurrent worker pool that ingests the IPC stream. It runs heuristic anomaly detection, checks IPs against a Geo-IP database, matches domains against a rule engine, and displays live metrics on a Terminal User Interface (TUI).
4. **Monitoring Stack (`/docker`):** A Docker Compose stack providing Prometheus metrics collection and Grafana dashboards for real-time observability of the control plane.

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

```
deepwire-dpi/
├── .github/
│   └── workflows/
│       └── ci.yml                    # GitHub Actions CI (C++ build + Go build)
├── engine/                           # C++ libpcap packet sniffer and DPI engine
│   ├── src/
│   │   ├── common/                   # Shared structs and headers (flow_data.h)
│   │   ├── ingress_handler/          # L2/L3 Packet capture, BPF filters, header stripping
│   │   ├── flow_state/               # L4 Session tracking and Garbage Collection
│   │   ├── protocol_inspec/          # L7 TLS/SNI Deep Packet Inspection
│   │   └── ipc_bridge/              # IPC serialization and Unix Domain Socket bridge
│   ├── include/                      # Public headers
│   └── CMakeLists.txt                # Multi-executable CMake build (4 targets)
├── control-plane/                    # Go concurrent listener and firewall enforcer
│   ├── rules/                        # Blocklists and MaxMind MMDB files
│   └── main.go                       # Goroutine worker pool, Geo-IP, and OS exec
├── contracts/                        # Shared IPC data schemas (JSON)
│   └── flow_event.json               # FlowEvent JSON schema contract
├── docker/                           # Monitoring infrastructure
│   ├── docker-compose.monitoring.yml # Prometheus + Grafana stack
│   ├── prometheus/
│   │   └── prometheus.yml            # Scrape config for control plane metrics
│   └── grafana/
│       └── provisioning/
│           └── datasources/
│               └── datasource.yml    # Auto-provisions Prometheus datasource
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites

- **C++ Engine:** `cmake` (3.10+), `make`, and libpcap development headers (`sudo apt-get install libpcap-dev`).
- **Go Control Plane:** Go 1.21+ installed.
- **Geo-IP Database:** Download the free GeoLite2 Country `.mmdb` file from MaxMind and place it in the `/control-plane/rules/` directory.
- **Permissions:** Root/Administrator access is strictly required to bind to the network interface and execute firewall commands.

### 1. Build the C++ Engine Services

The CMake configuration is designed to build the isolated C++ services independently for concurrent development.

```bash
cd engine
mkdir build && cd build
cmake ..
make
```

> This will output `ingress_service`, `state_service`, `inspec_service`, and `ipc_service` executables.

### 2. Run the Go Control Plane

Open a new terminal session and start the concurrent listener and TUI:

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

| Service | Language | Responsibility |
|---|---|---|
| **Ingress Handler** | C++ | BPF compilation, raw pcap ingestion, verifying Ethernet/IPv4 integrity, and safely jumping variable-length L3/L4 headers. |
| **Flow State** | C++ | 5-tuple TCP session tracking, hash collision mitigation, and connection garbage collection to prevent OOM errors during traffic spikes. |
| **Protocol Inspection** | C++ | Safe pointer arithmetic through variable-length TLS extensions to extract plaintext domain names without triggering segmentation faults. |
| **IPC Bridge** | C++ | Thread-safe queue consumption, JSON serialization of `FlowEvent` records, and Unix Domain Socket streaming to the Go control plane. |
| **Control Plane** | Go | Goroutine orchestration, Geo-IP database lookups, heuristic rate-limiting, and safe execution of OS-level firewall drops. |
