# DeepWire DPI Engine: Junior Onboarding & Theory Guide

Welcome to the **DeepWire DPI Core Engine** team! You will be working on the C++ side of our project, which is the high-performance packet sniffer and analysis engine. 

Since you all have strong Data Structures and Algorithms (DSA) foundations but are newer to computer networking and systems programming, this guide will bridge that gap. It explains the "what," "why," and "how" of the C++ Engine.

---

## 1. Crash Course: Computer Networks

Think of data sent over the internet as physical mail. When you send a letter, you put it in an envelope, write the destination address, the return address, and maybe stamp it. 

In networking, data is sent in **"Packets"**. Just like envelopes within envelopes (Russian nesting dolls), packets consist of **Headers** (the addresses) and the **Payload** (the actual data).

When a packet arrives at our server, it looks like this:
1. **Ethernet Header (Layer 2):** Contains MAC addresses (physical hardware addresses).
2. **IP Header (Layer 3):** Contains the Source IP and Destination IP. *(Who is talking to whom?)*
3. **TCP/UDP Header (Layer 4):** Contains the Source Port and Destination Port. *(Which specific application on the computer is talking?)*
4. **Application Payload (Layer 7):** The actual data being securely transmitted (e.g., a TLS Handshake requesting `youtube.com`).

### The "5-Tuple" (Crucial Concept)
In networking, every unique connection (like your browser loading a specific website) is identified by five pieces of information, called the **5-tuple**:
1. Source IP
2. Destination IP
3. Source Port
4. Destination Port
5. Protocol (TCP or UDP)

If we see multiple packets with the exact same 5-tuple, we know they belong to the same ongoing conversation (a **Flow**).

---

## 2. C++ Theory: What are `.h` (Header) Files?

In C++, code is typically split into two types of files:
* **`.h` (Header Files):** These contain the **Declarations** (the "API" or blueprint). They define `structs`, `classes`, and function signatures, but usually don't contain the actual logic.
* **`.cpp` (Source Files):** These contain the **Definitions** (the actual logic and implementation).

**Why do we separate them?** 
Because the DeepWire engine is split into 4 isolated services (Ingress, Flow State, Protocol Inspection, IPC). If *Ingress* and *Flow State* both need to know what a `FlowRecord` looks like, we define it **once** in `/common/flow_data.h`. Then, both services simply `#include "flow_data.h"`. This guarantees everyone is speaking the exact same language.

*(Look at the top of `flow_data.h`. You'll see `#pragma once`. This is a safeguard that prevents the compiler from copy-pasting the file multiple times if it's included by multiple different `.cpp` files.)*

---

## 3. The DeepWire Pipeline: How a Packet Travels

When a packet hits our server's network card, it travels down an assembly line. Your job is to build the workers on this assembly line.

### Step 1: Ingress Handler (`ingress_handler/`)
* **What it does:** Uses a library called `libpcap` to physically copy the raw packet out of the operating system's memory.
* **The Logic:** It looks at the raw binary data. It strips away the Ethernet header, reads the IP header to get the IPs, reads the TCP header to get the ports, and finds where the actual Payload starts.
* **The Output:** It packages all this extracted info into a `ParsedPacket` struct and passes it to the next step.

### Step 2: Flow State (`flow_state/`)
* **What it does:** Session tracking. It needs to know if this packet is the start of a brand new connection, or part of an ongoing one.
* **The Logic:** It takes the 5-tuple from the `ParsedPacket` and uses it as a key in a Hash Map (`std::unordered_map`). If the key exists, it updates the state. If it doesn't, it creates a new entry.
* **The Output:** It creates a `FlowRecord` (which tracks the lifecycle status like `NEW_FLOW` or `CLOSED`).

### Step 3: Protocol Inspection (`protocol_inspec/`)
* **What it does:** Deep Packet Inspection (DPI). It wants to know exactly *which website* the user is visiting.
* **The Logic:** It takes the raw `payload` from the `ParsedPacket`. Since HTTPS is encrypted, we can't read the data. *However*, the very first message sent (the TLS Handshake) sends the website name (the SNI domain) in **plaintext**. This module uses pointer arithmetic to jump through the TLS binary structure to extract `youtube.com`.
* **The Output:** It updates the `FlowRecord` by filling in the `sni_domain` field.

### Step 4: IPC Bridge (`ipc_bridge/`)
* **What it does:** Bridges C++ to our Go Control Plane.
* **The Logic:** It takes the final `FlowRecord` and converts it into a JSON string (a `FlowEvent`). It sends this JSON over a Unix Domain Socket to the Go program, which will then decide whether to block or allow the traffic.

### Step 5: The Go Control Plane (How Your Data is Used)
Once your C++ Engine sends the JSON `FlowEvent`, the Control Plane (written in Go) takes over. Here is exactly why the control plane needs the info you extract at each layer:
* **The IP Addresses (`src_ip` & `dest_ip`):** Used to query the MaxMind Geo-IP database. If the source IP originates from a blocked country (e.g., your firewall rules say "Block all traffic from outside my country"), the Control Plane instantly issues an OS-level drop command.
* **The `timestamp` & `src_ip`:** Tracked using a sliding-window rate limiter algorithm. If it sees 10,000 connection requests from the same IP in one second, it flags it as a DDoS attack (like a SYN Flood) and blocks the attacker.
* **The `sni_domain` (from Layer 7 TLS):** Matched against a blocklist engine. Even if the traffic is completely encrypted, because you extracted that the destination is `youtube.com` during the TLS handshake, the Control Plane can drop the connection if `youtube.com` is banned on your network.
* **The `status` (NEW_FLOW vs CLOSED):** Tells the Control Plane when to open a monitoring session in its dashboard (Grafana/Prometheus) and when to safely free up memory when an active connection is finally closed.
---

## 4. Syntax Walkthrough: `flow_data.h`

Let's look at the DSA concepts inside our shared `flow_data.h` file.

### Enums and Structs
```cpp
enum class FlowStatus {
    NEW_FLOW, EXISTING_FLOW, CLOSED
};
```
An `enum class` restricts a variable to only have one of these specific values. It prevents bugs (you can't accidentally set status to "HELLO").

### The Hash Map Key: `FlowKey`
For Step 2 (Flow State), we need an `unordered_map` to store active connections. The "key" for this map is the 5-tuple (`FlowKey`).

```cpp
struct FlowKey {
    std::string src_ip;
    std::string dest_ip;
    uint16_t    src_port;
    uint16_t    dest_port;
    std::string protocol; 

    // OVERRIDING THE EQUALITY OPERATOR
    bool operator==(const FlowKey& other) const { ... }
};
```
**Why do we have `operator==`?**
In C++, an `unordered_map` needs to know how to check if two keys are identical. Since `FlowKey` is a custom struct, C++ doesn't know how to compare them point-blank. We have to explicitly tell C++: *"Two FlowKeys are equal only if their IPs, Ports, and Protocol all match exactly."*

### The Hash Function: `FlowKeyHash`
```cpp
struct FlowKeyHash {
    std::size_t operator()(const FlowKey& key) const {
        // FNV-1a inspired hash combining
        std::size_t h = ...;
        // ... bitwise math ...
        return h;
    }
};
```
**Why do we need this?**
You know from DSA that a Hash Map converts a key into an integer index (a Hash) so it can achieve `O(1)` lookups. C++ knows how to hash a single string or a single integer, but it doesn't know how to hash a custom struct with 5 different fields! 

We wrote a custom struct `FlowKeyHash` that mathematically combines the hashes of the IPs, Ports, and Protocol into one giant, unique number. This allows us to use `std::unordered_map<FlowKey, FlowRecord, FlowKeyHash>`.

---

## 5. How You Should Write & Test Your Code

Because this code intercepts every single byte of internet traffic, it must be **blazing fast** and **memory safe**.

1. **Beware of Pointers:** In the Protocol Inspection and Ingress phases, you will be given raw `uint8_t* payload` pointers. If you read past the end of the `payload_len`, you will cause a **Segmentation Fault** and crash the entire internet connection. Always write bounds checks.
2. **Avoid Copying Strings:** String copies are slow. Wherever possible, pass `const std::string&` (pass by const reference) so you aren't duplicating data in memory.
3. **Unit Testing Logic:** You don't need to run a whole network to test your code. 
   * Write unit tests that instantiate a fake `uint8_t` array representing a raw network packet.
   * Pass it into your parsing logic and `ASSERT` that your logic extracts the correct IPs, Ports, and Domains.
4. **Memory Leaks:** Connections eventually close. In the Flow State module, if you add an entry to the `unordered_map` when a connection opens, you **must** delete it when the connection closes (or times out). If you don't, the map will grow infinitely until the server runs out of RAM (an OOM crash).

### Exactly How to Compile & Test Your Code
The project uses `CMake` for building. Whenever you write new logic in the `.cpp` files or add new unit tests in the `/engine/tests/` folder, follow this workflow:

1. **Navigate to the engine directory and create a build folder (if it doesn't exist):**
   ```bash
   cd engine/
   mkdir -p build && cd build/
   ```

2. **Generate the build files with CMake and compile:**
   ```bash
   cmake ..
   make
   ```
   *(Tip: Use `make -j4` to compile using 4 CPU cores to speed it up!)*

3. **Run your automated tests:**
   If your `CMakeLists.txt` is configured with `CTest`, run all tests at once:
   ```bash
   ctest --output-on-failure
   ```
   Or run a specific compiled test executable directly:
   ```bash
   ./tests/run_ingress_tests
   ```

### Code Contribution & GitHub Workflow

We maintain two permanent branches in this repository:
- `main` (Production-ready and stable)
- `testing` (Active development and integration)

You will **never** commit directly to these branches. To contribute your work, follow this exact workflow:

1. **Update your local testing branch**:
   Always start your work from the latest, most up-to-date integration branch.
   ```bash
   git checkout testing
   git pull origin testing
   ```

2. **Create your feature branch**:
   Name it using the convention `<your_name>_week<number>` (for example, `mehul_week1`).
   ```bash
   git checkout -b mehul_week1
   ```

3. **Write code and verify**:
   Fill in your designated `TODO` tasks in the C++ code, compile, and run the tests to verify your logic is sound.

4. **Commit your changes**:
   Stage your modified files and write a descriptive commit message.
   ```bash
   git add .
   git commit -m "engine: implemented BPF filtering logic in ingress handler"
   ```

5. **Push and Raise a Pull Request (PR)**:
   Push your new branch up to GitHub.
   ```bash
   git push origin mehul_week1
   ```
   Finally, go to our GitHub repository webpage and click **Compare & pull request**. 
   > **CRITICAL:** Ensure you are setting the "base branch" of your PR to `testing` (not `main`!). I will review your logic there before it gets merged.

### Next Steps
1. Review `flow_data.h` in the source code.
2. Pick a component (Ingress, Flow State, or Protocol Inspec).
3. Start implementing the logic incrementally using isolated C++ tests!
