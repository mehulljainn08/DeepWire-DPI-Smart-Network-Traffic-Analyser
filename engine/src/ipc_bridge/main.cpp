// ============================================================================
// DeepWire DPI — IPC Bridge Service
// ============================================================================
// OWNER: Junior 4 (IPC & Concurrency)
//
// PURPOSE:
//   Read FlowEvent records from a thread-safe queue, serialize them to Protobuf,
//   and transmit to the Go control plane over TCP connection protocol.
//
// Refer to flow_data.h for FlowRecord, FlowEvent, and FlowStatus.
//
// Build: cd engine && mkdir build && cd build && cmake .. && make
// Run:   ./ipc_service
// ============================================================================
// ============================================================================
// DeepWire DPI — IPC Bridge Service
// ============================================================================
#include "../common/flow_data.h"
#include "../proto/flow_event.pb.h"
#include <iostream>
#include <string>
#include <queue>
#include <mutex>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

std::queue<deepwire::FlowEvent> flow_queue;
std::mutex queue_mutex;

#define TCP_HOST "127.0.0.1"
#define TCP_PORT 9000

// Serialize FlowEvent to protobuf binary string
std::string to_proto_bytes(const deepwire::FlowEvent& event) {
    deepwire_proto::FlowEvent proto_event;
    proto_event.set_flow_id(event.flow_id);
    proto_event.set_status(static_cast<int>(event.status));
    proto_event.set_timestamp(event.timestamp);

    std::string serialized;
    proto_event.SerializeToString(&serialized);
    return serialized;
}

// TCP socket setup — connect to Go control plane
// Print warning on failure, do not crash
int setup_tcp_socket() {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        std::cerr << " Failed to create TCP socket " << std::endl;
        return -1;
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(TCP_PORT);

    if (inet_pton(AF_INET, TCP_HOST, &addr.sin_addr) <= 0) {
        std::cerr << " Invalid TCP address." << std::endl;
        close(sock_fd);
        return -1;
    }

    // Go control Plane connection 
    if (connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << " Could not connect to Go server." << std::endl;
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

// Consumer thread loop — runs in background via detach()
void consumer_thread_loop(int sock_fd) {
    while (true) {
        deepwire::FlowEvent event{};
        bool has_event = false;

        // Task 4: Lock mutex, check queue, pop event, unlock
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (!flow_queue.empty()) {
                event = flow_queue.front();
                flow_queue.pop();
                has_event = true;
            }
        }

        // Task 5: Serialize and send over socket using write()
        if (has_event) {
            std::string data = to_proto_bytes(event);
            uint32_t msg_len = htonl(static_cast<uint32_t>(data.size()));
            if (sock_fd >= 0) {
                write(sock_fd, &msg_len, sizeof(msg_len));
                write(sock_fd, data.c_str(), data.size());
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// Mock producer
void producer() {
    deepwire::FlowEvent event{};
    std::lock_guard<std::mutex> lock(queue_mutex);
    flow_queue.push(event);
}

int main() {
    cout << "=== DeepWire DPI — IPC Bridge Service ===" << endl;

    // Task 1: Setup TCP socket
    int sock_fd = setup_tcp_socket();

    // Task 2: Spawn background consumer thread and detach
    std::thread consumer(consumer_thread_loop, sock_fd);
    consumer.detach();

    // Start producer thread
    std::thread t(producer);
    t.join();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    if (sock_fd >= 0) close(sock_fd);
    return 0;
}
