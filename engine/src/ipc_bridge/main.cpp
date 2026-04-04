// ============================================================================
// DeepWire DPI — IPC Bridge Service
// ============================================================================
// OWNER: Junior 4 (IPC & Concurrency)
//
// PURPOSE:
//   Read FlowEvent records from a thread-safe queue, serialize them to JSON,
//   and transmit to the Go control plane over a Unix Domain Socket (or TCP).
//
// Refer to flow_data.h for FlowRecord, FlowEvent, and FlowStatus.
//
// Build: cd engine && mkdir build && cd build && cmake .. && make
// Run:   ./ipc_service
// ============================================================================

#include "../common/flow_data.h"
#include <iostream>
#include <string>
#include <queue>
#include <mutex>
#include <thread>
using namespace std;

// Shared queue holding FlowEvent objects
std::queue<deepwire::FlowEvent> flow_queue;

// Mutex to protect access to the queue
std::mutex queue_mutex;

// Mock producer: pushes one dummy event into the queue
void producer() {
    deepwire::FlowEvent event{}; // dummy event

    // Lock mutex for thread-safe push
    std::lock_guard<std::mutex> lock(queue_mutex);
    flow_queue.push(event);
}

int main() {
    cout << "=== DeepWire DPI — IPC Bridge Service ===" << endl;

    // Start producer thread
    std::thread t(producer);

    // Wait for producer to finish
    t.join();

    return 0;
}
