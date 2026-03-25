// ============================================================================
// DeepWire DPI — Control Plane (Go)
// ============================================================================
// OWNER: Mehul (Lead)
//
// PURPOSE:
//   Listens on a Unix Domain Socket for JSON flow events from the C++ engine.
//   Matches incoming SNI domains against a blocklist and executes OS-level
//   firewall rules to drop blacklisted connections in real-time.
//
// RUN:
//   cd control-plane && go run main.go
// ============================================================================

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// FlowEvent matches the IPC contract in contracts/flow_event.json
type FlowEvent struct {
	Timestamp int64  `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Protocol  string `json:"protocol"`
	SNIDomain string `json:"sni_domain"`
	Status    string `json:"status"`
}

const socketPath = "/tmp/deepwire.sock"

func main() {
	fmt.Println("=== DeepWire DPI — Control Plane ===")

	// --- Load blocklist ---
	blocklist := loadBlocklist("blocklist.txt")
	fmt.Printf("[Control] Loaded %d blocked domains\n", len(blocklist))
	for _, domain := range blocklist {
		fmt.Printf("  🚫 %s\n", domain)
	}

	// --- Clean up old socket file ---
	os.Remove(socketPath)

	// --- Create Unix Domain Socket listener ---
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("[ERROR] Could not create socket: %v", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	fmt.Printf("[Control] Listening on %s\n", socketPath)
	fmt.Println("[Control] Waiting for C++ engine connections...")

	// --- Graceful shutdown on Ctrl+C ---
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[Control] Shutting down...")
		listener.Close()
		os.Remove(socketPath)
		os.Exit(0)
	}()

	// --- Accept connections ---
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[WARN] Accept error: %v", err)
			continue
		}
		fmt.Println("[Control] Engine connected!")
		go handleConnection(conn, blocklist)
	}
}

// handleConnection reads newline-delimited JSON from the C++ engine
func handleConnection(conn net.Conn, blocklist []string) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)

	for scanner.Scan() {
		line := scanner.Text()

		var event FlowEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			log.Printf("[WARN] Invalid JSON: %v", err)
			continue
		}

		fmt.Printf("[Control] Flow: %s:%d → %s:%d | SNI: %s | Status: %s\n",
			event.SrcIP, event.SrcPort,
			event.DestIP, event.DestPort,
			event.SNIDomain, event.Status)

		// --- Check blocklist ---
		if isBlocked(event.SNIDomain, blocklist) {
			fmt.Printf("[Control] 🚨 BLOCKED: %s → Injecting firewall rule for %s\n",
				event.SNIDomain, event.DestIP)

			// TODO (Sprint 3): Execute iptables DROP rule
			// cmd := exec.Command("iptables", "-A", "OUTPUT", "-d", event.DestIP, "-j", "DROP")
			// cmd.Run()
		}
	}

	fmt.Println("[Control] Engine disconnected.")
}

// loadBlocklist reads domains from a file (one per line)
func loadBlocklist(filename string) []string {
	var domains []string

	file, err := os.Open(filename)
	if err != nil {
		// No blocklist file — create a default one
		fmt.Printf("[Control] No blocklist found, creating default %s\n", filename)
		defaultDomains := []string{
			"youtube.com",
			"facebook.com",
			"instagram.com",
			"tiktok.com",
		}
		f, _ := os.Create(filename)
		for _, d := range defaultDomains {
			f.WriteString(d + "\n")
		}
		f.Close()
		return defaultDomains
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			domains = append(domains, domain)
		}
	}
	return domains
}

// isBlocked checks if a domain matches the blocklist (exact or subdomain match)
func isBlocked(domain string, blocklist []string) bool {
	if domain == "" {
		return false
	}
	domain = strings.ToLower(domain)
	for _, blocked := range blocklist {
		blocked = strings.ToLower(blocked)
		if domain == blocked || strings.HasSuffix(domain, "."+blocked) {
			return true
		}
	}
	return false
}
