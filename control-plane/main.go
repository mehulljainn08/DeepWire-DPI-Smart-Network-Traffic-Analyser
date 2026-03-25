// ============================================================================
// DeepWire DPI — Control Plane (Go)
// ============================================================================
// OWNER: Mehul (Lead)
//
// PURPOSE:
//   Listens on a Unix Domain Socket for JSON flow events from the C++ engine.
//   Performs Geo-IP country lookups against a MaxMind GeoLite2 database,
//   matches incoming SNI domains against a blocklist, and executes OS-level
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

// ============================================================================
// Geo-IP Configuration
// ============================================================================
// Path to the MaxMind GeoLite2 Country database (.mmdb file).
// Download from: https://www.maxmind.com/en/geolite2/signup
// Place the file in the control-plane/rules/ directory.
// ============================================================================
const geoIPDatabasePath = "rules/GeoLite2-Country.mmdb"

// allowedCountries is the set of 2-letter ISO country codes that are
// permitted to communicate with our network.  Any source IP resolving
// to a country NOT in this set will be blocked at the OS firewall level.
// Set to nil or empty to disable country filtering entirely.
var allowedCountries = map[string]bool{
	"IN": true, // India
	"US": true, // United States
}

func main() {
	fmt.Println("=== DeepWire DPI — Control Plane ===")

	// --- Initialize Geo-IP database ---
	geoIPReady := loadGeoIPDatabase(geoIPDatabasePath)
	if geoIPReady {
		fmt.Printf("[Control] Geo-IP database loaded. Allowed countries: %v\n", allowedCountryList())
	} else {
		fmt.Println("[Control] ⚠️  Geo-IP database not loaded — country filtering DISABLED")
	}

	// --- Load blocklist ---
	blocklist := loadBlocklist("rules/blocklist.txt")
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
		go handleConnection(conn, blocklist, geoIPReady)
	}
}

// handleConnection reads newline-delimited JSON from the C++ engine
func handleConnection(conn net.Conn, blocklist []string, geoIPEnabled bool) {
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

		// --- Geo-IP country check (runs BEFORE blocklist for early rejection) ---
		if geoIPEnabled {
			countryCode, allowed := checkGeoIP(event.SrcIP)
			if !allowed {
				fmt.Printf("[Control] 🌍 GEO-BLOCKED: %s (country: %s) → Injecting firewall rule\n",
					event.SrcIP, countryCode)
				// TODO (Sprint 4): Execute iptables DROP rule for this source IP
				continue // Skip further processing — this packet is rejected
			}
			fmt.Printf("[Control] 🌍 Geo-IP OK: %s → %s\n", event.SrcIP, countryCode)
		}

		// --- Check domain blocklist ---
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

// ============================================================================
// Geo-IP Functions
// ============================================================================

// loadGeoIPDatabase opens the MaxMind .mmdb file and prepares the reader.
// Returns true if the database was loaded successfully.
//
// TODO: Integrate the oschwald/geoip2-golang library:
//
//	import "github.com/oschwald/geoip2-golang"
//
//	db, err := geoip2.Open(path)
//	if err != nil { ... }
//	defer db.Close()
//
// Store the *geoip2.Reader in a package-level variable for use in checkGeoIP().
func loadGeoIPDatabase(path string) bool {
	// Check if the .mmdb file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("[Control] Geo-IP database not found at: %s", path)
		log.Printf("[Control] Download from: https://www.maxmind.com/en/geolite2/signup")
		log.Printf("[Control] Place GeoLite2-Country.mmdb in the rules/ directory")
		return false
	}

	// TODO: Open the database using geoip2.Open(path)
	// Store the reader handle for use in checkGeoIP()
	fmt.Printf("[Control] Geo-IP database found: %s\n", path)
	return true
}

// checkGeoIP looks up the source IP in the MaxMind database and returns
// the 2-letter ISO country code and whether the country is allowed.
//
// TODO: Implement actual lookup using the geoip2 reader:
//
//	ip := net.ParseIP(srcIP)
//	record, err := db.Country(ip)
//	if err != nil { return "??", true }  // fail-open on lookup errors
//	code := record.Country.IsoCode
//	return code, allowedCountries[code]
func checkGeoIP(srcIP string) (countryCode string, allowed bool) {
	// Stub: fail-open until the .mmdb reader is integrated
	return "??", true
}

// allowedCountryList returns a sorted slice of allowed country codes for display.
func allowedCountryList() []string {
	list := make([]string, 0, len(allowedCountries))
	for code := range allowedCountries {
		list = append(list, code)
	}
	return list
}

// ============================================================================
// Blocklist Functions
// ============================================================================

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
