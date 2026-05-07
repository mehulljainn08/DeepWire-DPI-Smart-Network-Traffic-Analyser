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
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
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
const blocklistPath = "rules/blocklist.txt"

var GeoDB *geoip2.Reader

type data struct {
	Count       int
	WindowStart time.Time
}

var NewFlowMap = make(map[string]data)

// allowedCountries is the set of 2-letter ISO country codes that are
// permitted to communicate with our network.  Any source IP resolving
// to a country NOT in this set will be blocked at the OS firewall level.
// Set to nil or empty to disable country filtering entirely.
var allowedCountries = map[string]bool{
	"IN": true, // India
	"US": true, // United States
}

func main() {
	fmt.Println("=== DeepWire Logic Test ===")

	os.Remove(socketPath)
	sock, err := net.Listen("unix", socketPath)

	if err != nil {
		fmt.Println("Error listening on socket:", err)
		return
	}
	blocklist, err := loadBlocklist(blocklistPath)
	if err != nil {
		fmt.Println("Error loading blocklist:", err)
		return
	}

	defer sock.Close()

	success := loadGeoIPDatabase(geoIPDatabasePath)
	if success == false {
		fmt.Println("Error loading Geo-IP database:")
		return
	}
	for {
		conn, err := sock.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go handleConnection(conn, blocklist, true)
	}

}

// handleConnection reads newline-delimited JSON from the C++ engine
func handleConnection(conn net.Conn, blocklist map[string]struct{}, geoIPEnabled bool) {
	// TODO: Read and parse JSON from connection into FlowEvent

	// --- Geo-IP country check (runs BEFORE blocklist for early rejection) ---
	// TODO (Sprint 4): Execute iptables DROP rule for this source IP

	// --- Check domain blocklist ---
	// TODO (Sprint 3): Execute iptables DROP rule

	scanner := bufio.NewScanner(conn)

	for line := scanner.Scan(); line; line = scanner.Scan() {
		var flowEvent FlowEvent
		err := json.Unmarshal(scanner.Bytes(), &flowEvent)
		if err != nil {
			fmt.Println("Error unmarshalling flow event:", err)
			continue
		}

		country, allowed := checkGeoIP(flowEvent.SrcIP)
		if allowed == false {
			fmt.Println("Country not allowed:", country)
			exec.Command("iptables", "-A", "INPUT", "-s", flowEvent.SrcIP, "-j", "DROP").Run()
		}
		blocked := isBlocked(flowEvent.SNIDomain, blocklist)
		if blocked == true {
			fmt.Println("Domain blocked:", flowEvent.SNIDomain)
			err := exec.Command("iptables", "-A", "INPUT", "-s", flowEvent.SrcIP, "-j", "DROP").Run()
			if err != nil {
				fmt.Println("firewall error:", err)
			}
		}
	}

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
	// TODO: Open the database using geoip2.Open(path)
	// Store the reader handle for use in checkGeoIP()
	var err error
	GeoDB, err = geoip2.Open(path)

	if err != nil {
		fmt.Println("Error opening Geo-IP database:", err)
		return false
	}

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
	srcIP1 := net.ParseIP(srcIP)
	record, err := GeoDB.Country(srcIP1)

	if err != nil {
		return "??", true
	}
	country := record.Country.IsoCode

	return country, allowedCountries[country]

}

// allowedCountryList returns a sorted slice of allowed country codes for display.
func allowedCountryList() []string {

	var allowedCountrySlice []string
	for country := range allowedCountries {
		allowedCountrySlice = append(allowedCountrySlice, country)
	}
	return allowedCountrySlice
}

// blocklist functions
// loadBlocklist reads domains from a file
func loadBlocklist(filename string) (map[string]struct{}, error) {

	blocklist, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading blocklist:", err)
		return nil, err
	}
	lines := strings.Split(string(blocklist), "\n")
	set := make(map[string]struct{})

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[line] = struct{}{}
	}
	return set, nil
}

// isBlocked checks if a domain matches the blocklist (exact or subdomain match)
func isBlocked(domain string, blocklist map[string]struct{}) bool {

	for {

		_, ok := blocklist[domain]
		if ok {
			return true
		}

		dotIndex := strings.IndexByte(domain, '.')

		if dotIndex == -1 {
			break
		}

		domain = domain[dotIndex+1:]
	}

	return false
}
