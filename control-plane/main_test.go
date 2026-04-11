package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsBlockedMatchesExactAndSubdomain(t *testing.T) {
	blocklist := map[string]struct{}{
		"youtube.com": {},
		"example.org": {},
	}

	if !isBlocked("youtube.com", blocklist) {
		t.Fatal("expected exact domain to be blocked")
	}
	if !isBlocked("api.youtube.com", blocklist) {
		t.Fatal("expected subdomain to be blocked")
	}
	if isBlocked("notyoutube.com", blocklist) {
		t.Fatal("unexpected suffix-only match")
	}
	if isBlocked("", blocklist) {
		t.Fatal("empty domain should not be blocked")
	}
}

func TestLoadBlocklistSkipsCommentsAndWhitespace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")
	content := "# comment\n\n YouTube.com \nexample.org\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write blocklist: %v", err)
	}

	domains, err := loadBlocklist(path)
	if err != nil {
		t.Fatalf("loadBlocklist error: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}
	if _, ok := domains["YouTube.com"]; !ok {
		t.Errorf("missing YouTube.com in domains")
	}
	if _, ok := domains["example.org"]; !ok {
		t.Errorf("missing example.org in domains")
	}
}

func TestLoadGeoIPDatabaseReflectsFilePresence(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.mmdb")
	if loadGeoIPDatabase(missing) {
		t.Fatal("expected missing Geo-IP database to return false")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "GeoLite2-Country.mmdb")
	if err := os.WriteFile(path, []byte("placeholder"), 0o644); err != nil {
		t.Fatalf("write mmdb stub: %v", err)
	}

	// Because geoip2.Open is used, an invalid format should correctly fail.
	if loadGeoIPDatabase(path) {
		t.Fatal("expected existing but invalid Geo-IP database file to return false validation")
	}
}
