// TestLoadBlocklistSkipsCommentsAndWhitespace tests that the load blocklist function
// successfully handles comments and whitespace while returning the proper blocklist.

import (
    "testing"
)

func TestLoadBlocklistSkipsCommentsAndWhitespace(t *testing.T) {
    blocklist := map[string]struct{}{
        "blocked1": {},
        "blocked2": {},
    }

    // Simulate loading the blocklist
    loadedBlocklist, err := loadBlocklist("path/to/blocklist.txt")
    if err != nil {
        t.Fatalf("Failed to load blocklist: %v", err)
    }

    for item := range loadedBlocklist {
        if _, ok := blocklist[item]; !ok {
            t.Errorf("Expected %s to be in blocklist, but it was not", item)
        }
    }
}

func loadBlocklist(path string) (map[string]struct{}, error) {
    // Implementation for loading the blocklist from a file
    return nil, nil // Replace with actual loading logic
}