package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is the Store copy of the cross-repository C3 wire contract. A changed
// byte requires a deliberate new digest in every consumer repository.
func TestC3ReleaseAndStoreHostSyncGuard(t *testing.T) {
	const name = "C3-release-and-store-host.json"
	dir := filepath.Join("..", "..", "testdata", "contracts", "C3-release-and-store-host")
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("C3-release-and-store-host-sync: read vector: %v", err)
	}
	manifest, err := os.ReadFile(filepath.Join(dir, "C3-release-and-store-host.sha256"))
	if err != nil {
		t.Fatalf("C3-release-and-store-host-sync: read digest: %v", err)
	}
	parts := strings.Fields(string(manifest))
	if len(parts) != 2 || parts[1] != name {
		t.Fatalf("C3-release-and-store-host-sync: digest line must name %s", name)
	}
	if _, err := hex.DecodeString(parts[0]); err != nil || len(parts[0]) != 64 {
		t.Fatalf("C3-release-and-store-host-sync: malformed sha256 %q", parts[0])
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != parts[0] {
		t.Fatalf("C3-release-and-store-host-sync: bytes hash to %s, pinned %s", got, parts[0])
	}
}
