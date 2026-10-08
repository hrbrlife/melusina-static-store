package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPinsRequiresExactInstallerDigest(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"keys":{"dueprocess/test":"` + base64.StdEncoding.EncodeToString(public) + `"}}`)
	path := filepath.Join(t.TempDir(), "pins.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	pins, err := loadPins(path, hex.EncodeToString(sum[:]))
	if err != nil || string(pins["dueprocess/test"]) != string(public) {
		t.Fatalf("installer roster positive: %v", err)
	}
	if _, err := loadPins(path, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "pins-drift") {
		t.Fatalf("evidence-pack-custody-pins-drift: changed roster digest admitted: %v", err)
	}
}
