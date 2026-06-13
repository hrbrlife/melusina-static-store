package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestStoreDomainHash_PinnedVectors verifies the Go implementation against the
// shared cross-language vector file (contract C-5 / spec S8). Rust and JS ports
// MUST consume the same testdata/domain_hash_vectors.json.
func TestStoreDomainHash_PinnedVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/domain_hash_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Host    string `json:"host"`
			HashHex string `json:"hash_hex"`
			Note    string `json:"note"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	for _, v := range doc.Vectors {
		got := hex.EncodeToString(sliceOf(StoreDomainHash(v.Host)))
		if got != v.HashHex {
			t.Errorf("StoreDomainHash(%q) = %s, want %s (%s)", v.Host, got, v.HashHex, v.Note)
		}
	}
}

func sliceOf(a [32]byte) []byte { return a[:] }
