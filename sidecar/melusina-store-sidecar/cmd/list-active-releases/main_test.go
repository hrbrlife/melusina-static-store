package main

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func TestDecodeSandstormAppID(t *testing.T) {
	id := "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510"
	want := sha256.Sum256([]byte(id))
	got, err := decodeSandstormAppID(id)
	if err != nil {
		t.Fatalf("decodeSandstormAppID(%q): %v", id, err)
	}
	if got != want {
		t.Fatalf("decoded bytes differ")
	}
	for _, bad := range []string{"", strings.ToUpper(id), id[:51], strings.Repeat("!", 52)} {
		if _, err := decodeSandstormAppID(bad); err == nil {
			t.Fatalf("decodeSandstormAppID(%q) unexpectedly succeeded", bad)
		}
	}
}
