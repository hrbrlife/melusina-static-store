package main

import (
	"encoding/base32"
	"strings"
	"testing"
)

func TestDecodeSandstormAppID(t *testing.T) {
	want := make([]byte, 32)
	for i := range want {
		want[i] = byte(i)
	}
	id := strings.ToLower(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(want))
	got, err := decodeSandstormAppID(id)
	if err != nil {
		t.Fatalf("decodeSandstormAppID(%q): %v", id, err)
	}
	if string(got[:]) != string(want) {
		t.Fatalf("decoded bytes differ")
	}
	for _, bad := range []string{"", strings.ToUpper(id), id[:51], strings.Repeat("z", 52)} {
		if _, err := decodeSandstormAppID(bad); err == nil {
			t.Fatalf("decodeSandstormAppID(%q) unexpectedly succeeded", bad)
		}
	}
}
