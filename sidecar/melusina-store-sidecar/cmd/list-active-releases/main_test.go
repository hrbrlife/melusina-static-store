package main

import (
	"encoding/hex"
	"testing"
)

func TestDecodeSandstormAppIDKnownVector(t *testing.T) {
	got, err := decodeSandstormAppID("vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh0")
	if err != nil {
		t.Fatal(err)
	}
	if want := "dd621583e52c72fcdf1b306b510cf0174f9e80f0cfd269e8ff6a45f29d5a4b20"; hex.EncodeToString(got[:]) != want {
		t.Fatalf("decoded appId %x, want %s", got, want)
	}
}

func TestDecodeSandstormAppIDRejectsMalformed(t *testing.T) {
	for _, value := range []string{
		"short",
		"vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dhi",
		"vpj1c0z55jtgtrsv61pp237h2x7tx07htz96mu7ze92z57au9dh1",
	} {
		if _, err := decodeSandstormAppID(value); err == nil {
			t.Fatalf("accepted malformed appId %q", value)
		}
	}
}
