package main

import "testing"

func TestActiveEntriesRefusesUndecodableAccount(t *testing.T) {
	var appID [32]byte
	_, err := activeEntries([]programAccount{{pubkey: "bad-release-entry", data: nil}}, appID)
	if err == nil {
		t.Fatal("activeEntries accepted an undecodable ReleaseEntry; revocation must never run from a partial chain view")
	}
}
