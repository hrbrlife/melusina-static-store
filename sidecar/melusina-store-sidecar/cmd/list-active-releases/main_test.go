package main

import "testing"

func TestActiveEntriesRefusesUndecodableAccount(t *testing.T) {
	var appID [32]byte
	_, err := activeEntries([]programAccount{{pubkey: "bad-release-entry", data: nil}}, appID)
	if err == nil {
		t.Fatal("activeEntries accepted an undecodable ReleaseEntry; revocation must never run from a partial chain view")
	}
}

func TestDecodeProgramAccountsRefusesIncompleteRPCRecords(t *testing.T) {
	for _, tc := range []struct {
		name   string
		pubkey string
		data   []string
	}{
		{name: "missing data", pubkey: "release-entry", data: nil},
		{name: "empty data", pubkey: "release-entry", data: []string{"", "base64"}},
		{name: "invalid base64", pubkey: "release-entry", data: []string{"%%%", "base64"}},
		{name: "wrong encoding", pubkey: "release-entry", data: []string{"AA==", "base58"}},
		{name: "empty pubkey", pubkey: "", data: []string{"AA==", "base64"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var record struct {
				Pubkey  string `json:"pubkey"`
				Account struct {
					Data []string `json:"data"`
				} `json:"account"`
			}
			record.Pubkey = tc.pubkey
			record.Account.Data = tc.data
			if _, err := decodeProgramAccounts([]struct {
				Pubkey  string `json:"pubkey"`
				Account struct {
					Data []string `json:"data"`
				} `json:"account"`
			}{record}); err == nil {
				t.Fatal("decodeProgramAccounts accepted an incomplete RPC record")
			}
		})
	}
}

func TestDecodeProgramAccountsAcceptsCompleteBase64RPCRecord(t *testing.T) {
	var record struct {
		Pubkey  string `json:"pubkey"`
		Account struct {
			Data []string `json:"data"`
		} `json:"account"`
	}
	record.Pubkey = "release-entry"
	record.Account.Data = []string{"AA==", "base64"}
	accounts, err := decodeProgramAccounts([]struct {
		Pubkey  string `json:"pubkey"`
		Account struct {
			Data []string `json:"data"`
		} `json:"account"`
	}{record})
	if err != nil {
		t.Fatalf("decodeProgramAccounts rejected complete RPC record: %v", err)
	}
	if len(accounts) != 1 || accounts[0].pubkey != record.Pubkey || len(accounts[0].data) != 1 {
		t.Fatalf("decodeProgramAccounts returned %#v, want one decoded record", accounts)
	}
}
