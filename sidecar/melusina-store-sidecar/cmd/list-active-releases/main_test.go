package main

import (
	"encoding/json"
	"testing"
)

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
			var record rpcProgramAccount
			record.Pubkey = tc.pubkey
			record.Account.Data = tc.data
			if _, err := decodeProgramAccounts([]rpcProgramAccount{record}); err == nil {
				t.Fatal("decodeProgramAccounts accepted an incomplete RPC record")
			}
		})
	}
}

func TestDecodeProgramAccountsAcceptsCompleteBase64RPCRecord(t *testing.T) {
	var record rpcProgramAccount
	record.Pubkey = "release-entry"
	record.Account.Data = []string{"AA==", "base64"}
	accounts, err := decodeProgramAccounts([]rpcProgramAccount{record})
	if err != nil {
		t.Fatalf("decodeProgramAccounts rejected complete RPC record: %v", err)
	}
	if len(accounts) != 1 || accounts[0].pubkey != record.Pubkey || len(accounts[0].data) != 1 {
		t.Fatalf("decodeProgramAccounts returned %#v, want one decoded record", accounts)
	}
}

func TestProgramAccountsResponseRequiresExplicitResult(t *testing.T) {
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":1}`,
		`{"jsonrpc":"2.0","id":1,"result":null}`,
	} {
		var response programAccountsResponse
		if err := json.Unmarshal([]byte(raw), &response); err != nil {
			t.Fatalf("decode fixture: %v", err)
		}
		if response.Result != nil {
			t.Fatalf("result must stay nil for incomplete response %s", raw)
		}
	}

	var response programAccountsResponse
	if err := json.Unmarshal([]byte(`{"jsonrpc":"2.0","id":1,"result":[]}`), &response); err != nil {
		t.Fatalf("decode explicit empty result: %v", err)
	}
	if response.Result == nil {
		t.Fatal("explicit empty result must remain distinguishable from missing result")
	}
}
