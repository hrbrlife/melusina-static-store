package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestOriginalAnchorAllocatedStoreControlAccounts(t *testing.T) {
	raw, err := os.ReadFile("testdata/store-control-anchor-accounts.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		PolicyHex string
		GrantHex  string
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	policy, err := hex.DecodeString(f.PolicyHex)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := hex.DecodeString(f.GrantHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy) != 299 || len(grant) != 319 {
		t.Fatal("original Anchor allocation changed")
	}
	p, err := readStoreControlPolicyMeta(policy)
	if err != nil {
		t.Fatal(err)
	}
	g, err := readStorePublisherGrantMeta(grant)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Active || p.PolicyEpoch != 1 || p.PearlCommandPublicKey[0] != 11 || p.HumanApprovalPublicKey[0] != 12 || !g.Active || g.GrantEpoch != 1 || g.Actions != 3 || g.AppID[0] != 21 || g.PublisherEd25519Pubkey[0] != 22 {
		t.Fatal("compiled original account authority differs")
	}
	for _, test := range []struct {
		name   string
		data   []byte
		decode func([]byte) error
	}{
		{"policy", policy, func(b []byte) error { _, e := readStoreControlPolicyMeta(b); return e }},
		{"grant", grant, func(b []byte) error { _, e := readStorePublisherGrantMeta(b); return e }},
	} {
		for _, change := range []string{"nonzero-slack", "short-allocation", "long-allocation", "unknown-option"} {
			t.Run(test.name+"/"+change, func(t *testing.T) {
				b := append([]byte(nil), test.data...)
				switch change {
				case "nonzero-slack":
					b[len(b)-1] = 1
				case "short-allocation":
					b = b[:len(b)-1]
				case "long-allocation":
					b = append(b, 0)
				case "unknown-option":
					if test.name == "policy" {
						b[289] = 2
					} else {
						b[163] = 2
					}
				}
				if err := test.decode(b); err == nil {
					t.Fatal("malformed original allocation accepted")
				}
			})
		}
	}
}
