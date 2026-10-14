package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Each binding verifyPreparedClassTable applies to the Store response is
// isolated: the operator signs a validly encoded table that differs from the
// admitted positive in exactly one bound field. Signature validity alone must
// not let the publisher write that table out.
func TestPreparedClassTableIsolatedBindings(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1791850000, 0)
	hash := strings.Repeat("c", 64)
	request := classPrepareRequest{Schema: "melusina.sidecar-classes-prepare.v1", StoreID: "store-one",
		Rows: []classPrepareRow{
			{ID: "first-sidecar", Class: "sidecar_cascade", KeyCustody: "none"},
			{ID: "second-sidecar", Class: "sidecar_identity", KeyCustody: "sidecar-held-identity"},
		}}
	build := func(edit func(*signedClassTable)) []byte {
		t.Helper()
		table := signedClassTable{Schema: "melusina.sidecar-classes.v1", StoreID: request.StoreID,
			OperatorPubkey: primitives.EncodeBase58(public), SignedAtUnix: now.Unix()}
		for _, row := range request.Rows {
			table.Rows = append(table.Rows, signedClassRow{ID: row.ID, Class: row.Class, KeyCustody: row.KeyCustody,
				Source: "staged:" + hash})
		}
		if edit != nil {
			edit(&table)
		}
		for i := range table.Rows {
			table.Rows[i].DeclaredAt = time.Unix(table.SignedAtUnix, 0).UTC().Format(time.RFC3339)
		}
		table.OperatorSignature = primitives.EncodeBase58(ed25519.Sign(private, classTableMessage(table)))
		return mustClassJSON(t, table)
	}
	if _, err := verifyPreparedClassTable(build(nil), request, hash, public, now); err != nil {
		t.Fatalf("PREPARED_CLASS_TABLE_ISOLATION_POSITIVE_REFUSED: %v", err)
	}
	for name, edit := range map[string]func(*signedClassTable){
		"PREPARED_CLASS_TABLE_FOREIGN_STORE_ACCEPTED": func(tab *signedClassTable) { tab.StoreID = "store-two" },
		"PREPARED_CLASS_TABLE_STALE_SIGNATURE_ACCEPTED": func(tab *signedClassTable) {
			tab.SignedAtUnix = now.Add(-6 * time.Minute).Unix()
		},
		"PREPARED_CLASS_TABLE_FUTURE_SIGNATURE_ACCEPTED": func(tab *signedClassTable) {
			tab.SignedAtUnix = now.Add(2 * time.Minute).Unix()
		},
		"PREPARED_CLASS_TABLE_DROPPED_ROW_ACCEPTED": func(tab *signedClassTable) { tab.Rows = tab.Rows[:1] },
		"PREPARED_CLASS_TABLE_CUSTODY_MUTATION_ACCEPTED": func(tab *signedClassTable) {
			tab.Rows[1].KeyCustody = "none"
		},
	} {
		if _, err := verifyPreparedClassTable(build(edit), request, hash, public, now); err == nil {
			t.Fatal(name)
		}
	}
}
