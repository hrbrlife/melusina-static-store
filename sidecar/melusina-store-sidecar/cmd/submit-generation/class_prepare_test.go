package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func mustClassJSON(t *testing.T, value signedClassTable) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPreparedClassTableSignatureAndBindings(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1791850000, 0)
	hash := strings.Repeat("a", 64)
	request := classPrepareRequest{Schema: "melusina.sidecar-classes-prepare.v1", StoreID: "store-one",
		Rows: []classPrepareRow{{ID: "first-sidecar", Class: "sidecar_cascade", KeyCustody: "none"}}}
	table := signedClassTable{Schema: "melusina.sidecar-classes.v1", StoreID: request.StoreID,
		OperatorPubkey: primitives.EncodeBase58(public), SignedAtUnix: now.Unix(),
		Rows: []signedClassRow{{ID: "first-sidecar", Class: "sidecar_cascade", KeyCustody: "none",
			DeclaredAt: now.UTC().Format(time.RFC3339), Source: "staged:" + hash}}}
	table.OperatorSignature = primitives.EncodeBase58(ed25519.Sign(private, classTableMessage(table)))
	raw := mustClassJSON(t, table)
	if _, err := verifyPreparedClassTable(raw, request, hash, public, now); err != nil {
		t.Fatalf("PREPARED_CLASS_TABLE_POSITIVE_REFUSED: %v", err)
	}
	changed := table
	changed.Rows = append([]signedClassRow(nil), table.Rows...)
	changed.Rows[0].Class = "sidecar_identity"
	if _, err := verifyPreparedClassTable(mustClassJSON(t, changed), request, hash, public, now); err == nil {
		t.Fatal("PREPARED_CLASS_TABLE_CLASS_MUTATION_ACCEPTED")
	}
	if _, err := verifyPreparedClassTable(raw, request, strings.Repeat("b", 64), public, now); err == nil {
		t.Fatal("PREPARED_CLASS_TABLE_REQUEST_MUTATION_ACCEPTED")
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPreparedClassTable(raw, request, hash, other, now); err == nil {
		t.Fatal("PREPARED_CLASS_TABLE_FOREIGN_OPERATOR_ACCEPTED")
	}
}

func TestClassPreparePrivateBackendOnly(t *testing.T) {
	for _, address := range []string{"159.195.5.142:8443", "non-ip-host:8443", "127.0.0.1:8443", "10.253.250.10:0"} {
		if _, err := privateClassTransport(address, time.Minute); err == nil {
			t.Fatalf("CLASS_PREPARE_UNPINNED_BACKEND_ACCEPTED:%s", address)
		}
	}
	if _, err := privateClassTransport("10.253.250.10:8443", time.Minute); err != nil {
		t.Fatal(err)
	}
}
