package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	leaf := filepath.Join(t.TempDir(), "store-leaf.pem")
	if err := os.WriteFile(leaf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
		Bytes: server.TLS.Certificates[0].Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"159.195.5.142:18443", "non-ip-host:18443", "127.0.0.1:18443", "10.253.250.10:0", "10.253.250.10:8443"} {
		if _, err := privateClassTransport(server.URL, address, leaf, time.Minute); err == nil {
			t.Fatalf("CLASS_PREPARE_UNPINNED_BACKEND_ACCEPTED:%s", address)
		}
	}
	if _, err := privateClassTransport(server.URL, "10.88.180.29:18443", "", time.Minute); err == nil {
		t.Fatal("CLASS_PREPARE_PRIVATE_CONNECT_WITHOUT_LEAF_ACCEPTED")
	}
	if _, err := privateClassTransport(server.URL, "10.88.180.29:18443", leaf, time.Minute); err != nil {
		t.Fatal(err)
	}
	client, err := privateClassTransport(server.URL, "", leaf, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(server.URL)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CLASS_PREPARE_PINNED_TLS_REFUSED: %v", err)
	}
	response.Body.Close()
}
