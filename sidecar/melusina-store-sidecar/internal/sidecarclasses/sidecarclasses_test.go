package sidecarclasses

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
)

func testOperator(t *testing.T, sidecarID string) *identity.Private {
	t.Helper()
	var signSeed, boxSeed [32]byte
	for i := range signSeed {
		signSeed[i] = byte(i + 1)
		boxSeed[i] = byte(i + 2)
	}
	// Domain-separate the test identities by id so two calls never share keys.
	seedTag := sha256.Sum256([]byte("sidecarclasses-test:" + sidecarID))
	signSeed = seedTag
	ref := identity.Ref{
		Kind: identity.KindSidecar, ChainID: "solana:devnet",
		ProgramID: "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
		// LicenseMint must be a base58 32-byte value; a synthetic one is fine
		// for a signature test.
		LicenseMint: "So11111111111111111111111111111111111111112",
		Domain:      "bazaar.melusina-os.org", PDA: "11111111111111111111111111111111",
		SidecarID: sidecarID, KeyVersion: 1,
	}
	op, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

func fixtureRows() []Row {
	return []Row{
		{ID: "mermail", Class: ClassCascade, KeyCustody: CustodyNone, DeclaredAt: "2026-09-27T00:00:00Z", Source: "registry.go@0c695588+chaingate.go:262"},
		{ID: "swaprail", Class: ClassIdentity, KeyCustody: CustodySidecarHeldIdentit, DeclaredAt: "2026-09-27T00:00:00Z", Source: "registry.go@0c695588+repos"},
	}
}

func signedFixture(t *testing.T, op *identity.Private) Table {
	t.Helper()
	doc, err := Sign(op, Table{StoreID: "melusina-os-root-store", SignedAtUnix: 1789000000, Rows: fixtureRows()})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func authorizedKey(t *testing.T, op *identity.Private) ed25519.PublicKey {
	t.Helper()
	pub, err := op.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	op := testOperator(t, "store")
	doc := signedFixture(t, op)
	if err := Verify(authorizedKey(t, op), "melusina-os-root-store", doc); err != nil {
		t.Fatalf("valid signed table refused: %v", err)
	}
	if doc.Count() != 2 {
		t.Fatalf("row count: %d", doc.Count())
	}
	if class, ok := doc.ClassFor("mermail"); !ok || class != ClassCascade {
		t.Fatalf("mermail class: %q %v", class, ok)
	}
	if custody, ok := doc.CustodyFor("swaprail"); !ok || custody != CustodySidecarHeldIdentit {
		t.Fatalf("swaprail custody: %q %v", custody, ok)
	}
}

func TestSignatureBinding(t *testing.T) {
	op := testOperator(t, "store")
	doc := signedFixture(t, op)
	pub := authorizedKey(t, op)

	// One-byte mutation of the signed row set -> signature refuses.
	mutated := doc
	mutated.Rows = append([]Row(nil), doc.Rows...)
	mutated.Rows[0].Class = ClassIdentity
	mutated.Rows[0].KeyCustody = CustodySidecarHeldIdentit
	if err := Verify(pub, "melusina-os-root-store", mutated); err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("mutated table accepted: %v", err)
	}

	// A non-authorized (unknown) signer key is refused even over identical bytes.
	other := testOperator(t, "other")
	otherDoc := signedFixture(t, other)
	if err := Verify(pub, "melusina-os-root-store", otherDoc); err == nil || !strings.Contains(err.Error(), "signer mismatch") {
		t.Fatalf("unknown-key table accepted: %v", err)
	}

	// Empty destination is a bypass, never a wildcard.
	if err := Verify(pub, "", doc); err == nil || !strings.Contains(err.Error(), "destination") {
		t.Fatalf("empty destination accepted: %v", err)
	}
	if err := Verify(pub, "other-store", doc); err == nil || !strings.Contains(err.Error(), "destination mismatch") {
		t.Fatalf("wrong destination accepted: %v", err)
	}
}

func TestRowValidation(t *testing.T) {
	op := testOperator(t, "store")
	cases := []struct {
		name string
		row  Row
		want string
	}{
		{"unknown class", Row{ID: "x", Class: "sidecar_keyless", KeyCustody: CustodyNone, DeclaredAt: "t", Source: "s"}, "unknown class"},
		{"cascade with keys", Row{ID: "x", Class: ClassCascade, KeyCustody: CustodySidecarHeldIdentit, DeclaredAt: "t", Source: "s"}, "holds no keys"},
		{"identity without keys", Row{ID: "x", Class: ClassIdentity, KeyCustody: CustodyNone, DeclaredAt: "t", Source: "s"}, "must declare keyCustody"},
		{"no source", Row{ID: "x", Class: ClassCascade, KeyCustody: CustodyNone, DeclaredAt: "t"}, "derivation source"},
		{"duplicate", Row{ID: "mermail", Class: ClassCascade, KeyCustody: CustodyNone, DeclaredAt: "t", Source: "s"}, "more than once"},
	}
	for _, tc := range cases {
		rows := append(fixtureRows(), tc.row)
		if _, err := Sign(op, Table{StoreID: "s", SignedAtUnix: 1, Rows: rows}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: accepted without %q: %v", tc.name, tc.want, err)
		}
	}
}

func TestDeterministicContentHash(t *testing.T) {
	a := ContentHash(fixtureRows())
	b := ContentHash([]Row{fixtureRows()[1], fixtureRows()[0]}) // order is not signable freedom
	if a != b {
		t.Fatal("row order changed the canonical content hash")
	}
	sum := sha256.Sum256(nil)
	_ = sum
	raw, err := json.Marshal(signedFixture(t, testOperator(t, "store")))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"class":"sidecar_cascade"`) {
		t.Fatalf("canonical json shape drifted: %s", raw)
	}
}
