package estateprofile

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// Producer-owned D50 statement-v1 checks beside the locked C1 D50 contract:
// the statement preimage rebuilds byte for byte, the digest binding refuses a
// foreign digest by name, the charter binding is exact, and statement-form
// signatures verify over the rebuilt statement bytes while digest-form
// signatures are refused. The locked test holds the wire refusals; these hold
// the rebuilt bytes, the success path and the binding.
func TestD50StatementPreimageRebuildsExactly(t *testing.T) {
	document := c1FoundationStatement(t)
	value, err := DecodeFoundationAuthorization(document.Authorization)
	if err != nil {
		t.Fatalf("D50_STATEMENT_DECODE: %v", err)
	}
	digest, err := VerifyFoundationAuthorization(value, mustTime(t, document.FixtureClock))
	if err != nil {
		t.Fatalf("D50_STATEMENT_VERIFY: %v", err)
	}
	if digest != document.SHA256 {
		t.Fatalf("D50_STATEMENT_DIGEST: got %s, want %s", digest, document.SHA256)
	}
	preimage, err := FoundationAuthorizationPreimage(value)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256Hex(preimage); got != document.SHA256 {
		t.Fatalf("D50_STATEMENT_PREIMAGE_DIGEST: preimage sha %s, document digest %s", got, document.SHA256)
	}
	// The owner statement is transport metadata: it is NOT part of the
	// binary preimage. Rebuild the statement sentence from the DECODED
	// document (not the vector) and check it is exactly the signed bytes.
	statement := FoundationOwnerStatementBytes(value)
	want := "Melusina owner document\nkind=" + value.OwnerStatement.Kind +
		"\nestate=" + value.OwnerStatement.EstateWords +
		"\nexpires=" + value.OwnerStatement.Expiry +
		"\ndigest=" + value.OwnerStatement.Digest
	if statement != want {
		t.Fatalf("D50_STATEMENT_REBUILD: %q, want %q", statement, want)
	}
	if got := sha256Hex([]byte(statement)); got != "9cc7068e0358cf9d385819f23dbba2cedfc76ab1594121255d1bef51694fc11d" {
		t.Fatalf("D50_STATEMENT_REBUILD_DIGEST: %s", got)
	}
}

func TestD50StatementDigestBindingRefusesForeignDigest(t *testing.T) {
	document := c1FoundationStatement(t)
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(document.Authorization, &wire); err != nil {
		t.Fatal(err)
	}
	var statement map[string]json.RawMessage
	if err := json.Unmarshal(wire["ownerStatement"], &statement); err != nil {
		t.Fatal(err)
	}
	statement["digest"] = json.RawMessage(`"` + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + `"`)
	changed, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	wire["ownerStatement"] = changed
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	value, err := DecodeFoundationAuthorization(raw)
	if err != nil {
		t.Fatalf("D50_FOREIGN_DIGEST_DECODE: %v", err)
	}
	_, err = VerifyFoundationAuthorization(value, mustTime(t, document.FixtureClock))
	if err == nil || err.Error() != "owner-statement-mismatch" {
		t.Fatalf("D50_FOREIGN_DIGEST_ACCEPTED: got %v", err)
	}
}

func TestD50CharterBindingPositiveAndMismatch(t *testing.T) {
	document := c1FoundationStatement(t)
	value, err := DecodeFoundationAuthorization(document.Authorization)
	if err != nil {
		t.Fatalf("D50_CHARTER_DECODE: %v", err)
	}
	if err := RequireFoundationCharter(value, document.CharterSHA256); err != nil {
		t.Fatalf("D50_CHARTER_BINDING_REFUSED: %v", err)
	}
	if err := RequireFoundationCharter(value, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"); err == nil || err.Error() != "charter-digest-mismatch" {
		t.Fatalf("D50_CHARTER_MISMATCH_REFUSAL: got %v", err)
	}
}

func TestD50StatementFormSignatureVerifiedAndDigestFormRefused(t *testing.T) {
	document := c1FoundationStatement(t)
	value, err := DecodeFoundationAuthorization(document.Authorization)
	if err != nil {
		t.Fatalf("D50_SIGNATURE_FORM_DECODE: %v", err)
	}
	if value.SigningForm != "statement-v1" {
		t.Fatalf("D50_SIGNATURE_FORM: %q", value.SigningForm)
	}
	// Positive: every signature verifies over the rebuilt statement bytes.
	statement := FoundationOwnerStatementBytes(value)
	keys := map[string]ed25519.PublicKey{}
	for _, signer := range value.GenesisOwnerPolicy.Signers {
		key, ok := decodeEd25519PublicKey(signer.Ed25519PublicKey)
		if !ok {
			t.Fatalf("D50_STATEMENT_SIGNER_KEY: %s", signer.KeyID)
		}
		keys[signer.KeyID] = key
	}
	for _, signature := range value.Signatures {
		raw, err := base64.RawURLEncoding.DecodeString(signature.Signature)
		if err != nil || !ed25519.Verify(keys[signature.KeyID], []byte(statement), raw) {
			t.Fatalf("D50_STATEMENT_SIGNATURE_INVALID: %s", signature.KeyID)
		}
	}
	// Negative: the same policy keys signing the DIGEST instead of the
	// statement bytes are refused by name.
	var legacyView FoundationAuthorizationV1
	if err := json.Unmarshal(document.Authorization, &legacyView); err != nil {
		t.Fatal(err)
	}
	tampered := c1D50EditedAuthorization(t, func(doc map[string]json.RawMessage) {
		signatures := signDigest(legacyView.GenesisOwnerPolicy, document.SHA256, "owner-a", "owner-b")
		changed, err := json.Marshal(signatures)
		if err != nil {
			t.Fatal(err)
		}
		doc["signatures"] = changed
	})
	if err := c1D50VerifyAtFixtureTime(t, tampered); err == nil || err.Error() != "owner-signature-invalid" {
		t.Fatalf("D50_DIGEST_FORM_SIGNATURE_ACCEPTED: got %v", err)
	}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
