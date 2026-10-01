package estateprofile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

type c1StatementVector struct {
	Schema    string `json:"schema"`
	Threshold int    `json:"signerThreshold"`
	Signers   []struct {
		KeyID     string `json:"keyId"`
		PublicKey string `json:"ed25519PublicKey"`
	} `json:"signers"`
	Documents []struct {
		Kind            string        `json:"kind"`
		EstateWords     string        `json:"estateWords"`
		Expiry          string        `json:"expiry"`
		Digest          string        `json:"digest"`
		Statement       string        `json:"statement"`
		PreimageHex     string        `json:"preimageHex"`
		StatementSHA256 string        `json:"statementSha256"`
		Signatures      []SignatureV1 `json:"signatures"`
	} `json:"documents"`
}

func TestC1D50StatementBytesAndSignaturesAcrossKinds(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/owner-statement-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors c1StatementVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "melusina.owner.statement-v1-vectors.v1" || vectors.Threshold != 2 || len(vectors.Documents) != 6 {
		t.Fatalf("D50_STATEMENT_VECTOR_HEADER: schema=%s threshold=%d kinds=%d", vectors.Schema, vectors.Threshold, len(vectors.Documents))
	}
	keys := map[string]ed25519.PublicKey{}
	for _, signer := range vectors.Signers {
		key, err := hex.DecodeString(signer.PublicKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			t.Fatalf("D50_STATEMENT_SIGNER_KEY: %s: %v", signer.KeyID, err)
		}
		keys[signer.KeyID] = key
	}
	for _, row := range vectors.Documents {
		t.Run(row.Kind, func(t *testing.T) {
			want := fmt.Sprintf("Melusina owner document\nkind=%s\nestate=%s\nexpires=%s\ndigest=%s", row.Kind, row.EstateWords, row.Expiry, row.Digest)
			if row.Statement != want || hex.EncodeToString([]byte(want)) != row.PreimageHex {
				t.Fatal("D50_STATEMENT_PREIMAGE_DRIFT")
			}
			sum := sha256.Sum256([]byte(want))
			if hex.EncodeToString(sum[:]) != row.StatementSHA256 {
				t.Fatal("D50_STATEMENT_DIGEST_DRIFT")
			}
			if len(row.Signatures) < vectors.Threshold {
				t.Fatal("D50_STATEMENT_THRESHOLD_UNMET")
			}
			for _, signature := range row.Signatures {
				wire, err := base64.RawURLEncoding.DecodeString(signature.Signature)
				if err != nil || !ed25519.Verify(keys[signature.KeyID], []byte(want), wire) {
					t.Fatalf("D50_STATEMENT_SIGNATURE_INVALID: %s", signature.KeyID)
				}
			}
		})
	}
}

func TestC1D50GeneratedFoundationVectorSemantics(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/foundation-authorization-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Schema         string `json:"schema"`
		Authorizations []struct {
			Name          string          `json:"name"`
			Authorization json.RawMessage `json:"authorization"`
			PreimageHex   string          `json:"preimageHex"`
			SHA256        string          `json:"sha256"`
		} `json:"authorizations"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "melusina.estate.foundation-authorization-vectors.v1" {
		t.Fatalf("D50_FOUNDATION_VECTOR_SCHEMA: %s", vectors.Schema)
	}
	found := false
	for _, row := range vectors.Authorizations {
		if row.Name != "new-estate-foundation" {
			continue
		}
		found = true
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(row.Authorization, &wire); err != nil {
			t.Fatal(err)
		}
		var signingForm string
		if err := json.Unmarshal(wire["signingForm"], &signingForm); err != nil || signingForm != "statement-v1" ||
			len(wire["ownerStatement"]) == 0 || len(wire["estateCharterSha256"]) == 0 {
			t.Fatalf("D50_FOUNDATION_VECTOR_SIGNING_FORM_MISSING: %s, %v", signingForm, err)
		}
		document, err := DecodeFoundationAuthorization(row.Authorization)
		if err != nil {
			t.Fatalf("D50_FOUNDATION_VECTOR_DECODE: %v", err)
		}
		if document.GenesisOwnerPolicy.Threshold < 2 || len(document.Signatures) < int(document.GenesisOwnerPolicy.Threshold) {
			t.Fatal("D50_FOUNDATION_VECTOR_THRESHOLD")
		}
		preimage, err := FoundationAuthorizationPreimage(document)
		if err != nil || hex.EncodeToString(preimage) != row.PreimageHex {
			t.Fatalf("D50_FOUNDATION_VECTOR_PREIMAGE: %v", err)
		}
		issued, err := time.Parse(time.RFC3339, document.IssuedAt)
		if err != nil {
			t.Fatal(err)
		}
		expires, err := time.Parse(time.RFC3339, document.ExpiresAt)
		if err != nil || !expires.After(issued) {
			t.Fatalf("D50_FOUNDATION_VECTOR_EXPIRY: %v", err)
		}
		got, err := VerifyFoundationAuthorization(document, issued.Add(expires.Sub(issued)/2))
		if err != nil || got != row.SHA256 {
			t.Fatalf("D50_FOUNDATION_VECTOR_SIGNATURE: got %s, %v; want %s", got, err, row.SHA256)
		}
	}
	if !found {
		t.Fatal("D50_FOUNDATION_VECTOR_CASE_MISSING: new-estate-foundation")
	}
}

type c1FoundationStatementVector struct {
	FixtureClock  string          `json:"fixtureClock"`
	CharterSHA256 string          `json:"charterSha256"`
	Authorization json.RawMessage `json:"authorization"`
	SHA256        string          `json:"sha256"`
}

func c1FoundationStatement(t *testing.T) c1FoundationStatementVector {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/foundation-authorization-statement-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector c1FoundationStatementVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func TestC1D50FoundationStatementVerifier(t *testing.T) {
	vector := c1FoundationStatement(t)
	document, err := DecodeFoundationAuthorization(vector.Authorization)
	if err != nil {
		t.Fatalf("D50_FOUNDATION_STATEMENT_DECODE: %v", err)
	}
	now, err := time.Parse(time.RFC3339, vector.FixtureClock)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyFoundationAuthorization(document, now)
	if err != nil || got != vector.SHA256 {
		t.Fatalf("D50_FOUNDATION_STATEMENT_VERIFY: got %s, %v; want %s", got, err, vector.SHA256)
	}
}

func TestC1D50SuppliedStatementCannotOverrideDocument(t *testing.T) {
	vector := c1FoundationStatement(t)
	var document map[string]json.RawMessage
	if err := json.Unmarshal(vector.Authorization, &document); err != nil {
		t.Fatal(err)
	}
	var statement map[string]json.RawMessage
	if err := json.Unmarshal(document["ownerStatement"], &statement); err != nil {
		t.Fatal(err)
	}
	statement["digest"] = json.RawMessage(`"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`)
	changed, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	document["ownerStatement"] = changed
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	value, err := DecodeFoundationAuthorization(raw)
	if err == nil {
		now, parseErr := time.Parse(time.RFC3339, vector.FixtureClock)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		_, err = VerifyFoundationAuthorization(value, now)
	}
	if err == nil || err.Error() != "owner-statement-mismatch" {
		t.Fatalf("D50_OWNER_STATEMENT_MISMATCH: got %v", err)
	}
	c1D50RequireValidStatement(t)
}

func c1D50RequireValidStatement(t *testing.T) {
	t.Helper()
	vector := c1FoundationStatement(t)
	if err := c1D50VerifyAtFixtureTime(t, vector.Authorization); err != nil {
		t.Fatalf("D50_VALID_STATEMENT_REFUSED: %v", err)
	}
}

func c1D50EditedAuthorization(t *testing.T, edit func(map[string]json.RawMessage)) []byte {
	t.Helper()
	vector := c1FoundationStatement(t)
	var document map[string]json.RawMessage
	if err := json.Unmarshal(vector.Authorization, &document); err != nil {
		t.Fatal(err)
	}
	edit(document)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func c1D50VerifyAtFixtureTime(t *testing.T, raw []byte) error {
	t.Helper()
	vector := c1FoundationStatement(t)
	value, err := DecodeFoundationAuthorization(raw)
	if err != nil {
		return err
	}
	now, err := time.Parse(time.RFC3339, vector.FixtureClock)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyFoundationAuthorization(value, now)
	return err
}

func TestC1D50MissingStatementNeverFallsBack(t *testing.T) {
	raw := c1D50EditedAuthorization(t, func(document map[string]json.RawMessage) {
		delete(document, "ownerStatement")
	})
	if err := c1D50VerifyAtFixtureTime(t, raw); err == nil || err.Error() != "owner-statement-mismatch" {
		t.Fatalf("D50_MISSING_STATEMENT_FALLBACK: got %v", err)
	}
	c1D50RequireValidStatement(t)
}

func TestC1D50UnknownStatementKindRefused(t *testing.T) {
	raw := c1D50EditedAuthorization(t, func(document map[string]json.RawMessage) {
		var statement map[string]json.RawMessage
		if err := json.Unmarshal(document["ownerStatement"], &statement); err != nil {
			t.Fatal(err)
		}
		statement["kind"] = json.RawMessage(`"arbitrary-message"`)
		changed, err := json.Marshal(statement)
		if err != nil {
			t.Fatal(err)
		}
		document["ownerStatement"] = changed
	})
	if err := c1D50VerifyAtFixtureTime(t, raw); err == nil || err.Error() != "owner-document-kind-unknown" {
		t.Fatalf("D50_OWNER_DOCUMENT_KIND_UNKNOWN: got %v", err)
	}
	c1D50RequireValidStatement(t)
}

func TestC1D50CharterDigestBinding(t *testing.T) {
	vector := c1FoundationStatement(t)
	value, err := DecodeFoundationAuthorization(vector.Authorization)
	if err != nil {
		t.Fatalf("D50_CHARTER_DOCUMENT_DECODE: %v", err)
	}
	if err := RequireFoundationCharter(value, vector.CharterSHA256); err != nil {
		t.Fatalf("D50_CHARTER_DIGEST_ACCEPTED: %v", err)
	}
	if err := RequireFoundationCharter(value, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err == nil || err.Error() != "charter-digest-mismatch" {
		t.Fatalf("D50_CHARTER_DIGEST_MISMATCH: got %v", err)
	}
}

func TestC1D50DigestOnlySignatureCannotSatisfyStatementForm(t *testing.T) {
	vector := c1FoundationStatement(t)
	var legacyView FoundationAuthorizationV1
	if err := json.Unmarshal(vector.Authorization, &legacyView); err != nil {
		t.Fatal(err)
	}
	raw := c1D50EditedAuthorization(t, func(document map[string]json.RawMessage) {
		signatures := signDigest(legacyView.GenesisOwnerPolicy, vector.SHA256, "owner-a", "owner-b")
		changed, err := json.Marshal(signatures)
		if err != nil {
			t.Fatal(err)
		}
		document["signatures"] = changed
	})
	if err := c1D50VerifyAtFixtureTime(t, raw); err == nil || err.Error() != "owner-signature-invalid" {
		t.Fatalf("D50_DIGEST_ONLY_SIGNATURE_REFUSED: got %v", err)
	}
	c1D50RequireValidStatement(t)
}
