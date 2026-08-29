package controllerupgrade

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	testTenant = "11111111111111111111111111111111"
	testPDA    = "11111111111111111111111111111111"
	testHex    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testHex2   = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
)

func testReceipt(t *testing.T, now time.Time) (Receipt, VerificationConfig, ed25519.PrivateKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := Receipt{
		Schema: ReceiptSchema, ReceiptID: testHex, TenantLicenseNftMint: testTenant,
		TargetControllerID: TargetControllerID, CandidateVersion: "1.0.56",
		CandidateArtifactName: "melusina-update-controller-1.0.56-linux-amd64",
		CandidateSHA256:       testHex, CandidateSizeBytes: 4096, ExpectedPreviousSHA256: testHex2,
		InstallerReleasePDA: testPDA, InstallerReleaseSHA256: testHex,
		PlanDigest: testHex2, SquadsProofDigest: testHex,
		RequiredFlags: append([]string(nil), RequiredControllerFlags...), Challenge: testHex2,
		IssuedAtUnix: now.Add(-time.Minute).Unix(), ExpiresAtUnix: now.Add(10 * time.Minute).Unix(),
	}
	if err := r.Sign(private); err != nil {
		t.Fatal(err)
	}
	return r, VerificationConfig{TenantLicenseNftMint: testTenant, StoreReceiptPublicKey: r.SignerPublicKey, Now: func() time.Time { return now }}, private
}

func TestReceiptSignVerifyAndRejectsScopeWidening(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	r, cfg, private := testReceipt(t, now)
	if err := r.Verify(cfg, testHex2); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	for name, mutate := range map[string]func(*Receipt){
		"wrong tenant":         func(got *Receipt) { got.TenantLicenseNftMint = "11111111111111111111111111111112" },
		"flag downgrade":       func(got *Receipt) { got.RequiredFlags = got.RequiredFlags[:3] },
		"wrong controller":     func(got *Receipt) { got.TargetControllerID = "fineract-sidecar" },
		"unsafe artifact name": func(got *Receipt) { got.CandidateArtifactName = "../controller" },
		"zero artifact size":   func(got *Receipt) { got.CandidateSizeBytes = 0 },
		"expired": func(got *Receipt) {
			got.IssuedAtUnix = now.Add(-20 * time.Minute).Unix()
			got.ExpiresAtUnix = now.Add(-time.Minute).Unix()
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := r
			mutate(&got)
			if err := got.Sign(private); err != nil {
				t.Fatal(err)
			}
			if err := got.Verify(cfg, testHex2); err == nil {
				t.Fatal("Verify() accepted a widened receipt")
			}
		})
	}
}

func TestDecodeReceiptRejectsDuplicateUnknownAndTrailingFields(t *testing.T) {
	r, _, _ := testReceipt(t, time.Unix(1_700_000_000, 0).UTC())
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeReceipt(raw); err != nil {
		t.Fatalf("DecodeReceipt(valid): %v", err)
	}
	for _, raw := range [][]byte{
		[]byte(strings.Replace(string(raw), "{", `{"receiptId":"`+testHex+`",`, 1)),
		[]byte(strings.Replace(string(raw), "{", `{"unexpected":true,`, 1)),
		append(raw, []byte(" {}")...),
	} {
		if _, err := DecodeReceipt(raw); err == nil {
			t.Fatal("DecodeReceipt accepted malformed receipt JSON")
		}
	}
}
