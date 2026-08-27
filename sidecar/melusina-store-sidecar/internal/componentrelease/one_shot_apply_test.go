package componentrelease

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
)

const oneShotNow int64 = 1784282400

func signedOneShotFixture(t *testing.T) (*identity.Private, ed25519.PublicKey, OneShotApplyAuthorization, OneShotApplyExpectation) {
	t.Helper()
	op, pub := testOperator(t)
	gen, err := Sign(op, sampleGeneration())
	if err != nil {
		t.Fatalf("sign generation fixture: %v", err)
	}
	var component ComponentRelease
	for _, c := range gen.Components {
		if c.ComponentID == "melusina-store-sidecar" {
			component = c
			break
		}
	}
	if component.ComponentID == "" {
		t.Fatal("fixture has no sidecar component")
	}
	expected := OneShotApplyExpectation{
		ExpectedStoreID:      gen.StoreID,
		TargetControllerID:   "fineract-controller",
		TargetLicenseNftMint: component.Chain.LicenseNftMint,
		ComponentID:          "melusina-store-sidecar",
		GenerationID:         gen.GenerationID,
		GenerationHash:       gen.GenerationHash,
		RawGenerationSHA256:  strings.Repeat("7", 64),
		Component:            component,
		NowUnix:              oneShotNow,
	}
	a := OneShotApplyAuthorization{
		AuthorizationID:         strings.Repeat("a", 64),
		StoreID:                 expected.ExpectedStoreID,
		TargetControllerID:      expected.TargetControllerID,
		TargetLicenseNftMint:    expected.TargetLicenseNftMint,
		ComponentID:             expected.ComponentID,
		GenerationID:            expected.GenerationID,
		GenerationHash:          expected.GenerationHash,
		RawGenerationSHA256:     expected.RawGenerationSHA256,
		ComponentDigest:         ComponentReleaseDigestHex(component),
		ComponentSHA256:         component.SHA256,
		ComponentVersion:        component.Version,
		PreviousSHA256:          component.PreviousSHA256,
		IssuedAtUnix:            oneShotNow - 30,
		ExpiresAtUnix:           oneShotNow + 600,
		GovernanceReceiptID:     "governance-receipt-7f3",
		GovernanceReceiptSHA256: strings.Repeat("b", 64),
	}
	signed, err := SignOneShotApplyAuthorization(op, a)
	if err != nil {
		t.Fatalf("sign one-shot fixture: %v", err)
	}
	return op, pub, signed, expected
}

func TestOneShotApplyAuthorizationRoundTrip(t *testing.T) {
	_, pub, signed, expected := signedOneShotFixture(t)
	if signed.Schema != OneShotApplyAuthorizationSchema {
		t.Fatalf("schema = %q", signed.Schema)
	}
	if err := VerifyOneShotApplyAuthorization(pub, expected, signed); err != nil {
		t.Fatalf("verify valid one-shot receipt: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip OneShotApplyAuthorization
	if err := json.Unmarshal(raw, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOneShotApplyAuthorization(pub, expected, roundTrip); err != nil {
		t.Fatalf("verify JSON round trip: %v", err)
	}
}

func TestOneShotApplyAuthorizationRejectsWrongControllerBeforeSignatureUse(t *testing.T) {
	_, pub, signed, expected := signedOneShotFixture(t)
	expected.TargetControllerID = "other-controller"
	if err := VerifyOneShotApplyAuthorization(pub, expected, signed); err == nil {
		t.Fatal("accepted receipt for a different controller")
	}
}

func TestOneShotApplyAuthorizationRejectsGenerationAndComponentDrift(t *testing.T) {
	_, pub, signed, expected := signedOneShotFixture(t)
	expected.RawGenerationSHA256 = strings.Repeat("8", 64)
	if err := VerifyOneShotApplyAuthorization(pub, expected, signed); err == nil {
		t.Fatal("accepted a receipt for different served generation bytes")
	}

	_, pub, signed, expected = signedOneShotFixture(t)
	expected.Component.Version = "9.9.9"
	if err := VerifyOneShotApplyAuthorization(pub, expected, signed); err == nil {
		t.Fatal("accepted a receipt for a different component tuple")
	}
}

func TestOneShotApplyAuthorizationRejectsExpiredFutureAndOverlongReceipts(t *testing.T) {
	op, pub, signed, expected := signedOneShotFixture(t)
	signed.ExpiresAtUnix = expected.NowUnix
	if err := VerifyOneShotApplyAuthorization(pub, expected, signed); err == nil {
		t.Fatal("accepted expired receipt")
	}

	_, pub, signed, expected = signedOneShotFixture(t)
	signed.IssuedAtUnix = expected.NowUnix + 121
	if err := VerifyOneShotApplyAuthorization(pub, expected, signed); err == nil {
		t.Fatal("accepted materially future receipt")
	}

	_, pub, signed, expected = signedOneShotFixture(t)
	signed.IssuedAtUnix = expected.NowUnix - MaxOneShotApplyAuthorizationTTLSeconds - 1
	signed.ExpiresAtUnix = expected.NowUnix + 1
	if err := VerifyOneShotApplyAuthorization(pub, expected, signed); err == nil {
		t.Fatal("accepted an overlong receipt after tampering")
	}

	// Sign itself refuses an overlong lifetime before it can become a Store
	// artifact; this checks the producer and not just controller verification.
	_, _, unsigned, _ := signedOneShotFixture(t)
	unsigned.IssuedAtUnix = oneShotNow
	unsigned.ExpiresAtUnix = oneShotNow + MaxOneShotApplyAuthorizationTTLSeconds + 1
	if _, err := SignOneShotApplyAuthorization(op, unsigned); err == nil {
		t.Fatal("producer signed an overlong receipt")
	}
}

func TestOneShotApplyAuthorizationRejectsUnauthorizedOrTamperedSignature(t *testing.T) {
	_, _, signed, expected := signedOneShotFixture(t)
	_, other := testOperator(t)
	if err := VerifyOneShotApplyAuthorization(other, expected, signed); err == nil {
		t.Fatal("accepted receipt under an unpinned Store operator key")
	}

	_, pub, signed, expected := signedOneShotFixture(t)
	signed.GovernanceReceiptSHA256 = strings.Repeat("c", 64)
	if err := VerifyOneShotApplyAuthorization(pub, expected, signed); err == nil {
		t.Fatal("accepted a tampered governance receipt binding")
	}
}
