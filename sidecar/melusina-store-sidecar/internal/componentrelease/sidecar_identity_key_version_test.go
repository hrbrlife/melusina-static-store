package componentrelease

// A sidecar_identity component's keyVersion is a seed of its
// SidecarIdentityEntry address and is signed; every consumer derives with the
// signed value, so 0 (what an omitted keyVersion decodes to) is refused by
// name rather than read as 1 (seam audit round 4, finding 9). Sign refuses to
// produce such a document, and Verify, which the Store's serve gate and every
// tenant update controller run, refuses one already signed.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// keyBearingComponentIndex returns the index of the sample generation's
// sidecar_identity component.
func keyBearingComponentIndex(t *testing.T, doc DesiredGeneration) int {
	t.Helper()
	for i, c := range doc.Components {
		if c.Chain.Kind == AuthoritySidecarIdentity {
			return i
		}
	}
	t.Fatal("sample generation has no sidecar_identity component")
	return -1
}

func TestSidecarIdentityKeyVersionZeroIsRefusedByName(t *testing.T) {
	op, pub := testOperator(t)

	// Positive control: key versions 1 and 2 are structurally valid, sign and
	// verify.
	for _, keyVersion := range []uint32{1, 2} {
		doc := sampleGeneration()
		doc.Components[keyBearingComponentIndex(t, doc)].Chain.KeyVersion = keyVersion
		signed, err := Sign(op, doc)
		if err != nil {
			t.Fatalf("sidecar-identity-key-version-%d-refused-at-sign: %v", keyVersion, err)
		}
		if err := Verify(pub, "melusina-os-root-store", signed); err != nil {
			t.Fatalf("sidecar-identity-key-version-%d-refused-at-verify: %v", keyVersion, err)
		}
	}

	// An omitted keyVersion: the component's JSON carries no keyVersion key,
	// and it decodes to 0.
	doc := sampleGeneration()
	i := keyBearingComponentIndex(t, doc)
	raw, err := json.Marshal(doc.Components[i])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	var chain map[string]json.RawMessage
	if err := json.Unmarshal(fields["chain"], &chain); err != nil {
		t.Fatal(err)
	}
	if _, ok := chain["keyVersion"]; !ok {
		t.Fatal("sample sidecar_identity component carries no keyVersion to omit")
	}
	delete(chain, "keyVersion")
	if fields["chain"], err = json.Marshal(chain); err != nil {
		t.Fatal(err)
	}
	if raw, err = json.Marshal(fields); err != nil {
		t.Fatal(err)
	}
	var omitted ComponentRelease
	if err := json.Unmarshal(raw, &omitted); err != nil {
		t.Fatal(err)
	}
	if omitted.Chain.KeyVersion != 0 {
		t.Fatalf("an omitted keyVersion decoded as %d", omitted.Chain.KeyVersion)
	}
	doc.Components[i] = omitted

	err = omitted.validate()
	if !errors.Is(err, ErrSidecarIdentityKeyVersionZero) || !strings.Contains(err.Error(), "sidecar-identity-key-version-zero") {
		t.Fatalf("sidecar-identity-key-version-zero-accepted-at-validate: %v", err)
	}
	if _, err := Sign(op, doc); !errors.Is(err, ErrSidecarIdentityKeyVersionZero) {
		t.Fatalf("sidecar-identity-key-version-zero-accepted-at-sign: %v", err)
	}
	// A generation signed before this rule (the Store used to read 0 as 1 and
	// sign it): Verify refuses the bytes by the same name, although the
	// signature is valid.
	signed := signSkippingValidation(t, op, doc)
	if err := Verify(pub, "melusina-os-root-store", signed); !errors.Is(err, ErrSidecarIdentityKeyVersionZero) {
		t.Fatalf("sidecar-identity-key-version-zero-accepted-at-verify: %v", err)
	}
	// Mutate the control: the same signed-skipping document at key version 1
	// verifies, so the refusal above is the key version's.
	doc.Components[i].Chain.KeyVersion = 1
	if err := Verify(pub, "melusina-os-root-store", signSkippingValidation(t, op, doc)); err != nil {
		t.Fatalf("sidecar-identity-key-version-control-inert: key version 1 refused: %v", err)
	}
}
