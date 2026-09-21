package estateprofile

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	foundationAuthorizationIssuedAt  = "2026-09-21T01:00:00Z"
	foundationAuthorizationExpiresAt = "2026-09-21T02:00:00Z"
)

func foundationAuthorizationNow(t *testing.T) time.Time {
	t.Helper()
	now, err := time.Parse("2006-01-02T15:04:05Z", "2026-09-21T01:30:00Z")
	if err != nil {
		t.Fatal(err)
	}
	return now
}

func signFoundationAuthorization(t *testing.T, value FoundationAuthorizationV1, keyIDs ...string) FoundationAuthorizationV1 {
	t.Helper()
	value.Signatures = nil
	digest, err := FoundationAuthorizationSHA256(value)
	if err != nil {
		t.Fatalf("digest foundation authorization: %v", err)
	}
	value.Signatures = signDigest(value.GenesisOwnerPolicy, digest, keyIDs...)
	return value
}

// newFoundationAuthorization is entirely fictitious public vector input. The
// underlying policy/estate identity is the same deterministic test material as
// newEstateProfile; it has no authority outside this package.
func newFoundationAuthorization(t *testing.T) FoundationAuthorizationV1 {
	t.Helper()
	profile := newEstateProfile(t)
	value := FoundationAuthorizationV1{
		Schema:                FoundationAuthorizationSchema,
		Kind:                  FoundationAuthorizationKind,
		Purpose:               FoundationAuthorizationPurpose,
		EstateID:              profile.EstateID,
		EstateNonce:           profile.EstateNonce,
		GenesisOwnerPolicy:    profile.GenesisOwnerPolicy,
		CeremonyProfileSchema: FoundationCeremonyProfileSchema,
		CeremonyProfileSHA256: vectorDigest("foundation/ceremony-profile"),
		ReleaseSetSHA256:      vectorDigest("foundation/release-set"),
		TargetBindingSHA256:   vectorDigest("foundation/target-binding"),
		NetworkGenesisHash:    profile.Network.GenesisHash,
		IssuedAt:              foundationAuthorizationIssuedAt,
		ExpiresAt:             foundationAuthorizationExpiresAt,
		AuthorizationNonce:    vectorDigest("foundation/authorization-nonce"),
	}
	return signFoundationAuthorization(t, value, "owner-a", "owner-b")
}

func TestVerifyFoundationAuthorizationAcceptsExactlyTheGenesisThreshold(t *testing.T) {
	value := newFoundationAuthorization(t)
	if got, want := len(value.Signatures), int(value.GenesisOwnerPolicy.Threshold); got != want {
		t.Fatalf("positive control has %d signatures, want exactly threshold %d", got, want)
	}
	got, err := VerifyFoundationAuthorization(value, foundationAuthorizationNow(t))
	if err != nil {
		t.Fatalf("verify exact-threshold foundation authorization: %v", err)
	}
	want, err := FoundationAuthorizationSHA256(value)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("VerifyFoundationAuthorization digest = %s, want %s", got, want)
	}
}

func TestFoundationAuthorizationBindsEveryStaticRunnerInput(t *testing.T) {
	value := newFoundationAuthorization(t)
	_, err := RequireFoundationInputs(value, FoundationCeremonyProfileSchema, value.CeremonyProfileSHA256, value.ReleaseSetSHA256, value.TargetBindingSHA256, foundationAuthorizationNow(t))
	if err != nil {
		t.Fatalf("exact static input binding: %v", err)
	}
	for _, item := range []struct {
		name string
		call func() error
		want string
	}{
		{
			name: "ceremony schema", want: RefusalFoundationAuthorizationCeremonySchemaMismatch,
			call: func() error {
				_, err := RequireFoundationInputs(value, "melusina.estate-profile/v2", value.CeremonyProfileSHA256, value.ReleaseSetSHA256, value.TargetBindingSHA256, foundationAuthorizationNow(t))
				return err
			},
		},
		{
			name: "ceremony bytes", want: RefusalFoundationAuthorizationCeremonyProfileMismatch,
			call: func() error {
				_, err := RequireFoundationInputs(value, FoundationCeremonyProfileSchema, vectorDigest("foundation/other-ceremony"), value.ReleaseSetSHA256, value.TargetBindingSHA256, foundationAuthorizationNow(t))
				return err
			},
		},
		{
			name: "release bytes", want: RefusalFoundationAuthorizationReleaseSetMismatch,
			call: func() error {
				_, err := RequireFoundationInputs(value, FoundationCeremonyProfileSchema, value.CeremonyProfileSHA256, vectorDigest("foundation/other-release"), value.TargetBindingSHA256, foundationAuthorizationNow(t))
				return err
			},
		},
		{
			name: "target binding", want: RefusalFoundationAuthorizationTargetBindingMismatch,
			call: func() error {
				_, err := RequireFoundationInputs(value, FoundationCeremonyProfileSchema, value.CeremonyProfileSHA256, value.ReleaseSetSHA256, vectorDigest("foundation/other-target"), foundationAuthorizationNow(t))
				return err
			},
		},
	} {
		t.Run(item.name, func(t *testing.T) {
			requireRefusal(t, item.call(), item.want)
		})
	}
}

func TestFoundationAuthorizationRefusesChangedEstateEvenWhenResigned(t *testing.T) {
	value := newFoundationAuthorization(t)
	value.EstateID = vectorDigest("foundation/foreign-estate")
	value = signFoundationAuthorization(t, value, "owner-a", "owner-b")
	_, err := VerifyFoundationAuthorization(value, foundationAuthorizationNow(t))
	requireRefusal(t, err, RefusalFoundationAuthorizationIDNotSelfCertifying)
}

func TestFoundationAuthorizationRefusesInsufficientOrForeignSignatures(t *testing.T) {
	value := newFoundationAuthorization(t)
	value = signFoundationAuthorization(t, value, "owner-a")
	_, err := VerifyFoundationAuthorization(value, foundationAuthorizationNow(t))
	requireRefusal(t, err, RefusalFoundationAuthorizationSignaturesInsufficient)

	value = newFoundationAuthorization(t)
	value.Signatures[1].KeyID = "owner-z"
	_, err = VerifyFoundationAuthorization(value, foundationAuthorizationNow(t))
	requireRefusal(t, err, RefusalFoundationAuthorizationSignatureInvalid+":owner-z")
}

func TestFoundationAuthorizationRefusesOutsideItsWindow(t *testing.T) {
	value := newFoundationAuthorization(t)
	before, err := time.Parse("2006-01-02T15:04:05Z", "2026-09-21T00:59:59Z")
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyFoundationAuthorization(value, before)
	requireRefusal(t, err, RefusalFoundationAuthorizationNotYetValid)

	after, err := time.Parse("2006-01-02T15:04:05Z", "2026-09-21T02:00:01Z")
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyFoundationAuthorization(value, after)
	requireRefusal(t, err, RefusalFoundationAuthorizationExpired)

	value = newFoundationAuthorization(t)
	value.ExpiresAt = "2026-09-22T02:00:01Z"
	requireRefusal(t, ValidateFoundationAuthorization(value), RefusalFoundationAuthorizationTimeInvalid)
}

func TestFoundationAuthorizationRefusesWrongObservedGenesis(t *testing.T) {
	value := newFoundationAuthorization(t)
	if err := RequireFoundationGenesis(value, value.NetworkGenesisHash); err != nil {
		t.Fatalf("exact genesis: %v", err)
	}
	requireRefusal(t, RequireFoundationGenesis(value, vectorAddress("foundation/other-genesis")), RefusalFoundationAuthorizationGenesisMismatch)
}

func TestDecodeFoundationAuthorizationStrictlyRejectsDuplicateKey(t *testing.T) {
	value := newFoundationAuthorization(t)
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	needle := `"kind":"` + FoundationAuthorizationKind + `",`
	duplicated := strings.Replace(string(raw), needle, needle+`"kind":"`+FoundationAuthorizationKind+`",`, 1)
	_, err = DecodeFoundationAuthorization([]byte(duplicated))
	requireRefusal(t, err, RefusalJSONDuplicateKey+":$.kind")
}

func TestFoundationAuthorizationPreimageIsStable(t *testing.T) {
	value := newFoundationAuthorization(t)
	preimage, err := FoundationAuthorizationPreimage(value)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256Hex(preimage); got != "5c981d9316aa2ed9f36f44d92cb7712b9da1b83c9f779a3f0a92224ae3afa8a6" {
		t.Fatalf("foundation authorization preimage digest = %s", got)
	}
	digest, err := FoundationAuthorizationSHA256(value)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "5c981d9316aa2ed9f36f44d92cb7712b9da1b83c9f779a3f0a92224ae3afa8a6" {
		t.Fatalf("foundation authorization digest = %s", digest)
	}
}

type foundationAuthorizationVectorsDocument struct {
	Schema         string `json:"schema"`
	Authorizations []struct {
		Name          string          `json:"name"`
		Authorization json.RawMessage `json:"authorization"`
		PreimageHex   string          `json:"preimageHex"`
		SHA256        string          `json:"sha256"`
	} `json:"authorizations"`
}

func TestFoundationAuthorizationVectorsAreTheContract(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/foundation-authorization-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors foundationAuthorizationVectorsDocument
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "melusina.estate.foundation-authorization-vectors.v1" || len(vectors.Authorizations) == 0 {
		t.Fatalf("unexpected foundation authorization vectors header")
	}
	for _, item := range vectors.Authorizations {
		value, err := DecodeFoundationAuthorization(item.Authorization)
		if err != nil {
			t.Fatalf("%s: decode: %v", item.Name, err)
		}
		preimage, err := FoundationAuthorizationPreimage(value)
		if err != nil {
			t.Fatalf("%s: preimage: %v", item.Name, err)
		}
		if got := hex.EncodeToString(preimage); got != item.PreimageHex {
			t.Fatalf("%s: preimage differs from vector", item.Name)
		}
		digest, err := VerifyFoundationAuthorization(value, foundationAuthorizationNow(t))
		if err != nil {
			t.Fatalf("%s: verify: %v", item.Name, err)
		}
		if digest != item.SHA256 {
			t.Fatalf("%s: digest = %s, vector = %s", item.Name, digest, item.SHA256)
		}
	}
}
