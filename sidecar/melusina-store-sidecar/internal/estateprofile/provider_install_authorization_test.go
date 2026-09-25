package estateprofile

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	providerInstallVectorsPath   = "../../testdata/provider-install-authorization-vectors.json"
	providerInstallVectorsSchema = "melusina.estate.provider-install-authorization-vectors.v1"
	providerInstallIssuedAt      = "2026-09-24T01:00:00Z"
	providerInstallExpiresAt     = "2026-09-24T02:00:00Z"
)

var providerInstallNow = time.Date(2026, 9, 24, 1, 30, 0, 0, time.UTC)

// vectorRecipient derives a fictitious x25519 escrow recipient from a label.
// Like every key here it is test material with no authority anywhere.
func vectorRecipient(t *testing.T, label string) string {
	t.Helper()
	seed := sha256.Sum256([]byte("melusina-estate-profile-vector-recipient:" + label))
	private, err := ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		t.Fatalf("derive recipient %s: %v", label, err)
	}
	return "x25519:" + base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
}

func signProviderInstallAuthorization(t *testing.T, policy OwnerPolicyV1, value ProviderInstallAuthorizationV1, keyIDs ...string) ProviderInstallAuthorizationV1 {
	t.Helper()
	value.Signatures = nil
	digest, err := ProviderInstallAuthorizationSHA256(value)
	if err != nil {
		t.Fatalf("provider install authorization digest: %v", err)
	}
	value.Signatures = signDigest(policy, digest, keyIDs...)
	return value
}

// newProviderInstallAuthorization is fictitious public vector input for the
// rehearsal estate, signed by exactly its 2-of-3 owner threshold.
func newProviderInstallAuthorization(t *testing.T, profile EstateProfileV1) ProviderInstallAuthorizationV1 {
	t.Helper()
	profileDigest, err := VerifyProfile(profile)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	recipients := []string{vectorRecipient(t, "provider-install/recovery-holder-1"), vectorRecipient(t, "provider-install/recovery-holder-2")}
	sort.Strings(recipients)
	value := ProviderInstallAuthorizationV1{
		Schema:               ProviderInstallAuthorizationSchema,
		Kind:                 ProviderInstallAuthorizationKind,
		Purpose:              ProviderInstallAuthorizationPurpose,
		EstateID:             profile.EstateID,
		ProfileSHA256:        profileDigest,
		ProfileRevision:      profile.Revision,
		HostMachineIDHash:    vectorDigest("provider-install/host-machine-id"),
		Class:                ProviderInstallClassRehearsal,
		SpecSHA256:           vectorDigest("provider-install/substrate-spec"),
		SuiteManifestSHA256:  vectorDigest("provider-install/suite-manifest"),
		RecoveryRecipients:   recipients,
		IssuedAt:             providerInstallIssuedAt,
		ExpiresAt:            providerInstallExpiresAt,
		AuthorizationNonce:   vectorDigest("provider-install/authorization-nonce"),
		EdgeProfileSHA256:    vectorDigest("provider-install/edge-profile"),
		ProviderConfigSHA256: vectorDigest("provider-install/provider-config"),
	}
	return signProviderInstallAuthorization(t, profile.OwnerPolicy, value, "owner-a", "owner-b")
}

// The positive control: a threshold of the profile's current owners, over
// exactly this profile, inside the window.
func TestProviderInstallAuthorizationVerifiesUnderTheOwnerThreshold(t *testing.T) {
	profile := newEstateProfile(t)
	value := newProviderInstallAuthorization(t, profile)
	digest, err := VerifyProviderInstallAuthorization(profile, value, providerInstallNow)
	if err != nil {
		t.Fatalf("a threshold-signed provider install authorization was refused: %v", err)
	}
	want, err := ProviderInstallAuthorizationSHA256(value)
	if err != nil || digest != want {
		t.Fatalf("verified digest %s, want %s (%v)", digest, want, err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeProviderInstallAuthorization(raw)
	if err != nil {
		t.Fatalf("the canonical document did not decode: %v", err)
	}
	if _, err := VerifyProviderInstallAuthorization(profile, decoded, providerInstallNow); err != nil {
		t.Fatalf("the decoded document did not verify: %v", err)
	}
}

// NC-under-threshold: one owner of a 2-of-3 policy is not the owners.
func TestProviderInstallAuthorizationRefusesUnderThreshold(t *testing.T) {
	profile := newEstateProfile(t)
	value := signProviderInstallAuthorization(t, profile.OwnerPolicy, newProviderInstallAuthorization(t, profile), "owner-a")
	_, err := VerifyProviderInstallAuthorization(profile, value, providerInstallNow)
	requireRefusal(t, err, RefusalProviderInstallAuthorizationSignaturesInsufficient)
	value.Signatures = []SignatureV1{}
	_, err = VerifyProviderInstallAuthorization(profile, value, providerInstallNow)
	requireRefusal(t, err, RefusalProviderInstallAuthorizationSignaturesInsufficient)
}

// NC-non-owner-signer: a signer the owner policy does not list, and a listed
// key ID whose signature another key made, are each refused by the key ID
// even when the rest of the set would reach the threshold.
func TestProviderInstallAuthorizationRefusesANonOwnerSigner(t *testing.T) {
	profile := newEstateProfile(t)
	value := newProviderInstallAuthorization(t, profile)
	digest, err := ProviderInstallAuthorizationSHA256(value)
	if err != nil {
		t.Fatal(err)
	}
	outsider := vectorPrivateKey("policy.outsider.v1/owner-z")
	outsiderSignature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(outsider, []byte(digest)))

	withStranger := value
	withStranger.Signatures = append(append([]SignatureV1{}, value.Signatures...), SignatureV1{KeyID: "owner-z", Signature: outsiderSignature})
	_, err = VerifyProviderInstallAuthorization(profile, withStranger, providerInstallNow)
	requireRefusal(t, err, RefusalProviderInstallAuthorizationSignatureInvalid+":owner-z")

	impersonated := value
	impersonated.Signatures = append([]SignatureV1{}, value.Signatures...)
	impersonated.Signatures[1] = SignatureV1{KeyID: "owner-b", Signature: outsiderSignature}
	_, err = VerifyProviderInstallAuthorization(profile, impersonated, providerInstallNow)
	requireRefusal(t, err, RefusalProviderInstallAuthorizationSignatureInvalid+":owner-b")
}

// NC-cross-estate at the document: an authorization is bound to the estate,
// the exact profile bytes and the revision it was signed under. Each drifted
// field is re-signed by the same owners, so only the binding refuses it.
func TestProviderInstallAuthorizationRefusesAnotherEstateOrProfile(t *testing.T) {
	profile := newEstateProfile(t)
	for _, testCase := range []struct {
		field string
		edit  func(*ProviderInstallAuthorizationV1)
	}{
		{"estateId", func(value *ProviderInstallAuthorizationV1) {
			value.EstateID = vectorDigest("provider-install/another-estate")
		}},
		{"profileSha256", func(value *ProviderInstallAuthorizationV1) {
			value.ProfileSHA256 = vectorDigest("provider-install/another-profile")
		}},
		{"profileRevision", func(value *ProviderInstallAuthorizationV1) { value.ProfileRevision++ }},
	} {
		t.Run(testCase.field, func(t *testing.T) {
			value := newProviderInstallAuthorization(t, profile)
			testCase.edit(&value)
			value = signProviderInstallAuthorization(t, profile.OwnerPolicy, value, "owner-a", "owner-b")
			_, err := VerifyProviderInstallAuthorization(profile, value, providerInstallNow)
			requireRefusal(t, err, RefusalProviderInstallAuthorizationProfileMismatch+":"+testCase.field)
		})
	}
}

func TestProviderInstallAuthorizationIsOnlyValidInsideItsWindow(t *testing.T) {
	profile := newEstateProfile(t)
	value := newProviderInstallAuthorization(t, profile)
	issuedAt, _ := parseIssuedAt(providerInstallIssuedAt)
	expiresAt, _ := parseIssuedAt(providerInstallExpiresAt)
	for _, at := range []time.Time{issuedAt, expiresAt} {
		if _, err := VerifyProviderInstallAuthorization(profile, value, at); err != nil {
			t.Fatalf("the window edge %s was refused: %v", at, err)
		}
	}
	_, err := VerifyProviderInstallAuthorization(profile, value, issuedAt.Add(-time.Second))
	requireRefusal(t, err, RefusalProviderInstallAuthorizationNotYetValid)
	_, err = VerifyProviderInstallAuthorization(profile, value, expiresAt.Add(time.Second))
	requireRefusal(t, err, RefusalProviderInstallAuthorizationExpired)
	_, err = VerifyProviderInstallAuthorization(profile, value, time.Time{})
	requireRefusal(t, err, RefusalProviderInstallAuthorizationTimeInvalid)

	tooLong := value
	tooLong.ExpiresAt = issuedAt.Add(ProviderInstallAuthorizationMaxLifetime + time.Second).Format(issuedAtLayout)
	requireRefusal(t, ValidateProviderInstallAuthorization(tooLong), RefusalProviderInstallAuthorizationTimeInvalid)
	backwards := value
	backwards.ExpiresAt = backwards.IssuedAt
	requireRefusal(t, ValidateProviderInstallAuthorization(backwards), RefusalProviderInstallAuthorizationTimeInvalid)
}

func TestProviderInstallAuthorizationRecipientsAreCanonicalAndBounded(t *testing.T) {
	profile := newEstateProfile(t)
	base := newProviderInstallAuthorization(t, profile)
	many := make([]string, 0, MaxProviderInstallRecoveryRecipients+1)
	for index := 0; index <= MaxProviderInstallRecoveryRecipients; index++ {
		many = append(many, vectorRecipient(t, "provider-install/many-"+string(rune('a'+index))))
	}
	sort.Strings(many)
	valid := base.RecoveryRecipients[0]
	encoded := strings.TrimPrefix(valid, "x25519:")
	lowOrder := "x25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for name, recipients := range map[string][]string{
		"none":           {},
		"seventeen":      many,
		"unsorted":       {base.RecoveryRecipients[1], base.RecoveryRecipients[0]},
		"duplicate":      {valid, valid},
		"no prefix":      {encoded},
		"age prefix":     {"age1" + encoded},
		"padded":         {valid + "="},
		"short key":      {"x25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, 31))},
		"low-order zero": {lowOrder},
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			value.RecoveryRecipients = recipients
			requireRefusal(t, ValidateProviderInstallAuthorization(value), RefusalProviderInstallAuthorizationFieldMalformed+":recoveryRecipients")
		})
	}
	// Positive control: the most recipients the escrow accepts.
	value := base
	value.RecoveryRecipients = many[:MaxProviderInstallRecoveryRecipients]
	if err := ValidateProviderInstallAuthorization(value); err != nil {
		t.Fatalf("sixteen canonical recipients were refused: %v", err)
	}
}

func TestProviderInstallAuthorizationShapeIsClosed(t *testing.T) {
	profile := newEstateProfile(t)
	base := newProviderInstallAuthorization(t, profile)
	for field, edit := range map[string]func(*ProviderInstallAuthorizationV1){
		"hostMachineIdHash": func(value *ProviderInstallAuthorizationV1) {
			value.HostMachineIDHash = "sha256:" + value.HostMachineIDHash
		},
		"specSha256":          func(value *ProviderInstallAuthorizationV1) { value.SpecSHA256 = strings.ToUpper(value.SpecSHA256) },
		"suiteManifestSha256": func(value *ProviderInstallAuthorizationV1) { value.SuiteManifestSHA256 = strings.Repeat("0", 64) },
		"authorizationNonce":  func(value *ProviderInstallAuthorizationV1) { value.AuthorizationNonce = "" },
		"edgeProfileSha256":   func(value *ProviderInstallAuthorizationV1) { value.EdgeProfileSHA256 = "" },
		"providerConfigSha256": func(value *ProviderInstallAuthorizationV1) {
			value.ProviderConfigSHA256 = "sha256:" + value.ProviderConfigSHA256
		},
		"class":           func(value *ProviderInstallAuthorizationV1) { value.Class = "staging" },
		"profileRevision": func(value *ProviderInstallAuthorizationV1) { value.ProfileRevision = 0 },
	} {
		t.Run(field, func(t *testing.T) {
			value := base
			edit(&value)
			requireRefusal(t, ValidateProviderInstallAuthorization(value), RefusalProviderInstallAuthorizationFieldMalformed+":"+field)
		})
	}
	wrongPurpose := base
	wrongPurpose.Purpose = StoreEnrollmentPurpose
	requireRefusal(t, ValidateProviderInstallAuthorization(wrongPurpose), RefusalProviderInstallAuthorizationSchemaUnsupported)

	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(string(raw), `"class":"rehearsal",`, `"class":"rehearsal","class":"production",`, 1)
	_, err = DecodeProviderInstallAuthorization([]byte(duplicate))
	requireRefusal(t, err, RefusalJSONDuplicateKey+":$.class")
	unknown := strings.Replace(string(raw), `"class":"rehearsal",`, `"class":"rehearsal","operatorSignature":"x",`, 1)
	_, err = DecodeProviderInstallAuthorization([]byte(unknown))
	requireRefusal(t, err, RefusalJSONUnknownField+":$.operatorSignature")
	store := strings.Replace(string(raw), `"kind":"`+ProviderInstallAuthorizationKind+`"`, `"kind":"`+StoreEnrollmentKind+`"`, 1)
	_, err = DecodeProviderInstallAuthorization([]byte(store))
	requireRefusal(t, err, RefusalProviderInstallAuthorizationSchemaUnsupported)
}

// Every field the owners sign moves the digest, so no field can be swapped
// under an existing signature set.
func TestProviderInstallAuthorizationDigestBindsEveryField(t *testing.T) {
	profile := newEstateProfile(t)
	base := newProviderInstallAuthorization(t, profile)
	baseDigest, err := ProviderInstallAuthorizationSHA256(base)
	if err != nil {
		t.Fatal(err)
	}
	for field, edit := range map[string]func(*ProviderInstallAuthorizationV1){
		"estateId":            func(value *ProviderInstallAuthorizationV1) { value.EstateID = vectorDigest("x/estate") },
		"profileSha256":       func(value *ProviderInstallAuthorizationV1) { value.ProfileSHA256 = vectorDigest("x/profile") },
		"profileRevision":     func(value *ProviderInstallAuthorizationV1) { value.ProfileRevision = 2 },
		"hostMachineIdHash":   func(value *ProviderInstallAuthorizationV1) { value.HostMachineIDHash = vectorDigest("x/host") },
		"class":               func(value *ProviderInstallAuthorizationV1) { value.Class = ProviderInstallClassProduction },
		"specSha256":          func(value *ProviderInstallAuthorizationV1) { value.SpecSHA256 = vectorDigest("x/spec") },
		"suiteManifestSha256": func(value *ProviderInstallAuthorizationV1) { value.SuiteManifestSHA256 = vectorDigest("x/suite") },
		"recoveryRecipients":  func(value *ProviderInstallAuthorizationV1) { value.RecoveryRecipients = value.RecoveryRecipients[:1] },
		"issuedAt":            func(value *ProviderInstallAuthorizationV1) { value.IssuedAt = "2026-09-24T01:00:01Z" },
		"expiresAt":           func(value *ProviderInstallAuthorizationV1) { value.ExpiresAt = "2026-09-24T02:00:01Z" },
		"authorizationNonce":  func(value *ProviderInstallAuthorizationV1) { value.AuthorizationNonce = vectorDigest("x/nonce") },
		"edgeProfileSha256":   func(value *ProviderInstallAuthorizationV1) { value.EdgeProfileSHA256 = vectorDigest("x/edge-profile") },
		"providerConfigSha256": func(value *ProviderInstallAuthorizationV1) {
			value.ProviderConfigSHA256 = vectorDigest("x/provider-config")
		},
	} {
		value := base
		value.RecoveryRecipients = append([]string{}, base.RecoveryRecipients...)
		edit(&value)
		digest, err := ProviderInstallAuthorizationSHA256(value)
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		if digest == baseDigest {
			t.Fatalf("changing %s did not change the signed digest", field)
		}
		if _, err := VerifyProviderInstallAuthorization(profile, value, providerInstallNow); err == nil {
			t.Fatalf("changing %s under the original signatures still verified", field)
		}
	}
}

type providerInstallVectorsDocument struct {
	Schema         string                          `json:"schema"`
	Notes          []string                        `json:"notes"`
	ProfileSHA256  string                          `json:"profileSha256"`
	VerifyAt       string                          `json:"verifyAt"`
	Authorizations []providerInstallVectorDocument `json:"authorizations"`
}

type providerInstallVectorDocument struct {
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Authorization json.RawMessage `json:"authorization"`
	PreimageHex   string          `json:"preimageHex"`
	SHA256        string          `json:"sha256"`
	Refusal       string          `json:"refusal"`
}

func buildProviderInstallVectors(t *testing.T) providerInstallVectorsDocument {
	t.Helper()
	profile := newEstateProfile(t)
	profileDigest, err := VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	threshold := newProviderInstallAuthorization(t, profile)
	underThreshold := signProviderInstallAuthorization(t, profile.OwnerPolicy, threshold, "owner-a")
	document := providerInstallVectorsDocument{
		Schema: providerInstallVectorsSchema,
		Notes: []string{
			"Generated by go test ./internal/estateprofile/ -update-vectors from the package's fixture labels. It contains no private key and has no authority on any network.",
			"The profile is the rehearsal estate of estate-profile-vectors.json; its owner keys are sha256(\"melusina-estate-profile-vector-key:policy.rehearsal.owners.v1/\" + keyId). The host, Spec, suite, nonce, edge profile and provider configuration digests are fictitious placeholders.",
			"preimageHex is the exact binary preimage of ProviderInstallAuthorizationSHA256. A second implementation must reproduce it byte for byte before it may verify a provider-install authorization.",
			"refusal is empty for a vector that verifies at verifyAt under the profile, and otherwise the exact refusal it must produce.",
		},
		ProfileSHA256: profileDigest,
		VerifyAt:      providerInstallNow.Format(issuedAtLayout),
	}
	for _, item := range []struct {
		name, description, refusal string
		value                      ProviderInstallAuthorizationV1
	}{
		{"rehearsal-owner-threshold", "A rehearsal provider install signed by owner-a and owner-b, exactly the 2-of-3 threshold of the profile's current owner policy, valid 01:00-02:00 UTC.", "", threshold},
		{"rehearsal-under-threshold", "The same authorization signed by owner-a alone.", RefusalProviderInstallAuthorizationSignaturesInsufficient, underThreshold},
	} {
		raw, err := json.Marshal(item.value)
		if err != nil {
			t.Fatal(err)
		}
		preimage, err := ProviderInstallAuthorizationPreimage(item.value)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := ProviderInstallAuthorizationSHA256(item.value)
		if err != nil {
			t.Fatal(err)
		}
		document.Authorizations = append(document.Authorizations, providerInstallVectorDocument{
			Name: item.name, Description: item.description, Authorization: raw,
			PreimageHex: hex.EncodeToString(preimage), SHA256: digest, Refusal: item.refusal,
		})
	}
	return document
}

// TestProviderInstallAuthorizationVectorsAreTheContract keeps the committed
// vectors and the fixtures one object, and holds every vector to its stated
// outcome. Run with -update-vectors to rewrite the file.
func TestProviderInstallAuthorizationVectorsAreTheContract(t *testing.T) {
	generated, err := json.MarshalIndent(buildProviderInstallVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	generated = append(generated, '\n')
	if *updateVectors {
		if err := os.WriteFile(providerInstallVectorsPath, generated, 0o644); err != nil {
			t.Fatalf("write %s: %v", providerInstallVectorsPath, err)
		}
		t.Logf("wrote %s (%d bytes)", filepath.Base(providerInstallVectorsPath), len(generated))
		return
	}
	committed, err := os.ReadFile(providerInstallVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", providerInstallVectorsPath, err)
	}
	if !bytes.Equal(committed, generated) {
		t.Fatalf("%s is not what the fixtures generate; re-run with -update-vectors and read the diff before committing it", providerInstallVectorsPath)
	}
	var document providerInstallVectorsDocument
	if err := json.Unmarshal(committed, &document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != providerInstallVectorsSchema || len(document.Authorizations) < 2 {
		t.Fatalf("unexpected provider install vectors header")
	}
	verifyAt, ok := parseIssuedAt(document.VerifyAt)
	if !ok {
		t.Fatalf("verifyAt %q does not parse", document.VerifyAt)
	}
	profile := newEstateProfile(t)
	for _, item := range document.Authorizations {
		value, err := DecodeProviderInstallAuthorization(item.Authorization)
		if err != nil {
			t.Fatalf("%s: decode: %v", item.Name, err)
		}
		preimage, err := ProviderInstallAuthorizationPreimage(value)
		if err != nil {
			t.Fatalf("%s: preimage: %v", item.Name, err)
		}
		if got := hex.EncodeToString(preimage); got != item.PreimageHex {
			t.Fatalf("%s: preimage differs from the vector", item.Name)
		}
		sum := sha256.Sum256(preimage)
		if hex.EncodeToString(sum[:]) != item.SHA256 {
			t.Fatalf("%s: sha256 of the preimage differs from the vector", item.Name)
		}
		digest, err := VerifyProviderInstallAuthorization(profile, value, verifyAt)
		switch {
		case item.Refusal == "" && err != nil:
			t.Fatalf("%s: verify: %v", item.Name, err)
		case item.Refusal == "" && digest != item.SHA256:
			t.Fatalf("%s: verified digest %s, vector %s", item.Name, digest, item.SHA256)
		case item.Refusal != "":
			requireRefusal(t, err, item.Refusal)
		}
	}
}
