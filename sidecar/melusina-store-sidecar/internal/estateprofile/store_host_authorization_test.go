package estateprofile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	storeHostVectorsPath   = "../../testdata/store-host-authorization-vectors.json"
	storeHostVectorsSchema = "melusina.estate.store-host-authorization-vectors.v1"
	storeHostIssuedAt      = "2026-09-24T01:00:00Z"
	storeHostExpiresAt     = "2026-09-24T02:00:00Z"
)

var storeHostNow = time.Date(2026, 9, 24, 1, 30, 0, 0, time.UTC)

func signStoreHostAuthorization(t *testing.T, policy OwnerPolicyV1, value StoreHostAuthorizationV1, keyIDs ...string) StoreHostAuthorizationV1 {
	t.Helper()
	value.Signatures = nil
	digest, err := StoreHostAuthorizationSHA256(value)
	if err != nil {
		t.Fatalf("store host authorization digest: %v", err)
	}
	value.Signatures = signDigest(policy, digest, keyIDs...)
	return value
}

// newStoreHostAuthorization is fictitious public vector input for the
// rehearsal estate, signed by exactly the 2-of-3 threshold of its GENESIS
// owner policy. Every digest is a labelled placeholder.
func newStoreHostAuthorization(t *testing.T) (OwnerPolicyV1, StoreHostAuthorizationV1) {
	t.Helper()
	profile := newEstateProfile(t)
	policyDigest, err := OwnerPolicySHA256(profile.GenesisOwnerPolicy)
	if err != nil {
		t.Fatal(err)
	}
	value := StoreHostAuthorizationV1{
		Schema:                     StoreHostAuthorizationSchema,
		Kind:                       StoreHostAuthorizationKind,
		Purpose:                    StoreHostAuthorizationPurpose,
		EstateID:                   profile.EstateID,
		EstateNonce:                profile.EstateNonce,
		GenesisOwnerPolicySHA256:   policyDigest,
		ReleaseSetSequence:         7,
		ReleaseSetSHA256:           vectorDigest("store-host/f0-release-set"),
		StoreBootstrapSHA256:       vectorDigest("store-host/store-bootstrap"),
		StoreBootstrapVersion:      "1.2.3",
		StoreBootstrapSourceCommit: vectorSourceCommit("store-host/store-source"),
		StoreHostSpecSHA256:        vectorDigest("store-host/spec"),
		HostMachineIDHash:          vectorDigest("store-host/host-machine-id"),
		RootStoreHostname:          "store.estate.test",
		PlacementKind:              StoreHostPlacementDedicated,
		ContainerName:              "root-store",
		BridgeName:                 "storebr0",
		BackendAddress:             "10.77.0.10",
		IssuedAt:                   storeHostIssuedAt,
		ExpiresAt:                  storeHostExpiresAt,
		AuthorizationNonce:         vectorDigest("store-host/authorization-nonce"),
	}
	return profile.GenesisOwnerPolicy, signStoreHostAuthorization(t, profile.GenesisOwnerPolicy, value, "owner-a", "owner-b")
}

func storeHostReleaseOf(value StoreHostAuthorizationV1) StoreHostRelease {
	return StoreHostRelease{
		ReleaseSetSequence: value.ReleaseSetSequence, ReleaseSetSHA256: value.ReleaseSetSHA256,
		StoreBootstrapSHA256: value.StoreBootstrapSHA256, StoreBootstrapVersion: value.StoreBootstrapVersion,
		StoreBootstrapSourceCommit: value.StoreBootstrapSourceCommit, StoreHostSpecSHA256: value.StoreHostSpecSHA256,
	}
}

func storeHostPlacementOf(value StoreHostAuthorizationV1) StoreHostPlacement {
	return StoreHostPlacement{
		HostMachineIDHash: value.HostMachineIDHash, RootStoreHostname: value.RootStoreHostname, PlacementKind: value.PlacementKind,
		ContainerName: value.ContainerName, BridgeName: value.BridgeName, BackendAddress: value.BackendAddress,
	}
}

// The positive control: exactly the genesis threshold, over exactly this
// estate, inside the window, with every binding equal to the measurement.
func TestStoreHostAuthorizationVerifiesUnderTheGenesisThreshold(t *testing.T) {
	genesis, value := newStoreHostAuthorization(t)
	if got, want := len(value.Signatures), int(genesis.Threshold); got != want {
		t.Fatalf("positive control has %d signatures, want exactly threshold %d", got, want)
	}
	digest, err := RequireStoreHostAuthorization(genesis, value, storeHostReleaseOf(value), storeHostPlacementOf(value), storeHostNow)
	if err != nil {
		t.Fatalf("a genesis-threshold store host authorization was refused: %v", err)
	}
	want, err := StoreHostAuthorizationSHA256(value)
	if err != nil || digest != want {
		t.Fatalf("verified digest %s, want %s (%v)", digest, want, err)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeStoreHostAuthorization(raw)
	if err != nil {
		t.Fatalf("the canonical document did not decode: %v", err)
	}
	if !reflect.DeepEqual(decoded, value) {
		t.Fatalf("the decoded document differs from the one encoded")
	}
	if _, err := VerifyStoreHostAuthorization(genesis, decoded, storeHostNow); err != nil {
		t.Fatalf("the decoded document did not verify: %v", err)
	}
	// The rehearsal placement is the other member of the closed union.
	rehearsal := value
	rehearsal.PlacementKind = StoreHostPlacementRehearsalEdgeColocated
	rehearsal = signStoreHostAuthorization(t, genesis, rehearsal, "owner-a", "owner-c")
	if _, err := VerifyStoreHostAuthorization(genesis, rehearsal, storeHostNow); err != nil {
		t.Fatalf("a rehearsal placement signed by the genesis threshold was refused: %v", err)
	}
}

// NC-under-threshold: one owner of a 2-of-3 genesis policy is not the owners.
func TestStoreHostAuthorizationRefusesUnderThreshold(t *testing.T) {
	genesis, value := newStoreHostAuthorization(t)
	one := signStoreHostAuthorization(t, genesis, value, "owner-a")
	_, err := VerifyStoreHostAuthorization(genesis, one, storeHostNow)
	requireRefusal(t, err, RefusalStoreHostAuthorizationSignaturesInsufficient)
	none := value
	none.Signatures = []SignatureV1{}
	_, err = VerifyStoreHostAuthorization(genesis, none, storeHostNow)
	requireRefusal(t, err, RefusalStoreHostAuthorizationSignaturesInsufficient)
	_, err = RequireStoreHostAuthorization(genesis, one, storeHostReleaseOf(one), storeHostPlacementOf(one), storeHostNow)
	requireRefusal(t, err, RefusalStoreHostAuthorizationSignaturesInsufficient)
}

// NC-non-owner-signer: a key ID the genesis policy does not list, and a
// listed key ID whose signature another key made, are each refused by the key
// ID even when the rest of the set reaches the threshold.
func TestStoreHostAuthorizationRefusesANonOwnerSigner(t *testing.T) {
	genesis, value := newStoreHostAuthorization(t)
	digest, err := StoreHostAuthorizationSHA256(value)
	if err != nil {
		t.Fatal(err)
	}
	outsider := vectorPrivateKey("policy.outsider.v1/owner-z")
	outsiderSignature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(outsider, []byte(digest)))

	withStranger := value
	withStranger.Signatures = append(append([]SignatureV1{}, value.Signatures...), SignatureV1{KeyID: "owner-z", Signature: outsiderSignature})
	_, err = VerifyStoreHostAuthorization(genesis, withStranger, storeHostNow)
	requireRefusal(t, err, RefusalStoreHostAuthorizationSignatureInvalid+":owner-z")

	impersonated := value
	impersonated.Signatures = append([]SignatureV1{}, value.Signatures...)
	impersonated.Signatures[1] = SignatureV1{KeyID: "owner-b", Signature: outsiderSignature}
	_, err = VerifyStoreHostAuthorization(genesis, impersonated, storeHostNow)
	requireRefusal(t, err, RefusalStoreHostAuthorizationSignatureInvalid+":owner-b")
}

// NC-other-authority: only the genesis owner policy the consumer holds out of
// band authorizes. A document bound to, and signed by, another policy is
// refused by its policy digest before any signature is read; a document whose
// estate is not the one the genesis policy and nonce derive is refused as not
// self-certifying even when the genesis threshold signed it.
func TestStoreHostAuthorizationRefusesAnotherAuthorityOrEstate(t *testing.T) {
	genesis, value := newStoreHostAuthorization(t)
	successor := newEstateMigrate(t, newEstateProfile(t), false).OwnerPolicy
	if reflect.DeepEqual(successor, genesis) {
		t.Fatal("the successor policy fixture is the genesis policy, so this test would prove nothing")
	}

	// The successor owners sign a document naming their own policy: the
	// consumer, holding the genesis policy, refuses the binding.
	successorDigest, err := OwnerPolicySHA256(successor)
	if err != nil {
		t.Fatal(err)
	}
	foreign := value
	foreign.GenesisOwnerPolicySHA256 = successorDigest
	foreign = signStoreHostAuthorization(t, successor, foreign, successor.Signers[0].KeyID, successor.Signers[1].KeyID, successor.Signers[2].KeyID)
	_, err = VerifyStoreHostAuthorization(genesis, foreign, storeHostNow)
	requireRefusal(t, err, RefusalStoreHostAuthorizationOwnerPolicyMismatch)

	// The genesis document offered to a consumer holding another policy.
	_, err = VerifyStoreHostAuthorization(successor, value, storeHostNow)
	requireRefusal(t, err, RefusalStoreHostAuthorizationOwnerPolicyMismatch)

	for field, edit := range map[string]func(*StoreHostAuthorizationV1){
		"estateId":    func(value *StoreHostAuthorizationV1) { value.EstateID = vectorDigest("store-host/another-estate") },
		"estateNonce": func(value *StoreHostAuthorizationV1) { value.EstateNonce = vectorDigest("store-host/another-nonce") },
	} {
		t.Run(field, func(t *testing.T) {
			drifted := value
			edit(&drifted)
			drifted = signStoreHostAuthorization(t, genesis, drifted, "owner-a", "owner-b")
			_, err := VerifyStoreHostAuthorization(genesis, drifted, storeHostNow)
			requireRefusal(t, err, RefusalStoreHostAuthorizationIDNotSelfCertifying)
		})
	}
}

func TestStoreHostAuthorizationIsOnlyValidInsideItsWindow(t *testing.T) {
	genesis, value := newStoreHostAuthorization(t)
	issuedAt, _ := parseIssuedAt(storeHostIssuedAt)
	expiresAt, _ := parseIssuedAt(storeHostExpiresAt)
	for _, at := range []time.Time{issuedAt, expiresAt} {
		if _, err := VerifyStoreHostAuthorization(genesis, value, at); err != nil {
			t.Fatalf("the window edge %s was refused: %v", at, err)
		}
	}
	_, err := VerifyStoreHostAuthorization(genesis, value, issuedAt.Add(-time.Second))
	requireRefusal(t, err, RefusalStoreHostAuthorizationNotYetValid)
	_, err = VerifyStoreHostAuthorization(genesis, value, expiresAt.Add(time.Second))
	requireRefusal(t, err, RefusalStoreHostAuthorizationExpired)
	_, err = VerifyStoreHostAuthorization(genesis, value, time.Time{})
	requireRefusal(t, err, RefusalStoreHostAuthorizationTimeInvalid)

	longest := value
	longest.ExpiresAt = issuedAt.Add(StoreHostAuthorizationMaxLifetime).Format(issuedAtLayout)
	if err := ValidateStoreHostAuthorization(longest); err != nil {
		t.Fatalf("a 24-hour window was refused: %v", err)
	}
	tooLong := value
	tooLong.ExpiresAt = issuedAt.Add(StoreHostAuthorizationMaxLifetime + time.Second).Format(issuedAtLayout)
	requireRefusal(t, ValidateStoreHostAuthorization(tooLong), RefusalStoreHostAuthorizationTimeInvalid)
	backwards := value
	backwards.ExpiresAt = backwards.IssuedAt
	requireRefusal(t, ValidateStoreHostAuthorization(backwards), RefusalStoreHostAuthorizationTimeInvalid)
	fractional := value
	fractional.IssuedAt = "2026-09-24T01:00:00.5Z"
	requireRefusal(t, ValidateStoreHostAuthorization(fractional), RefusalStoreHostAuthorizationTimeInvalid)
}

func TestStoreHostAuthorizationShapeIsClosed(t *testing.T) {
	_, base := newStoreHostAuthorization(t)
	for _, testCase := range []struct {
		field string
		edit  func(*StoreHostAuthorizationV1)
	}{
		{"estateId", func(value *StoreHostAuthorizationV1) { value.EstateID = strings.ToUpper(value.EstateID) }},
		{"estateNonce", func(value *StoreHostAuthorizationV1) { value.EstateNonce = strings.Repeat("0", 64) }},
		{"genesisOwnerPolicySha256", func(value *StoreHostAuthorizationV1) { value.GenesisOwnerPolicySHA256 = "" }},
		{"releaseSetSha256", func(value *StoreHostAuthorizationV1) { value.ReleaseSetSHA256 = "sha256:" + value.ReleaseSetSHA256 }},
		{"storeBootstrapSha256", func(value *StoreHostAuthorizationV1) { value.StoreBootstrapSHA256 = value.StoreBootstrapSHA256[:63] }},
		{"storeHostSpecSha256", func(value *StoreHostAuthorizationV1) { value.StoreHostSpecSHA256 = "" }},
		{"hostMachineIdHash", func(value *StoreHostAuthorizationV1) { value.HostMachineIDHash = "sha256:" + value.HostMachineIDHash }},
		{"authorizationNonce", func(value *StoreHostAuthorizationV1) { value.AuthorizationNonce = "" }},
		{"releaseSetSequence", func(value *StoreHostAuthorizationV1) { value.ReleaseSetSequence = 0 }},
		{"releaseSetSequence", func(value *StoreHostAuthorizationV1) { value.ReleaseSetSequence = MaxSafeInteger + 1 }},
		{"storeBootstrapVersion", func(value *StoreHostAuthorizationV1) { value.StoreBootstrapVersion = "v1.2.3" }},
		{"storeBootstrapVersion", func(value *StoreHostAuthorizationV1) { value.StoreBootstrapVersion = "1.2" }},
		{"storeBootstrapVersion", func(value *StoreHostAuthorizationV1) {
			value.StoreBootstrapVersion = "1.2.3-" + strings.Repeat("a", MaxStoreHostVersionLength)
		}},
		{"storeBootstrapSourceCommit", func(value *StoreHostAuthorizationV1) { value.StoreBootstrapSourceCommit = strings.Repeat("0", 40) }},
		{"storeBootstrapSourceCommit", func(value *StoreHostAuthorizationV1) {
			value.StoreBootstrapSourceCommit = vectorDigest("x/64-hex-commit")
		}},
		{"rootStoreHostname", func(value *StoreHostAuthorizationV1) { value.RootStoreHostname = "Store.Estate.Test" }},
		{"rootStoreHostname", func(value *StoreHostAuthorizationV1) { value.RootStoreHostname = "store" }},
		{"rootStoreHostname", func(value *StoreHostAuthorizationV1) { value.RootStoreHostname = "store.estate.test." }},
		{"rootStoreHostname", func(value *StoreHostAuthorizationV1) { value.RootStoreHostname = "10.0.0.1" }},
		{"placementKind", func(value *StoreHostAuthorizationV1) { value.PlacementKind = "edge" }},
		{"placementKind", func(value *StoreHostAuthorizationV1) { value.PlacementKind = "" }},
		{"containerName", func(value *StoreHostAuthorizationV1) { value.ContainerName = "Root-Store" }},
		{"containerName", func(value *StoreHostAuthorizationV1) { value.ContainerName = "root-store-" }},
		{"bridgeName", func(value *StoreHostAuthorizationV1) { value.BridgeName = "store-bridge-0001" }},
		{"bridgeName", func(value *StoreHostAuthorizationV1) { value.BridgeName = "0storebr" }},
		{"backendAddress", func(value *StoreHostAuthorizationV1) { value.BackendAddress = "203.0.113.10" }},
		{"backendAddress", func(value *StoreHostAuthorizationV1) { value.BackendAddress = "127.0.0.1" }},
		{"backendAddress", func(value *StoreHostAuthorizationV1) { value.BackendAddress = "10.77.0.010" }},
		{"backendAddress", func(value *StoreHostAuthorizationV1) { value.BackendAddress = "fd00::10" }},
		{"backendAddress", func(value *StoreHostAuthorizationV1) { value.BackendAddress = "10.77.0.10/24" }},
		{"backendAddress", func(value *StoreHostAuthorizationV1) { value.BackendAddress = "::ffff:10.77.0.10" }},
	} {
		t.Run(testCase.field, func(t *testing.T) {
			value := base
			testCase.edit(&value)
			requireRefusal(t, ValidateStoreHostAuthorization(value), RefusalStoreHostAuthorizationFieldMalformed+":"+testCase.field)
		})
	}
	// Positive controls beside the refusals: each other accepted spelling.
	for name, edit := range map[string]func(*StoreHostAuthorizationV1){
		"192.168 backend":       func(value *StoreHostAuthorizationV1) { value.BackendAddress = "192.168.40.2" },
		"172.16 backend":        func(value *StoreHostAuthorizationV1) { value.BackendAddress = "172.31.255.254" },
		"pre-release version":   func(value *StoreHostAuthorizationV1) { value.StoreBootstrapVersion = "1.0.56-rc.1" },
		"fifteen-byte bridge":   func(value *StoreHostAuthorizationV1) { value.BridgeName = "storebr-0123456" },
		"rehearsal placement":   func(value *StoreHostAuthorizationV1) { value.PlacementKind = StoreHostPlacementRehearsalEdgeColocated },
		"deep rehearsal domain": func(value *StoreHostAuthorizationV1) { value.RootStoreHostname = "store.rig.estate.test" },
	} {
		value := base
		edit(&value)
		if err := ValidateStoreHostAuthorization(value); err != nil {
			t.Fatalf("%s was refused: %v", name, err)
		}
	}

	for _, wrong := range []func(*StoreHostAuthorizationV1){
		func(value *StoreHostAuthorizationV1) { value.Purpose = FoundationAuthorizationPurpose },
		func(value *StoreHostAuthorizationV1) { value.Kind = ProviderInstallAuthorizationKind },
		func(value *StoreHostAuthorizationV1) { value.Schema = FoundationAuthorizationSchema },
	} {
		value := base
		wrong(&value)
		requireRefusal(t, ValidateStoreHostAuthorization(value), RefusalStoreHostAuthorizationSchemaUnsupported)
	}

	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(string(raw), `"placementKind":"dedicated-host",`, `"placementKind":"dedicated-host","placementKind":"rehearsal-edge-colocated",`, 1)
	_, err = DecodeStoreHostAuthorization([]byte(duplicate))
	requireRefusal(t, err, RefusalJSONDuplicateKey+":$.placementKind")
	unknown := strings.Replace(string(raw), `"placementKind":"dedicated-host",`, `"placementKind":"dedicated-host","publishedPort":443,`, 1)
	_, err = DecodeStoreHostAuthorization([]byte(unknown))
	requireRefusal(t, err, RefusalJSONUnknownField+":$.publishedPort")
	foundationKind := strings.Replace(string(raw), `"kind":"`+StoreHostAuthorizationKind+`"`, `"kind":"`+FoundationAuthorizationKind+`"`, 1)
	_, err = DecodeStoreHostAuthorization([]byte(foundationKind))
	requireRefusal(t, err, RefusalStoreHostAuthorizationSchemaUnsupported)
	missing := strings.Replace(string(raw), `"bridgeName":"storebr0",`, ``, 1)
	_, err = DecodeStoreHostAuthorization([]byte(missing))
	requireRefusal(t, err, RefusalJSONMissingField+":$.bridgeName")
}

// Every field the owners sign moves the digest, so no field can be swapped
// under an existing signature set. The edit table is held to the struct by
// reflection: a field added without an edit here fails by name.
func TestStoreHostAuthorizationDigestBindsEveryField(t *testing.T) {
	genesis, base := newStoreHostAuthorization(t)
	baseDigest, err := StoreHostAuthorizationSHA256(base)
	if err != nil {
		t.Fatal(err)
	}
	edits := map[string]func(*StoreHostAuthorizationV1){
		"schema":  nil,
		"kind":    nil,
		"purpose": nil,
		"estateId": func(value *StoreHostAuthorizationV1) {
			value.EstateID = vectorDigest("x/estate")
		},
		"estateNonce":              func(value *StoreHostAuthorizationV1) { value.EstateNonce = vectorDigest("x/nonce-estate") },
		"genesisOwnerPolicySha256": func(value *StoreHostAuthorizationV1) { value.GenesisOwnerPolicySHA256 = vectorDigest("x/policy") },
		"releaseSetSequence":       func(value *StoreHostAuthorizationV1) { value.ReleaseSetSequence++ },
		"releaseSetSha256":         func(value *StoreHostAuthorizationV1) { value.ReleaseSetSHA256 = vectorDigest("x/release-set") },
		"storeBootstrapSha256":     func(value *StoreHostAuthorizationV1) { value.StoreBootstrapSHA256 = vectorDigest("x/bootstrap") },
		"storeBootstrapVersion":    func(value *StoreHostAuthorizationV1) { value.StoreBootstrapVersion = "1.2.4" },
		"storeBootstrapSourceCommit": func(value *StoreHostAuthorizationV1) {
			value.StoreBootstrapSourceCommit = vectorSourceCommit("x/commit")
		},
		"storeHostSpecSha256": func(value *StoreHostAuthorizationV1) { value.StoreHostSpecSHA256 = vectorDigest("x/spec") },
		"hostMachineIdHash":   func(value *StoreHostAuthorizationV1) { value.HostMachineIDHash = vectorDigest("x/host") },
		"rootStoreHostname":   func(value *StoreHostAuthorizationV1) { value.RootStoreHostname = "bazaar.estate.test" },
		"placementKind": func(value *StoreHostAuthorizationV1) {
			value.PlacementKind = StoreHostPlacementRehearsalEdgeColocated
		},
		"containerName":      func(value *StoreHostAuthorizationV1) { value.ContainerName = "root-store-2" },
		"bridgeName":         func(value *StoreHostAuthorizationV1) { value.BridgeName = "storebr1" },
		"backendAddress":     func(value *StoreHostAuthorizationV1) { value.BackendAddress = "10.77.0.11" },
		"issuedAt":           func(value *StoreHostAuthorizationV1) { value.IssuedAt = "2026-09-24T01:00:01Z" },
		"expiresAt":          func(value *StoreHostAuthorizationV1) { value.ExpiresAt = "2026-09-24T02:00:01Z" },
		"authorizationNonce": func(value *StoreHostAuthorizationV1) { value.AuthorizationNonce = vectorDigest("x/nonce") },
		"signatures":         nil,
	}
	kind := reflect.TypeOf(StoreHostAuthorizationV1{})
	for index := 0; index < kind.NumField(); index++ {
		name := strings.Split(kind.Field(index).Tag.Get("json"), ",")[0]
		if _, listed := edits[name]; !listed {
			t.Fatalf("STORE_HOST_FIELD_UNTESTED: %s is a field of the document with no digest-binding edit here", name)
		}
	}
	if len(edits) != kind.NumField() {
		t.Fatalf("the edit table names %d fields, the document has %d", len(edits), kind.NumField())
	}
	for field, edit := range edits {
		if edit == nil {
			continue // the three constants are refused by shape; signatures are excluded by design
		}
		value := base
		value.Signatures = append([]SignatureV1{}, base.Signatures...)
		edit(&value)
		digest, err := StoreHostAuthorizationSHA256(value)
		if err != nil {
			t.Fatalf("%s: %v", field, err)
		}
		if digest == baseDigest {
			t.Fatalf("STORE_HOST_FIELD_UNBOUND: changing %s did not change the signed digest", field)
		}
		if _, err := VerifyStoreHostAuthorization(genesis, value, storeHostNow); err == nil {
			t.Fatalf("changing %s under the original signatures still verified", field)
		}
	}
}

// Every binding the executor compares is refused by its own field name when
// the measurement differs in that field alone, and the tables are held to the
// two measurement types by reflection.
func TestStoreHostAuthorizationBindsEveryReleaseAndPlacementInput(t *testing.T) {
	genesis, value := newStoreHostAuthorization(t)
	release := storeHostReleaseOf(value)
	placement := storeHostPlacementOf(value)
	releaseEdits := map[string]func(*StoreHostRelease){
		"releaseSetSequence":         func(measured *StoreHostRelease) { measured.ReleaseSetSequence++ },
		"releaseSetSha256":           func(measured *StoreHostRelease) { measured.ReleaseSetSHA256 = vectorDigest("m/release-set") },
		"storeBootstrapSha256":       func(measured *StoreHostRelease) { measured.StoreBootstrapSHA256 = vectorDigest("m/bootstrap") },
		"storeBootstrapVersion":      func(measured *StoreHostRelease) { measured.StoreBootstrapVersion = "1.2.4" },
		"storeBootstrapSourceCommit": func(measured *StoreHostRelease) { measured.StoreBootstrapSourceCommit = vectorSourceCommit("m/commit") },
		"storeHostSpecSha256":        func(measured *StoreHostRelease) { measured.StoreHostSpecSHA256 = vectorDigest("m/spec") },
	}
	placementEdits := map[string]func(*StoreHostPlacement){
		"hostMachineIdHash": func(measured *StoreHostPlacement) { measured.HostMachineIDHash = vectorDigest("m/host") },
		"rootStoreHostname": func(measured *StoreHostPlacement) { measured.RootStoreHostname = "store2.estate.test" },
		"placementKind": func(measured *StoreHostPlacement) {
			measured.PlacementKind = StoreHostPlacementRehearsalEdgeColocated
		},
		"containerName":  func(measured *StoreHostPlacement) { measured.ContainerName = "root-store-2" },
		"bridgeName":     func(measured *StoreHostPlacement) { measured.BridgeName = "storebr1" },
		"backendAddress": func(measured *StoreHostPlacement) { measured.BackendAddress = "10.77.0.11" },
	}
	if got := reflect.TypeOf(StoreHostRelease{}).NumField(); got != len(releaseEdits) {
		t.Fatalf("STORE_HOST_RELEASE_BINDING_UNTESTED: StoreHostRelease has %d fields, the table %d", got, len(releaseEdits))
	}
	if got := reflect.TypeOf(StoreHostPlacement{}).NumField(); got != len(placementEdits) {
		t.Fatalf("STORE_HOST_PLACEMENT_BINDING_UNTESTED: StoreHostPlacement has %d fields, the table %d", got, len(placementEdits))
	}
	for field, edit := range releaseEdits {
		t.Run("release/"+field, func(t *testing.T) {
			measured := release
			edit(&measured)
			requireRefusal(t, RequireStoreHostRelease(value, measured), RefusalStoreHostAuthorizationInputMismatch+":"+field)
			_, err := RequireStoreHostAuthorization(genesis, value, measured, placement, storeHostNow)
			requireRefusal(t, err, RefusalStoreHostAuthorizationInputMismatch+":"+field)
		})
	}
	for field, edit := range placementEdits {
		t.Run("placement/"+field, func(t *testing.T) {
			measured := placement
			edit(&measured)
			requireRefusal(t, RequireStoreHostPlacement(value, measured), RefusalStoreHostAuthorizationInputMismatch+":"+field)
			_, err := RequireStoreHostAuthorization(genesis, value, release, measured, storeHostNow)
			requireRefusal(t, err, RefusalStoreHostAuthorizationInputMismatch+":"+field)
		})
	}
	// An empty measurement is a mismatch, never a wildcard.
	requireRefusal(t, RequireStoreHostRelease(value, StoreHostRelease{}), RefusalStoreHostAuthorizationInputMismatch+":releaseSetSequence")
	requireRefusal(t, RequireStoreHostPlacement(value, StoreHostPlacement{}), RefusalStoreHostAuthorizationInputMismatch+":hostMachineIdHash")
}

type storeHostVectorsDocument struct {
	Schema                   string                    `json:"schema"`
	Notes                    []string                  `json:"notes"`
	GenesisOwnerPolicySHA256 string                    `json:"genesisOwnerPolicySha256"`
	VerifyAt                 string                    `json:"verifyAt"`
	Authorizations           []storeHostVectorDocument `json:"authorizations"`
}

type storeHostVectorDocument struct {
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Authorization json.RawMessage `json:"authorization"`
	PreimageHex   string          `json:"preimageHex"`
	SHA256        string          `json:"sha256"`
	Refusal       string          `json:"refusal"`
}

func buildStoreHostVectors(t *testing.T) storeHostVectorsDocument {
	t.Helper()
	genesis, threshold := newStoreHostAuthorization(t)
	policyDigest, err := OwnerPolicySHA256(genesis)
	if err != nil {
		t.Fatal(err)
	}
	underThreshold := signStoreHostAuthorization(t, genesis, threshold, "owner-a")
	rehearsal := threshold
	rehearsal.PlacementKind = StoreHostPlacementRehearsalEdgeColocated
	rehearsal = signStoreHostAuthorization(t, genesis, rehearsal, "owner-b", "owner-c")
	document := storeHostVectorsDocument{
		Schema: storeHostVectorsSchema,
		Notes: []string{
			"Generated by go test ./internal/estateprofile/ -update-vectors from the package's fixture labels. It contains no private key and has no authority on any network.",
			"The genesis owner policy is the rehearsal estate's of estate-profile-vectors.json; its owner keys are sha256(\"melusina-estate-profile-vector-key:policy.rehearsal.owners.v1/\" + keyId). The release-set, store-bootstrap, Spec, host and nonce digests and the source commit are fictitious placeholders.",
			"preimageHex is the exact binary preimage of StoreHostAuthorizationSHA256. A second implementation must reproduce it byte for byte before it may verify a Store-host authorization.",
			"refusal is empty for a vector that verifies at verifyAt under the genesis owner policy, and otherwise the exact refusal it must produce.",
		},
		GenesisOwnerPolicySHA256: policyDigest,
		VerifyAt:                 storeHostNow.Format(issuedAtLayout),
	}
	for _, item := range []struct {
		name, description, refusal string
		value                      StoreHostAuthorizationV1
	}{
		{"dedicated-genesis-threshold", "A dedicated-host root Store signed by owner-a and owner-b, exactly the 2-of-3 threshold of the genesis owner policy, valid 01:00-02:00 UTC.", "", threshold},
		{"rehearsal-genesis-threshold", "The same host as a one-machine rehearsal beside the edge, signed by owner-b and owner-c.", "", rehearsal},
		{"dedicated-under-threshold", "The dedicated-host authorization signed by owner-a alone.", RefusalStoreHostAuthorizationSignaturesInsufficient, underThreshold},
	} {
		raw, err := json.Marshal(item.value)
		if err != nil {
			t.Fatal(err)
		}
		preimage, err := StoreHostAuthorizationPreimage(item.value)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := StoreHostAuthorizationSHA256(item.value)
		if err != nil {
			t.Fatal(err)
		}
		document.Authorizations = append(document.Authorizations, storeHostVectorDocument{
			Name: item.name, Description: item.description, Authorization: raw,
			PreimageHex: hex.EncodeToString(preimage), SHA256: digest, Refusal: item.refusal,
		})
	}
	return document
}

// TestStoreHostAuthorizationVectorsAreTheContract keeps the committed vectors
// and the fixtures one object, and holds every vector to its stated outcome.
// Run with -update-vectors to rewrite the file.
func TestStoreHostAuthorizationVectorsAreTheContract(t *testing.T) {
	generated, err := json.MarshalIndent(buildStoreHostVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	generated = append(generated, '\n')
	if *updateVectors {
		if err := os.WriteFile(storeHostVectorsPath, generated, 0o644); err != nil {
			t.Fatalf("write %s: %v", storeHostVectorsPath, err)
		}
		t.Logf("wrote %s (%d bytes)", filepath.Base(storeHostVectorsPath), len(generated))
		return
	}
	committed, err := os.ReadFile(storeHostVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", storeHostVectorsPath, err)
	}
	if !bytes.Equal(committed, generated) {
		t.Fatalf("%s is not what the fixtures generate; re-run with -update-vectors and read the diff before committing it", storeHostVectorsPath)
	}
	var document storeHostVectorsDocument
	if err := json.Unmarshal(committed, &document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != storeHostVectorsSchema || len(document.Authorizations) < 3 {
		t.Fatalf("unexpected store host vectors header")
	}
	verifyAt, ok := parseIssuedAt(document.VerifyAt)
	if !ok {
		t.Fatalf("verifyAt %q does not parse", document.VerifyAt)
	}
	genesis := newEstateProfile(t).GenesisOwnerPolicy
	if digest, err := OwnerPolicySHA256(genesis); err != nil || digest != document.GenesisOwnerPolicySHA256 {
		t.Fatalf("the vectors name genesis policy %s, the fixture digests to %s (%v)", document.GenesisOwnerPolicySHA256, digest, err)
	}
	for _, item := range document.Authorizations {
		value, err := DecodeStoreHostAuthorization(item.Authorization)
		if err != nil {
			t.Fatalf("%s: decode: %v", item.Name, err)
		}
		preimage, err := StoreHostAuthorizationPreimage(value)
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
		digest, err := VerifyStoreHostAuthorization(genesis, value, verifyAt)
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
