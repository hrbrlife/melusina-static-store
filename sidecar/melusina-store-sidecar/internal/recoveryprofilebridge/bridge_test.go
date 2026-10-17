package recoveryprofilebridge

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("melusina-estate-profile-vector-key:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}
func testHash(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}
func testAddress(label string) string {
	sum := sha256.Sum256([]byte(label))
	return primitives.Pubkey(sum).Base58()
}
func rawHash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func signProfile(t *testing.T, p estateprofile.EstateProfileV1) estateprofile.EstateProfileV1 {
	t.Helper()
	p.Signatures = nil
	digest, err := estateprofile.ProfileSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyID := range []string{"owner-a", "owner-b"} {
		sig := ed25519.Sign(testKey(p.OwnerPolicy.PolicyID+"/"+keyID), []byte(digest))
		p.Signatures = append(p.Signatures, estateprofile.SignatureV1{KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(sig)})
	}
	if _, err := estateprofile.VerifyProfile(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func fixture(t *testing.T) (Signed, []byte, []byte, Observation) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "estate-profile-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Profiles []struct {
			Name    string                        `json:"name"`
			Profile estateprofile.EstateProfileV1 `json:"profile"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	var old estateprofile.EstateProfileV1
	for _, v := range vectors.Profiles {
		if v.Name == "new-estate-revision-1" {
			old = v.Profile
		}
	}
	if old.Schema == "" {
		t.Fatal("vector absent")
	}
	oldDigest, err := estateprofile.VerifyProfile(old)
	if err != nil {
		t.Fatal(err)
	}
	newProfile := old
	newProfile.Revision = 2
	newProfile.IssuedAt = "2026-09-21T00:00:00Z"
	newProfile.Prev = estateprofile.PrevV1{Revision: 1, SHA256: oldDigest}
	newProfile.Store.OperatorKey = testAddress("bridge-new-store-operator")
	newProfile = signProfile(t, newProfile)
	newDigest, _ := estateprofile.VerifyProfile(newProfile)
	oldRaw, _ := json.Marshal(old)
	newRaw, _ := json.Marshal(newProfile)
	coreMultisig, coreVault, registry := "", "", ""
	for _, r := range old.Roles {
		if r.Role == estateprofile.AuthorityRoleCore {
			coreMultisig, coreVault = r.Multisig, r.Vault
		}
	}
	for _, p := range old.Programs {
		if p.Role == estateprofile.ProgramRoleLicenseRegistry {
			registry = p.ProgramID
		}
	}
	members := []Member{}
	for _, role := range []string{"installer", "shell-bundle", "update-controller"} {
		artifactHash := testHash(role + "-bytes")
		master, err := primitives.PubkeyFromBase58(old.Anchors.MasterMint)
		if err != nil {
			t.Fatal(err)
		}
		program, err := primitives.PubkeyFromBase58(registry)
		if err != nil {
			t.Fatal(err)
		}
		artifactBytes, _ := hex.DecodeString(artifactHash)
		entryPDA, _, err := primitives.DeriveInstallerRelease(master, *(*[32]byte)(artifactBytes), program)
		if err != nil {
			t.Fatal(err)
		}
		members = append(members, Member{Role: role, ArtifactSHA256: testHash(role + "-bytes"), ArtifactSize: 100,
			EntryPDA: entryPDA.Base58(), EntryRawSHA256: testHash(role + "-entry"), EntryProfileDigest: oldDigest, EntryStatus: "Active"})
	}
	s := Statement{Schema: Schema, AdmissionSHA256: testHash("admission"), AdmissionNonce: testHash("nonce"),
		EstateID: old.EstateID, Genesis: old.Network.GenesisHash, MasterMint: old.Anchors.MasterMint,
		RegistryProgram: registry, CoreMultisig: coreMultisig, CoreVault: coreVault,
		OldProfileRawSHA256: rawHash(oldRaw), OldProfileDigest: oldDigest,
		SuccessorProfileRawSHA256: rawHash(newRaw), SuccessorProfileDigest: newDigest,
		LiveTrustRawSHA256: testHash("live-trust"), FoundationSequence: 106, F1Sequence: 107,
		FoundationSetSHA256: testHash("signed-f0"), F1SetSHA256: testHash("signed-f1"),
		InstallerSHA256: memberHash(members, "installer"), ShellSHA256: memberHash(members, "shell-bundle"),
		StoreArchiveSHA256: testHash("store-archive"), StoreBinarySHA256: testHash("store-binary"),
		DeployerCommit: testHash("deployer")[:40], StoreCommit: testHash("store")[:40],
		NewOperator: newProfile.Store.OperatorKey, RotationApprovalSHA256: testHash("rotation"), Members: members}
	observation := Observation{AdmissionSHA256: s.AdmissionSHA256, AdmissionNonce: s.AdmissionNonce,
		AdmissionOldProfileRawSHA256: s.OldProfileRawSHA256, AdmissionOldProfileDigest: s.OldProfileDigest,
		AdmissionNewOperator: s.NewOperator, AdmissionRotationApprovalSHA256: s.RotationApprovalSHA256,
		AdmissionInstallerSHA256: s.InstallerSHA256, AdmissionShellSHA256: s.ShellSHA256,
		AdmissionStoreArchiveSHA256: s.StoreArchiveSHA256, AdmissionStoreBinarySHA256: s.StoreBinarySHA256,
		AdmissionDeployerCommit: s.DeployerCommit, AdmissionStoreCommit: s.StoreCommit,
		FoundationSequence: 106, F1Sequence: 107, FoundationSetSHA256: s.FoundationSetSHA256,
		F1SetSHA256: s.F1SetSHA256, TrustRawSHA256: s.LiveTrustRawSHA256,
		TrustProfileDigest: oldDigest, TrustPublisherKeys: old.ReleaseTrust.PublisherKeys,
		TrustThreshold: old.ReleaseTrust.Threshold, Members: members, CoreThreshold: 3}
	intent, err := IntentDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	observation.FoundationBridgeIntentSHA256 = intent
	b := Signed{Statement: s}
	for _, label := range []string{"council-1", "council-2", "council-3", "council-4"} {
		observation.CoreMembers = append(observation.CoreMembers, primitives.Pubkey(*(*[32]byte)(testKey(label).Public().(ed25519.PublicKey))).Base58())
	}
	signBridge(t, &b, old.OwnerPolicy.PolicyID)
	return b, oldRaw, newRaw, observation
}

func signBridge(t *testing.T, b *Signed, policyID string) {
	t.Helper()
	digest, err := Digest(b.Statement)
	if err != nil {
		t.Fatal(err)
	}
	b.OwnerSignatures = nil
	for _, keyID := range []string{"owner-a", "owner-b"} {
		sig := ed25519.Sign(testKey(policyID+"/"+keyID), []byte(digest))
		b.OwnerSignatures = append(b.OwnerSignatures, estateprofile.SignatureV1{KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(sig)})
	}
	b.CouncilSignatures = nil
	for _, label := range []string{"council-1", "council-2", "council-3"} {
		key := testKey(label)
		b.CouncilSignatures = append(b.CouncilSignatures, CouncilSignature{
			Member:    primitives.Pubkey(*(*[32]byte)(key.Public().(ed25519.PublicKey))).Base58(),
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(digest)))})
	}
}

func TestRecoveryBridgePositiveAndCanonicalDecode(t *testing.T) {
	b, old, next, observed := fixture(t)
	if _, err := Verify(b, old, next, observed); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(b)
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(decoded, old, next, observed); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(append([]byte(" "), raw...)); err != nil {
		t.Fatal(err)
	}
	duplicate := []byte(`{"statement":{},"statement":{}}`)
	if _, err := Decode(duplicate); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestRecoveryBridgeChangedAdmissionOrF1(t *testing.T) {
	b, old, next, observed := fixture(t)
	observed.AdmissionSHA256 = testHash("another-admission")
	if _, err := Verify(b, old, next, observed); !errors.Is(err, ErrAdmission) {
		t.Fatalf("admission: %v", err)
	}
	observed.AdmissionSHA256 = b.Statement.AdmissionSHA256
	observed.F1Sequence++
	if _, err := Verify(b, old, next, observed); !errors.Is(err, ErrAdmission) {
		t.Fatalf("F1: %v", err)
	}
	observed.F1Sequence = b.Statement.F1Sequence
	observed.FoundationSetSHA256 = testHash("substituted-signed-f0")
	if _, err := Verify(b, old, next, observed); !errors.Is(err, ErrAdmission) {
		t.Fatalf("signed F0 digest: %v", err)
	}
	observed.FoundationSetSHA256 = b.Statement.FoundationSetSHA256
	observed.F1SetSHA256 = testHash("substituted-signed-f1")
	if _, err := Verify(b, old, next, observed); !errors.Is(err, ErrAdmission) {
		t.Fatalf("signed F1 digest: %v", err)
	}
}

func TestRecoveryBridgeOwnerCouncilQuorumDistinct(t *testing.T) {
	b, old, next, observed := fixture(t)
	b.OwnerSignatures = b.OwnerSignatures[:1]
	if _, err := Verify(b, old, next, observed); !errors.Is(err, ErrSignature) {
		t.Fatalf("owner: %v", err)
	}
	b, old, next, observed = fixture(t)
	b.CouncilSignatures[2] = b.CouncilSignatures[1]
	if _, err := Verify(b, old, next, observed); !errors.Is(err, ErrSignature) {
		t.Fatalf("council: %v", err)
	}
}

func TestRecoveryBridgeProfileLineageAndOperator(t *testing.T) {
	b, old, next, observed := fixture(t)
	var p estateprofile.EstateProfileV1
	if err := json.Unmarshal(next, &p); err != nil {
		t.Fatal(err)
	}
	p.Store.OperatorKey = testAddress("another-operator")
	p = signProfile(t, p)
	changed, _ := json.Marshal(p)
	if _, err := Verify(b, old, changed, observed); !errors.Is(err, ErrProfile) {
		t.Fatalf("operator: %v", err)
	}
}

func TestRecoveryBridgeRefusesOtherOwnerSignedProfileChanges(t *testing.T) {
	b, old, next, observed := fixture(t)
	var p estateprofile.EstateProfileV1
	if err := json.Unmarshal(next, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.ExternalPrograms) == 0 {
		t.Fatal("fixture has no external program")
	}
	p.ExternalPrograms[0].ExecutableSHA256 = testHash("foreign-external-program")
	p = signProfile(t, p)
	changed, _ := json.Marshal(p)
	newDigest, _ := estateprofile.VerifyProfile(p)
	b.Statement.SuccessorProfileRawSHA256 = rawHash(changed)
	b.Statement.SuccessorProfileDigest = newDigest
	signBridge(t, &b, p.OwnerPolicy.PolicyID)
	observed.FoundationBridgeIntentSHA256, _ = IntentDigest(b.Statement)
	if _, err := Verify(b, old, changed, observed); !errors.Is(err, ErrProfile) {
		t.Fatalf("separately owner-signed external program change rode narrow bridge: %v", err)
	}
}

func TestRecoveryBridgeTrustAndEntryReadbackDrift(t *testing.T) {
	b, old, next, observed := fixture(t)
	observed.TrustRawSHA256 = testHash("drifted-trust")
	if _, err := Verify(b, old, next, observed); !errors.Is(err, ErrChainDrift) {
		t.Fatalf("trust: %v", err)
	}
	observed.TrustRawSHA256 = b.Statement.LiveTrustRawSHA256
	observed.Members = append([]Member(nil), observed.Members...)
	observed.Members[0].EntryRawSHA256 = testHash("drifted-entry")
	if _, err := Verify(b, old, next, observed); !errors.Is(err, ErrChainDrift) {
		t.Fatalf("entry: %v", err)
	}
}

func TestRecoveryBridgeOnlyThreeF1Hashes(t *testing.T) {
	b, _, _, _ := fixture(t)
	b.Statement.Members = append(b.Statement.Members, Member{Role: "fourth"})
	if _, err := Digest(b.Statement); !errors.Is(err, ErrMember) {
		t.Fatalf("fourth: %v", err)
	}
	b, _, _, _ = fixture(t)
	b.Statement.Members[0].EntryPDA = testAddress("wrong-entry-pda")
	if _, err := IntentDigest(b.Statement); !errors.Is(err, ErrMember) {
		t.Fatalf("unrelated entry PDA: %v", err)
	}
}

func TestRecoveryBridgeIntentPrecedesEntryRegistrationButCompletionBindsReadbacks(t *testing.T) {
	b, old, next, observed := fixture(t)
	intent, err := IntentDigest(b.Statement)
	if err != nil {
		t.Fatal(err)
	}
	beforeRegistration := b.Statement
	beforeRegistration.FoundationSetSHA256 = ""
	beforeRegistration.F1SetSHA256 = ""
	beforeRegistration.Members = append([]Member(nil), beforeRegistration.Members...)
	for index := range beforeRegistration.Members {
		beforeRegistration.Members[index].EntryRawSHA256 = ""
		beforeRegistration.Members[index].EntryProfileDigest = ""
		beforeRegistration.Members[index].EntryStatus = ""
	}
	if got, err := IntentDigest(beforeRegistration); err != nil || got != intent {
		t.Fatalf("intent changed after registration: %s %v", got, err)
	}
	if got, err := VerifyIntent(beforeRegistration, old, next, observed); err != nil || got != intent {
		t.Fatalf("signed-profile intent refused before entry registration: %s %v", got, err)
	}
	if _, err := Digest(beforeRegistration); !errors.Is(err, ErrMalformed) {
		t.Fatalf("incomplete bridge was signable: %v", err)
	}
	intentRaw, _ := json.Marshal(beforeRegistration)
	if _, err := DecodeIntent(intentRaw); err != nil {
		t.Fatalf("canonical unsigned intent: %v", err)
	}
	completedRaw, _ := json.Marshal(b.Statement)
	if _, err := DecodeIntent(completedRaw); !errors.Is(err, ErrScope) {
		t.Fatalf("completed bridge was accepted as an intent: %v", err)
	}
	b.Statement.Members = append([]Member(nil), b.Statement.Members...)
	b.Statement.Members[0].EntryRawSHA256 = testHash("substituted-entry")
	if _, err := Verify(b, old, next, observed); !errors.Is(err, ErrChainDrift) {
		t.Fatalf("substituted entry: %v", err)
	}
	observed.FoundationBridgeIntentSHA256 = testHash("different-intent")
	if _, err := Verify(b, old, next, observed); !errors.Is(err, ErrAdmission) {
		t.Fatalf("different F0 intent: %v", err)
	}
}
