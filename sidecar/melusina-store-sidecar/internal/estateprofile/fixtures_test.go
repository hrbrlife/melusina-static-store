package estateprofile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"
)

// Every key here is derived from a fixed label, so the committed vectors and
// every run of these tests agree byte for byte with no stored secret. This is
// test material: it holds no authority on any network and never leaves this
// package. Only the public halves and the signatures reach testdata.
func vectorPrivateKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("melusina-estate-profile-vector-key:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func vectorPublicKey(label string) string {
	key := vectorPrivateKey(label).Public().(ed25519.PublicKey)
	return hex.EncodeToString(key)
}

// vectorAddress derives a clearly fictitious but canonically valid base58
// address. Illustrative vectors use it wherever the real value is not public;
// nothing derived this way is an estate fact.
func vectorAddress(label string) string {
	sum := sha256.Sum256([]byte("MELUSINA_ILLUSTRATIVE_PLACEHOLDER_V1:" + label))
	return encodeBase58(sum[:])
}

func vectorDigest(label string) string {
	sum := sha256.Sum256([]byte("MELUSINA_ILLUSTRATIVE_PLACEHOLDER_V1:" + label))
	return hex.EncodeToString(sum[:])
}

func vectorSourceCommit(label string) string {
	sum := sha256.Sum256([]byte("MELUSINA_ILLUSTRATIVE_PLACEHOLDER_V1:" + label))
	return hex.EncodeToString(sum[:20])
}

// vectorPolicy builds a policy from labels that are already its sorted keyIds.
func vectorPolicy(policyID string, revision uint64, threshold uint32, keyIDs ...string) OwnerPolicyV1 {
	signers := make([]OwnerSignerV1, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		signers = append(signers, OwnerSignerV1{KeyID: keyID, Ed25519PublicKey: vectorPublicKey(policyID + "/" + keyID)})
	}
	sort.Slice(signers, func(left, right int) bool { return signers[left].KeyID < signers[right].KeyID })
	return OwnerPolicyV1{PolicyID: policyID, Revision: revision, Threshold: threshold, Signers: signers}
}

// signDigest signs the ASCII bytes of a lowercase hex digest, which is the one
// thing any signature in this document type ever covers.
func signDigest(policy OwnerPolicyV1, digest string, keyIDs ...string) []SignatureV1 {
	signatures := make([]SignatureV1, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		private := vectorPrivateKey(policy.PolicyID + "/" + keyID)
		signatures = append(signatures, SignatureV1{
			KeyID:     keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(digest))),
		})
	}
	sort.Slice(signatures, func(left, right int) bool { return signatures[left].KeyID < signatures[right].KeyID })
	return signatures
}

// signProfile attaches owner signatures over the profile's own digest.
func signProfile(t *testing.T, profile EstateProfileV1, keyIDs ...string) EstateProfileV1 {
	t.Helper()
	profile.Signatures = nil
	digest, err := ProfileSHA256(profile)
	if err != nil {
		t.Fatalf("digest the profile to sign: %v", err)
	}
	profile.Signatures = signDigest(profile.OwnerPolicy, digest, keyIDs...)
	return profile
}

const (
	newEstatePolicyID       = "policy.rehearsal.owners.v1"
	newEstateSuccessorID    = "policy.rehearsal.owners-2027.v1"
	paypeDevnetPolicyID     = "policy.paype.owners.v1"
	vectorIssuedAt          = "2026-09-20T00:00:00Z"
	vectorSuccessorIssuedAt = "2026-09-21T00:00:00Z"

	// Public values of the estate as it stands today, read from tracked
	// sources in the deployer line, not from any live host.
	paypeDevnetGenesisHash    = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
	paypeSquadsV4ProgramID    = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
	paypeLicenseRegistryID    = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	paypeWitnessVerifierID    = "ALLaDf2kgENEPFY63fhzC2cVBVfAZLzSDRn9yKjwQgnM"
	paypeCoreVault            = "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V"
	paypeRootInstallAdmin     = "Arkupda1Giah5RdtyZX4GzNMnpoJTxcGVkNwwS7rfR32"
	paypeRootStoreDomain      = "bazaar.melusina-os.org"
	paypeRootStoreID          = "melusina-os-root-store"
	paypeRootStoreOperatorKey = "4J2hbufiTKmvgfxjGVNqhoQXiKVDsYwaor6hcaDKjzZV"
	paypeMasterMint           = "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe"
	paypeResellerMint         = "9yfmmcTG8BBiSPHf6kZC77tUzm46VMnfyrLzd3E2ii9J"
)

func rootDomainSHA256(domain string) string {
	sum := sha256.Sum256([]byte(domain))
	return hex.EncodeToString(sum[:])
}

// newEstateProfile is a complete, signed revision 1 of a fictitious estate:
// every value is derived, none of it names anything that exists.
func newEstateProfile(t *testing.T) EstateProfileV1 {
	t.Helper()
	policy := vectorPolicy(newEstatePolicyID, 1, 2, "owner-a", "owner-b", "owner-c")
	nonce := vectorDigest("rehearsal/estateNonce")
	estateID, err := EstateID(policy, nonce)
	if err != nil {
		t.Fatalf("estate id: %v", err)
	}
	publisherKeys := []string{vectorPublicKey("rehearsal/publisher-1"), vectorPublicKey("rehearsal/publisher-2")}
	sort.Strings(publisherKeys)
	profile := EstateProfileV1{
		Schema:             ProfileSchema,
		Kind:               ProfileKind,
		EstateID:           estateID,
		EstateNonce:        nonce,
		GenesisOwnerPolicy: policy,
		Revision:           1,
		IssuedAt:           vectorIssuedAt,
		OwnerPolicy:        policy,
		PolicySuccession:   []PolicySuccessionV1{},
		ReleaseTrust:       ReleaseTrustV1{PublisherKeys: publisherKeys, Threshold: 1},
		Network: NetworkV1{
			Label:       "melusina-rehearsal",
			GenesisHash: vectorAddress("rehearsal/genesisHash"),
			Commitment:  NetworkCommitment,
		},
		Programs: []ProgramV1{
			{
				Role:                ProgramRoleLicenseRegistry,
				ProgramID:           vectorAddress("rehearsal/license-registry/programId"),
				UpgradeAuthority:    vectorAddress("rehearsal/core/vault"),
				SourceCommit:        vectorSourceCommit("rehearsal/license-registry/sourceCommit"),
				BuildManifestSHA256: vectorDigest("rehearsal/license-registry/buildManifest"),
				ExecutableSHA256:    vectorDigest("rehearsal/license-registry/executable"),
				IDLSHA256:           vectorDigest("rehearsal/license-registry/idl"),
			},
			{
				Role:                ProgramRoleWitnessVerifier,
				ProgramID:           vectorAddress("rehearsal/witness-verifier/programId"),
				UpgradeAuthority:    vectorAddress("rehearsal/core/vault"),
				SourceCommit:        vectorSourceCommit("rehearsal/witness-verifier/sourceCommit"),
				BuildManifestSHA256: vectorDigest("rehearsal/witness-verifier/buildManifest"),
				ExecutableSHA256:    vectorDigest("rehearsal/witness-verifier/executable"),
				IDLSHA256:           vectorDigest("rehearsal/witness-verifier/idl"),
			},
		},
		ExternalPrograms: []ExternalProgramV1{
			{Role: ExternalRoleATA, ProgramID: vectorAddress("rehearsal/ata/programId"), ExecutableSHA256: vectorDigest("rehearsal/ata/executable")},
			{Role: ExternalRoleSquadsV4, ProgramID: vectorAddress("rehearsal/squads-v4/programId"), ExecutableSHA256: vectorDigest("rehearsal/squads-v4/executable")},
			{Role: ExternalRoleToken, ProgramID: vectorAddress("rehearsal/token/programId"), ExecutableSHA256: vectorDigest("rehearsal/token/executable")},
		},
		Anchors: AnchorsV1{
			MasterMint:          vectorAddress("rehearsal/masterMint"),
			ResellerMint:        vectorAddress("rehearsal/resellerMint"),
			RegistryAuthority:   vectorAddress("rehearsal/registryAuthority"),
			SquadsProgramConfig: vectorAddress("rehearsal/squadsProgramConfig"),
			SquadsTreasury:      vectorAddress("rehearsal/squadsTreasury"),
		},
		Roles: []AuthorityRoleV1{
			{
				Role: AuthorityRoleCore, Kind: AuthorityKindSquads,
				Multisig: vectorAddress("rehearsal/core/multisig"), Vault: vectorAddress("rehearsal/core/vault"),
				Threshold: 3, MemberCount: 4, PermissionMasks: []uint32{7, 7, 7, 7},
				ConfigAuthority: "11111111111111111111111111111111", TimeLockSeconds: 0,
			},
			{
				Role: AuthorityRoleRootInstallAdmin, Kind: AuthorityKindKey,
				Vault: vectorAddress("rehearsal/root-install-admin"), Threshold: 1, MemberCount: 1,
				PermissionMasks: []uint32{},
			},
			{
				Role: AuthorityRoleStoreRelease, Kind: AuthorityKindSquads,
				Multisig: vectorAddress("rehearsal/store-release/multisig"), Vault: vectorAddress("rehearsal/store-release/vault"),
				Threshold: 2, MemberCount: 3, PermissionMasks: []uint32{7, 7, 7},
				ConfigAuthority: "11111111111111111111111111111111", TimeLockSeconds: 0,
			},
		},
		Store: StoreV1{
			RootDomain:       "bazaar.rehearsal.invalid",
			RootDomainSHA256: rootDomainSHA256("bazaar.rehearsal.invalid"),
			StoreID:          "rehearsal-root-store",
			OperatorKey:      vectorAddress("rehearsal/store/operatorKey"),
			ReleaseRole:      AuthorityRoleStoreRelease,
			IsRoot:           true,
		},
		Recalls: []RecallV1{},
		Prev:    PrevV1{},
	}
	return signProfile(t, profile, "owner-a", "owner-b")
}

// newEstateMigrate is revision 2 of the same estate: the owners handed
// authority to a successor policy with a threshold-signed succession step, and
// recalled the revision they left behind.
func newEstateMigrate(t *testing.T, previous EstateProfileV1, recallPrevious bool) EstateProfileV1 {
	t.Helper()
	previousDigest, err := ProfileSHA256(previous)
	if err != nil {
		t.Fatalf("digest the previous revision: %v", err)
	}
	successor := vectorPolicy(newEstateSuccessorID, 2, 3, "owner-a", "owner-b", "owner-c", "owner-d")
	step := PolicySuccessionV1{
		FromPolicySHA256: ownerPolicySHA256Unchecked(previous.GenesisOwnerPolicy),
		ToPolicy:         successor,
		Revision:         2,
	}
	step.Signatures = signDigest(previous.GenesisOwnerPolicy, policySuccessionSHA256(previous.EstateID, step), "owner-a", "owner-c")

	profile := previous
	profile.Revision = 2
	profile.IssuedAt = vectorSuccessorIssuedAt
	profile.OwnerPolicy = successor
	profile.PolicySuccession = []PolicySuccessionV1{step}
	profile.Prev = PrevV1{Revision: previous.Revision, SHA256: previousDigest}
	profile.Recalls = []RecallV1{}
	if recallPrevious {
		profile.Recalls = []RecallV1{{SHA256: previousDigest, Reason: "revision 1 owner key set retired"}}
	}
	return signProfile(t, profile, "owner-a", "owner-b", "owner-d")
}

// paypeDevnetProfile describes the estate that exists today from public values
// only. Every value the public record does not carry is a derived placeholder,
// listed by paypeIllustrativeFields; the vector is illustrative and is not an
// authority for what the live estate holds.
func paypeDevnetProfile(t *testing.T) EstateProfileV1 {
	t.Helper()
	policy := vectorPolicy(paypeDevnetPolicyID, 1, 3, "owner-a", "owner-b", "owner-c", "owner-d")
	nonce := vectorDigest("paype/estateNonce")
	estateID, err := EstateID(policy, nonce)
	if err != nil {
		t.Fatalf("estate id: %v", err)
	}
	profile := EstateProfileV1{
		Schema:             ProfileSchema,
		Kind:               ProfileKind,
		EstateID:           estateID,
		EstateNonce:        nonce,
		GenesisOwnerPolicy: policy,
		Revision:           1,
		IssuedAt:           vectorIssuedAt,
		OwnerPolicy:        policy,
		PolicySuccession:   []PolicySuccessionV1{},
		ReleaseTrust:       ReleaseTrustV1{PublisherKeys: []string{vectorPublicKey("paype/publisher-1")}, Threshold: 1},
		Network: NetworkV1{
			Label:       "devnet",
			GenesisHash: paypeDevnetGenesisHash,
			Commitment:  NetworkCommitment,
		},
		Programs: []ProgramV1{
			{
				Role:                ProgramRoleLicenseRegistry,
				ProgramID:           paypeLicenseRegistryID,
				UpgradeAuthority:    paypeCoreVault,
				SourceCommit:        vectorSourceCommit("paype/license-registry/sourceCommit"),
				BuildManifestSHA256: vectorDigest("paype/license-registry/buildManifest"),
				ExecutableSHA256:    vectorDigest("paype/license-registry/executable"),
				IDLSHA256:           vectorDigest("paype/license-registry/idl"),
			},
			{
				Role:                ProgramRoleWitnessVerifier,
				ProgramID:           paypeWitnessVerifierID,
				UpgradeAuthority:    paypeCoreVault,
				SourceCommit:        vectorSourceCommit("paype/witness-verifier/sourceCommit"),
				BuildManifestSHA256: vectorDigest("paype/witness-verifier/buildManifest"),
				ExecutableSHA256:    vectorDigest("paype/witness-verifier/executable"),
				IDLSHA256:           vectorDigest("paype/witness-verifier/idl"),
			},
		},
		ExternalPrograms: []ExternalProgramV1{
			{Role: ExternalRoleSquadsV4, ProgramID: paypeSquadsV4ProgramID, ExecutableSHA256: vectorDigest("paype/squads-v4/executable")},
		},
		Anchors: AnchorsV1{
			MasterMint:          paypeMasterMint,
			ResellerMint:        paypeResellerMint,
			RegistryAuthority:   vectorAddress("paype/registryAuthority"),
			SquadsProgramConfig: vectorAddress("paype/squadsProgramConfig"),
			SquadsTreasury:      vectorAddress("paype/squadsTreasury"),
		},
		Roles: []AuthorityRoleV1{
			{
				Role: AuthorityRoleCore, Kind: AuthorityKindSquads,
				Multisig: vectorAddress("paype/core/multisig"), Vault: paypeCoreVault,
				Threshold: 3, MemberCount: 4, PermissionMasks: []uint32{7, 7, 7, 7},
				ConfigAuthority: "11111111111111111111111111111111", TimeLockSeconds: 0,
			},
			{
				Role: AuthorityRoleRootInstallAdmin, Kind: AuthorityKindKey,
				Vault: paypeRootInstallAdmin, Threshold: 1, MemberCount: 1, PermissionMasks: []uint32{},
			},
			{
				Role: AuthorityRoleStoreRelease, Kind: AuthorityKindSquads,
				Multisig: vectorAddress("paype/store-release/multisig"), Vault: vectorAddress("paype/store-release/vault"),
				Threshold: 3, MemberCount: 4, PermissionMasks: []uint32{7, 7, 7, 7},
				ConfigAuthority: "11111111111111111111111111111111", TimeLockSeconds: 0,
			},
		},
		Store: StoreV1{
			RootDomain:       paypeRootStoreDomain,
			RootDomainSHA256: rootDomainSHA256(paypeRootStoreDomain),
			StoreID:          paypeRootStoreID,
			OperatorKey:      paypeRootStoreOperatorKey,
			ReleaseRole:      AuthorityRoleStoreRelease,
			IsRoot:           true,
		},
		Recalls: []RecallV1{},
		Prev:    PrevV1{},
	}
	return signProfile(t, profile, "owner-a", "owner-b", "owner-c")
}

// paypeIllustrativeFields names every field of the paype vector that no public
// source supplied, so nobody reads a placeholder as a measurement.
var paypeIllustrativeFields = []string{
	"anchors.registryAuthority",
	"anchors.squadsProgramConfig",
	"anchors.squadsTreasury",
	"externalPrograms.squads-v4.executableSha256",
	"genesisOwnerPolicy",
	"ownerPolicy",
	"programs.*.buildManifestSha256",
	"programs.*.executableSha256",
	"programs.*.idlSha256",
	"programs.*.sourceCommit",
	"releaseTrust",
	"roles.core.multisig",
	"roles.store-release.multisig",
	"roles.store-release.vault",
	"signatures",
}

// marshalProfile serialises in declaration order, which is also the digest
// order, so a negative vector is the positive document with one edit.
func marshalProfile(t *testing.T, profile EstateProfileV1) []byte {
	t.Helper()
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	return raw
}

// requireRefusal asserts the exact refusal string, not merely that an error
// happened: the name is the wire contract and a different name is a different
// outcome.
func requireRefusal(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected refusal %q, got no error", want)
	}
	if RefusalName(err) == "" {
		t.Fatalf("expected refusal %q, got a non-package error %v", want, err)
	}
	if err.Error() != want {
		t.Fatalf("expected refusal %q, got %q", want, err.Error())
	}
}
