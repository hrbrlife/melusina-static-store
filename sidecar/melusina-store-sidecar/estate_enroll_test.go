package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type fixedStoreGenesisReader struct {
	genesis string
	err     error
}

func (r fixedStoreGenesisReader) FetchGenesisHash(context.Context) (string, error) {
	return r.genesis, r.err
}

type fixedConfiguredStoreGenesisReader struct {
	fixedStoreGenesisReader
	hashes []string
}

func (r fixedConfiguredStoreGenesisReader) FetchConfiguredGenesisHashes(context.Context) ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	return append([]string(nil), r.hashes...), nil
}

// fixedStoreGenesisChainReader gives startup its full chainReader shape while
// keeping the test's only relevant network answer, getGenesisHash, explicit.
type fixedStoreGenesisChainReader struct {
	*mockChainReader
	fixedStoreGenesisReader
}

func newFixedStoreGenesisChainReader(genesis string) *fixedStoreGenesisChainReader {
	return &fixedStoreGenesisChainReader{
		mockChainReader:         newMockChainReader(),
		fixedStoreGenesisReader: fixedStoreGenesisReader{genesis: genesis},
	}
}

type storeEnrollmentRuntimeFixture struct {
	profile     estateprofile.EstateProfileV1
	state       storeEnrollmentState
	declaration storeEstateDeclaration
	cfg         Config
	identity    *verifiedBootIdentity
	genesis     string
}

func signStoreEnrollmentRuntimeProfile(t *testing.T, profile estateprofile.EstateProfileV1) estateprofile.EstateProfileV1 {
	t.Helper()
	profile.Signatures = nil
	digest, err := estateprofile.ProfileSHA256(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyID := range []string{"owner-a", "owner-b"} {
		private := storeEnrollmentStatePrivate(profile.OwnerPolicy.PolicyID, keyID)
		profile.Signatures = append(profile.Signatures, estateprofile.SignatureV1{
			KeyID:     keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(digest))),
		})
	}
	if _, err := estateprofile.VerifyProfile(profile); err != nil {
		t.Fatalf("re-signed runtime profile: %v", err)
	}
	return profile
}

func newStoreEnrollmentRuntimeFixture(t *testing.T) storeEnrollmentRuntimeFixture {
	t.Helper()
	base := storeEstateProfileFixture(t)
	operatorDomain := "operator.rehearsal.invalid"
	operator := newTestIdentity(t, "store", base.Anchors.MasterMint, operatorDomain)
	profile := base
	profile.Store.OperatorKey = operator.Public().SignPubkeyB58
	profile = signStoreEnrollmentRuntimeProfile(t, profile)
	profileDigest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}

	tlsFingerprint := sha256.Sum256([]byte("estate-enroll-runtime-tls"))
	binaryHash := sha256.Sum256([]byte("estate-enroll-runtime-binary"))
	sidecarPDA := randPubkeyB58(t)
	enrollment := estateprofile.StoreEnrollmentV1{
		Schema:             estateprofile.StoreEnrollmentSchema,
		Kind:               estateprofile.StoreEnrollmentKind,
		Purpose:            estateprofile.StoreEnrollmentPurpose,
		EstateID:           profile.EstateID,
		ProfileSHA256:      profileDigest,
		ProfileRevision:    profile.Revision,
		NetworkGenesisHash: profile.Network.GenesisHash,
		RootDomain:         profile.Store.RootDomain,
		RootDomainSHA256:   profile.Store.RootDomainSHA256,
		StoreID:            profile.Store.StoreID,
		StoreOperatorKey:   operator.Public().SignPubkeyB58,
		StoreBoxKey:        operator.Public().BoxPubkeyB58,
		LicenseNFTMint:     profile.Anchors.MasterMint,
		LicenseRegistryID:  storeEnrollmentStateProgramID(t, profile, estateprofile.ProgramRoleLicenseRegistry),
		SidecarID:          "store",
		BindingKeyVersion:  1,
		OperatorKeyVersion: 1,
		OperatorDomain:     operatorDomain,
		SidecarIdentityPDA: sidecarPDA,
		TLSCertFingerprint: hex.EncodeToString(tlsFingerprint[:]),
		BinarySHA256:       hex.EncodeToString(binaryHash[:]),
		IssuedAt:           "2026-09-20T01:00:00Z",
		ExpiresAt:          "2026-09-20T02:00:00Z",
		EnrollmentNonce:    storeEnrollmentStateDigest("runtime-nonce"),
	}
	digest, err := estateprofile.StoreEnrollmentSHA256(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyID := range []string{"owner-a", "owner-b"} {
		enrollment.Signatures = append(enrollment.Signatures, estateprofile.SignatureV1{
			KeyID:     keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(storeEnrollmentStatePrivate(profile.OwnerPolicy.PolicyID, keyID), []byte(digest))),
		})
	}
	state, err := newStoreEnrollmentState(profile, enrollment, storeEnrollmentStateNow)
	if err != nil {
		t.Fatal(err)
	}
	declaration := storeEstateDeclarationForProfile(t, profile)
	declaration.LicenseNFTMint = profile.Anchors.MasterMint
	cfg := Config{
		LicenseNFTMint:       declaration.LicenseNFTMint,
		StoreAuthority:       declaration.StoreAuthority,
		ProgramID:            declaration.ProgramID,
		Domain:               declaration.Domain,
		StoreID:              declaration.StoreID,
		ResellerNFTMint:      declaration.ResellerNFTMint,
		ReleaseMasterNftMint: declaration.ReleaseMasterNFTMint,
		ReleaseSquadsAuthority: ReleaseSquadsAuthority{
			Multisig:    declaration.ReleaseSquadsAuthority.Multisig,
			Vault:       declaration.ReleaseSquadsAuthority.Vault,
			ProgramID:   declaration.ReleaseSquadsAuthority.ProgramID,
			Threshold:   declaration.ReleaseSquadsAuthority.Threshold,
			MemberCount: declaration.ReleaseSquadsAuthority.MemberCount,
		},
		// The literal, not rootstore.SidecarID: a changed constant must fail
		// these fixtures rather than move them with it.
		BootIdentity: BootIdentityConfig{SidecarID: "store"},
	}
	// The master mint the boot cascade pinned is the profile's anchor, as
	// deriveVerifiedBootIdentity reads it from release_master_nft_mint.
	cascadeMaster, err := primitives.PubkeyFromBase58(declaration.ReleaseMasterNFTMint)
	if err != nil {
		t.Fatal(err)
	}
	return storeEnrollmentRuntimeFixture{
		profile:     profile,
		state:       state,
		declaration: declaration,
		cfg:         cfg,
		identity: &verifiedBootIdentity{
			operator:           operator,
			facts:              bootIdentityFacts{tlsFingerprint: tlsFingerprint, binaryHash: binaryHash},
			sidecarID:          "store",
			bindingKeyVersion:  1,
			operatorKeyVersion: 1,
			operatorDomain:     operatorDomain,
			sidecarIdentityPDA: sidecarPDA,
			cascadeMasterMint:  cascadeMaster,
		},
		genesis: profile.Network.GenesisHash,
	}
}

func TestVerifyStoreEnrollmentRuntimeBindsExactFactsAndGenesis(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	got, err := verifyStoreEnrollmentRuntime(context.Background(), f.cfg, f.declaration, f.state, f.identity, fixedStoreGenesisReader{genesis: f.genesis})
	if err != nil {
		t.Fatalf("valid runtime enrollment refused: %v", err)
	}
	if got != f.genesis {
		t.Fatalf("observed genesis = %q, want %q", got, f.genesis)
	}

	foreignOperator := newTestIdentity(t, "store", f.cfg.LicenseNFTMint, f.identity.operatorDomain)
	foreign := *f.identity
	foreign.operator = foreignOperator
	if _, err := verifyStoreEnrollmentRuntime(context.Background(), f.cfg, f.declaration, f.state, &foreign, fixedStoreGenesisReader{genesis: f.genesis}); err == nil || !strings.Contains(err.Error(), "store-enrollment-facts-mismatch") {
		t.Fatalf("foreign local operator accepted: %v", err)
	}

	if _, err := verifyStoreEnrollmentRuntime(context.Background(), f.cfg, f.declaration, f.state, f.identity, fixedStoreGenesisReader{genesis: randPubkeyB58(t)}); err == nil || !strings.Contains(err.Error(), "store-rpc-genesis-mismatch") {
		t.Fatalf("foreign RPC genesis accepted: %v", err)
	}

	if _, err := verifyStoreEnrollmentRuntime(context.Background(), f.cfg, f.declaration, f.state, f.identity, fixedConfiguredStoreGenesisReader{fixedStoreGenesisReader: fixedStoreGenesisReader{genesis: f.genesis}, hashes: []string{f.genesis, randPubkeyB58(t)}}); err == nil || !strings.Contains(err.Error(), "store-rpc-genesis-mismatch") {
		t.Fatalf("foreign configured fallback genesis accepted: %v", err)
	}

	wrongConfig := f.cfg
	wrongConfig.StoreID = "different-store"
	if _, err := verifyStoreEnrollmentRuntime(context.Background(), wrongConfig, f.declaration, f.state, f.identity, fixedStoreGenesisReader{genesis: f.genesis}); err == nil || !strings.Contains(err.Error(), "store-estate-profile-config-mismatch:store_id") {
		t.Fatalf("config drift accepted: %v", err)
	}
}

func TestVerifyConfiguredStoreEnrollmentRefusesMissingInitialStateByName(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f.cfg.EstateEnrollmentStatePath = filepath.Join(dir, "enrollment.json")
	_, err := verifyConfiguredStoreEnrollment(context.Background(), f.cfg, filepath.Join(dir, "store.config.json"), f.identity, nil)
	if !errors.Is(err, errStoreEstateProfileNotEnrolled) || !strings.Contains(err.Error(), "store-estate-profile-not-enrolled") {
		t.Fatalf("missing state error = %v", err)
	}
}

func TestVerifyConfiguredStoreEnrollmentReadsTheDurablePinAndStrictDeclaration(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "enrollment.json")
	if err := writeStoreEnrollmentStateNew(statePath, f.state, uint32(os.Geteuid())); err != nil {
		t.Fatalf("write enrollment state: %v", err)
	}
	f.cfg.EstateEnrollmentStatePath = statePath
	configPath := filepath.Join(dir, "store.config.json")
	config := map[string]any{
		"license_nft_mint":        f.declaration.LicenseNFTMint,
		"store_authority":         f.declaration.StoreAuthority,
		"program_id":              f.declaration.ProgramID,
		"domain":                  f.declaration.Domain,
		"store_id":                f.declaration.StoreID,
		"reseller_nft_mint":       f.declaration.ResellerNFTMint,
		"release_master_nft_mint": f.declaration.ReleaseMasterNFTMint,
		"release_squads_authority": map[string]any{
			"multisig":     f.declaration.ReleaseSquadsAuthority.Multisig,
			"vault":        f.declaration.ReleaseSquadsAuthority.Vault,
			"program_id":   f.declaration.ReleaseSquadsAuthority.ProgramID,
			"threshold":    f.declaration.ReleaseSquadsAuthority.Threshold,
			"member_count": f.declaration.ReleaseSquadsAuthority.MemberCount,
		},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := verifyConfiguredStoreEnrollment(context.Background(), f.cfg, configPath, f.identity, newFixedStoreGenesisChainReader(f.genesis))
	if err != nil {
		t.Fatalf("configured runtime refused its durable enrollment: %v", err)
	}
	if got == nil || got.ProfilePin != f.state.ProfilePin {
		t.Fatalf("configured runtime returned wrong enrollment state: %#v", got)
	}

	delete(config, "store_authority")
	raw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyConfiguredStoreEnrollment(context.Background(), f.cfg, configPath, f.identity, newFixedStoreGenesisChainReader(f.genesis)); err == nil || !strings.Contains(err.Error(), "store-estate-profile-config-missing:store_authority") {
		t.Fatalf("runtime accepted declaration with omitted store authority: %v", err)
	}
}

func TestVerifyConfiguredStoreEnrollmentRefusesAValidButForeignReleaseQuorum(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "enrollment.json")
	if err := writeStoreEnrollmentStateNew(statePath, f.state, uint32(os.Geteuid())); err != nil {
		t.Fatalf("write enrollment state: %v", err)
	}
	configPath := filepath.Join(dir, "store.config.json")
	config := map[string]any{
		"license_nft_mint":             f.declaration.LicenseNFTMint,
		"store_authority":              f.declaration.StoreAuthority,
		"program_id":                   f.declaration.ProgramID,
		"domain":                       f.declaration.Domain,
		"store_id":                     f.declaration.StoreID,
		"reseller_nft_mint":            f.declaration.ResellerNFTMint,
		"release_master_nft_mint":      f.declaration.ReleaseMasterNFTMint,
		"estate_enrollment_state_path": statePath,
		"rpc_url":                      "https://primary.example/rpc",
		"release_squads_authority": map[string]any{
			"multisig":     f.declaration.ReleaseSquadsAuthority.Multisig,
			"vault":        f.declaration.ReleaseSquadsAuthority.Vault,
			"program_id":   f.declaration.ReleaseSquadsAuthority.ProgramID,
			"threshold":    3,
			"member_count": 3,
		},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig should parse an explicit, meaningful quorum before enrollment checks it: %v", err)
	}
	if _, err := verifyConfiguredStoreEnrollment(context.Background(), loaded, configPath, f.identity, newFixedStoreGenesisChainReader(f.genesis)); err == nil || !strings.Contains(err.Error(), "store-estate-profile-config-mismatch: roles.store-release.threshold") {
		t.Fatalf("enrolled Store accepted a quorum not authorized by its profile: %v", err)
	}
}

// An enrolled Store's release authority is the one its owner-signed profile
// names. This is what binds a fresh estate's publisher tuple in both build
// flavors, and the only binding the estate-bootstrap build has: it compiles no
// fixed authority for any domain. A config that substitutes the vault, the
// multisig or the Squads program loads, and is then refused by name at the
// enrolled startup gate; the exact profile tuple is the positive control.
func TestVerifyConfiguredStoreEnrollmentRefusesASubstitutedReleaseAuthority(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "enrollment.json")
	if err := writeStoreEnrollmentStateNew(statePath, f.state, uint32(os.Geteuid())); err != nil {
		t.Fatalf("write enrollment state: %v", err)
	}
	verify := func(t *testing.T, mutate func(map[string]any)) error {
		t.Helper()
		config := map[string]any{
			"license_nft_mint":             f.declaration.LicenseNFTMint,
			"store_authority":              f.declaration.StoreAuthority,
			"program_id":                   f.declaration.ProgramID,
			"domain":                       f.declaration.Domain,
			"store_id":                     f.declaration.StoreID,
			"reseller_nft_mint":            f.declaration.ResellerNFTMint,
			"release_master_nft_mint":      f.declaration.ReleaseMasterNFTMint,
			"estate_enrollment_state_path": statePath,
			"rpc_url":                      "https://primary.example/rpc",
			"boot_identity":                map[string]any{"sidecar_id": "store"},
			"release_squads_authority": map[string]any{
				"multisig":     f.declaration.ReleaseSquadsAuthority.Multisig,
				"vault":        f.declaration.ReleaseSquadsAuthority.Vault,
				"program_id":   f.declaration.ReleaseSquadsAuthority.ProgramID,
				"threshold":    f.declaration.ReleaseSquadsAuthority.Threshold,
				"member_count": f.declaration.ReleaseSquadsAuthority.MemberCount,
			},
		}
		mutate(config)
		configPath := filepath.Join(t.TempDir(), "store.config.json")
		raw, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadConfig(configPath)
		if err != nil {
			t.Fatalf("LoadConfig refused a well-formed enrolled config before the enrollment gate: %v", err)
		}
		_, err = verifyConfiguredStoreEnrollment(context.Background(), loaded, configPath, f.identity, newFixedStoreGenesisChainReader(f.genesis))
		return err
	}
	if err := verify(t, func(map[string]any) {}); err != nil {
		t.Fatalf("enrolled Store refused its exact profile release authority: %v", err)
	}
	for field, want := range map[string]string{
		"vault":      "store-estate-profile-config-mismatch: estate-profile-anchor-mismatch:roles.store-release.vault",
		"multisig":   "store-estate-profile-config-mismatch: estate-profile-anchor-mismatch:roles.store-release.multisig",
		"program_id": "store-estate-profile-config-mismatch: estate-profile-anchor-mismatch:externalPrograms.squads-v4.programId",
	} {
		t.Run(field, func(t *testing.T) {
			substitute := randPubkeyB58(t)
			err := verify(t, func(config map[string]any) {
				config["release_squads_authority"].(map[string]any)[field] = substitute
			})
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("enrolled Store accepted a substituted release %s: %v", field, err)
			}
		})
	}
}

func TestStoreEnrollmentRuntimeFactsUseTheVerifiedSnapshot(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	facts, err := storeEnrollmentRuntimeFacts(f.declaration, f.identity)
	if err != nil {
		t.Fatal(err)
	}
	if facts.StoreOperatorKey != f.identity.operator.Public().SignPubkeyB58 || facts.StoreBoxKey != f.identity.operator.Public().BoxPubkeyB58 {
		t.Fatalf("facts did not come from the verified operator: %+v", facts)
	}
	if facts.SidecarIdentityPDA != f.identity.sidecarIdentityPDA || facts.OperatorDomain != f.identity.operatorDomain {
		t.Fatalf("facts did not preserve verified binding coordinates: %+v", facts)
	}
}

func TestWatchStoreEnrollmentGenesisReportsAChangedConfiguredEndpoint(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errorsOut := watchStoreEnrollmentGenesis(ctx, f.state.Enrollment, fixedConfiguredStoreGenesisReader{
		fixedStoreGenesisReader: fixedStoreGenesisReader{genesis: f.genesis},
		hashes:                  []string{f.genesis, randPubkeyB58(t)},
	}, time.Millisecond)
	select {
	case err := <-errorsOut:
		if err == nil || !strings.Contains(err.Error(), "store-rpc-genesis-mismatch") {
			t.Fatalf("watcher error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("watcher did not report foreign configured endpoint")
	}
}

func signRuntimeStoreEnrollmentCandidate(t *testing.T, profile estateprofile.EstateProfileV1, candidate estateprofile.StoreEnrollmentV1, keyIDs ...string) estateprofile.StoreEnrollmentV1 {
	t.Helper()
	candidate.Signatures = nil
	digest, err := estateprofile.StoreEnrollmentSHA256(candidate)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyID := range keyIDs {
		candidate.Signatures = append(candidate.Signatures, estateprofile.SignatureV1{
			KeyID:     keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(storeEnrollmentStatePrivate(profile.OwnerPolicy.PolicyID, keyID), []byte(digest))),
		})
	}
	return candidate
}

func TestPrepareStoreEnrollmentCandidateBuildsTheExactSignableRuntimeSnapshot(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	profileDigest, err := estateprofile.VerifyProfile(f.profile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 20, 1, 30, 0, 0, time.UTC)
	candidate, err := prepareStoreEnrollmentCandidate(
		context.Background(), f.cfg, f.declaration, f.profile, profileDigest, f.identity,
		fixedConfiguredStoreGenesisReader{fixedStoreGenesisReader: fixedStoreGenesisReader{genesis: f.genesis}, hashes: []string{f.genesis, f.genesis}},
		now, 15*time.Minute, bytes.Repeat([]byte{0x5a}, sha256.Size),
	)
	if err != nil {
		t.Fatalf("prepare candidate: %v", err)
	}
	if len(candidate.Signatures) != 0 {
		t.Fatalf("candidate carries owner signatures before owners sign it: %#v", candidate.Signatures)
	}
	if candidate.EstateID != f.profile.EstateID || candidate.ProfileSHA256 != profileDigest || candidate.ProfileRevision != f.profile.Revision || candidate.StoreOperatorKey != f.profile.Store.OperatorKey || candidate.StoreBoxKey != f.identity.operator.Public().BoxPubkeyB58 {
		t.Fatalf("candidate does not bind the exact profile and verified Store identity: %+v", candidate)
	}
	if candidate.IssuedAt != "2026-09-20T01:30:00Z" || candidate.ExpiresAt != "2026-09-20T01:45:00Z" {
		t.Fatalf("candidate window = %q through %q", candidate.IssuedAt, candidate.ExpiresAt)
	}
	if err := estateprofile.RequireStoreEnrollmentFacts(candidate, mustStoreEnrollmentRuntimeFacts(t, f)); err != nil {
		t.Fatalf("candidate does not bind the verified local facts: %v", err)
	}
	signed := signRuntimeStoreEnrollmentCandidate(t, f.profile, candidate, "owner-a", "owner-b")
	if _, err := estateprofile.VerifyStoreEnrollment(f.profile, signed, now.Add(time.Minute)); err != nil {
		t.Fatalf("owners cannot authorize the emitted candidate: %v", err)
	}
}

func mustStoreEnrollmentRuntimeFacts(t *testing.T, f storeEnrollmentRuntimeFixture) estateprofile.StoreEnrollmentFacts {
	t.Helper()
	facts, err := storeEnrollmentRuntimeFacts(f.declaration, f.identity)
	if err != nil {
		t.Fatal(err)
	}
	return facts
}

func TestPrepareStoreEnrollmentCandidateRefusesForeignIdentityAndConfiguredFallback(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	profileDigest, err := estateprofile.VerifyProfile(f.profile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 20, 1, 30, 0, 0, time.UTC)
	nonce := bytes.Repeat([]byte{0x7c}, sha256.Size)
	foreignIdentity := *f.identity
	foreignIdentity.operator = newTestIdentity(t, "store", f.cfg.LicenseNFTMint, f.identity.operatorDomain)
	if _, err := prepareStoreEnrollmentCandidate(context.Background(), f.cfg, f.declaration, f.profile, profileDigest, &foreignIdentity, fixedStoreGenesisReader{genesis: f.genesis}, now, 15*time.Minute, nonce); err == nil || !strings.Contains(err.Error(), "local operator does not match") {
		t.Fatalf("candidate accepted a foreign local operator: %v", err)
	}
	if _, err := prepareStoreEnrollmentCandidate(context.Background(), f.cfg, f.declaration, f.profile, profileDigest, f.identity, fixedConfiguredStoreGenesisReader{fixedStoreGenesisReader: fixedStoreGenesisReader{genesis: f.genesis}, hashes: []string{f.genesis, randPubkeyB58(t)}}, now, 15*time.Minute, nonce); err == nil || !strings.Contains(err.Error(), "store-rpc-genesis-mismatch") {
		t.Fatalf("candidate accepted a foreign configured fallback: %v", err)
	}
}

func TestPrepareStoreEnrollmentCandidateRefusesInvalidLifetimeAndProfileDigest(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	profileDigest, err := estateprofile.VerifyProfile(f.profile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 20, 1, 30, 0, 0, time.UTC)
	nonce := bytes.Repeat([]byte{0x31}, sha256.Size)
	if _, err := prepareStoreEnrollmentCandidate(context.Background(), f.cfg, f.declaration, f.profile, profileDigest, f.identity, fixedStoreGenesisReader{genesis: f.genesis}, now, 59*time.Second, nonce); err == nil || !strings.Contains(err.Error(), "valid-for") {
		t.Fatalf("candidate accepted a sub-minute signing window: %v", err)
	}
	if _, err := prepareStoreEnrollmentCandidate(context.Background(), f.cfg, f.declaration, f.profile, strings.Repeat("0", 64), f.identity, fixedStoreGenesisReader{genesis: f.genesis}, now, 15*time.Minute, nonce); err == nil || !strings.Contains(err.Error(), "profile digest does not match") {
		t.Fatalf("candidate accepted a substituted profile digest: %v", err)
	}
}

// storeEnrollmentFixtureUnderSidecarID re-issues the runtime fixture under
// another sidecar id: the configured id, the derived identity and an
// owner-signed enrollment all agree on it. Only the root-Store constant check
// can then tell it from the real fixture.
func storeEnrollmentFixtureUnderSidecarID(t *testing.T, sidecarID string) storeEnrollmentRuntimeFixture {
	t.Helper()
	f := newStoreEnrollmentRuntimeFixture(t)
	enrollment := f.state.Enrollment
	enrollment.SidecarID = sidecarID
	enrollment = signRuntimeStoreEnrollmentCandidate(t, f.profile, enrollment, "owner-a", "owner-b")
	state, err := newStoreEnrollmentState(f.profile, enrollment, storeEnrollmentStateNow)
	if err != nil {
		t.Fatalf("owner-signed enrollment under sidecar id %q: %v", sidecarID, err)
	}
	f.state = state
	identity := *f.identity
	identity.sidecarID = sidecarID
	f.identity = &identity
	f.cfg.BootIdentity.SidecarID = sidecarID
	return f
}

func requireRootStoreSidecarRefusal(t *testing.T, label string, err error) {
	t.Helper()
	if !errors.Is(err, errStoreEstateSidecarIDNotRootStore) || !strings.Contains(fmt.Sprint(err), "store-estate-profile-config-mismatch:boot_identity.sidecar_id") {
		t.Fatalf("%s: error = %v, want the named boot_identity.sidecar_id refusal", label, err)
	}
}

func TestStoreEnrollmentRefusesANonRootStoreSidecarID(t *testing.T) {
	// Positive control: the same fixture under the root Store id is accepted
	// by every gate the negative cases exercise.
	root := storeEnrollmentFixtureUnderSidecarID(t, "store")
	if _, err := verifyStoreEnrollmentRuntime(context.Background(), root.cfg, root.declaration, root.state, root.identity, fixedStoreGenesisReader{genesis: root.genesis}); err != nil {
		t.Fatalf("positive control: root Store sidecar id refused: %v", err)
	}
	profileDigest, err := estateprofile.VerifyProfile(root.profile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 20, 1, 30, 0, 0, time.UTC)
	nonce := bytes.Repeat([]byte{0x42}, sha256.Size)
	if _, err := prepareStoreEnrollmentCandidate(context.Background(), root.cfg, root.declaration, root.profile, profileDigest, root.identity, fixedStoreGenesisReader{genesis: root.genesis}, now, 15*time.Minute, nonce); err != nil {
		t.Fatalf("positive control: enrollment request under the root Store sidecar id refused: %v", err)
	}

	for _, sidecarID := range []string{"melusina-os-root-store-v2", "store-v2", "rehearsal-root-store"} {
		t.Run(sidecarID, func(t *testing.T) {
			f := storeEnrollmentFixtureUnderSidecarID(t, sidecarID)
			profileDigest, err := estateprofile.VerifyProfile(f.profile)
			if err != nil {
				t.Fatal(err)
			}
			// The owner-signed document, the derived identity and the config
			// all agree, so the facts comparison alone would accept it.
			requireRootStoreSidecarRefusal(t, "enrolled runtime", func() error {
				_, err := verifyStoreEnrollmentRuntime(context.Background(), f.cfg, f.declaration, f.state, f.identity, fixedStoreGenesisReader{genesis: f.genesis})
				return err
			}())
			requireRootStoreSidecarRefusal(t, "enrollment request", func() error {
				_, err := prepareStoreEnrollmentCandidate(context.Background(), f.cfg, f.declaration, f.profile, profileDigest, f.identity, fixedStoreGenesisReader{genesis: f.genesis}, now, 15*time.Minute, nonce)
				return err
			}())
			requireRootStoreSidecarRefusal(t, "configured id", requireLoadedConfigMatchesStoreDeclaration(f.cfg, f.declaration))
			_, err = storeEnrollmentRuntimeFacts(f.declaration, f.identity)
			requireRootStoreSidecarRefusal(t, "derived identity", err)
		})
	}
}

// Each gate is checked on its own, so removing either one fails a named case.
func TestStoreEnrollmentChecksConfiguredAndDerivedSidecarIDSeparately(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	if err := requireLoadedConfigMatchesStoreDeclaration(f.cfg, f.declaration); err != nil {
		t.Fatalf("positive control: root Store config refused: %v", err)
	}
	if _, err := storeEnrollmentRuntimeFacts(f.declaration, f.identity); err != nil {
		t.Fatalf("positive control: root Store identity refused: %v", err)
	}
	for _, configured := range []string{"", " store", "store ", "Store", "melusina-os-root-store-v2"} {
		cfg := f.cfg
		cfg.BootIdentity.SidecarID = configured
		requireRootStoreSidecarRefusal(t, fmt.Sprintf("configured %q", configured), requireLoadedConfigMatchesStoreDeclaration(cfg, f.declaration))
	}
	derived := *f.identity
	derived.sidecarID = "melusina-os-root-store-v2"
	_, err := storeEnrollmentRuntimeFacts(f.declaration, &derived)
	requireRootStoreSidecarRefusal(t, "derived identity with root Store config", err)
}

// enrollStoreEstate refuses before it pins a registry or reads the chain. The
// config's RPC endpoint is unroutable, and the positive control reaches a
// later, different refusal.
func TestEstateEnrollRefusesANonRootStoreSidecarIDBeforeAnyChainRead(t *testing.T) {
	saved := programID
	t.Cleanup(func() { programID = saved })
	f := newStoreEnrollmentRuntimeFixture(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	profileRaw, err := json.Marshal(f.profile)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentRaw, err := json.Marshal(f.state.Enrollment)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "estate-profile.json")
	enrollmentPath := filepath.Join(dir, "enrollment.json")
	for path, raw := range map[string][]byte{profilePath: profileRaw, enrollmentPath: enrollmentRaw} {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	enroll := func(sidecarID string) error {
		config := map[string]any{
			"license_nft_mint":             f.declaration.LicenseNFTMint,
			"store_authority":              f.declaration.StoreAuthority,
			"program_id":                   f.declaration.ProgramID,
			"domain":                       f.declaration.Domain,
			"store_id":                     f.declaration.StoreID,
			"reseller_nft_mint":            f.declaration.ResellerNFTMint,
			"release_master_nft_mint":      f.declaration.ReleaseMasterNFTMint,
			"estate_enrollment_state_path": filepath.Join(dir, "state", "enrollment-state.json"),
			"rpc_url":                      "https://127.0.0.1:9/unroutable",
			"boot_identity":                map[string]any{"sidecar_id": sidecarID},
			"release_squads_authority": map[string]any{
				"multisig":     f.declaration.ReleaseSquadsAuthority.Multisig,
				"vault":        f.declaration.ReleaseSquadsAuthority.Vault,
				"program_id":   f.declaration.ReleaseSquadsAuthority.ProgramID,
				"threshold":    f.declaration.ReleaseSquadsAuthority.Threshold,
				"member_count": f.declaration.ReleaseSquadsAuthority.MemberCount,
			},
		}
		raw, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		configPath := filepath.Join(dir, "store.config.json")
		if err := os.WriteFile(configPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = enrollStoreEstate(estateEnrollOptions{configPath: configPath, profilePath: profilePath, enrollmentPath: enrollmentPath}, storeEnrollmentStateNow)
		return err
	}

	requireRootStoreSidecarRefusal(t, "estate-enroll", enroll("melusina-os-root-store-v2"))
	if programID != saved {
		t.Fatalf("estate-enroll pinned registry %s before refusing the sidecar id", programID.Base58())
	}
	// Positive control: under the root Store id the same enrollment passes the
	// check and stops at the absent shard set, which is a different named refusal.
	err = enroll("store")
	if errors.Is(err, errStoreEstateSidecarIDNotRootStore) || !errors.Is(err, errStoreEstateProfileNotEnrolled) || !strings.Contains(fmt.Sprint(err), "boot_identity.shards_dir is required") {
		t.Fatalf("positive control: estate-enroll under the root Store id = %v, want the absent-shards refusal", err)
	}
}
