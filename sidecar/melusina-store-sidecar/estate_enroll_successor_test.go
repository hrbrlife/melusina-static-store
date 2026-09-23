package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// The Store had been serving for a day when its executable was rebuilt.
var storeEnrollmentSuccessorNow = time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)

// storeEnrollmentSuccessorTarget is an enrolled Store on disk: its explicit
// configuration, its initial enrollment state and, when requested, the empty
// writer.lock a first install or update helper leaves behind.
type storeEnrollmentSuccessorTarget struct {
	dir        string
	configPath string
	statePath  string
	lockPath   string
	uid        uint32
}

func newStoreEnrollmentSuccessorTarget(t *testing.T, f *storeEnrollmentRuntimeFixture, withLock bool) storeEnrollmentSuccessorTarget {
	t.Helper()
	dir := t.TempDir()
	target := storeEnrollmentSuccessorTarget{dir: dir, uid: uint32(os.Geteuid())}
	stateDir := filepath.Join(dir, "state")
	migrationDir := filepath.Join(dir, "migration")
	for _, path := range []string{dir, stateDir, migrationDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	target.statePath = filepath.Join(stateDir, "estate-enrollment.json")
	target.lockPath = filepath.Join(migrationDir, storeWriterLockName)
	if err := writeStoreEnrollmentStateNew(target.statePath, f.state, target.uid); err != nil {
		t.Fatalf("write initial enrollment state: %v", err)
	}
	if withLock {
		if err := os.WriteFile(target.lockPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := map[string]any{
		"license_nft_mint":             f.declaration.LicenseNFTMint,
		"store_authority":              f.declaration.StoreAuthority,
		"program_id":                   f.declaration.ProgramID,
		"domain":                       f.declaration.Domain,
		"store_id":                     f.declaration.StoreID,
		"reseller_nft_mint":            f.declaration.ResellerNFTMint,
		"release_master_nft_mint":      f.declaration.ReleaseMasterNFTMint,
		"estate_enrollment_state_path": target.statePath,
		"catalog_migration_state_dir":  migrationDir,
		"rpc_url":                      "https://127.0.0.1:9/unroutable",
		"boot_identity":                map[string]any{"sidecar_id": "store"},
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
	target.configPath = filepath.Join(dir, "store.config.json")
	if err := os.WriteFile(target.configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	f.cfg.EstateEnrollmentStatePath = target.statePath
	f.cfg.CatalogMigrationStateDir = migrationDir
	return target
}

// runtimeIdentityWith is the fixture Store after a governed change: the same
// derived operator, and the executable, TLS leaf or binding the chain now pins.
func runtimeIdentityWith(f storeEnrollmentRuntimeFixture, binaryLabel, tlsLabel string, bindingKeyVersion uint32, sidecarIdentityPDA string) *verifiedBootIdentity {
	identity := *f.identity
	if binaryLabel != "" {
		identity.facts.binaryHash = sha256.Sum256([]byte(binaryLabel))
	}
	if tlsLabel != "" {
		identity.facts.tlsFingerprint = sha256.Sum256([]byte(tlsLabel))
	}
	if bindingKeyVersion != 0 {
		identity.bindingKeyVersion = bindingKeyVersion
		identity.sidecarIdentityPDA = sidecarIdentityPDA
	}
	return &identity
}

func signRuntimeStoreEnrollmentSuccessor(t *testing.T, policyID string, candidate estateprofile.StoreEnrollmentSuccessorV1, keyIDs ...string) estateprofile.StoreEnrollmentSuccessorV1 {
	t.Helper()
	candidate.Signatures = nil
	digest, err := estateprofile.StoreEnrollmentSuccessorSHA256(candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Signatures = []estateprofile.SignatureV1{}
	for _, keyID := range keyIDs {
		candidate.Signatures = append(candidate.Signatures, estateprofile.SignatureV1{
			KeyID:     keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(storeEnrollmentStatePrivate(policyID, keyID), []byte(digest))),
		})
	}
	return candidate
}

func mustStoreEnrollmentSuccessorDigest(t *testing.T, value estateprofile.StoreEnrollmentSuccessorV1) string {
	t.Helper()
	digest, err := estateprofile.StoreEnrollmentSuccessorSHA256(value)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// requestStoreEnrollmentSuccessor is the Store half of steps 2 and 3: the
// rebuilt executable emits its request from the held state and two of the
// profile's owners sign it.
func requestStoreEnrollmentSuccessor(t *testing.T, f storeEnrollmentRuntimeFixture, target storeEnrollmentSuccessorTarget, identity *verifiedBootIdentity, now time.Time, keyIDs ...string) (storeEnrollmentState, estateprofile.StoreEnrollmentSuccessorV1) {
	t.Helper()
	held, err := readStoreEnrollmentState(target.statePath, target.uid)
	if err != nil {
		t.Fatalf("read held state: %v", err)
	}
	return requestStoreEnrollmentSuccessorFromState(t, f, held, identity, now, keyIDs...)
}

func requestStoreEnrollmentSuccessorFromState(t *testing.T, f storeEnrollmentRuntimeFixture, held storeEnrollmentState, identity *verifiedBootIdentity, now time.Time, keyIDs ...string) (storeEnrollmentState, estateprofile.StoreEnrollmentSuccessorV1) {
	t.Helper()
	candidate, err := prepareStoreEnrollmentSuccessorCandidate(context.Background(), f.cfg, f.declaration, held, identity, fixedStoreGenesisReader{genesis: f.genesis}, now, 15*time.Minute, bytes.Repeat([]byte{0x2b}, sha256.Size))
	if err != nil {
		t.Fatalf("successor request: %v", err)
	}
	if len(candidate.Signatures) != 0 {
		t.Fatalf("request carries signatures before the owners sign: %#v", candidate.Signatures)
	}
	return held, signRuntimeStoreEnrollmentSuccessor(t, f.profile.OwnerPolicy.PolicyID, candidate, keyIDs...)
}

func requireErrorContains(t *testing.T, label string, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: error = %v, want %q", label, err, want)
	}
}

func requireHeldEnrollment(t *testing.T, target storeEnrollmentSuccessorTarget, sequence uint64, digest string) storeEnrollmentState {
	t.Helper()
	state, err := readStoreEnrollmentState(target.statePath, target.uid)
	if err != nil {
		t.Fatalf("read enrollment state: %v", err)
	}
	if state.sequence() != sequence || state.currentSHA256() != digest {
		t.Fatalf("held enrollment = sequence %d %s, want sequence %d %s", state.sequence(), state.currentSHA256(), sequence, digest)
	}
	return state
}

// The day-two failure this change exists for, kept as a control: with no
// successor, a rebuilt executable, a renewed certificate and a rotated binding
// each refuse at startup by field, and nothing is accepted by observation.
func TestEnrolledStoreRefusesAChangedBindingWithoutASuccessor(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	target := newStoreEnrollmentSuccessorTarget(t, &f, true)
	chain := newFixedStoreGenesisChainReader(f.genesis)
	if _, err := verifyConfiguredStoreEnrollment(context.Background(), f.cfg, target.configPath, f.identity, chain); err != nil {
		t.Fatalf("positive control: the enrolled executable refused: %v", err)
	}
	for _, item := range []struct {
		label    string
		identity *verifiedBootIdentity
		refusal  string
	}{
		{"rebuilt executable", runtimeIdentityWith(f, "rebuilt-binary", "", 0, ""), "store-enrollment-facts-mismatch:binarySha256"},
		{"renewed certificate", runtimeIdentityWith(f, "", "renewed-tls", 0, ""), "store-enrollment-facts-mismatch:tlsCertFingerprint"},
		{"rotated binding", runtimeIdentityWith(f, "", "renewed-tls", 2, randPubkeyB58(t)), "store-enrollment-facts-mismatch:sidecarIdentityPda"},
	} {
		_, err := verifyConfiguredStoreEnrollment(context.Background(), f.cfg, target.configPath, item.identity, chain)
		requireErrorContains(t, item.label, err, item.refusal)
	}
	requireHeldEnrollment(t, target, 1, f.state.EnrollmentSHA256)
}

func TestStoreEnrollmentSuccessorIsAppliedAndSurvivesRestart(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	target := newStoreEnrollmentSuccessorTarget(t, &f, true)
	chain := newFixedStoreGenesisChainReader(f.genesis)
	rebuilt := runtimeIdentityWith(f, "rebuilt-binary", "", 0, "")

	held, second := requestStoreEnrollmentSuccessor(t, f, target, rebuilt, storeEnrollmentSuccessorNow, "owner-a", "owner-b")
	if second.EnrollmentSequence != 2 || second.InitialEnrollmentSHA256 != f.state.EnrollmentSHA256 || second.PredecessorEnrollmentSHA256 != f.state.EnrollmentSHA256 {
		t.Fatalf("request does not extend the held initial enrollment: %+v", second)
	}
	if len(second.Recalls) != 1 || second.Recalls[0].SHA256 != f.state.EnrollmentSHA256 {
		t.Fatalf("request does not recall the enrollment it supersedes: %+v", second.Recalls)
	}
	if second.BinarySHA256 == f.state.Enrollment.BinarySHA256 || second.TLSCertFingerprint != f.state.Enrollment.TLSCertFingerprint {
		t.Fatalf("request does not bind exactly the rebuilt executable: %+v", second)
	}
	report, err := commitStoreEnrollmentSuccessor(context.Background(), f.cfg, f.declaration, held, rebuilt, chain, second, storeEnrollmentSuccessorNow.Add(time.Minute), target.uid)
	if err != nil {
		t.Fatalf("apply owner-signed successor: %v", err)
	}
	secondDigest := mustStoreEnrollmentSuccessorDigest(t, second)
	if report.Status != "store-estate-enrollment-succeeded" || report.EnrollmentSequence != 2 || report.EnrollmentSHA256 != secondDigest || report.SupersededEnrollmentSHA256 != f.state.EnrollmentSHA256 || report.SupersededEnrollmentSequence != 1 || report.InitialEnrollmentSHA256 != f.state.EnrollmentSHA256 || report.BinarySHA256 != second.BinarySHA256 {
		t.Fatalf("successor report = %+v", report)
	}

	// Restart: the startup gate reads the durable successor and accepts the
	// rebuilt executable, and a Store rolled back to the old one refuses.
	started, err := verifyConfiguredStoreEnrollment(context.Background(), f.cfg, target.configPath, rebuilt, chain)
	if err != nil {
		t.Fatalf("restart on the rebuilt executable refused: %v", err)
	}
	if started.sequence() != 2 || started.currentSHA256() != secondDigest || started.EnrollmentSHA256 != f.state.EnrollmentSHA256 {
		t.Fatalf("restart holds sequence %d %s", started.sequence(), started.currentSHA256())
	}
	_, err = verifyConfiguredStoreEnrollment(context.Background(), f.cfg, target.configPath, f.identity, chain)
	requireErrorContains(t, "rolled-back executable", err, "store-enrollment-facts-mismatch:binarySha256")

	// Replays: the applied successor again, and the initial enrollment again.
	_, err = commitStoreEnrollmentSuccessor(context.Background(), f.cfg, f.declaration, *started, rebuilt, chain, second, storeEnrollmentSuccessorNow.Add(2*time.Minute), target.uid)
	requireErrorContains(t, "replayed successor", err, estateprofile.RefusalStoreEnrollmentSuccessorNotForward)
	if err := writeStoreEnrollmentStateNew(target.statePath, f.state, target.uid); !errors.Is(err, errStoreEnrollmentStateExists) {
		t.Fatalf("initial enrollment replayed over a successor state: %v", err)
	}

	// A certificate renewal under a new binding version is the next successor.
	renewed := runtimeIdentityWith(f, "rebuilt-binary", "renewed-tls", 2, randPubkeyB58(t))
	_, err = verifyConfiguredStoreEnrollment(context.Background(), f.cfg, target.configPath, renewed, chain)
	requireErrorContains(t, "renewed certificate before its successor", err, "store-enrollment-facts-mismatch:sidecarIdentityPda")
	atSecond, third := requestStoreEnrollmentSuccessor(t, f, target, renewed, storeEnrollmentSuccessorNow.Add(3*time.Minute), "owner-b", "owner-c")
	if third.EnrollmentSequence != 3 || third.PredecessorEnrollmentSHA256 != secondDigest || third.BindingKeyVersion != 2 {
		t.Fatalf("certificate successor does not extend sequence 2: %+v", third)
	}
	if _, err := commitStoreEnrollmentSuccessor(context.Background(), f.cfg, f.declaration, atSecond, renewed, chain, third, storeEnrollmentSuccessorNow.Add(4*time.Minute), target.uid); err != nil {
		t.Fatalf("apply certificate successor: %v", err)
	}
	atThird := requireHeldEnrollment(t, target, 3, mustStoreEnrollmentSuccessorDigest(t, third))
	if !reflect.DeepEqual(atThird.Recalled, sortedStrings(f.state.EnrollmentSHA256, secondDigest)) {
		t.Fatalf("recalled set = %v", atThird.Recalled)
	}
	if _, err := verifyConfiguredStoreEnrollment(context.Background(), f.cfg, target.configPath, renewed, chain); err != nil {
		t.Fatalf("restart on the renewed certificate refused: %v", err)
	}
	// The sequence-2 document is still inside its signing window and still
	// validly signed; it is older than what the Store holds.
	_, err = commitStoreEnrollmentSuccessor(context.Background(), f.cfg, f.declaration, atThird, rebuilt, chain, second, storeEnrollmentSuccessorNow.Add(5*time.Minute), target.uid)
	requireErrorContains(t, "replayed older successor", err, estateprofile.RefusalStoreEnrollmentSuccessorNotForward)
	requireHeldEnrollment(t, target, 3, mustStoreEnrollmentSuccessorDigest(t, third))
}

func sortedStrings(values ...string) []string {
	out := append([]string(nil), values...)
	slices.Sort(out)
	return out
}

func TestStoreEnrollmentSuccessorRefusesBelowThresholdAndForeignOwnersWithoutWriting(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	target := newStoreEnrollmentSuccessorTarget(t, &f, true)
	chain := newFixedStoreGenesisChainReader(f.genesis)
	rebuilt := runtimeIdentityWith(f, "rebuilt-binary", "", 0, "")
	held, valid := requestStoreEnrollmentSuccessor(t, f, target, rebuilt, storeEnrollmentSuccessorNow, "owner-a", "owner-b")
	now := storeEnrollmentSuccessorNow.Add(time.Minute)
	for _, item := range []struct {
		label     string
		successor estateprofile.StoreEnrollmentSuccessorV1
		refusal   string
	}{
		{"one owner", signRuntimeStoreEnrollmentSuccessor(t, f.profile.OwnerPolicy.PolicyID, valid, "owner-a"), estateprofile.RefusalStoreEnrollmentSignaturesInsufficient},
		{"no owner", signRuntimeStoreEnrollmentSuccessor(t, f.profile.OwnerPolicy.PolicyID, valid), estateprofile.RefusalStoreEnrollmentSignaturesInsufficient},
		{"foreign owners under the owners' key ids", signRuntimeStoreEnrollmentSuccessor(t, "foreign-owner-policy", valid, "owner-a", "owner-b"), estateprofile.RefusalStoreEnrollmentSignatureInvalid + ":owner-a"},
		{"a key outside the policy", signRuntimeStoreEnrollmentSuccessor(t, f.profile.OwnerPolicy.PolicyID, valid, "owner-a", "owner-z"), estateprofile.RefusalStoreEnrollmentSignatureInvalid + ":owner-z"},
	} {
		_, err := commitStoreEnrollmentSuccessor(context.Background(), f.cfg, f.declaration, held, rebuilt, chain, item.successor, now, target.uid)
		requireErrorContains(t, item.label, err, item.refusal)
		requireHeldEnrollment(t, target, 1, f.state.EnrollmentSHA256)
		_, err = verifyConfiguredStoreEnrollment(context.Background(), f.cfg, target.configPath, rebuilt, chain)
		requireErrorContains(t, item.label+" then restart", err, "store-enrollment-facts-mismatch:binarySha256")
	}
	// A validly signed successor whose facts are not the running executable's
	// is refused before the state moves.
	_, err := commitStoreEnrollmentSuccessor(context.Background(), f.cfg, f.declaration, held, runtimeIdentityWith(f, "another-binary", "", 0, ""), chain, valid, now, target.uid)
	requireErrorContains(t, "successor for another executable", err, "store-enrollment-facts-mismatch:binarySha256")
	// An expired one is refused.
	_, err = commitStoreEnrollmentSuccessor(context.Background(), f.cfg, f.declaration, held, rebuilt, chain, valid, storeEnrollmentSuccessorNow.Add(time.Hour), target.uid)
	requireErrorContains(t, "expired successor", err, estateprofile.RefusalStoreEnrollmentExpired)
	requireHeldEnrollment(t, target, 1, f.state.EnrollmentSHA256)
	// Positive control: the same held state takes the valid successor.
	if _, err := commitStoreEnrollmentSuccessor(context.Background(), f.cfg, f.declaration, held, rebuilt, chain, valid, now, target.uid); err != nil {
		t.Fatalf("positive control: valid successor refused: %v", err)
	}
}

func TestStoreEnrollmentSuccessorRequestRefusesAnUnchangedOrForeignStore(t *testing.T) {
	saved := programID
	t.Cleanup(func() { programID = saved })
	f := newStoreEnrollmentRuntimeFixture(t)
	target := newStoreEnrollmentSuccessorTarget(t, &f, true)
	held, err := readStoreEnrollmentState(target.statePath, target.uid)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x19}, sha256.Size)
	genesis := fixedStoreGenesisReader{genesis: f.genesis}
	_, err = prepareStoreEnrollmentSuccessorCandidate(context.Background(), f.cfg, f.declaration, held, f.identity, genesis, storeEnrollmentSuccessorNow, 15*time.Minute, nonce)
	requireErrorContains(t, "unchanged executable", err, estateprofile.RefusalStoreEnrollmentSuccessorUnchanged)

	foreign := *runtimeIdentityWith(f, "rebuilt-binary", "", 0, "")
	foreign.operator = newTestIdentity(t, "store", f.cfg.LicenseNFTMint, f.identity.operatorDomain)
	_, err = prepareStoreEnrollmentSuccessorCandidate(context.Background(), f.cfg, f.declaration, held, &foreign, genesis, storeEnrollmentSuccessorNow, 15*time.Minute, nonce)
	requireErrorContains(t, "foreign operator", err, estateprofile.RefusalStoreEnrollmentProfileMismatch+":storeOperatorKey")

	_, err = prepareStoreEnrollmentSuccessorCandidate(context.Background(), f.cfg, f.declaration, held, runtimeIdentityWith(f, "rebuilt-binary", "", 0, ""), fixedStoreGenesisReader{genesis: randPubkeyB58(t)}, storeEnrollmentSuccessorNow, 15*time.Minute, nonce)
	requireErrorContains(t, "foreign genesis", err, estateprofile.RefusalStoreRPCGenesisMismatch)

	if err := os.Remove(target.statePath); err != nil {
		t.Fatal(err)
	}
	_, err = createStoreEnrollmentSuccessorRequest(estateEnrollmentSuccessorRequestOptions{configPath: target.configPath, lifetime: 15 * time.Minute}, storeEnrollmentSuccessorNow)
	if !errors.Is(err, errStoreEstateProfileNotEnrolled) {
		t.Fatalf("successor request without a held enrollment = %v", err)
	}
}

// estate-enroll-successor runs only while the Store is stopped: it takes the
// serving Store's writer lock, and decides owner authority before any chain
// read.
func TestEstateEnrollSuccessorRequiresTheStoppedStoresWriterLock(t *testing.T) {
	saved := programID
	t.Cleanup(func() { programID = saved })
	f := newStoreEnrollmentRuntimeFixture(t)
	target := newStoreEnrollmentSuccessorTarget(t, &f, false)
	rebuilt := runtimeIdentityWith(f, "rebuilt-binary", "", 0, "")
	_, valid := requestStoreEnrollmentSuccessor(t, f, target, rebuilt, storeEnrollmentSuccessorNow, "owner-a", "owner-b")
	writeDocument := func(name string, value estateprofile.StoreEnrollmentSuccessorV1) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(target.dir, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	validPath := writeDocument("successor.json", valid)
	belowPath := writeDocument("below-threshold.json", signRuntimeStoreEnrollmentSuccessor(t, f.profile.OwnerPolicy.PolicyID, valid, "owner-a"))
	enroll := func(path string) error {
		_, err := enrollStoreEstateSuccessor(estateEnrollSuccessorOptions{
			configPath:     target.configPath,
			enrollmentPath: path,
			writerLockUID:  target.uid,
			writerLockGID:  uint32(os.Getegid()),
		}, storeEnrollmentSuccessorNow.Add(time.Minute))
		return err
	}

	requireErrorContains(t, "no writer.lock", enroll(validPath), "requires the stopped Store's writer lock")
	if err := os.WriteFile(target.lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	serving, err := acquireExistingWriterLockOwned(target.lockPath, target.uid, uint32(os.Getegid()))
	if err != nil {
		t.Fatalf("simulate the serving Store's lock: %v", err)
	}
	requireErrorContains(t, "serving Store", enroll(validPath), "lock writer.lock exclusively")
	if err := serving.Close(); err != nil {
		t.Fatal(err)
	}
	requireErrorContains(t, "below threshold", enroll(belowPath), estateprofile.RefusalStoreEnrollmentSignaturesInsufficient)
	// Positive control: the stopped Store's lock and a valid successor pass
	// every pre-chain check and stop at boot identity, a different refusal.
	err = enroll(validPath)
	if !errors.Is(err, errStoreEstateProfileNotEnrolled) || !strings.Contains(err.Error(), "boot_identity.shards_dir is required") {
		t.Fatalf("positive control: estate-enroll-successor = %v, want the absent-shards refusal", err)
	}
	requireHeldEnrollment(t, target, 1, f.state.EnrollmentSHA256)
}

func TestReplaceStoreEnrollmentStateRefusesAMovedOrBackwardState(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	target := newStoreEnrollmentSuccessorTarget(t, &f, true)
	rebuilt := runtimeIdentityWith(f, "rebuilt-binary", "", 0, "")
	held, second := requestStoreEnrollmentSuccessor(t, f, target, rebuilt, storeEnrollmentSuccessorNow, "owner-a", "owner-b")
	next, err := advanceStoreEnrollmentState(held, second, storeEnrollmentSuccessorNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := replaceStoreEnrollmentState(target.statePath, held, next, target.uid); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if err := replaceStoreEnrollmentState(target.statePath, held, next, target.uid); !errors.Is(err, errStoreEnrollmentStateChanged) {
		t.Fatalf("replace from a stale held state = %v", err)
	}
	requireErrorContains(t, "same sequence", replaceStoreEnrollmentState(target.statePath, next, next, target.uid), estateprofile.RefusalStoreEnrollmentSuccessorNotForward)
	requireErrorContains(t, "backwards", replaceStoreEnrollmentState(target.statePath, next, held, target.uid), estateprofile.RefusalStoreEnrollmentSuccessorNotForward)
	entries, err := os.ReadDir(filepath.Dir(target.statePath))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("state directory holds %d entries after refused replacements, want only the state", len(entries))
	}
	got := requireHeldEnrollment(t, target, 2, mustStoreEnrollmentSuccessorDigest(t, second))
	if !reflect.DeepEqual(got, next) {
		t.Fatalf("state round trip differs\n got: %#v\nwant: %#v", got, next)
	}
}

func TestStoreEnrollmentStateRefusesTamperedSuccessorEvidence(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	target := newStoreEnrollmentSuccessorTarget(t, &f, true)
	rebuilt := runtimeIdentityWith(f, "rebuilt-binary", "", 0, "")
	held, second := requestStoreEnrollmentSuccessor(t, f, target, rebuilt, storeEnrollmentSuccessorNow, "owner-a", "owner-b")
	next, err := advanceStoreEnrollmentState(held, second, storeEnrollmentSuccessorNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStoreEnrollmentState(next); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	for _, item := range []struct {
		label  string
		change func(*storeEnrollmentState)
		want   string
	}{
		{"successor digest", func(s *storeEnrollmentState) { s.SuccessorSHA256 = strings.Repeat("1", 64) }, "successor digest mismatch"},
		{"dropped recall", func(s *storeEnrollmentState) { s.Recalled = []string{} }, "omits a recall"},
		{"self recall", func(s *storeEnrollmentState) {
			s.Recalled = sortedStrings(append(append([]string(nil), s.Recalled...), s.SuccessorSHA256)...)
		}, estateprofile.RefusalStoreEnrollmentRecalled},
		{"evidence without successor", func(s *storeEnrollmentState) { s.Successor = nil; s.SuccessorSHA256 = "" }, "successor evidence without a successor"},
		{"unsorted recalled", func(s *storeEnrollmentState) {
			s.Recalled = []string{strings.Repeat("f", 64), s.Recalled[0]}
		}, "not a bounded, sorted"},
		{"one owner signature", func(s *storeEnrollmentState) {
			successor := *s.Successor
			successor.Signatures = successor.Signatures[:1]
			s.Successor = &successor
		}, estateprofile.RefusalStoreEnrollmentSignaturesInsufficient},
		{"schema v1", func(s *storeEnrollmentState) { s.Schema = "melusina.store-estate-enrollment-state.v1" }, "schema mismatch"},
		// Owner-signed, profile-consistent successors that are not this
		// Store's: only the persisted-successor identity check refuses them.
		{"owner-signed successor anchored to another Store", func(s *storeEnrollmentState) {
			foreign := *s.Successor
			foreign.InitialEnrollmentSHA256 = strings.Repeat("c", 64)
			foreign = signRuntimeStoreEnrollmentSuccessor(t, f.profile.OwnerPolicy.PolicyID, foreign, "owner-a", "owner-b")
			s.Successor = &foreign
			s.SuccessorSHA256 = mustStoreEnrollmentSuccessorDigest(t, foreign)
		}, estateprofile.RefusalStoreEnrollmentSuccessorAnchorMismatch},
		{"owner-signed successor with another box key", func(s *storeEnrollmentState) {
			foreign := *s.Successor
			foreign.StoreBoxKey = randPubkeyB58(t)
			foreign = signRuntimeStoreEnrollmentSuccessor(t, f.profile.OwnerPolicy.PolicyID, foreign, "owner-a", "owner-b")
			s.Successor = &foreign
			s.SuccessorSHA256 = mustStoreEnrollmentSuccessorDigest(t, foreign)
		}, estateprofile.RefusalStoreEnrollmentSuccessorIdentityChanged + ":storeBoxKey"},
	} {
		tampered := next
		tampered.Recalled = append([]string(nil), next.Recalled...)
		item.change(&tampered)
		requireErrorContains(t, item.label, validateStoreEnrollmentState(tampered), item.want)
		raw, err := json.Marshal(tampered)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target.statePath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = readStoreEnrollmentState(target.statePath, target.uid)
		requireErrorContains(t, item.label+" on disk", err, item.want)
	}
}
