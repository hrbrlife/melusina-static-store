package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

var storeEnrollmentStateNow = time.Date(2026, 9, 20, 1, 30, 0, 0, time.UTC)

func storeEnrollmentStateDigest(label string) string {
	sum := sha256.Sum256([]byte("store-enrollment-state-test:" + label))
	return hex.EncodeToString(sum[:])
}

func storeEnrollmentStatePrivate(policyID, keyID string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("melusina-estate-profile-vector-key:" + policyID + "/" + keyID))
	return ed25519.NewKeyFromSeed(seed[:])
}

func storeEnrollmentStateProgramID(t *testing.T, profile estateprofile.EstateProfileV1, role string) string {
	t.Helper()
	return profileProgramID(t, profile, role)
}

func validStoreEnrollmentStateInput(t *testing.T) (estateprofile.EstateProfileV1, estateprofile.StoreEnrollmentV1) {
	t.Helper()
	profile := storeEstateProfileFixture(t)
	profileDigest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
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
		StoreOperatorKey:   profile.Store.OperatorKey,
		StoreBoxKey:        randPubkeyB58(t),
		LicenseNFTMint:     randPubkeyB58(t),
		LicenseRegistryID:  storeEnrollmentStateProgramID(t, profile, estateprofile.ProgramRoleLicenseRegistry),
		SidecarID:          "rehearsal-root-store",
		BindingKeyVersion:  1,
		OperatorKeyVersion: 1,
		OperatorDomain:     "operator.rehearsal.invalid",
		SidecarIdentityPDA: randPubkeyB58(t),
		TLSCertFingerprint: storeEnrollmentStateDigest("tls"),
		BinarySHA256:       storeEnrollmentStateDigest("binary"),
		IssuedAt:           "2026-09-20T01:00:00Z",
		ExpiresAt:          "2026-09-20T02:00:00Z",
		EnrollmentNonce:    storeEnrollmentStateDigest("nonce"),
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
	return profile, enrollment
}

func TestStoreEnrollmentStateWritesAndReadsOnlyOneInitialState(t *testing.T) {
	profile, enrollment := validStoreEnrollmentStateInput(t)
	state, err := newStoreEnrollmentState(profile, enrollment, storeEnrollmentStateNow)
	if err != nil {
		t.Fatalf("new state: %v", err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "enrollment.json")
	uid := uint32(os.Geteuid())
	if err := writeStoreEnrollmentStateNew(path, state, uid); err != nil {
		t.Fatalf("write state: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || fileUID(info) != uid {
		t.Fatalf("state mode/owner = %s/%d", info.Mode(), fileUID(info))
	}
	got, err := readStoreEnrollmentState(path, uid)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if !reflect.DeepEqual(got, state) {
		t.Fatalf("state round trip differs\n got: %#v\nwant: %#v", got, state)
	}
	if err := writeStoreEnrollmentStateNew(path, state, uid); !errors.Is(err, errStoreEnrollmentStateExists) {
		t.Fatalf("second initial write = %v, want state exists", err)
	}
}

func TestStoreEnrollmentStateRefusesTamperingAndDuplicateJSON(t *testing.T) {
	profile, enrollment := validStoreEnrollmentStateInput(t)
	state, err := newStoreEnrollmentState(profile, enrollment, storeEnrollmentStateNow)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "enrollment.json")
	uid := uint32(os.Geteuid())
	if err := writeStoreEnrollmentStateNew(path, state, uid); err != nil {
		t.Fatal(err)
	}
	tampered := state
	tampered.EnrollmentSHA256 = strings.Repeat("0", 64)
	raw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStoreEnrollmentState(path, uid); err == nil || !strings.Contains(err.Error(), "authorization digest mismatch") {
		t.Fatalf("tampered state accepted: %v", err)
	}

	if err := os.WriteFile(path, []byte(`{"schema":"melusina.store-estate-enrollment-state.v1","schema":"melusina.store-estate-enrollment-state.v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStoreEnrollmentState(path, uid); err == nil || !strings.Contains(err.Error(), `duplicate key "schema"`) {
		t.Fatalf("duplicate state accepted: %v", err)
	}
}

func TestStoreEnrollmentStateRefusesInsecureParentAndRelativePath(t *testing.T) {
	profile, enrollment := validStoreEnrollmentStateInput(t)
	state, err := newStoreEnrollmentState(profile, enrollment, storeEnrollmentStateNow)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	if err := writeStoreEnrollmentStateNew(filepath.Join(dir, "enrollment.json"), state, uid); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("insecure parent accepted: %v", err)
	}
	if _, err := cleanStoreEnrollmentStatePath("enrollment.json"); err == nil {
		t.Fatal("relative state path accepted")
	}
}

func TestStoreEnrollmentStateReadRefusesDirectoryThatBecomesInsecure(t *testing.T) {
	profile, enrollment := validStoreEnrollmentStateInput(t)
	state, err := newStoreEnrollmentState(profile, enrollment, storeEnrollmentStateNow)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "enrollment.json")
	uid := uint32(os.Geteuid())
	if err := writeStoreEnrollmentStateNew(path, state, uid); err != nil {
		t.Fatalf("write state: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := readStoreEnrollmentState(path, uid); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("state in insecure directory accepted: %v", err)
	}
}

func TestStoreEnrollmentStateConcurrentInitialWriteHasOneWinner(t *testing.T) {
	profile, enrollment := validStoreEnrollmentStateInput(t)
	state, err := newStoreEnrollmentState(profile, enrollment, storeEnrollmentStateNow)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "enrollment.json")
	uid := uint32(os.Geteuid())
	const writers = 8
	start := make(chan struct{})
	errorsOut := make(chan error, writers)
	var group sync.WaitGroup
	for range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			errorsOut <- writeStoreEnrollmentStateNew(path, state, uid)
		}()
	}
	close(start)
	group.Wait()
	close(errorsOut)
	var succeeded, exists int
	for err := range errorsOut {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, errStoreEnrollmentStateExists):
			exists++
		default:
			t.Fatalf("concurrent initial write: %v", err)
		}
	}
	if succeeded != 1 || exists != writers-1 {
		t.Fatalf("concurrent writes: succeeded=%d exists=%d, want 1/%d", succeeded, exists, writers-1)
	}
	if _, err := readStoreEnrollmentState(path, uid); err != nil {
		t.Fatalf("read winning enrollment state: %v", err)
	}
}

func TestStoreEnrollmentStateNeverReplacesAnExistingSymlink(t *testing.T) {
	profile, enrollment := validStoreEnrollmentStateInput(t)
	state, err := newStoreEnrollmentState(profile, enrollment, storeEnrollmentStateNow)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "enrollment.json")
	if err := os.Symlink("elsewhere.json", path); err != nil {
		t.Fatal(err)
	}
	if err := writeStoreEnrollmentStateNew(path, state, uint32(os.Geteuid())); !errors.Is(err, errStoreEnrollmentStateExists) {
		t.Fatalf("existing symlink replaced or accepted: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("initial writer replaced the symlink: %s", info.Mode())
	}
}

func TestStoreEnrollmentStateRequestTargetRequiresTheSameFreshSecureLocation(t *testing.T) {
	profile, enrollment := validStoreEnrollmentStateInput(t)
	state, err := newStoreEnrollmentState(profile, enrollment, storeEnrollmentStateNow)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "enrollment.json")
	uid := uint32(os.Geteuid())
	if err := requireStoreEnrollmentStateTargetAbsent(path, uid); err != nil {
		t.Fatalf("fresh secure request target refused: %v", err)
	}
	if err := writeStoreEnrollmentStateNew(path, state, uid); err != nil {
		t.Fatal(err)
	}
	if err := requireStoreEnrollmentStateTargetAbsent(path, uid); !errors.Is(err, errStoreEnrollmentStateExists) {
		t.Fatalf("request target accepted an existing enrollment state: %v", err)
	}
}
