package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
)

func TestStagedAppRejectsAppIDThatCannotFitDerivedJSONFilename(t *testing.T) {
	spk := []byte("spk::long-app-id")
	packageHash := sha256.Sum256(spk)
	metadata := []byte(`{"appId":"` + strings.Repeat("a", maxCatalogAppIDBytes+1) + `","packageId":"` + hex.EncodeToString(packageHash[:])[:32] + `","version":"1.2.3"}`)
	appHash, err := apphash.Canonical(bytes.NewReader(spk), metadata)
	if err != nil {
		t.Fatal(err)
	}
	releaseHash := sha256.Sum256([]byte("release::long-app-id"))
	rel := ReleaseJSON{AppHash: appHash, ReleaseHash: hex.EncodeToString(releaseHash[:]), Version: "1.2.3"}
	if _, err := buildStagedAppManifest(spk, metadata, mustJSON(t, rel), rel, slotHint{}, time.Now()); err == nil || !strings.Contains(err.Error(), "derived filename") {
		t.Fatalf("overlong appId accepted: %v", err)
	}
}

func testStageMaterial(t *testing.T, label string, at time.Time) (stagedAppManifest, []byte, []byte, []byte) {
	t.Helper()
	spk := []byte("spk::" + label)
	packageHash := sha256.Sum256(spk)
	metadata := []byte(`{"appId":"stage-test-app","packageId":"` + hex.EncodeToString(packageHash[:])[:32] + `","version":"1.2.3"}`)
	appHash, err := apphash.Canonical(bytes.NewReader(spk), metadata)
	if err != nil {
		t.Fatal(err)
	}
	releaseHash := sha256.Sum256([]byte("release::" + label))
	rel := ReleaseJSON{
		Schema:       "melusina-release-v1",
		AppHash:      appHash,
		ReleaseHash:  hex.EncodeToString(releaseHash[:]),
		Version:      "1.2.3",
		SignedAtUnix: at.Unix(),
	}
	release := mustJSON(t, rel)
	manifest, err := buildStagedAppManifest(spk, metadata, release, rel, slotHint{Developer: "dev", Repo: "repo", Slug: "app"}, at)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, spk, metadata, release
}

func TestStagedApp_DurableIdempotentAndTamperEvident(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0).UTC()
	manifest, spk, metadata, release := testStageMaterial(t, "v1", at)
	if err := persistStagedApp(root, manifest, spk, metadata, release); err != nil {
		t.Fatal(err)
	}

	// A retry at a later wall-clock time is the same content-addressed candidate
	// and preserves the original durable timestamp.
	retry := manifest
	retry.StoredAt += 120
	if err := persistStagedApp(root, retry, spk, metadata, release); err != nil {
		t.Fatalf("idempotent retry failed: %v", err)
	}
	// The Squads ceremony finalizes fields that cannot exist at pre-chain stage
	// time. They must not change the candidate address or make a retry conflict
	// with the already durable provisional object.
	finalRel := mustReleaseJSON(release)
	finalRel.SignedAtUnix += 180
	finalRel.ReleaseEntryPda = "finalized-release-pda"
	finalRel.AuthorSig = "finalized-author-signature"
	finalRel.QuorumPolicy = QuorumPolicy{Threshold: 3, MemberCount: 4, MultisigPda: "core-app-team"}
	finalRelease := mustJSON(t, finalRel)
	finalManifest, err := buildStagedAppManifest(spk, metadata, finalRelease, finalRel, manifest.SlotHint, at.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if finalManifest.StageID != manifest.StageID {
		t.Fatal("ceremony finalization changed the content-addressed candidate id")
	}
	if err := persistStagedApp(root, finalManifest, spk, metadata, finalRelease); err != nil {
		t.Fatalf("finalized release retry conflicted with provisional stage: %v", err)
	}
	loaded, gotSPK, gotMeta, gotRelease, err := loadStagedApp(root, manifest.StageID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.StoredAt != manifest.StoredAt || !bytes.Equal(gotSPK, spk) || !bytes.Equal(gotMeta, metadata) || !bytes.Equal(gotRelease, release) {
		t.Fatal("staged candidate changed across idempotent retry")
	}
	st, err := os.Stat(filepath.Join(root, manifest.StageID))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("candidate directory mode = %v, want 0700", st.Mode().Perm())
	}

	if err := os.WriteFile(filepath.Join(root, manifest.StageID, "app.spk"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := loadStagedApp(root, manifest.StageID); err == nil {
		t.Fatal("tampered staged bytes were accepted")
	}
}

func TestStagedAppV2BindsAndPersistsExactRuntimeContract(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0).UTC()
	legacy, spk, metadata, legacyRelease := testStageMaterial(t, "runtime-v2", at)
	rel := mustReleaseJSON(legacyRelease)
	runtimeContract := runtimeContractForTest(t, spk, metadata, rel)
	runtimeSum := sha256.Sum256(runtimeContract)
	rel.RuntimeContractSchema = runtimecontract.Schema
	rel.RuntimeContractSHA256 = hex.EncodeToString(runtimeSum[:])
	release := mustJSON(t, rel)

	manifest, err := buildStagedAppManifest(spk, metadata, release, rel, legacy.SlotHint, at, runtimeContract)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != appStageSchemaV2 {
		t.Fatalf("runtime-bound stage schema = %q, want %q", manifest.Schema, appStageSchemaV2)
	}
	if manifest.StageID == legacy.StageID {
		t.Fatal("runtime-bound candidate reused the legacy v1 stage ID")
	}
	if manifest.RuntimeContractSHA256 != hex.EncodeToString(runtimeSum[:]) || manifest.RuntimeContractSize != len(runtimeContract) {
		t.Fatalf("runtime binding not recorded in stage manifest: %+v", manifest)
	}
	if err := persistStagedApp(root, manifest, spk, metadata, release, runtimeContract); err != nil {
		t.Fatal(err)
	}
	loaded, gotSPK, gotMetadata, gotRelease, gotRuntime, err := loadStagedAppWithRuntime(root, manifest.StageID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != manifest || !bytes.Equal(gotSPK, spk) || !bytes.Equal(gotMetadata, metadata) ||
		!bytes.Equal(gotRelease, release) || !bytes.Equal(gotRuntime, runtimeContract) {
		t.Fatal("v2 stage did not round-trip the exact submitted candidate")
	}
	runtimePath := filepath.Join(root, manifest.StageID, "RUNTIME-CONTRACT.json")
	info, err := os.Stat(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("runtime contract mode = %v, want 0600", info.Mode().Perm())
	}
	if err := os.WriteFile(runtimePath, append([]byte(nil), runtimeContract[:len(runtimeContract)-1]...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err := loadStagedAppWithRuntime(root, manifest.StageID); err == nil {
		t.Fatal("truncated staged runtime contract was accepted")
	}
}

func TestStagedAppV2RejectsReleaseContractBindingMutation(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1_700_000_000, 0).UTC()
	legacy, spk, metadata, legacyRelease := testStageMaterial(t, "runtime-binding-mutation", at)
	rel := mustReleaseJSON(legacyRelease)
	runtimeContract := runtimeContractForTest(t, spk, metadata, rel)
	runtimeSum := sha256.Sum256(runtimeContract)
	rel.RuntimeContractSchema = runtimecontract.Schema
	rel.RuntimeContractSHA256 = hex.EncodeToString(runtimeSum[:])
	release := mustJSON(t, rel)
	manifest, err := buildStagedAppManifest(spk, metadata, release, rel, legacy.SlotHint, at, runtimeContract)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistStagedApp(root, manifest, spk, metadata, release, runtimeContract); err != nil {
		t.Fatal(err)
	}

	// StageID deliberately excludes the provisional RELEASE.json byte hash so
	// the ceremony can finalize its permitted fields. Rebinding the release to
	// different runtime bytes must still fail even if an attacker also updates
	// releaseSha256/releaseSize in the unsigned stage ledger.
	rel.RuntimeContractSHA256 = strings.Repeat("f", 64)
	mutatedRelease := mustJSON(t, rel)
	mutatedReleaseSum := sha256.Sum256(mutatedRelease)
	manifest.ReleaseSHA256 = hex.EncodeToString(mutatedReleaseSum[:])
	manifest.ReleaseSize = len(mutatedRelease)
	stageDir := filepath.Join(root, manifest.StageID)
	if err := os.WriteFile(filepath.Join(stageDir, "RELEASE.json"), mutatedRelease, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stageDir, "stage.json"), append(mustJSON(t, manifest), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err := loadStagedAppWithRuntime(root, manifest.StageID); err == nil || !strings.Contains(err.Error(), "runtime contract") {
		t.Fatalf("mutated RELEASE-to-contract binding was accepted: %v", err)
	}
}

func TestStageAndRolloutReceipts_AreDomainSeparatedAndSigned(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	manifest, _, _, _ := testStageMaterial(t, "receipt", at)
	op := newTestIdentity(t, "operator", randPubkeyB58(t), "store.example")
	domainHash := sha256.Sum256([]byte("store-domain"))
	pubBytes, err := op.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.PublicKey(pubBytes)

	stageReceipt, err := signStageReceipt(op, manifest, domainHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyStageReceipt(pub, stageReceipt); err != nil {
		t.Fatal(err)
	}
	state := appRolloutState{
		Schema:         appRolloutSchema,
		AppID:          manifest.AppID,
		CurrentStageID: manifest.StageID,
		CurrentAppHash: manifest.AppHash,
		CurrentVersion: manifest.Version,
		ActivatedAt:    at.Unix(),
	}
	rolloutReceipt, err := signAppRolloutReceipt(op, state, domainHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAppRolloutReceipt(pub, rolloutReceipt); err != nil {
		t.Fatal(err)
	}
	if stageReceipt.OperatorSignature == rolloutReceipt.OperatorSignature {
		t.Fatal("domain-separated stage and rollout receipts unexpectedly share a signature")
	}
	rolloutReceipt.CurrentVersion = "9.9.9"
	if err := verifyAppRolloutReceipt(pub, rolloutReceipt); err == nil {
		t.Fatal("tampered rollout version retained a valid signature")
	}
}
