package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
)

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
