package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type rolloutFixture struct {
	manifest  stagedAppManifest
	spk       []byte
	metadata  []byte
	release   []byte
	rel       ReleaseJSON
	packageID string
	appIDRaw  [32]byte
	relPDA    string
}

func makeRolloutFixture(t *testing.T, masterMint, appID, version, label string, at time.Time) rolloutFixture {
	t.Helper()
	spk := []byte("rollout-spk::" + label)
	spkHash := sha256.Sum256(spk)
	packageID := hex.EncodeToString(spkHash[:])[:32]
	metadata := []byte(`{"appId":"` + appID + `","packageId":"` + packageID + `","version":"` + version + `"}`)
	appHashHex, err := apphash.Canonical(bytes.NewReader(spk), metadata)
	if err != nil {
		t.Fatal(err)
	}
	appHash, err := hash32FromHex(appHashHex)
	if err != nil {
		t.Fatal(err)
	}
	master, err := primitives.PubkeyFromBase58(masterMint)
	if err != nil {
		t.Fatal(err)
	}
	releasePDA, _, err := pda.Release(master, appHash, programID)
	if err != nil {
		t.Fatal(err)
	}
	releaseHash := sha256.Sum256([]byte("rollout-release::" + label))
	rel := ReleaseJSON{
		Schema:             "melusina-release-v1",
		AppHash:            appHashHex,
		ReleaseHash:        hex.EncodeToString(releaseHash[:]),
		Version:            version,
		SignedAtUnix:       at.Unix(),
		MasterNftMint:      masterMint,
		LicenseSquadsVault: testStoreAuthority,
		ReleaseEntryPda:    releasePDA.Base58(),
		QuorumPolicy:       QuorumPolicy{MultisigPda: testStoreAuthority},
	}
	release := mustJSON(t, rel)
	manifest, err := buildStagedAppManifest(spk, metadata, release, rel, slotHint{}, at)
	if err != nil {
		t.Fatal(err)
	}
	return rolloutFixture{
		manifest:  manifest,
		spk:       spk,
		metadata:  metadata,
		release:   release,
		rel:       rel,
		packageID: packageID,
		appIDRaw:  sha256.Sum256([]byte("rollout-app-id::" + appID)),
		relPDA:    releasePDA.Base58(),
	}
}

func writeRolloutDist(t *testing.T, cfg Config, f rolloutFixture) {
	t.Helper()
	for _, dir := range []string{
		filepath.Join(cfg.DistDir, "apps"),
		filepath.Join(cfg.DistDir, "packages"),
		filepath.Join(cfg.DistDir, "signatures", f.manifest.AppID),
		filepath.Join(cfg.DistDir, "attest", f.manifest.AppID),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	index := catalogIndex{Apps: []catalogIndexApp{{AppID: f.manifest.AppID, PackageID: f.packageID}}}
	indexBytes, _ := json.Marshal(index)
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "apps", "index.json"), indexBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "packages", f.packageID), f.spk, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "signatures", f.manifest.AppID, "metadata.json"), f.metadata, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "attest", f.manifest.AppID, "RELEASE.json"), f.release, 0o644); err != nil {
		t.Fatal(err)
	}
}

// pinRolloutListingActive supplies the exact per-store listing needed to serve
// a retained rollback release. A rollback is still an app projection, not an
// exemption from the same target-scoped visibility gate as the current row.
func pinRolloutListingActive(t *testing.T, m *mockChainReader, cfg Config, f rolloutFixture) {
	t.Helper()
	storeAuthority, err := primitives.PubkeyFromBase58(cfg.StoreAuthority)
	if err != nil {
		t.Fatal(err)
	}
	licenseMint, err := primitives.PubkeyFromBase58(cfg.LicenseNFTMint)
	if err != nil {
		t.Fatal(err)
	}
	appHash, err := hash32FromHex(f.rel.AppHash)
	if err != nil {
		t.Fatal(err)
	}
	releaseEntry, err := primitives.PubkeyFromBase58(f.relPDA)
	if err != nil {
		t.Fatal(err)
	}
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, domainHash, programID)
	if err != nil {
		t.Fatal(err)
	}
	listingPDA, _, err := pda.StoreReleaseListing(storeAuthority, appHash, programID)
	if err != nil {
		t.Fatal(err)
	}
	m.storeAuthz[authzPDA.Base58()] = mockStoreAuthz{
		status:     verify.AuthorizationStatusActive,
		authority:  verify.Pubkey(storeAuthority),
		tierMask:   0xff,
		domainHash: domainHash,
	}
	m.storeListing[listingPDA.Base58()] = mockStoreReleaseListing{
		storeAuthority:        storeAuthority,
		appHash:               appHash,
		releaseEntry:          releaseEntry,
		storeDomainHash:       domainHash,
		operatorAuthorization: authzPDA,
		status:                storeListingStatusActive,
	}
}

func TestPrepareAppRollout_RetainsPriorAndSignsWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	if err := os.Chmod(cfg.PrivateStageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cfg.PrivateStageDir, "rollouts"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.AppRollbackWindowSeconds = 300
	master := randPubkeyB58(t)
	old := makeRolloutFixture(t, master, "rollout-app", "1.0.0", "old", now.Add(-time.Hour))
	current := makeRolloutFixture(t, master, "rollout-app", "2.0.0", "current", now)
	writeRolloutDist(t, cfg, old)
	if err := persistStagedApp(cfg.PrivateStageDir, current.manifest, current.spk, current.metadata, current.release); err != nil {
		t.Fatal(err)
	}

	state, err := prepareAppRollout(cfg, current.manifest, now)
	if err != nil {
		t.Fatal(err)
	}
	if state.CurrentStageID != current.manifest.StageID || state.PreviousStageID == "" || state.PreviousAppHash != old.rel.AppHash {
		t.Fatalf("bad rollout state: %+v", state)
	}
	if state.PreviousValidUntil != now.Add(5*time.Minute).Unix() {
		t.Fatalf("rollback deadline=%d want=%d", state.PreviousValidUntil, now.Add(5*time.Minute).Unix())
	}
	if _, err := os.Stat(filepath.Join(cfg.PrivateStageDir, state.PreviousStageID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prepare mutated private stage before claim: %v", err)
	}
	rolloutPath, err := rolloutStatePath(cfg, current.manifest.AppID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rolloutPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prepare wrote rollout state before claim: %v", err)
	}
	if err := commitAppRollout(cfg, state); err != nil {
		t.Fatal(err)
	}
	retained, gotSPK, _, _, err := loadStagedApp(cfg.PrivateStageDir, state.PreviousStageID)
	if err != nil {
		t.Fatal(err)
	}
	if retained.AppHash != old.rel.AppHash || !bytes.Equal(gotSPK, old.spk) {
		t.Fatal("prior release was not retained byte-identically")
	}

	op := newTestIdentity(t, "rollout-operator", randPubkeyB58(t), cfg.Domain)
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	receipt, err := signAppRolloutReceipt(op, state, domainHash)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := op.Public().SignPublicKey()
	if err := verifyAppRolloutReceipt(ed25519.PublicKey(pub), receipt); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareAppRollout_RefusesToReplacePendingFailedPromotion(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	if err := os.Chmod(cfg.PrivateStageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cfg.PrivateStageDir, "rollouts"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.AppRollbackWindowSeconds = 300
	master := randPubkeyB58(t)
	served := makeRolloutFixture(t, master, "pending-app", "1.0.0", "served", now.Add(-time.Hour))
	pending := makeRolloutFixture(t, master, "pending-app", "2.0.0", "pending", now)
	replacement := makeRolloutFixture(t, master, "pending-app", "3.0.0", "replacement", now.Add(time.Minute))
	writeRolloutDist(t, cfg, served)
	for _, candidate := range []rolloutFixture{pending, replacement} {
		if err := persistStagedApp(cfg.PrivateStageDir, candidate.manifest, candidate.spk, candidate.metadata, candidate.release); err != nil {
			t.Fatal(err)
		}
	}
	pendingState, err := prepareAppRollout(cfg, pending.manifest, now)
	if err != nil {
		t.Fatal(err)
	}
	if pendingState.PreviousAppHash != served.manifest.AppHash {
		t.Fatalf("pending rollout did not retain served release: %+v", pendingState)
	}
	if err := commitAppRollout(cfg, pendingState); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareAppRollout(cfg, replacement.manifest, now.Add(time.Minute)); err == nil ||
		!strings.Contains(err.Error(), "pending rollout") {
		t.Fatalf("replacement displaced a never-published pending rollout: %v", err)
	}
	retry, err := prepareAppRollout(cfg, pending.manifest, now.Add(time.Minute))
	if err != nil || retry.CurrentStageID != pending.manifest.StageID {
		t.Fatalf("exact pending candidate was not retryable: state=%+v err=%v", retry, err)
	}

	writeRolloutDist(t, cfg, pending)
	indexBytes, err := os.ReadFile(filepath.Join(cfg.DistDir, "apps", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	indexHash := sha256.Sum256(indexBytes)
	pointer := AppCatalogPointer{
		AppID:         pending.manifest.AppID,
		PackageID:     pending.packageID,
		Version:       pending.manifest.Version,
		AppHash:       pending.manifest.AppHash,
		StageID:       pending.manifest.StageID,
		CatalogSHA256: hex.EncodeToString(indexHash[:]),
	}
	if err := os.MkdirAll(filepath.Join(cfg.DistDir, "apps", "pointers"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "apps", "pointers", pending.manifest.AppID+".json"), mustJSON(t, pointer), 0o644); err != nil {
		t.Fatal(err)
	}
	next, err := prepareAppRollout(cfg, replacement.manifest, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("published prior rollout did not permit the next candidate: %v", err)
	}
	if next.PreviousAppHash != pending.manifest.AppHash {
		t.Fatalf("next rollout did not retain the actually published release: %+v", next)
	}
}

func TestServeGate_PreviousReleaseRequiresWindowAndActiveChainEntry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	if err := os.Chmod(cfg.PrivateStageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cfg.PrivateStageDir, "rollouts"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.AppRollbackWindowSeconds = 300
	cfg.ServeVerifyTTLSeconds = -1
	master := randPubkeyB58(t)
	old := makeRolloutFixture(t, master, "rollout-serve-app", "1.0.0", "old", now.Add(-time.Hour))
	current := makeRolloutFixture(t, master, "rollout-serve-app", "2.0.0", "current", now)
	writeRolloutDist(t, cfg, old)
	if err := persistStagedApp(cfg.PrivateStageDir, current.manifest, current.spk, current.metadata, current.release); err != nil {
		t.Fatal(err)
	}
	state, err := prepareAppRollout(cfg, current.manifest, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitAppRollout(cfg, state); err != nil {
		t.Fatal(err)
	}
	// Simulate successful catalog promotion: current is public; old survives only
	// in the private retained candidate selected by the rollout state.
	if err := os.Remove(filepath.Join(cfg.DistDir, "packages", old.packageID)); err != nil {
		t.Fatal(err)
	}
	writeRolloutDist(t, cfg, current)

	m := newMockChainReader()
	oldHash, _ := hash32FromHex(old.rel.AppHash)
	m.releaseEntry[old.relPDA] = mockReleaseEntry{
		appHash:      oldHash,
		appID:        old.appIDRaw,
		version:      old.rel.Version,
		status:       verify.AttestationStatusActive,
		registeredAt: old.rel.SignedAtUnix,
	}
	pinRolloutListingActive(t, m, cfg, old)
	gate := newServeGate(cfg, m, http.FileServer(http.Dir(cfg.DistDir)))
	clock := now.Add(time.Minute)
	gate.now = func() time.Time { return clock }
	w := httptest.NewRecorder()
	gate.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/packages/"+old.packageID, nil))
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), old.spk) {
		t.Fatalf("active previous release not served: code=%d body=%s", w.Code, w.Body.String())
	}
	clock = time.Unix(state.PreviousValidUntil, 0)
	w = httptest.NewRecorder()
	gate.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/packages/"+old.packageID, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("cached previous release survived deadline: code=%d want 404", w.Code)
	}

	expiredGate := newServeGate(cfg, m, http.FileServer(http.Dir(cfg.DistDir)))
	expiredGate.now = func() time.Time { return time.Unix(state.PreviousValidUntil+1, 0) }
	w = httptest.NewRecorder()
	expiredGate.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/packages/"+old.packageID, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expired previous release code=%d want 404", w.Code)
	}

	m.releaseEntry[old.relPDA] = mockReleaseEntry{
		appHash: oldHash,
		appID:   old.appIDRaw,
		version: old.rel.Version,
		status:  verify.AttestationStatusRevoked,
	}
	revokedGate := newServeGate(cfg, m, http.FileServer(http.Dir(cfg.DistDir)))
	revokedGate.now = func() time.Time { return now.Add(time.Minute) }
	w = httptest.NewRecorder()
	revokedGate.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/packages/"+old.packageID, nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("revoked previous release code=%d want 403", w.Code)
	}
}
