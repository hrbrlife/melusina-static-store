package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
)

// This optional evidence test lets a release operator validate the exact
// materialized cohort used for a live repair without hard-coding a workstation
// path into normal CI.  CI exercises the same parser with the synthetic case
// below; production preparation sets MELUSINA_GOVERNED_COHORT explicitly.
func TestLoadGovernedCohortFromExplicitEvidence(t *testing.T) {
	root := os.Getenv("MELUSINA_GOVERNED_COHORT")
	if root == "" {
		t.Skip("set MELUSINA_GOVERNED_COHORT to validate a materialized cohort")
	}
	cfg := Config{Domain: defaultBazaarDomain, ReleaseSquadsAuthority: ReleaseSquadsAuthority{
		Multisig: defaultBazaarSquadsMultisig, Vault: defaultBazaarSquadsVault,
		ProgramID: defaultBazaarSquadsProgramID, Threshold: defaultBazaarSquadsThreshold, MemberCount: defaultBazaarSquadsMemberCount,
	}}
	authority := mustRehydrationAuthority(t, cfg)
	artifacts, _, err := loadGovernedCohort(root, uint32(os.Getuid()), authority)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 32 {
		t.Fatalf("governed cohort has %d apps, want 32", len(artifacts))
	}
}

func TestCatalogRehydrateBuildsFreshStagesAndRetiresOnlyExplicitLegacyRows(t *testing.T) {
	root := t.TempDir()
	uid := uint32(os.Getuid())
	operator := newTestIdentity(t, "rehydrate", randPubkeyB58(t), defaultBazaarDomain)
	cfg := Config{
		Domain:                   defaultBazaarDomain,
		StoreAuthority:           operator.Public().SignPubkeyB58,
		CatalogRepoRoot:          root,
		PrivateStageDir:          filepath.Join(root, "stages"),
		CatalogGenerationRoot:    filepath.Join(root, "generations"),
		CatalogMigrationStateDir: filepath.Join(root, "migrations"),
		ReleaseSquadsAuthority: ReleaseSquadsAuthority{
			Multisig: defaultBazaarSquadsMultisig, Vault: defaultBazaarSquadsVault,
			ProgramID: defaultBazaarSquadsProgramID, Threshold: defaultBazaarSquadsThreshold, MemberCount: defaultBazaarSquadsMemberCount,
		},
	}
	for _, dir := range []string{cfg.PrivateStageDir, cfg.CatalogMigrationStateDir, rolloutStateDir(cfg)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(cfg.CatalogGenerationRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	cleanupImmutableCatalog(t, cfg.CatalogGenerationRoot)

	appOne := strings.Repeat("a", 52)
	appTwo := strings.Repeat("b", 52)
	legacy := strings.Repeat("c", 52)
	artifactOne := newRehydrationFixtureArtifact(t, appOne, "one")
	artifactTwo := newRehydrationFixtureArtifact(t, appTwo, "two")
	legacyArtifact := newRehydrationFixtureArtifact(t, legacy, "legacy")
	writeRehydrationFixtureCohort(t, filepath.Join(root, "cohort"), []governedCohortArtifact{artifactOne, artifactTwo})
	writeRehydrationFixtureSourceGeneration(t, cfg.CatalogGenerationRoot, appCatalogGenerationPrefix+strings.Repeat("1", 32), []governedCohortArtifact{artifactOne, artifactTwo, legacyArtifact})
	if err := os.Symlink(appCatalogGenerationPrefix+strings.Repeat("1", 32), filepath.Join(cfg.CatalogGenerationRoot, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}

	// These are intentionally malformed historical stages. Their rollout
	// selections retain the correct appHash/version, but the private bytes do
	// not validate. Rehydration must preserve these directories and create new
	// content-addressed stages instead of modifying them in place.
	for index, artifact := range []governedCohortArtifact{artifactOne, artifactTwo} {
		oldStage := rehydrationCorruptStageID(byte(index + 1))
		if err := os.Mkdir(filepath.Join(cfg.PrivateStageDir, oldStage), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cfg.PrivateStageDir, oldStage, "stage.json"), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		state := appRolloutState{Schema: appRolloutSchema, AppID: artifact.entry.AppID, CurrentStageID: oldStage, CurrentAppHash: artifact.manifest.AppHash, CurrentVersion: artifact.manifest.Version, ActivatedAt: 1}
		if err := writeAppRollout(cfg, state); err != nil {
			t.Fatal(err)
		}
	}
	legacyStage := rehydrationCorruptStageID("legacy-stage")
	if err := writeAppRollout(cfg, appRolloutState{Schema: appRolloutSchema, AppID: legacy, CurrentStageID: legacyStage, CurrentAppHash: legacyArtifact.manifest.AppHash, CurrentVersion: legacyArtifact.manifest.Version, ActivatedAt: 1}); err != nil {
		t.Fatal(err)
	}

	policy := governedInstallationPolicy{Audience: "workspace", InstallMode: "self-service", PearlRole: "workspace", ClientAccess: "self-owned", AdminSurface: "same-pearl"}
	now := time.Unix(1_800_000_000, 0).UTC()
	report, err := runCatalogRehydrateWithDependencies(context.Background(), cfg, operator, catalogRehydrateOptions{
		cohortDir: filepath.Join(root, "cohort"), expectedAppCount: 2, expectedRolloutCount: 3,
		retireAppIDs: rehydrateStringList{legacy}, apply: true,
	}, rehydrationDependencies{
		expectedUID: uid,
		now:         func() time.Time { return now },
		policies:    map[string]governedInstallationPolicy{appOne: policy, appTwo: policy},
		verify:      func(context.Context, governedCohortArtifact) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.State != "completed" || report.Apps != 2 || len(report.RetiredApps) != 1 || report.RetiredApps[0] != legacy {
		t.Fatalf("rehydration report = %#v", report)
	}
	if _, _, _, _, err := loadStagedApp(cfg.PrivateStageDir, artifactOne.manifest.StageID); err != nil {
		t.Fatalf("first fresh stage is not valid: %v", err)
	}
	if _, _, _, _, err := loadStagedApp(cfg.PrivateStageDir, artifactTwo.manifest.StageID); err != nil {
		t.Fatalf("second fresh stage is not valid: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(cfg.PrivateStageDir, rehydrationCorruptStageID(byte(1)))); err != nil {
		t.Fatalf("corrupt historical stage was not preserved: %v", err)
	}
	classified, err := classifyRolloutStatesAt(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(classified.serving) != 2 || classified.serving[appOne].CurrentStageID != artifactOne.manifest.StageID || classified.serving[appTwo].CurrentStageID != artifactTwo.manifest.StageID {
		t.Fatalf("serving rehydrated rollouts = %#v", classified.serving)
	}
	if _, retired := classified.serving[legacy]; retired {
		t.Fatal("explicitly retired legacy app remains serving")
	}
	retirements, err := readCatalogRetirements(cfg)
	if err != nil || retirements[legacy].AppID != legacy {
		t.Fatalf("retirement receipt = %#v, err=%v", retirements, err)
	}
	store := AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot}
	current, err := store.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != report.RecoveredSnapshotID {
		t.Fatalf("current generation %s, want %s", current.ID, report.RecoveredSnapshotID)
	}
	if err := validateRehydratedCatalogSnapshot(current, classified.serving, cfg, operator, mustRehydrationAuthority(t, cfg), map[string]governedInstallationPolicy{appOne: policy, appTwo: policy}); err != nil {
		t.Fatalf("recovered catalog failed verification: %v", err)
	}
	for _, stale := range []string{legacyArtifact.entry.PackageID} {
		if _, err := os.Lstat(filepath.Join(current.Root, "packages", stale)); !os.IsNotExist(err) {
			t.Fatalf("retired package %s remains in recovered catalog: %v", stale, err)
		}
	}
}

func rehydrationCorruptStageID(value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func mustRehydrationAuthority(t *testing.T, cfg Config) configuredSquadsAuthority {
	t.Helper()
	authority, err := cfg.sharedSquadsAuthority()
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func newRehydrationFixtureArtifact(t *testing.T, appID, tag string) governedCohortArtifact {
	t.Helper()
	spk := []byte("rehydration-fixture-spk-" + tag)
	spkHash := sha256.Sum256(spk)
	packageID := hex.EncodeToString(spkHash[:])[:32]
	metadata := []byte(`{"appId":"` + appID + `","packageId":"` + packageID + `","version":"1.0.0","name":"Fixture ` + tag + `","description":"A richer fixture metadata document."}`)
	appHash, err := apphash.Canonical(bytes.NewReader(spk), metadata)
	if err != nil {
		t.Fatal(err)
	}
	releaseSeed := sha256.Sum256([]byte("rehydration-release-" + tag))
	rel := ReleaseJSON{
		Schema: "melusina-release-v1", AppHash: appHash, ReleaseHash: hex.EncodeToString(releaseSeed[:]), Version: "1.0.0",
		SignedAtUnix: 1_700_000_000, MasterNftMint: randPubkeyB58(t), LicenseSquadsVault: defaultBazaarSquadsVault,
		ReleaseEntryPda: randPubkeyB58(t), ReleaseNonce: "fixture-" + tag,
		QuorumPolicy: QuorumPolicy{Threshold: defaultBazaarSquadsThreshold, MemberCount: defaultBazaarSquadsMemberCount, MultisigPda: defaultBazaarSquadsMultisig},
	}
	contract := runtimeContractForTest(t, spk, metadata, rel)
	contractHash := sha256.Sum256(contract)
	rel.RuntimeContractSchema = "melusina-app-runtime-contract-v1"
	rel.RuntimeContractSHA256 = hex.EncodeToString(contractHash[:])
	release, err := json.Marshal(rel)
	if err != nil {
		t.Fatal(err)
	}
	releaseHash := sha256.Sum256(release)
	entry := governedCohortApp{
		AppID: appID, Version: "1.0.0", AppHash: appHash, ReleaseEntryPDA: rel.ReleaseEntryPda, PackageID: packageID,
		SHA256: hex.EncodeToString(spkHash[:]), Size: len(spk), ReleaseSHA256: hex.EncodeToString(releaseHash[:]), RuntimeContractSHA256: hex.EncodeToString(contractHash[:]),
	}
	artifact, err := validateGovernedCohortArtifact(entry, spk, metadata, release, contract, mustRehydrationAuthority(t, Config{Domain: defaultBazaarDomain, ReleaseSquadsAuthority: ReleaseSquadsAuthority{Multisig: defaultBazaarSquadsMultisig, Vault: defaultBazaarSquadsVault, ProgramID: defaultBazaarSquadsProgramID, Threshold: defaultBazaarSquadsThreshold, MemberCount: defaultBazaarSquadsMemberCount}}))
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func writeRehydrationFixtureCohort(t *testing.T, root string, artifacts []governedCohortArtifact) {
	t.Helper()
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	receipt := governedCohortReceipt{Schema: governedCohortSchema, Origin: defaultBazaarPublicOrigin}
	for _, artifact := range artifacts {
		receipt.Apps = append(receipt.Apps, artifact.entry)
		dir := filepath.Join(root, "packages", "governed", "cohort", artifact.entry.AppID)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string][]byte{"app.spk": artifact.spk, "metadata.json": artifact.metadata, "RELEASE.json": artifact.release, "RUNTIME-CONTRACT.json": artifact.runtimeContract} {
			if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "COHORT-RECEIPT.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeRehydrationFixtureSourceGeneration(t *testing.T, root, id string, artifacts []governedCohortArtifact) {
	t.Helper()
	generation := filepath.Join(root, id)
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(generation, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	index := catalogIndex{}
	for _, artifact := range artifacts {
		index.Apps = append(index.Apps, catalogIndexApp{AppID: artifact.entry.AppID, PackageID: artifact.entry.PackageID})
		writeFile(t, filepath.Join(generation, "packages", artifact.entry.PackageID), artifact.spk)
		writeFile(t, filepath.Join(generation, "signatures", artifact.entry.AppID, "metadata.json"), artifact.metadata)
		writeFile(t, filepath.Join(generation, "attest", artifact.entry.AppID, "RELEASE.json"), artifact.release)
		writeFile(t, filepath.Join(generation, "attest", artifact.entry.AppID, "RUNTIME-CONTRACT.json"), artifact.runtimeContract)
	}
	body, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(generation, "apps", "index.json"), body)
	if err := syncAndSealCatalogTree(generation); err != nil {
		t.Fatal(err)
	}
}
