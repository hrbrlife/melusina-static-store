package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestAppCatalogRecoveryInvalidCurrentSelectsNewestValidPrior(t *testing.T) {
	root := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	oldID := appCatalogGenerationPrefix + strings.Repeat("1", 32)
	newID := appCatalogGenerationPrefix + strings.Repeat("2", 32)
	writeRecoveryGeneration(t, root, oldID, []string{"app-one"}, priv)
	writeRecoveryGeneration(t, root, newID, []string{"app-one"}, priv)
	corruptRecoveryPointer(t, filepath.Join(root, newID), "app-one")
	setGenerationTime(t, filepath.Join(root, oldID), time.Unix(10, 0))
	setGenerationTime(t, filepath.Join(root, newID), time.Unix(20, 0))
	if err := os.Symlink(newID, filepath.Join(root, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}

	got, err := recoverTestCurrent(root, recoveryRollouts("app-one"), pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != oldID {
		t.Fatalf("recovered %s, want %s", got.ID, oldID)
	}
	if target, _ := os.Readlink(filepath.Join(root, appCatalogCurrentLink)); target != oldID {
		t.Fatalf("current target = %q, want %q", target, oldID)
	}
}

func TestAppCatalogRecoveryCompletesRolloutCommittedBeforeCurrentSwitch(t *testing.T) {
	root := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	oldID := appCatalogGenerationPrefix + strings.Repeat("0", 32)
	preparedID := appCatalogGenerationPrefix + strings.Repeat("f", 32)
	writeRecoveryGeneration(t, root, oldID, []string{"app-one"}, priv)
	writeRecoveryGeneration(t, root, preparedID, []string{"app-one"}, priv)
	prepared := recoveryRollouts("app-one")["app-one"]
	prepared.CurrentStageID = recoveryManifest("app-one", "2.0.0").StageID
	prepared.CurrentVersion = "2.0.0"
	rewriteRecoveryPointerSelection(t, filepath.Join(root, preparedID), prepared, priv)
	setGenerationTime(t, filepath.Join(root, oldID), time.Unix(10, 0))
	setGenerationTime(t, filepath.Join(root, preparedID), time.Unix(20, 0))
	if err := os.Symlink(oldID, filepath.Join(root, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	got, err := recoverTestCurrent(root, map[string]appRolloutState{"app-one": prepared}, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != preparedID {
		t.Fatalf("recovered %s, want prepared generation %s", got.ID, preparedID)
	}
}

func TestAppCatalogRecoveryNoValidGenerationFailsWithoutCleanup(t *testing.T) {
	root := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	id := appCatalogGenerationPrefix + strings.Repeat("3", 32)
	writeRecoveryGeneration(t, root, id, []string{"app-one"}, priv)
	corruptRecoveryPointer(t, filepath.Join(root, id), "app-one")
	if err := os.Symlink(id, filepath.Join(root, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(root, "."+appCatalogGenerationPrefix+strings.Repeat("4", 32)+".tmp")
	if err := os.Mkdir(orphan, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverTestCurrent(root, recoveryRollouts("app-one"), pub); err == nil {
		t.Fatal("recovery accepted a catalog with no valid generation")
	}
	if _, err := os.Lstat(orphan); err != nil {
		t.Fatalf("orphan cleaned before verified selection: %v", err)
	}
}

func TestAppCatalogRecoveryRejectsInvalidPointerAndPartialCurrent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		current []string
		corrupt bool
	}{
		{name: "invalid-pointer", current: []string{"app-one", "app-two"}, corrupt: true},
		{name: "partial-pointer-set", current: []string{"app-one"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			validID := appCatalogGenerationPrefix + strings.Repeat("5", 32)
			currentID := appCatalogGenerationPrefix + strings.Repeat("6", 32)
			writeRecoveryGeneration(t, root, validID, []string{"app-one", "app-two"}, priv)
			writeRecoveryGeneration(t, root, currentID, tc.current, priv)
			if tc.corrupt {
				corruptRecoveryPointer(t, filepath.Join(root, currentID), "app-two")
			}
			setGenerationTime(t, filepath.Join(root, validID), time.Unix(10, 0))
			setGenerationTime(t, filepath.Join(root, currentID), time.Unix(20, 0))
			if err := os.Symlink(currentID, filepath.Join(root, appCatalogCurrentLink)); err != nil {
				t.Fatal(err)
			}
			got, err := recoverTestCurrent(root, recoveryRollouts("app-one", "app-two"), pub)
			if err != nil {
				t.Fatal(err)
			}
			if got.ID != validID {
				t.Fatalf("recovered %s, want %s", got.ID, validID)
			}
		})
	}
}

func TestAppCatalogRecoveryCleansOnlySafeOrphansAfterVerification(t *testing.T) {
	root := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	id := appCatalogGenerationPrefix + strings.Repeat("7", 32)
	writeRecoveryGeneration(t, root, id, []string{"app-one"}, priv)
	if err := os.Symlink(id, filepath.Join(root, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	tmpID := appCatalogGenerationPrefix + strings.Repeat("8", 32)
	tmp := filepath.Join(root, "."+tmpID+".tmp")
	writeFile(t, filepath.Join(tmp, "apps", "partial"), []byte("partial"))
	currentTmp := filepath.Join(root, ".current-"+strings.Repeat("9", 32))
	if err := os.Symlink(appCatalogGenerationPrefix+strings.Repeat("9", 32), currentTmp); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverTestCurrent(root, recoveryRollouts("app-one"), pub); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{tmp, currentTmp} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("safe orphan %s remains: %v", path, err)
		}
	}

	unsafe := filepath.Join(root, "."+appCatalogGenerationPrefix+strings.Repeat("a", 32)+".tmp")
	if err := os.Mkdir(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(unsafe, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverTestCurrent(root, recoveryRollouts("app-one"), pub); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("unsafe orphan accepted: %v", err)
	}
}

func TestAppCatalogRecoveryRejectsSignedGenerationThatContradictsDurableRollout(t *testing.T) {
	root := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	id := appCatalogGenerationPrefix + strings.Repeat("b", 32)
	writeRecoveryGeneration(t, root, id, []string{"app-one"}, priv)
	if err := os.Symlink(id, filepath.Join(root, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	rollouts := recoveryRollouts("app-one")
	state := rollouts["app-one"]
	state.CurrentStageID = strings.Repeat("e", 64)
	rollouts["app-one"] = state
	if _, err := recoverTestCurrent(root, rollouts, pub); err == nil || !strings.Contains(err.Error(), "durable rollout selection") {
		t.Fatalf("accepted signed stale generation after rollout commit: %v", err)
	}
}

func TestAppCatalogRecoveryRejectsWritableOrSubstitutedSelectedBytes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string)
		want   string
	}{
		{
			name: "writable-generation",
			mutate: func(t *testing.T, generation string) {
				if err := os.Chmod(filepath.Join(generation, "packages"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: "mode is 0755",
		},
		{
			name: "substituted-package",
			mutate: func(t *testing.T, generation string) {
				packageID := recoveryPackageID("app-one")
				path := filepath.Join(generation, "packages", packageID)
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("substituted"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o444); err != nil {
					t.Fatal(err)
				}
			},
			want: "appHash mismatch",
		},
		{
			name: "release-byte-drift-with-same-fields",
			mutate: func(t *testing.T, generation string) {
				path := filepath.Join(generation, "attest", "app-one", "RELEASE.json")
				body := []byte(readFile(t, path))
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0o444); err != nil {
					t.Fatal(err)
				}
			},
			want: "bytes differ from exact staged candidate",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			id := appCatalogGenerationPrefix + strings.Repeat("a", 32)
			writeRecoveryGeneration(t, root, id, []string{"app-one"}, priv)
			if err := os.Symlink(id, filepath.Join(root, appCatalogCurrentLink)); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, filepath.Join(root, id))
			if _, err := recoverTestCurrent(root, recoveryRollouts("app-one"), pub); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unsafe generation accepted: %v", err)
			}
		})
	}
}

func TestAppCatalogRecoveryRequiresStageAndExactOwner(t *testing.T) {
	root := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	id := appCatalogGenerationPrefix + strings.Repeat("e", 32)
	writeRecoveryGeneration(t, root, id, []string{"app-one"}, priv)
	if err := os.Symlink(id, filepath.Join(root, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	rollouts := recoveryRollouts("app-one")
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	store := AppCatalogGenerationStore{Root: root}
	if _, err := store.RecoverCurrent(rollouts, pub, recoveryDomainHash(), "", uid, gid); err == nil || !strings.Contains(err.Error(), "private-stage root") {
		t.Fatalf("missing private-stage root accepted: %v", err)
	}
	stageRoot := filepath.Join(root, "stages")
	if _, err := store.RecoverCurrent(rollouts, pub, recoveryDomainHash(), stageRoot, uid+1, gid); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("wrong generation uid accepted: %v", err)
	}
	if _, err := store.RecoverCurrent(rollouts, pub, recoveryDomainHash(), stageRoot, uid, gid+1); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("wrong generation gid accepted: %v", err)
	}
}

func recoveryDomainHash() string { return strings.Repeat("d", 64) }

func recoveryRollouts(appIDs ...string) map[string]appRolloutState {
	rollouts := make(map[string]appRolloutState, len(appIDs))
	for _, appID := range appIDs {
		spk, metadata, _, appHash := recoveryReleaseBytes(appID, "1.0.0")
		_ = spk
		_ = metadata
		rollouts[appID] = appRolloutState{
			Schema:         appRolloutSchema,
			AppID:          appID,
			CurrentStageID: recoveryManifest(appID, "1.0.0").StageID,
			CurrentAppHash: appHash,
			CurrentVersion: "1.0.0",
		}
	}
	return rollouts
}

func writeRecoveryGeneration(t *testing.T, root, id string, appIDs []string, private ed25519.PrivateKey) {
	t.Helper()
	generation := filepath.Join(root, id)
	t.Cleanup(func() {
		_ = filepath.Walk(generation, func(path string, info os.FileInfo, err error) error {
			if err == nil && info != nil {
				if info.IsDir() {
					_ = os.Chmod(path, 0o755)
				} else {
					_ = os.Chmod(path, 0o644)
				}
			}
			return nil
		})
	})
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(generation, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	index := catalogIndex{}
	packageIDs := make(map[string]string, len(appIDs))
	appHashes := make(map[string]string, len(appIDs))
	for _, appID := range appIDs {
		spk, metadata, release, appHash := recoveryReleaseBytes(appID, "1.0.0")
		persistRecoveryStage(t, root, appID, "1.0.0")
		spkHash := sha256.Sum256(spk)
		packageID := hex.EncodeToString(spkHash[:])[:32]
		packageIDs[appID] = packageID
		appHashes[appID] = appHash
		index.Apps = append(index.Apps, catalogIndexApp{AppID: appID, PackageID: packageID})
		writeFile(t, filepath.Join(generation, "packages", packageID), spk)
		writeFile(t, filepath.Join(generation, "signatures", appID, "metadata.json"), metadata)
		writeFile(t, filepath.Join(generation, "attest", appID, "RELEASE.json"), release)
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(generation, "apps", "index.json"), indexBytes)
	digest := sha256.Sum256(indexBytes)
	for _, appID := range appIDs {
		pointer := AppCatalogPointer{
			Schema: appCatalogPointerSchema, AppID: appID,
			PackageID: packageIDs[appID], Version: "1.0.0",
			AppHash: appHashes[appID], ReleaseHash: strings.Repeat("b", 64),
			StageID: recoveryManifest(appID, "1.0.0").StageID, CatalogSHA256: hex.EncodeToString(digest[:]),
			ServingDomainHash: strings.Repeat("d", 64), PublishedAt: 1,
		}
		message, err := appCatalogPointerMessage(pointer)
		if err != nil {
			t.Fatal(err)
		}
		pointer.OperatorSignature = primitives.EncodeBase58(ed25519.Sign(private, message))
		body, _ := json.Marshal(pointer)
		writeFile(t, filepath.Join(generation, "apps", "pointers", appID+".json"), body)
	}
	if err := syncAndSealCatalogTree(generation); err != nil {
		t.Fatal(err)
	}
}

func recoveryReleaseBytes(appID, version string) ([]byte, []byte, []byte, string) {
	spk := []byte("recovery-spk:" + appID)
	spkHash := sha256.Sum256(spk)
	packageID := hex.EncodeToString(spkHash[:])[:32]
	metadata := []byte(fmt.Sprintf(`{"appId":%q,"packageId":%q}`, appID, packageID))
	appHash, err := apphash.Canonical(bytes.NewReader(spk), metadata)
	if err != nil {
		panic(err)
	}
	release := []byte(fmt.Sprintf(`{"appHash":%q,"releaseHash":%q,"version":%q}`, appHash, strings.Repeat("b", 64), version))
	return spk, metadata, release, appHash
}

func recoveryManifest(appID, version string) stagedAppManifest {
	spk, metadata, release, _ := recoveryReleaseBytes(appID, version)
	manifest, err := buildStagedAppManifest(spk, metadata, release, mustReleaseJSON(release), slotHint{}, time.Unix(1, 0))
	if err != nil {
		panic(err)
	}
	return manifest
}

func persistRecoveryStage(t *testing.T, root, appID, version string) {
	t.Helper()
	stageRoot := filepath.Join(root, "stages")
	if err := os.MkdirAll(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	spk, metadata, release, _ := recoveryReleaseBytes(appID, version)
	if err := persistStagedApp(stageRoot, recoveryManifest(appID, version), spk, metadata, release); err != nil {
		t.Fatal(err)
	}
}

func recoverTestCurrent(root string, rollouts map[string]appRolloutState, pub ed25519.PublicKey) (AppCatalogSnapshot, error) {
	return (AppCatalogGenerationStore{Root: root}).RecoverCurrent(
		rollouts, pub, recoveryDomainHash(), filepath.Join(root, "stages"), uint32(os.Getuid()), uint32(os.Getgid()))
}

func recoveryPackageID(appID string) string {
	hash := sha256.Sum256([]byte("recovery-spk:" + appID))
	return hex.EncodeToString(hash[:])[:32]
}

func corruptRecoveryPointer(t *testing.T, generation, appID string) {
	t.Helper()
	path := filepath.Join(generation, "apps", "pointers", appID+".json")
	var pointer AppCatalogPointer
	if err := json.Unmarshal([]byte(readFile(t, path)), &pointer); err != nil {
		t.Fatal(err)
	}
	pointer.OperatorSignature = "1"
	body, _ := json.Marshal(pointer)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
}

func rewriteRecoveryPointerSelection(t *testing.T, generation string, rollout appRolloutState, private ed25519.PrivateKey) {
	t.Helper()
	path := filepath.Join(generation, "apps", "pointers", rollout.AppID+".json")
	var pointer AppCatalogPointer
	if err := json.Unmarshal([]byte(readFile(t, path)), &pointer); err != nil {
		t.Fatal(err)
	}
	pointer.StageID = rollout.CurrentStageID
	pointer.AppHash = rollout.CurrentAppHash
	pointer.Version = rollout.CurrentVersion
	releasePath := filepath.Join(generation, "attest", rollout.AppID, "RELEASE.json")
	_, _, release, _ := recoveryReleaseBytes(rollout.AppID, rollout.CurrentVersion)
	persistRecoveryStage(t, filepath.Dir(generation), rollout.AppID, rollout.CurrentVersion)
	if err := os.Chmod(releasePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(releasePath, release, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(releasePath, 0o444); err != nil {
		t.Fatal(err)
	}
	message, err := appCatalogPointerMessage(pointer)
	if err != nil {
		t.Fatal(err)
	}
	pointer.OperatorSignature = primitives.EncodeBase58(ed25519.Sign(private, message))
	body, err := json.Marshal(pointer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
}

func setGenerationTime(t *testing.T, path string, when time.Time) {
	t.Helper()
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}
