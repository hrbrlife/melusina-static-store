package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

	got, err := (AppCatalogGenerationStore{Root: root}).RecoverCurrent(recoveryRollouts("app-one"), pub)
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
	if _, err := (AppCatalogGenerationStore{Root: root}).RecoverCurrent(recoveryRollouts("app-one"), pub); err == nil {
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
			got, err := (AppCatalogGenerationStore{Root: root}).RecoverCurrent(recoveryRollouts("app-one", "app-two"), pub)
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
	if _, err := (AppCatalogGenerationStore{Root: root}).RecoverCurrent(recoveryRollouts("app-one"), pub); err != nil {
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
	if _, err := (AppCatalogGenerationStore{Root: root}).RecoverCurrent(recoveryRollouts("app-one"), pub); err == nil || !strings.Contains(err.Error(), "symlink") {
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
	if _, err := (AppCatalogGenerationStore{Root: root}).RecoverCurrent(rollouts, pub); err == nil || !strings.Contains(err.Error(), "durable rollout selection") {
		t.Fatalf("accepted signed stale generation after rollout commit: %v", err)
	}
}

func recoveryRollouts(appIDs ...string) map[string]appRolloutState {
	rollouts := make(map[string]appRolloutState, len(appIDs))
	for _, appID := range appIDs {
		rollouts[appID] = appRolloutState{
			Schema:         appRolloutSchema,
			AppID:          appID,
			CurrentStageID: strings.Repeat("c", 64),
			CurrentAppHash: strings.Repeat("a", 64),
			CurrentVersion: "1.0.0",
		}
	}
	return rollouts
}

func writeRecoveryGeneration(t *testing.T, root, id string, appIDs []string, private ed25519.PrivateKey) {
	t.Helper()
	generation := filepath.Join(root, id)
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(generation, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	index := catalogIndex{}
	for i, appID := range appIDs {
		packageID := strings.Repeat(string(rune('1'+i)), 32)
		index.Apps = append(index.Apps, catalogIndexApp{AppID: appID, PackageID: packageID})
		writeFile(t, filepath.Join(generation, "packages", packageID), []byte(appID))
		writeFile(t, filepath.Join(generation, "signatures", appID, "metadata.json"), []byte("{}"))
		writeFile(t, filepath.Join(generation, "attest", appID, "RELEASE.json"), []byte("{}"))
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(generation, "apps", "index.json"), indexBytes)
	digest := sha256.Sum256(indexBytes)
	for i, appID := range appIDs {
		pointer := AppCatalogPointer{
			Schema: appCatalogPointerSchema, AppID: appID,
			PackageID: strings.Repeat(string(rune('1'+i)), 32), Version: "1.0.0",
			AppHash: strings.Repeat("a", 64), ReleaseHash: strings.Repeat("b", 64),
			StageID: strings.Repeat("c", 64), CatalogSHA256: hex.EncodeToString(digest[:]),
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
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func setGenerationTime(t *testing.T, path string, when time.Time) {
	t.Helper()
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
}
