package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppCatalogGenerationBootstrapCopiesAndSwitchesLast(t *testing.T) {
	root := t.TempDir()
	flat := filepath.Join(root, "dist")
	generations := filepath.Join(root, "app-generations")
	cleanupImmutableCatalog(t, generations)
	writeGenerationFixture(t, flat, "app-one", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "old")
	writeFile(t, filepath.Join(flat, "releases", "sidecar", "store.tar.xz"), []byte("not-app-catalog"))

	store := AppCatalogGenerationStore{Root: generations}
	snapshot, err := store.BootstrapFromFlat(flat, validateCatalogSnapshotStructure)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(filepath.Join(generations, appCatalogCurrentLink))
	if err != nil {
		t.Fatal(err)
	}
	if target != snapshot.ID || filepath.IsAbs(target) || strings.Contains(target, "..") {
		t.Fatalf("unsafe current target %q for snapshot %+v", target, snapshot)
	}
	if _, err := os.Stat(filepath.Join(snapshot.Root, "releases")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("non-app namespace copied into generation: %v", err)
	}
	sourceInfo, err := os.Stat(filepath.Join(flat, "packages", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	if err != nil {
		t.Fatal(err)
	}
	copyInfo, err := os.Stat(filepath.Join(snapshot.Root, "packages", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(sourceInfo, copyInfo) {
		t.Fatal("bootstrap hardlinked legacy package into immutable generation")
	}
	if got := readFile(t, filepath.Join(flat, "packages", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); got != "old" {
		t.Fatalf("legacy flat catalog changed: %q", got)
	}
}

func TestAppCatalogGenerationBuildValidatesPointersBeforeAtomicSwitch(t *testing.T) {
	root := t.TempDir()
	flat := filepath.Join(root, "dist")
	generations := filepath.Join(root, "app-generations")
	cleanupImmutableCatalog(t, generations)
	writeGenerationFixture(t, flat, "app-one", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "old")
	store := AppCatalogGenerationStore{Root: generations}
	old, err := store.BootstrapFromFlat(flat, validateCatalogSnapshotStructure)
	if err != nil {
		t.Fatal(err)
	}
	oldFile, err := old.Open("packages/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	defer oldFile.Close()

	store.Hook = func(step string) error {
		if step != "before-current-rename" {
			return nil
		}
		current, err := store.ResolveCurrent()
		if err != nil {
			return err
		}
		if current.ID != old.ID {
			t.Fatalf("current changed before final link rename: old=%s current=%s", old.ID, current.ID)
		}
		return nil
	}
	newSnapshot, err := store.BuildAndSwitch(func(candidateRoot string) error {
		packageID := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		writeGenerationFixture(t, candidateRoot, "app-one", packageID, "new")
		writePointerFixture(t, candidateRoot, "app-one", packageID)
		return nil
	}, func(snapshot AppCatalogSnapshot) error {
		return ValidateAppCatalogSnapshot(snapshot, []string{"app-one"}, nil)
	})
	if err != nil {
		t.Fatal(err)
	}
	current, err := store.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != newSnapshot.ID || current.ID == old.ID {
		t.Fatalf("current did not atomically advance: old=%s new=%s current=%s", old.ID, newSnapshot.ID, current.ID)
	}
	oldBytes, err := io.ReadAll(oldFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(oldBytes) != "old" {
		t.Fatalf("request snapshot changed across generation switch: %q", oldBytes)
	}
	newFile, err := current.Open("packages/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err != nil {
		t.Fatal(err)
	}
	defer newFile.Close()
	newBytes, err := io.ReadAll(newFile)
	if err != nil || string(newBytes) != "new" {
		t.Fatalf("new generation package = %q, %v", newBytes, err)
	}
}

func TestAppCatalogGenerationValidationRejectsPartialAndMismatchedPointers(t *testing.T) {
	root := t.TempDir()
	writeGenerationFixture(t, root, "app-one", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "body")
	writePointerFixture(t, root, "app-one", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	snapshot := AppCatalogSnapshot{ID: appCatalogGenerationPrefix + strings.Repeat("a", 32), Root: root}
	if err := ValidateAppCatalogSnapshot(snapshot, []string{"app-one", "app-two"}, nil); err == nil || !strings.Contains(err.Error(), "app-two") {
		t.Fatalf("partial pointer set accepted: %v", err)
	}

	pointerPath := filepath.Join(root, "apps", "pointers", "app-one.json")
	var pointer AppCatalogPointer
	if err := json.Unmarshal([]byte(readFile(t, pointerPath)), &pointer); err != nil {
		t.Fatal(err)
	}
	pointer.CatalogSHA256 = strings.Repeat("0", 64)
	body, err := json.Marshal(pointer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pointerPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAppCatalogSnapshot(snapshot, []string{"app-one"}, nil); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("mismatched catalog digest accepted: %v", err)
	}
}

func TestAppCatalogGenerationRefusesUnsafeCurrentAndContentLinks(t *testing.T) {
	root := t.TempDir()
	store := AppCatalogGenerationStore{Root: root}
	if err := os.Symlink("../escape", filepath.Join(root, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveCurrent(); err == nil {
		t.Fatal("traversing current symlink accepted")
	}
	if err := os.Remove(filepath.Join(root, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	id := appCatalogGenerationPrefix + strings.Repeat("b", 32)
	generation := filepath.Join(root, id)
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(generation, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(generation, "packages", "bad")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(id, filepath.Join(root, appCatalogCurrentLink)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ResolveCurrent(); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("catalog content symlink accepted: %v", err)
	}
}

func TestAppCatalogGenerationFaultBeforeCurrentRenameLeavesOldCurrent(t *testing.T) {
	root := t.TempDir()
	flat := filepath.Join(root, "dist")
	generations := filepath.Join(root, "app-generations")
	cleanupImmutableCatalog(t, generations)
	writeGenerationFixture(t, flat, "app-one", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "old")
	store := AppCatalogGenerationStore{Root: generations}
	old, err := store.BootstrapFromFlat(flat, validateCatalogSnapshotStructure)
	if err != nil {
		t.Fatal(err)
	}
	store.Hook = func(step string) error {
		if step == "before-current-rename" {
			return errors.New("injected crash")
		}
		return nil
	}
	if _, err := store.BuildAndSwitch(nil, validateCatalogSnapshotStructure); err == nil {
		t.Fatal("injected pre-switch fault was ignored")
	}
	current, err := store.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != old.ID {
		t.Fatalf("pre-switch fault changed current: old=%s current=%s", old.ID, current.ID)
	}
}

func TestAppCatalogGenerationPromotionNeverRecreatesMissingRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing-generations")
	store := AppCatalogGenerationStore{Root: root}
	if _, err := store.BuildAndSwitch(nil, validateCatalogSnapshotStructure); err == nil {
		t.Fatal("steady-state promotion recreated a missing generation root")
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("promotion mutated missing generation root: %v", err)
	}
}

func validateCatalogSnapshotStructure(snapshot AppCatalogSnapshot) error {
	return validateCatalogTree(snapshot.Root)
}

func cleanupImmutableCatalog(t *testing.T, root string) {
	t.Helper()
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}
			if info.IsDir() {
				_ = os.Chmod(path, 0o755)
			} else {
				_ = os.Chmod(path, 0o644)
			}
			return nil
		})
	})
}

func writeGenerationFixture(t *testing.T, root, appID, packageID, packageBody string) {
	t.Helper()
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(root, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	index := catalogIndex{Apps: []catalogIndexApp{{AppID: appID, PackageID: packageID}}}
	body, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "apps", "index.json"), body)
	writeFile(t, filepath.Join(root, "packages", packageID), []byte(packageBody))
	writeFile(t, filepath.Join(root, "signatures", appID, "metadata.json"), []byte(`{"appId":"`+appID+`","packageId":"`+packageID+`"}`))
	writeFile(t, filepath.Join(root, "attest", appID, "RELEASE.json"), []byte(`{"appId":"`+appID+`"}`))
}

func writePointerFixture(t *testing.T, root, appID, packageID string) {
	t.Helper()
	indexBytes, err := os.ReadFile(filepath.Join(root, "apps", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(indexBytes)
	pointer := AppCatalogPointer{
		AppID:         appID,
		PackageID:     packageID,
		CatalogSHA256: hex.EncodeToString(digest[:]),
	}
	body, err := json.Marshal(pointer)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "apps", "pointers", appID+".json"), body)
}

func writeFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
