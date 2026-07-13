package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogAssemblerMaterializesVerifiedTriple(t *testing.T) {
	dir := t.TempDir()
	spk := []byte("signed package")
	sum := sha256.Sum256(spk)
	sha := hex.EncodeToString(sum[:])
	appID := "testapp0000000000000000000000000000000000000000000000"
	metadata := []byte(`{"appId":"` + appID + `","packageId":"` + sha[:32] + `","name":"Test","version":"1.2.3"}`)
	release := []byte(`{"appHash":"abc","signedAtUnix":123}`)
	assembler := NewCatalogAssembler("/unused", dir)
	if err := assembler.AssemblePublishedApp(spk, release, metadata); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(dir, "packages", sha[:32]),
		filepath.Join(dir, "signatures", appID, "metadata.json"),
		filepath.Join(dir, "attest", appID, "RELEASE.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("missing materialized path %s: %v", path, err)
		}
	}
	var index struct {
		Apps []map[string]any `json:"apps"`
	}
	body, err := os.ReadFile(filepath.Join(dir, "apps", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Apps) != 1 || index.Apps[0]["appId"] != appID ||
		index.Apps[0]["sha256"] != sha || index.Apps[0]["updatedAt"] != float64(123000) {
		t.Fatalf("unexpected index row: %#v", index.Apps)
	}
}

func TestProjectCatalogIndexRejectsShortPackagePrefix(t *testing.T) {
	root := t.TempDir()
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(root, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	spk := []byte("short-prefix-package")
	sha := sha256.Sum256(spk)
	metadata := []byte(`{"appId":"short-prefix-app","packageId":"` + hex.EncodeToString(sha[:])[:1] + `"}`)
	if _, err := projectCatalogIndex(AppCatalogSnapshot{Root: root}, spk, []byte(`{}`), metadata); err == nil || !strings.Contains(err.Error(), "does not prefix") {
		t.Fatalf("short packageId prefix accepted: %v", err)
	}
}

func TestCatalogAssemblerReplacesOneAppWithoutDroppingOthers(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "apps"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "apps", "index.json"),
		[]byte(`{"apps":[{"appId":"other","name":"Other"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	spk := []byte("new package")
	sum := sha256.Sum256(spk)
	sha := hex.EncodeToString(sum[:])
	metadata := []byte(`{"appId":"newapp00000000000000000000000000000000000000000000000","packageId":"` + sha[:32] + `","name":"New","version":"1"}`)
	if err := NewCatalogAssembler("", dir).AssemblePublishedApp(
		spk, []byte(`{"signedAtUnix":1}`), metadata); err != nil {
		t.Fatal(err)
	}
	var index struct {
		Apps []map[string]any `json:"apps"`
	}
	body, _ := os.ReadFile(filepath.Join(dir, "apps", "index.json"))
	if err := json.Unmarshal(body, &index); err != nil {
		t.Fatal(err)
	}
	if len(index.Apps) != 2 {
		t.Fatalf("existing app dropped: %#v", index.Apps)
	}
}
