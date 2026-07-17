package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func validConfigMap(t *testing.T, stateDir string) map[string]any {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"schema":                 controllerConfigSchema,
		"autoApply":              false,
		"pollIntervalSeconds":    300,
		"deepStableSeconds":      120,
		"promoteDeadlineSeconds": 600,
		"operatorPubkey":         primitives.EncodeBase58(pub),
		"expectedStoreId":        "melusina-os-root-store",
		"bundleOrigin":           "https://bazaar.melusina-os.org",
		"storeGenerationUrl":     "https://bazaar.melusina-os.org/update/generation.json",
		"componentRegistryPath":  filepath.Join(stateDir, "registry.json"),
		"programId":              "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
		"masterNftMint":          "MasterMint1111111111111111111111111111111111",
		"licenseNftMint":         "LicenseMint111111111111111111111111111111111",
		"solanaRpcUrl":           "https://devnet.example/rpc",
		"stateDir":               stateDir,
		"receiptDir":             filepath.Join(stateDir, "receipts"),
	}
}

func writeConfigFile(t *testing.T, dir string, body []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadControllerConfigAcceptsValid(t *testing.T) {
	dir := t.TempDir()
	body, err := json.Marshal(validConfigMap(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, dir, body, 0o600)
	cfg, err := loadControllerConfigOwned(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.ExpectedStoreID != "melusina-os-root-store" || cfg.PollIntervalSeconds != 300 {
		t.Fatalf("config did not round-trip: %+v", cfg)
	}
	if _, err := cfg.operatorKey(); err != nil {
		t.Fatalf("operator key did not decode: %v", err)
	}
}

func TestLoadControllerConfigRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	m := validConfigMap(t, dir)
	m["bogusField"] = "surprise"
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, dir, body, 0o600)
	if _, err := loadControllerConfigOwned(path, uint32(os.Getuid())); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field not rejected: %v", err)
	}
}

func TestLoadControllerConfigRejectsBudgetOver900(t *testing.T) {
	dir := t.TempDir()
	m := validConfigMap(t, dir)
	m["promoteDeadlineSeconds"] = 601 // 300 + 601 = 901 > 900
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, dir, body, 0o600)
	if _, err := loadControllerConfigOwned(path, uint32(os.Getuid())); err == nil ||
		!strings.Contains(err.Error(), "timing policy") {
		t.Fatalf("discovery+promote budget over 900 not rejected: %v", err)
	}
}

func TestLoadControllerConfigRejectsDeepStableBelowFloor(t *testing.T) {
	dir := t.TempDir()
	m := validConfigMap(t, dir)
	m["deepStableSeconds"] = 119 // below the 120s controller floor
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, dir, body, 0o600)
	if _, err := loadControllerConfigOwned(path, uint32(os.Getuid())); err == nil ||
		!strings.Contains(err.Error(), "timing policy") {
		t.Fatalf("deep-stable below floor not rejected: %v", err)
	}
}

func TestLoadControllerConfigRejectsWorldWritable(t *testing.T) {
	dir := t.TempDir()
	body, err := json.Marshal(validConfigMap(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, dir, body, 0o666)
	if _, err := loadControllerConfigOwned(path, uint32(os.Getuid())); err == nil ||
		!strings.Contains(err.Error(), "too permissive") {
		t.Fatalf("world-writable config not rejected: %v", err)
	}
}

func TestLoadControllerConfigRejectsDuplicateKey(t *testing.T) {
	dir := t.TempDir()
	body, err := json.Marshal(validConfigMap(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	// Inject a duplicate top-level key by reopening the object.
	dup := strings.Replace(string(body), "{", `{"channel":"a","channel":"b",`, 1)
	path := writeConfigFile(t, dir, []byte(dup), 0o600)
	if _, err := loadControllerConfigOwned(path, uint32(os.Getuid())); err == nil ||
		!strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate key not rejected: %v", err)
	}
}

func TestLoadControllerConfigRejectsReceiptDirMismatch(t *testing.T) {
	dir := t.TempDir()
	m := validConfigMap(t, dir)
	m["receiptDir"] = filepath.Join(dir, "elsewhere")
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfigFile(t, dir, body, 0o600)
	if _, err := loadControllerConfigOwned(path, uint32(os.Getuid())); err == nil ||
		!strings.Contains(err.Error(), "receiptDir must be") {
		t.Fatalf("receiptDir divergence not rejected: %v", err)
	}
}
