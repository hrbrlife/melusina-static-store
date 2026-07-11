package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeTmpConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "store.config.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfig_ValidAppliesDefaults(t *testing.T) {
	cfg, err := LoadConfig(writeTmpConfig(t, `{"license_nft_mint":"LIC","domain":"store.example.org"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.StoreID != "melusina-store" {
		t.Errorf("StoreID default = %q, want melusina-store", cfg.StoreID)
	}
	if cfg.RootStoreURL != "https://melusina-os.org" {
		t.Errorf("RootStoreURL default = %q", cfg.RootStoreURL)
	}
	if cfg.ProgramID != defaultLicenseProgramID {
		t.Errorf("ProgramID default = %q", cfg.ProgramID)
	}
	if cfg.ListenAddr != ":8443" {
		t.Errorf("ListenAddr default = %q", cfg.ListenAddr)
	}
	if cfg.DistDir != "dist-publish" {
		t.Errorf("DistDir default = %q", cfg.DistDir)
	}
	if cfg.PrivateStageDir != filepath.Join(cfg.CatalogRepoRoot, ".melusina-private-stage") {
		t.Errorf("PrivateStageDir default = %q", cfg.PrivateStageDir)
	}
}

func TestLoadConfig_RequiresDomain(t *testing.T) {
	if _, err := LoadConfig(writeTmpConfig(t, `{"license_nft_mint":"LIC"}`)); err == nil {
		t.Fatal("expected error for missing domain")
	}
}

func TestLoadConfig_RequiresLicense(t *testing.T) {
	if _, err := LoadConfig(writeTmpConfig(t, `{"domain":"store.example.org"}`)); err == nil {
		t.Fatal("expected error for missing license_nft_mint")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	if _, err := LoadConfig("/no/such/store.config.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfig_OverridesApplied(t *testing.T) {
	const bsenProgramID = "BSENx6t1GVPzhnnd4yiojxWk7HjKZiiRQEkriHg6Mpix"
	cfg, err := LoadConfig(writeTmpConfig(t, `{"license_nft_mint":"LIC","program_id":"`+bsenProgramID+`","domain":"s.example.org","store_id":"reseller-store","listen_addr":":9000","dist_dir":"out"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StoreID != "reseller-store" || cfg.ListenAddr != ":9000" || cfg.DistDir != "out" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if cfg.ProgramID != bsenProgramID {
		t.Errorf("ProgramID override = %q", cfg.ProgramID)
	}
}

func TestLoadConfig_RejectsInvalidProgramID(t *testing.T) {
	if _, err := LoadConfig(writeTmpConfig(t, `{"license_nft_mint":"LIC","domain":"store.example.org","program_id":"not a pubkey"}`)); err == nil {
		t.Fatal("expected error for invalid program_id")
	}
}

func TestLoadConfig_RejectsPublicPrivateStage(t *testing.T) {
	root := t.TempDir()
	dist := filepath.Join(root, "public")
	stage := filepath.Join(dist, "private-candidates")
	content := fmt.Sprintf(`{"license_nft_mint":"LIC","domain":"store.example.org","dist_dir":%q,"private_stage_dir":%q}`, dist, stage)
	if _, err := LoadConfig(writeTmpConfig(t, content)); err == nil {
		t.Fatal("expected private_stage_dir nested under dist_dir to fail")
	}
}
