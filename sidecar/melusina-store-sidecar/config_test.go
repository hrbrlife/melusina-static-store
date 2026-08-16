package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testStoreAuthority = "11111111111111111111111111111111"

func writeTmpConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "store.config.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfig_ValidAppliesDefaults(t *testing.T) {
	cfg, err := LoadConfig(writeTmpConfig(t, `{"license_nft_mint":"LIC","store_authority":"`+testStoreAuthority+`","domain":"store.example.org"}`))
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
	if cfg.RPCAttempts != defaultRPCAttempts {
		t.Errorf("RPCAttempts default = %d, want %d", cfg.RPCAttempts, defaultRPCAttempts)
	}
}

func TestLoadConfig_NormalizesTrustedRPCEndpoints(t *testing.T) {
	cfg, err := LoadConfig(writeTmpConfig(t, `{
		"license_nft_mint":"LIC",
		"store_authority":"`+testStoreAuthority+`",
		"domain":"store.example.org",
		"rpc_url":" https://primary.example/rpc?api-key=secret ",
		"rpc_fallback_urls":["https://fallback.example/rpc"],
		"rpc_attempts":3
	}`))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.RPCURL != "https://primary.example/rpc?api-key=secret" {
		t.Fatalf("primary RPC URL was not normalized: %q", cfg.RPCURL)
	}
	if len(cfg.RPCFallbackURLs) != 1 || cfg.RPCFallbackURLs[0] != "https://fallback.example/rpc" {
		t.Fatalf("fallback URLs = %#v", cfg.RPCFallbackURLs)
	}
	if cfg.RPCAttempts != 3 {
		t.Fatalf("rpc_attempts = %d, want 3", cfg.RPCAttempts)
	}
}

func TestLoadConfig_RejectsUnsafeOrAmbiguousRPCEndpoints(t *testing.T) {
	base := `"license_nft_mint":"LIC","store_authority":"` + testStoreAuthority + `","domain":"store.example.org"`
	for name, suffix := range map[string]string{
		"fallback_without_primary": `,"rpc_fallback_urls":["https://fallback.example"]`,
		"duplicate":                `,"rpc_url":"https://primary.example","rpc_fallback_urls":["https://primary.example"]`,
		"bad_scheme":               `,"rpc_url":"file:///tmp/not-rpc"`,
		"unbounded_attempts":       `,"rpc_url":"https://primary.example","rpc_attempts":4`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeTmpConfig(t, `{`+base+suffix+`}`)); err == nil {
				t.Fatal("unsafe RPC configuration was accepted")
			}
		})
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

func TestLoadConfig_StoreAuthorityIsOptionalUntilListingProjectionIsConfigured(t *testing.T) {
	cfg, err := LoadConfig(writeTmpConfig(t, `{"license_nft_mint":"LIC","domain":"store.example.org"}`))
	if err != nil {
		t.Fatalf("legacy store without listing projection = %v", err)
	}
	if cfg.StoreAuthority != "" {
		t.Fatalf("legacy store authority = %q, want empty", cfg.StoreAuthority)
	}
	if _, err := LoadConfig(writeTmpConfig(t, `{"license_nft_mint":"LIC","store_authority":"not a pubkey","domain":"store.example.org"}`)); err == nil || !strings.Contains(err.Error(), "store_authority is invalid") {
		t.Fatalf("invalid store authority error = %v", err)
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	if _, err := LoadConfig("/no/such/store.config.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfig_OverridesApplied(t *testing.T) {
	const bsenProgramID = "BSENx6t1GVPzhnnd4yiojxWk7HjKZiiRQEkriHg6Mpix"
	cfg, err := LoadConfig(writeTmpConfig(t, `{"license_nft_mint":"LIC","store_authority":"`+testStoreAuthority+`","program_id":"`+bsenProgramID+`","domain":"s.example.org","store_id":"reseller-store","listen_addr":":9000","dist_dir":"out"}`))
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
	if _, err := LoadConfig(writeTmpConfig(t, `{"license_nft_mint":"LIC","store_authority":"`+testStoreAuthority+`","domain":"store.example.org","program_id":"not a pubkey"}`)); err == nil {
		t.Fatal("expected error for invalid program_id")
	}
}

func TestLoadConfig_RejectsPublicPrivateStage(t *testing.T) {
	root := t.TempDir()
	dist := filepath.Join(root, "public")
	stage := filepath.Join(dist, "private-candidates")
	content := fmt.Sprintf(`{"license_nft_mint":"LIC","store_authority":"%s","domain":"store.example.org","dist_dir":%q,"private_stage_dir":%q}`, testStoreAuthority, dist, stage)
	if _, err := LoadConfig(writeTmpConfig(t, content)); err == nil {
		t.Fatal("expected private_stage_dir nested under dist_dir to fail")
	}
}

func TestLoadConfig_WriteModeRequiresExplicitPersistentRoots(t *testing.T) {
	root := t.TempDir()
	base := map[string]string{
		"private_stage_dir":           filepath.Join(root, "stage"),
		"catalog_generation_root":     filepath.Join(root, "generations"),
		"catalog_migration_state_dir": filepath.Join(root, "migrations"),
	}
	for _, missing := range []string{"private_stage_dir", "catalog_generation_root", "catalog_migration_state_dir"} {
		t.Run(missing, func(t *testing.T) {
			fields := ""
			for name, value := range base {
				if name != missing {
					fields += fmt.Sprintf(",%q:%q", name, value)
				}
			}
			content := fmt.Sprintf(`{"license_nft_mint":"LIC","store_authority":"%s","domain":"store.example.org","boot_identity":{"shards_dir":%q}%s}`, testStoreAuthority, filepath.Join(root, "shards"), fields)
			_, err := LoadConfig(writeTmpConfig(t, content))
			if err == nil || !strings.Contains(err.Error(), missing+" is required") {
				t.Fatalf("error = %v, want required %s", err, missing)
			}
		})
	}
}

func TestLoadConfig_WriteModeAcceptsExplicitDisjointRoots(t *testing.T) {
	root := t.TempDir()
	content := fmt.Sprintf(`{
		"license_nft_mint":"LIC",
		"store_authority":"%s",
		"domain":"store.example.org",
		"dist_dir":%q,
		"private_stage_dir":%q,
		"catalog_generation_root":%q,
		"catalog_migration_state_dir":%q,
		"boot_identity":{"shards_dir":%q}
	}`, testStoreAuthority, filepath.Join(root, "dist"), filepath.Join(root, "stage"), filepath.Join(root, "generations"), filepath.Join(root, "migrations"), filepath.Join(root, "shards"))
	cfg, err := LoadConfig(writeTmpConfig(t, content))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CatalogGenerationRoot != filepath.Join(root, "generations") || cfg.CatalogMigrationStateDir != filepath.Join(root, "migrations") {
		t.Fatalf("explicit catalog roots not preserved: %+v", cfg)
	}
}

func TestLoadConfig_RejectsLexicallyOverlappingCatalogRoots(t *testing.T) {
	root := t.TempDir()
	tests := []struct {
		name       string
		stage      string
		generation string
		migration  string
	}{
		{
			name:       "generation under dist",
			stage:      filepath.Join(root, "stage"),
			generation: filepath.Join(root, "dist", "generations"),
			migration:  filepath.Join(root, "migrations"),
		},
		{
			name:       "stage contains migration",
			stage:      filepath.Join(root, "private"),
			generation: filepath.Join(root, "generations"),
			migration:  filepath.Join(root, "private", "migrations"),
		},
		{
			name:       "generation equals migration",
			stage:      filepath.Join(root, "stage"),
			generation: filepath.Join(root, "state"),
			migration:  filepath.Join(root, "state"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := fmt.Sprintf(`{
				"license_nft_mint":"LIC",
				"store_authority":"%s",
				"domain":"store.example.org",
				"dist_dir":%q,
				"private_stage_dir":%q,
				"catalog_generation_root":%q,
				"catalog_migration_state_dir":%q,
				"boot_identity":{"shards_dir":%q}
			}`, testStoreAuthority, filepath.Join(root, "dist"), tt.stage, tt.generation, tt.migration, filepath.Join(root, "shards"))
			_, err := LoadConfig(writeTmpConfig(t, content))
			if err == nil || !strings.Contains(err.Error(), "must be lexically disjoint") {
				t.Fatalf("error = %v, want lexical-disjoint refusal", err)
			}
		})
	}
}
