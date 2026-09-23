package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/pda"
)

const testStoreAuthority = "11111111111111111111111111111111"

func writeTmpConfig(t *testing.T, content string) string {
	t.Helper()
	trimmed := strings.TrimSpace(content)
	if !strings.HasSuffix(trimmed, "}") {
		t.Fatalf("test config is not a JSON object")
	}
	// Every existing config-focused test gets a valid shared-authority tuple
	// and, unless it names its own, the fixture registry program, so it can
	// continue to isolate the validation rule it names. Dedicated tests below
	// cover both required fields.
	content = strings.TrimSuffix(trimmed, "}")
	if !strings.Contains(content, `"program_id"`) {
		content += `,"program_id":"` + testLicenseProgramID + `"`
	}
	content += `,"release_squads_authority":{"multisig":"` + testStoreAuthority + `","vault":"` + testStoreAuthority + `","program_id":"` + testStoreAuthority + `","threshold":3,"member_count":4}}`
	return writeRawTmpConfig(t, content)
}

func writeRawTmpConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "store.config.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfig_RequiresSharedReleaseSquadsAuthority(t *testing.T) {
	_, err := LoadConfig(writeRawTmpConfig(t, `{"license_nft_mint":"LIC","program_id":"`+testLicenseProgramID+`","domain":"store.example.org"}`))
	if err == nil || !strings.Contains(err.Error(), "release_squads_authority.multisig") {
		t.Fatalf("missing shared authority error = %v", err)
	}
}

func TestLoadConfig_DefaultBazaarPinsOneSquadsAuthority(t *testing.T) {
	base := `{"license_nft_mint":"LIC","program_id":"` + testLicenseProgramID + `","domain":"bazaar.melusina-os.org","release_squads_authority":{"multisig":"` + defaultBazaarSquadsMultisig + `","vault":"` + defaultBazaarSquadsVault + `","program_id":"` + defaultBazaarSquadsProgramID + `","threshold":3,"member_count":4}}`
	if _, err := LoadConfig(writeRawTmpConfig(t, base)); err != nil {
		t.Fatalf("fixed default Bazaar authority rejected: %v", err)
	}
	wrongVault := strings.Replace(base, defaultBazaarSquadsVault, testStoreAuthority, 1)
	if _, err := LoadConfig(writeRawTmpConfig(t, wrongVault)); err == nil || !strings.Contains(err.Error(), "one fixed Bazaar Squads authority") {
		t.Fatalf("default Bazaar accepted a different shared authority: %v", err)
	}
}

func TestLoadConfig_ValidAppliesDefaults(t *testing.T) {
	cfg, err := LoadConfig(writeTmpConfig(t, `{"license_nft_mint":"LIC","store_authority":"`+testStoreAuthority+`","domain":"store.example.org"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.StoreID != "melusina-store" {
		t.Errorf("StoreID default = %q, want melusina-store", cfg.StoreID)
	}
	if cfg.RootStoreURL != "" {
		t.Errorf("RootStoreURL has a compiled default %q; it must come from config", cfg.RootStoreURL)
	}
	if cfg.ProgramID != testLicenseProgramID {
		t.Errorf("ProgramID = %q, want the configured %q", cfg.ProgramID, testLicenseProgramID)
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

func TestLoadConfig_RecordsExplicitStoreLinkAppPublishCutover(t *testing.T) {
	controlDir := t.TempDir()
	cfg, err := LoadConfig(writeTmpConfig(t, `{"license_nft_mint":"LIC","store_authority":"`+testStoreAuthority+`","domain":"store.example.org","listing_signer_socket":"/run/melusina/listing-signer.sock","policy":{"require_pearl_control_for_app_publish":true},"store_link_control_mtls":{"listen_addr":"127.0.0.1:9443","cert_path":"`+controlDir+`/server.crt","key_path":"`+controlDir+`/server.key","client_ca_path":"`+controlDir+`/ca.crt","store_link_client_cert_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Policy.RequirePearlControlForAppPublish {
		t.Fatal("explicit direct app-publish retirement was lost during config load")
	}
}

func TestLoadConfig_RequiresCompletePrivateStoreLinkControlListenerAtCutover(t *testing.T) {
	base := `{"license_nft_mint":"LIC","store_authority":"` + testStoreAuthority + `","domain":"store.example.org","policy":{"require_pearl_control_for_app_publish":true}`
	if _, err := LoadConfig(writeTmpConfig(t, base+`}`)); err == nil || !strings.Contains(err.Error(), "store_link_control_mtls is required") {
		t.Fatalf("cutover without private Store Link listener = %v", err)
	}
	if _, err := LoadConfig(writeTmpConfig(t, base+`,"store_link_control_mtls":{"listen_addr":"127.0.0.1:9443"}}`)); err == nil || !strings.Contains(err.Error(), "store_link_control_mtls.") {
		t.Fatalf("partial private Store Link listener = %v", err)
	}
}

func TestLoadConfig_RequiresConstrainedListingSignerForPearlControl(t *testing.T) {
	controlDir := t.TempDir()
	base := `{"license_nft_mint":"LIC","store_authority":"` + testStoreAuthority + `","domain":"store.example.org","policy":{"require_pearl_control_for_app_publish":true},"store_link_control_mtls":{"listen_addr":"127.0.0.1:9443","cert_path":"` + controlDir + `/server.crt","key_path":"` + controlDir + `/server.key","client_ca_path":"` + controlDir + `/ca.crt","store_link_client_cert_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	if _, err := LoadConfig(writeTmpConfig(t, base+`}`)); err == nil || !strings.Contains(err.Error(), "listing_signer_socket is required") {
		t.Fatalf("Pearl-controlled listing enforcement accepted an in-process signer fallback: %v", err)
	}
	cfg, err := LoadConfig(writeTmpConfig(t, base+`,"listing_signer_socket":"/run/melusina/listing-signer.sock"}`))
	if err != nil {
		t.Fatalf("Pearl-controlled Store rejected its constrained signer: %v", err)
	}
	if cfg.ListingSignerSocket != "/run/melusina/listing-signer.sock" {
		t.Fatalf("listing signer socket = %q", cfg.ListingSignerSocket)
	}
}

func TestLoadConfig_ListingSignerSocketMustBeAbsolute(t *testing.T) {
	base := `"license_nft_mint":"LIC","store_authority":"` + testStoreAuthority + `","domain":"store.example.org"`
	cfg, err := LoadConfig(writeTmpConfig(t, `{`+base+`,"listing_signer_socket":"/run/melusina/listing-signer.sock"}`))
	if err != nil {
		t.Fatalf("absolute listing signer socket: %v", err)
	}
	if cfg.ListingSignerSocket != "/run/melusina/listing-signer.sock" {
		t.Fatalf("listing signer socket = %q", cfg.ListingSignerSocket)
	}
	for _, socket := range []string{"listing-signer.sock", "/"} {
		if _, err := LoadConfig(writeTmpConfig(t, `{`+base+`,"listing_signer_socket":"`+socket+`"}`)); err == nil || !strings.Contains(err.Error(), "listing_signer_socket") {
			t.Fatalf("unsafe listing signer socket %q was accepted: %v", socket, err)
		}
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

func TestLoadConfig_EnrolledStoreRequiresAnExplicitRPCTrustRoot(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "estate-enrollment.json")
	base := `{"license_nft_mint":"LIC","store_authority":"` + testStoreAuthority + `","domain":"store.example.org","estate_enrollment_state_path":"` + statePath + `"}`
	if _, err := LoadConfig(writeTmpConfig(t, base)); err == nil || !strings.Contains(err.Error(), "rpc_url is required when estate_enrollment_state_path is configured") {
		t.Fatalf("enrolled Store without explicit RPC trust root = %v", err)
	}
	withRPC := strings.TrimSuffix(base, "}") + `,"rpc_url":"https://primary.example/rpc"}`
	if _, err := LoadConfig(writeTmpConfig(t, withRPC)); err != nil {
		t.Fatalf("enrolled Store with explicit RPC trust root: %v", err)
	}
}

func profileEnrolledStoreConfig(t *testing.T, statePath string) map[string]any {
	t.Helper()
	profile := storeEstateProfileFixture(t)
	declaration := storeEstateDeclarationForProfile(t, profile)
	return map[string]any{
		"license_nft_mint":             declaration.LicenseNFTMint,
		"store_authority":              declaration.StoreAuthority,
		"program_id":                   declaration.ProgramID,
		"domain":                       declaration.Domain,
		"store_id":                     declaration.StoreID,
		"reseller_nft_mint":            declaration.ResellerNFTMint,
		"release_master_nft_mint":      declaration.ReleaseMasterNFTMint,
		"estate_enrollment_state_path": statePath,
		"rpc_url":                      "https://primary.example/rpc",
		"release_squads_authority": map[string]any{
			"multisig":     declaration.ReleaseSquadsAuthority.Multisig,
			"vault":        declaration.ReleaseSquadsAuthority.Vault,
			"program_id":   declaration.ReleaseSquadsAuthority.ProgramID,
			"threshold":    declaration.ReleaseSquadsAuthority.Threshold,
			"member_count": declaration.ReleaseSquadsAuthority.MemberCount,
		},
	}
}

func writeJSONConfig(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return writeRawTmpConfig(t, string(raw))
}

func TestLoadConfig_ProfileEnrolledStoreAcceptsItsExplicitProfileQuorum(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "estate-enrollment.json")
	cfg, err := LoadConfig(writeJSONConfig(t, profileEnrolledStoreConfig(t, statePath)))
	if err != nil {
		t.Fatalf("LoadConfig refused the signed-profile 2-of-3 role: %v", err)
	}
	if cfg.ReleaseSquadsAuthority.Threshold != 2 || cfg.ReleaseSquadsAuthority.MemberCount != 3 {
		t.Fatalf("profile quorum = %d/%d, want 2/3", cfg.ReleaseSquadsAuthority.Threshold, cfg.ReleaseSquadsAuthority.MemberCount)
	}
	authority, err := cfg.sharedSquadsAuthority()
	if err != nil {
		t.Fatalf("serve-time authority rejected the accepted profile quorum: %v", err)
	}
	if authority.Threshold != 2 || authority.MemberCount != 3 {
		t.Fatalf("serve-time profile quorum = %d/%d, want 2/3", authority.Threshold, authority.MemberCount)
	}
}

func TestLoadConfig_LegacyStoreRetainsFixedReleaseQuorum(t *testing.T) {
	config := profileEnrolledStoreConfig(t, "")
	delete(config, "estate_enrollment_state_path")
	delete(config, "rpc_url")
	_, err := LoadConfig(writeJSONConfig(t, config))
	if err == nil || !strings.Contains(err.Error(), "release_squads_authority quorum must be 3/4") {
		t.Fatalf("unenrolled Store accepted profile-specific 2/3 quorum: %v", err)
	}
}

func TestLoadConfig_ProfileEnrolledStoreRefusesImplicitOrInvalidQuorum(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"missing_threshold": func(config map[string]any) {
			delete(config["release_squads_authority"].(map[string]any), "threshold")
		},
		"missing_member_count": func(config map[string]any) {
			delete(config["release_squads_authority"].(map[string]any), "member_count")
		},
		"one_of_three": func(config map[string]any) {
			config["release_squads_authority"].(map[string]any)["threshold"] = 1
		},
		"threshold_exceeds_members": func(config map[string]any) {
			authority := config["release_squads_authority"].(map[string]any)
			authority["threshold"] = 4
			authority["member_count"] = 3
		},
	} {
		want := map[string]string{
			"missing_threshold":         "threshold and member_count are required",
			"missing_member_count":      "threshold and member_count are required",
			"one_of_three":              "threshold must be at least 2",
			"threshold_exceeds_members": "threshold must not exceed member_count",
		}[name]
		t.Run(name, func(t *testing.T) {
			config := profileEnrolledStoreConfig(t, filepath.Join(t.TempDir(), "estate-enrollment.json"))
			mutate(config)
			_, err := LoadConfig(writeJSONConfig(t, config))
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("invalid enrolled quorum accepted or misidentified: %v", err)
			}
		})
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

// The license-registry program is an estate fact. A config that does not name
// one is refused by name; nothing compiled into the Store stands in for it.
func TestLoadConfig_RequiresExplicitLicenseRegistryProgramID(t *testing.T) {
	// The profile-enrolled shape loads in both build flavors, so the same
	// refusal and the same positive control run in the estate-bootstrap build
	// that ships in the Store component.
	for name, test := range map[string]struct {
		mutate func(map[string]any)
		want   string
	}{
		"absent":         {func(config map[string]any) { delete(config, "program_id") }, "config: program_id is required"},
		"empty":          {func(config map[string]any) { config["program_id"] = "" }, "config: program_id is required"},
		"whitespace":     {func(config map[string]any) { config["program_id"] = "  " }, "config: program_id is required"},
		"system_program": {func(config map[string]any) { config["program_id"] = "11111111111111111111111111111111" }, "config: program_id must not be the System Program"},
	} {
		t.Run(name, func(t *testing.T) {
			config := profileEnrolledStoreConfig(t, filepath.Join(t.TempDir(), "estate-enrollment.json"))
			test.mutate(config)
			_, err := LoadConfig(writeJSONConfig(t, config))
			if err == nil || err.Error() != test.want {
				t.Fatalf("LoadConfig error = %v, want %q", err, test.want)
			}
		})
	}
	config := profileEnrolledStoreConfig(t, filepath.Join(t.TempDir(), "estate-enrollment.json"))
	configured := config["program_id"].(string)
	config["program_id"] = " " + configured + " "
	cfg, err := LoadConfig(writeJSONConfig(t, config))
	if err != nil {
		t.Fatalf("explicit program_id refused: %v", err)
	}
	if cfg.ProgramID != configured {
		t.Fatalf("ProgramID = %q, want the configured %q", cfg.ProgramID, configured)
	}
}

// Every entry point pins the registry from validated config. Until then the
// process holds no registry at all, and the accessor refuses rather than
// derive a PDA under the System Program.
func TestLicenseRegistryProgramIDIsOnlyEverTheConfiguredPin(t *testing.T) {
	saved := programID
	t.Cleanup(func() { programID = saved })

	programID = pda.Pubkey{}
	func() {
		defer func() {
			recovered := recover()
			if recovered == nil || !strings.Contains(fmt.Sprint(recovered), "program_id read before it was pinned from config") {
				t.Fatalf("unpinned registry read = %v, want a named refusal", recovered)
			}
		}()
		_ = licenseRegistryProgramID()
		t.Fatal("unpinned registry was readable")
	}()

	for _, raw := range []string{"", "  ", "11111111111111111111111111111111", "not a pubkey"} {
		if err := setProgramIDFromConfig(raw); err == nil {
			t.Fatalf("setProgramIDFromConfig(%q) pinned a registry", raw)
		}
		if programID != (pda.Pubkey{}) {
			t.Fatalf("refused pin %q still changed the registry to %s", raw, programID.Base58())
		}
	}
	configured := randPubkeyB58(t)
	if err := setProgramIDFromConfig(" " + configured + " "); err != nil {
		t.Fatalf("pin configured registry: %v", err)
	}
	if got := licenseRegistryProgramID().Base58(); got != configured {
		t.Fatalf("pinned registry = %s, want %s", got, configured)
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
