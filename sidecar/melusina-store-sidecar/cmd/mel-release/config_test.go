package main

import (
	"strings"
	"testing"
)

func TestLoadConfigRequiresStoreLicenseMint(t *testing.T) {
	for key, value := range map[string]string{
		"MEL_RELEASE_CONFIG":          "/tmp/bazaar-catalog.yaml",
		"MEL_RELEASE_SIGNER_PROVIDER": "provider",
		"MEL_RELEASE_STORE_URL":       defaultBazaarOrigin,
		"MEL_RELEASE_STORE_PUBKEY":    "/tmp/store-pubkey.json",
		"MEL_RELEASE_PUBLISHER_KEY":   "/tmp/publisher.key",
	} {
		t.Setenv(key, value)
	}
	t.Setenv("MEL_RELEASE_STORE_LICENSE_MINT", "")

	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "MEL_RELEASE_STORE_LICENSE_MINT") {
		t.Fatalf("loadConfig() error = %v, want missing Store license mint", err)
	}

	t.Setenv("MEL_RELEASE_STORE_LICENSE_MINT", "store-license-mint")
	config, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() with Store license mint: %v", err)
	}
	if config.StoreLicenseMint != "store-license-mint" {
		t.Fatalf("StoreLicenseMint = %q", config.StoreLicenseMint)
	}
}

func TestLoadPreflightConfigDoesNotRequireOrRetainMutationCredentials(t *testing.T) {
	for key, value := range map[string]string{
		"MEL_RELEASE_CONFIG":             "/tmp/bazaar-catalog.yaml",
		"MEL_RELEASE_SIGNER_PROVIDER":    "provider",
		"MEL_RELEASE_STORE_URL":          defaultBazaarOrigin,
		"MEL_RELEASE_STORE_PUBKEY":       "",
		"MEL_RELEASE_STORE_LICENSE_MINT": "",
		"MEL_RELEASE_PUBLISHER_KEY":      "",
	} {
		t.Setenv(key, value)
	}
	preflight, err := loadPreflightConfig()
	if err != nil {
		t.Fatalf("loadPreflightConfig(): %v", err)
	}
	if preflight.StorePubkey != "" || preflight.StoreLicenseMint != "" || preflight.PublisherKey != "" {
		t.Fatalf("preflight config retained mutation credential paths: %+v", preflight)
	}
	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "MEL_RELEASE_STORE_PUBKEY") {
		t.Fatalf("loadConfig() without mutation credentials error = %v", err)
	}
}

func TestLoadConfigRejectsAlternateStore(t *testing.T) {
	for key, value := range map[string]string{
		"MEL_RELEASE_CONFIG":             "/tmp/bazaar-catalog.yaml",
		"MEL_RELEASE_SIGNER_PROVIDER":    "provider",
		"MEL_RELEASE_STORE_URL":          "https://example.test",
		"MEL_RELEASE_STORE_PUBKEY":       "/tmp/store-pubkey.json",
		"MEL_RELEASE_STORE_LICENSE_MINT": "store-license-mint",
		"MEL_RELEASE_PUBLISHER_KEY":      "/tmp/publisher.key",
	} {
		t.Setenv(key, value)
	}
	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "MEL_RELEASE_STORE_URL must be") {
		t.Fatalf("loadConfig() alternate Store error = %v", err)
	}
}

func TestExecProviderForwardsStoreLicenseMint(t *testing.T) {
	provider := newExecProvider(Config{StoreLicenseMint: "store-license-mint"})
	if provider.env["MEL_RELEASE_STORE_LICENSE_MINT"] != "store-license-mint" {
		t.Fatalf("provider Store license mint = %q", provider.env["MEL_RELEASE_STORE_LICENSE_MINT"])
	}
}

func TestConfigBindsOneCatalogPinnedSquadsAuthority(t *testing.T) {
	authority := SquadsAuthority{
		Multisig:    "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V",
		Vault:       "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3",
		ProgramID:   "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf",
		Threshold:   defaultSquadsThreshold,
		MemberCount: defaultSquadsMemberCount,
	}
	catalog := &Catalog{ReleaseSquadsAuthority: authority}
	var cfg Config
	if err := cfg.bindCatalogSquadsAuthority(catalog); err != nil {
		t.Fatalf("bindCatalogSquadsAuthority: %v", err)
	}
	if cfg.SquadsMultisig != authority.Multisig || cfg.SquadsVault != authority.Vault || cfg.SquadsProgramID != authority.ProgramID || cfg.SquadsThreshold != authority.Threshold || cfg.SquadsMemberCount != authority.MemberCount {
		t.Fatalf("bound authority = %+v, want %+v", cfg, authority)
	}
	if err := (&Config{SquadsVault: authority.Multisig}).bindCatalogSquadsAuthority(catalog); err == nil || !strings.Contains(err.Error(), "cannot override") {
		t.Fatalf("foreign authority override error = %v", err)
	}
}
