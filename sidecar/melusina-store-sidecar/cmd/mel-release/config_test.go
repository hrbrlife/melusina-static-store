package main

import (
	"strings"
	"testing"
)

func setMinimumReleaseConfigEnv(t *testing.T, storeURL string) {
	t.Helper()
	t.Setenv("MEL_RELEASE_CONFIG", "/tmp/release-family.yaml")
	t.Setenv("MEL_RELEASE_SIGNER_PROVIDER", "/tmp/provider")
	t.Setenv("MEL_RELEASE_STORE_URL", storeURL)
	t.Setenv("MEL_RELEASE_STORE_PUBKEY", "/tmp/store-public.json")
	t.Setenv("MEL_RELEASE_PUBLISHER_KEY", "/tmp/publisher.json")
	t.Setenv("MEL_RELEASE_STATE_DIR", t.TempDir())
	t.Setenv("MEL_RELEASE_STORE_LICENSE_MINT", "")
}

func TestLoadConfigBindsPublicBazaarToCanonicalLicenseMint(t *testing.T) {
	setMinimumReleaseConfigEnv(t, publicBazaarOrigin)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StoreLicenseMint != publicBazaarLicenseMint {
		t.Fatalf("public Bazaar license mint = %q", cfg.StoreLicenseMint)
	}
	provider := newExecProvider(cfg)
	if provider.env["MEL_RELEASE_STORE_LICENSE_MINT"] != publicBazaarLicenseMint {
		t.Fatal("canonical license mint was not passed explicitly to the signer provider")
	}
}

func TestLoadConfigRejectsStalePublicBazaarLicenseMint(t *testing.T) {
	setMinimumReleaseConfigEnv(t, publicBazaarOrigin)
	t.Setenv("MEL_RELEASE_STORE_LICENSE_MINT", "stale-public-mint")
	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "canonical public Bazaar mint") {
		t.Fatalf("stale public Bazaar mint error = %v", err)
	}
}

func TestLoadConfigRequiresExplicitMintForCustomStore(t *testing.T) {
	setMinimumReleaseConfigEnv(t, "https://store.example.test")
	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "MEL_RELEASE_STORE_LICENSE_MINT") {
		t.Fatalf("custom store without explicit license mint error = %v", err)
	}
	t.Setenv("MEL_RELEASE_STORE_LICENSE_MINT", "custom-mint")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StoreLicenseMint != "custom-mint" {
		t.Fatalf("custom license mint = %q", cfg.StoreLicenseMint)
	}
}
