package main

import (
	"strings"
	"testing"
)

func TestLoadConfigRequiresStoreLicenseMint(t *testing.T) {
	for key, value := range map[string]string{
		"MEL_RELEASE_CONFIG":          "/tmp/release-family.yaml",
		"MEL_RELEASE_SIGNER_PROVIDER": "provider",
		"MEL_RELEASE_STORE_URL":       "https://bazaar.example.test",
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

func TestExecProviderForwardsStoreLicenseMint(t *testing.T) {
	provider := newExecProvider(Config{StoreLicenseMint: "store-license-mint"})
	if provider.env["MEL_RELEASE_STORE_LICENSE_MINT"] != "store-license-mint" {
		t.Fatalf("provider Store license mint = %q", provider.env["MEL_RELEASE_STORE_LICENSE_MINT"])
	}
}
