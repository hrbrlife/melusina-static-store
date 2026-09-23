package main

import (
	"strings"
	"testing"
)

func TestLoadConfigRequiresStoreLicenseMint(t *testing.T) {
	setNewEstateReleaseEnv(t)
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
	setNewEstateReleaseEnv(t)
	for _, key := range []string{"MEL_RELEASE_STORE_PUBKEY", "MEL_RELEASE_STORE_LICENSE_MINT", "MEL_RELEASE_PUBLISHER_KEY"} {
		t.Setenv(key, "")
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

func TestLoadConfigHonorsBoundedOperationTimeout(t *testing.T) {
	setNewEstateReleaseEnv(t)
	t.Setenv("MEL_RELEASE_OP_TIMEOUT_SECS", "1800")
	config, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() with long operation timeout: %v", err)
	}
	if config.OpTimeoutSecs != 1800 {
		t.Fatalf("OpTimeoutSecs = %d, want 1800", config.OpTimeoutSecs)
	}

	for _, raw := range []string{"479", "1801", "not-a-number"} {
		t.Setenv("MEL_RELEASE_OP_TIMEOUT_SECS", raw)
		if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "MEL_RELEASE_OP_TIMEOUT_SECS") {
			t.Fatalf("loadConfig() timeout %q error = %v, want bounded timeout error", raw, err)
		}
	}
}

func TestExecProviderForwardsStoreLicenseMint(t *testing.T) {
	provider := newExecProvider(Config{StoreLicenseMint: "store-license-mint"})
	if provider.env["MEL_RELEASE_STORE_LICENSE_MINT"] != "store-license-mint" {
		t.Fatalf("provider Store license mint = %q", provider.env["MEL_RELEASE_STORE_LICENSE_MINT"])
	}
}
