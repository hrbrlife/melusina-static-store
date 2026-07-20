package main

import "testing"

func TestLegacyStaticCatalogFallbackIsOptIn(t *testing.T) {
	cfg := Config{}
	if cfg.LegacyStaticCatalogFallback {
		t.Fatal("legacy static catalog fallback must default to disabled")
	}

	cfg.LegacyStaticCatalogFallback = true
	if !cfg.LegacyStaticCatalogFallback {
		t.Fatal("explicit recovery flag was not retained")
	}

	// An empty runtime is the fail-closed representation used by main's
	// recovery branch: app handlers require appNonces before they can claim a
	// replay token or mutate a catalog generation.
	var runtime catalogRuntime
	if runtime.appNonces != nil || runtime.catalogGenerations.Root != "" {
		t.Fatal("fallback runtime must not enable catalog mutation")
	}
}
