package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is the per-operator configuration for the store sidecar.
//
// ONE reusable artifact: melusina-os.org and every reseller run the identical
// binary, differing only by this config + their three attest shards. "Root vs
// reseller" is an on-chain fact (StoreOperatorAuthorization.is_root), never a
// code branch — see FEDERATED-STORE-MVP.md §3.
//
// Scaffold note: the loader currently reads JSON (stdlib, builds offline). The
// documented operator format is store.yaml (see store.yaml.example); YAML
// loading is wired together with the melusina-attest module replaces in the
// gated /publish phase (post-C1).
type TLSConfig struct {
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

type Policy struct {
	// AllowedTiers: capability tiers this store may list (regular/admin/...).
	AllowedTiers []string `json:"allowed_tiers"`
	// RequireScanReport: reject publishes lacking an attested clean scan report.
	RequireScanReport bool `json:"require_scan_report"`
	// AcceptPublishers: base58 ReleaseEntry PDAs / publisher identities trusted to submit.
	AcceptPublishers []string `json:"accept_publishers"`
}

type Config struct {
	LicenseNFTMint  string    `json:"license_nft_mint"`
	Domain          string    `json:"domain"` // bare host; store_domain_hash = sha256(ascii_lower(strip_trailing_dot(domain)))
	StoreID         string    `json:"store_id"`
	ResellerNFTMint string    `json:"reseller_nft_mint,omitempty"`
	RootStoreURL    string    `json:"root_store_url"`
	Policy          Policy    `json:"policy"`
	RPCURL          string    `json:"rpc_url"`
	ListenAddr      string    `json:"listen_addr"`
	DistDir         string    `json:"dist_dir"`
	TLS             TLSConfig `json:"tls"`
}

func defaultConfig() Config {
	return Config{
		StoreID:      "melusina-store",
		RootStoreURL: "https://melusina-os.org",
		ListenAddr:   ":8443",
		DistDir:      "dist-publish",
	}
}

// LoadConfig reads and validates the operator config.
func LoadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.Domain == "" {
		return cfg, fmt.Errorf("config: domain is required")
	}
	if cfg.LicenseNFTMint == "" {
		return cfg, fmt.Errorf("config: license_nft_mint is required")
	}
	if cfg.DistDir == "" {
		cfg.DistDir = "dist-publish"
	}
	return cfg, nil
}
