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
	LicenseNFTMint  string `json:"license_nft_mint"`
	Domain          string `json:"domain"` // bare host; store_domain_hash = sha256(ascii_lower(strip_trailing_dot(domain)))
	StoreID         string `json:"store_id"`
	ResellerNFTMint string `json:"reseller_nft_mint,omitempty"`
	RootStoreURL    string `json:"root_store_url"`
	Policy          Policy `json:"policy"`
	RPCURL          string `json:"rpc_url"`
	ListenAddr      string `json:"listen_addr"`
	DistDir         string `json:"dist_dir"`
	// CatalogRepoRoot is the static_store working tree from which the in-process
	// catalog assembler (build-store.sh) runs after a publish passes the on-chain
	// gate. build-store.sh is a CONVENIENCE assembler, NOT the trust authority —
	// the Go verify (VerifyPublish) is the gate. Defaults to ".".
	CatalogRepoRoot string    `json:"catalog_repo_root"`
	TLS             TLSConfig `json:"tls"`

	// ServeVerifyTTLSeconds bounds how long a verified serve-time verdict
	// (appHash -> Active on-chain ReleaseEntry) is cached before the chain is
	// re-checked on an SPK GET (serve-gate, B1-01). Within the window the chain
	// RPC is skipped; a REVOKED entry therefore keeps serving for at most this
	// long — the documented revoke-visibility window. 0/unset => 60s default;
	// negative => disable the cache (re-verify on every GET).
	ServeVerifyTTLSeconds int `json:"serve_verify_ttl_seconds"`

	// Mirror is the reseller-only ROOT-MIRROR worker config (FEDERATED-STORE-MVP
	// §C2.6). A reseller sidecar serves the base Melusina installer + basic
	// (Foundation) apps by MIRRORING melusina-os.org (the root) — it NEVER
	// originates them. The root operator (StoreOperatorAuthorization.is_root) does
	// NOT mirror; the worker self-disables when the on-chain authz says is_root.
	Mirror MirrorConfig `json:"mirror"`
}

// MirrorConfig parameterizes the reseller ROOT-MIRROR worker (§C2.6). All fields
// are reseller-only: the worker is a no-op on a root operator.
type MirrorConfig struct {
	// Enabled turns the worker on. A reseller config sets this true; the root
	// leaves it false. Even when true, the worker self-disables if the on-chain
	// StoreOperatorAuthorization for this store reports is_root.
	Enabled bool `json:"enabled"`
	// RootOperatorPubkey is the base58 Ed25519 pubkey of the ROOT operator's
	// trust-bundle signing identity. The worker verifies the root's
	// /.well-known/melusina/trust-bundle.json signature against THIS key; a
	// bundle that does not verify is rejected (fail-closed). Required when Enabled.
	RootOperatorPubkey string `json:"root_operator_pubkey"`
	// RootMasterNftMint is the base58 Master NFT mint the root's InstallerRelease
	// PDA is derived under (seeds ["installer_release", master_nft_mint,
	// installer_hash]). Required when Enabled.
	RootMasterNftMint string `json:"root_master_nft_mint"`
	// BaseInstallerHash is the lowercase-hex sha256 of the base Melusina installer
	// binary the root pins. The worker re-derives InstallerReleaseEntry from
	// RootMasterNftMint + this hash and asserts it is Active before re-serving the
	// base binary. Required when Enabled.
	BaseInstallerHash string `json:"base_installer_hash"`
	// IntervalSeconds is the mirror poll cadence. <=0 falls back to 300s (5 min).
	IntervalSeconds int `json:"interval_seconds"`
}

func defaultConfig() Config {
	return Config{
		StoreID:         "melusina-store",
		RootStoreURL:    "https://melusina-os.org",
		ListenAddr:      ":8443",
		DistDir:         "dist-publish",
		CatalogRepoRoot: ".",
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
	if cfg.CatalogRepoRoot == "" {
		cfg.CatalogRepoRoot = "."
	}
	return cfg, nil
}
