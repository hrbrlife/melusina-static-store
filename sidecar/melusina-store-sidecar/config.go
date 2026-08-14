package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	primitives "github.com/melusina-os/melusina-solana-primitives"
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
	// AcceptPublishers: base58 SIGNING PUBKEYS (identity.Public.SignPubkeyB58)
	// this store's policy authorizes to submit — the SOLE signer authority
	// resolveAcceptedPublisherKey pins into envelope.Verify's
	// ExpectedSignerPubkeyB58. A ReleaseEntry PDA does NOT authorize a publish
	// (D-10): a PDA is not decodable as an ed25519 public key, so it can never
	// resolve to a signer key. Empty fails closed on /publish and
	// /publish/installer.
	AcceptPublishers []string `json:"accept_publishers"`
}

type Config struct {
	LicenseNFTMint string `json:"license_nft_mint"`
	// StoreAuthority is the public key that owns this store's exact
	// StoreReleaseListing PDAs. It is deliberately explicit: serve-time must
	// never discover a store by scanning arbitrary listings, because that would
	// allow a different store's projection to authorize this one.
	StoreAuthority  string `json:"store_authority"`
	ProgramID       string `json:"program_id"`
	Domain          string `json:"domain"` // bare host; store_domain_hash = sha256(ascii_lower(strip_trailing_dot(domain)))
	StoreID         string `json:"store_id"`
	ResellerNFTMint string `json:"reseller_nft_mint,omitempty"`
	RootStoreURL    string `json:"root_store_url"`
	// PublicBaseURL is THIS store's own public origin — the absolute
	// https://bazaar.<domain> URL the external host update controller fetches
	// /update/generation.json from and downloads component bundles from. The
	// sidecar listens on an INTERNAL container host (cfg.Domain = store.sidecar.host)
	// behind the bazaar TLS edge, so it cannot derive its public origin from
	// cfg.Domain or by sniffing the request Host (doctrine §2.10: network-facing
	// endpoints are set explicitly in the deployer, sidecars never sniff their
	// environment; signing an attacker-influenced Host into a bundleUrl would also
	// be a signing-oracle footgun). Each component's bundleUrl in the signed
	// desired generation is built from this base. Unset => publishing a generation
	// whose bundles would be advertised on an internal/guessed host fails closed.
	// Example: "https://bazaar.melusina-os.org".
	PublicBaseURL string `json:"public_base_url"`
	// ReleaseMasterNftMint is the Master NFT mint used to derive
	// InstallerReleaseEntry PDAs for whole-file artifacts served under
	// /releases/<class>/<name>. Empty means the /releases serve gate fails closed
	// unless mirror.root_master_nft_mint is set as the legacy/root fallback.
	ReleaseMasterNftMint string `json:"release_master_nft_mint,omitempty"`
	Policy               Policy `json:"policy"`
	RPCURL               string `json:"rpc_url"`
	ListenAddr           string `json:"listen_addr"`
	DistDir              string `json:"dist_dir"`
	// PrivateStageDir is the non-public, content-addressed candidate store used by
	// the two-phase app release path. Candidate bytes land here before any chain
	// mutation and are promoted only after the matching ReleaseEntry is Active.
	// It MUST NOT be equal to, or nested below, DistDir because DistDir is served
	// publicly. A write-capable store MUST set it explicitly. An operator-less,
	// read-only store retains the legacy <catalog_repo_root>/.melusina-private-stage
	// default because it cannot accept or promote candidates.
	PrivateStageDir string `json:"private_stage_dir,omitempty"`
	// CatalogGenerationRoot owns immutable app-catalog generations and the
	// relative "current" symlink. It is never served directly and must be
	// lexically disjoint from DistDir, PrivateStageDir, and
	// CatalogMigrationStateDir. Required for a write-capable store.
	CatalogGenerationRoot string `json:"catalog_generation_root,omitempty"`
	// CatalogMigrationStateDir is the externally initialized migration-state
	// directory. Its existing mode-0600 writer.lock is acquired for the complete
	// lifetime of every write-capable process. Startup never creates this root or
	// the lock. Required for a write-capable store.
	CatalogMigrationStateDir string `json:"catalog_migration_state_dir,omitempty"`
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
	// AppRollbackWindowSeconds is how long the immediately previous Active app
	// release remains eligible for authenticated package serving after catalog
	// promotion. 0/unset defaults to 24h; negative disables previous-release
	// serving. Chain status is still authoritative: a revoked previous release is
	// refused immediately (subject to ServeVerifyTTLSeconds).
	AppRollbackWindowSeconds int `json:"app_rollback_window_seconds"`

	// Mirror is the reseller-only ROOT-MIRROR worker config (FEDERATED-STORE-MVP
	// §C2.6). A reseller sidecar serves the base Melusina installer + basic
	// (Foundation) apps by MIRRORING melusina-os.org (the root) — it NEVER
	// originates them. The root operator (StoreOperatorAuthorization.is_root) does
	// NOT mirror; the worker self-disables when the on-chain authz says is_root.
	Mirror MirrorConfig `json:"mirror"`

	// BootIdentity provisions the gated /publish operator identity (B1-02). When
	// unset, the operator stays nil and /publish fails closed (503) — read+serve
	// are unaffected. When set, the sidecar DERIVES its operator from the three
	// deploy-provisioned attest shards and binds it on-chain before enabling
	// /publish (fail-closed). See README "Boot identity (gated /publish)".
	BootIdentity BootIdentityConfig `json:"boot_identity"`
}

// BootIdentityConfig provisions the gated /publish operator boot-identity
// ceremony (audit 2026-06-17 B1-02). The operator's signing identity (receipt
// signer + envelope destination) is DERIVED from the three deploy-provisioned
// attest shards and then bound, fail-closed, to an on-chain SidecarIdentityEntry
// whose signing_pubkey/encryption_pubkey/domain_hash/tls_cert_fingerprint/binary_hash
// must all match. A misprovisioned or mismatched identity refuses to boot (Inv 5);
// a deliberately-omitted ShardsDir leaves the operator nil → /publish 503.
//
// DEPLOYER-PROVISIONED material (NOT in-repo — see README):
//   - the three shard files under ShardsDir,
//   - an Active on-chain SidecarIdentityEntry registered (register_sidecar_identity)
//     under (license_nft_mint, SidecarID, KeyVersion) pinning the derived keys +
//     this store's domain hash, TLS cert fingerprint, and binary hash.
type BootIdentityConfig struct {
	// ShardsDir holds the three attest shards, each a file of either 64
	// lowercase-hex chars OR 32 raw bytes (whitespace trimmed):
	//   author.shard            (attest author shard)
	//   host-observation.shard  (host observation shard)
	//   release.shard           (release shard)
	// SECRET material — provision mode 0600, NEVER commit. Empty disables the
	// operator (read-only store; /publish 503).
	ShardsDir string `json:"shards_dir"`
	// SidecarID is the canonical on-chain seed id the SidecarIdentityEntry (and
	// the Foundation sidecar cascade) are published under, e.g. "store". Required
	// when ShardsDir is set. Must satisfy primitives.ValidateSidecarID.
	SidecarID string `json:"sidecar_id"`
	// ChainID is the attest identity-ref chain id, e.g. "solana:devnet". Required
	// when ShardsDir is set (it salts the derived key via the ref digest).
	ChainID string `json:"chain_id"`
	// KeyVersion is the SidecarIdentityEntry key_version seed. 0 => 1.
	KeyVersion uint32 `json:"key_version"`
	// OperatorKeyVersion optionally keeps the long-lived signing/encryption
	// identity anchored to an earlier SidecarIdentityEntry PDA while KeyVersion
	// advances to bind a renewed TLS certificate or replacement binary. Zero
	// preserves the legacy behavior: derive the operator from KeyVersion.
	//
	// This separation is required because StoreOperatorAuthorization pins the
	// operator public key, while SidecarIdentityEntry also pins rotatable
	// deployment facts. Rotating those facts must not silently rotate the store
	// authority that already owns its release listings.
	OperatorKeyVersion uint32 `json:"operator_key_version,omitempty"`
	// OperatorDomain is the domain in the stable operator identity Ref. Empty
	// preserves the legacy behavior: use cfg.Domain. This exists for stores that
	// normalized their serving domain after the operator was authorized.
	OperatorDomain string `json:"operator_domain,omitempty"`
	// TLSCertPath optionally overrides tls.cert_path for the on-chain
	// SidecarIdentityEntry tls_cert_fingerprint binding. This lets a root store
	// bind its public edge certificate while still serving container-local TLS.
	// Empty => use tls.cert_path.
	TLSCertPath string `json:"tls_cert_path,omitempty"`
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
		ProgramID:       defaultLicenseProgramID,
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
	cfg.StoreAuthority = strings.TrimSpace(cfg.StoreAuthority)
	if cfg.StoreAuthority == "" {
		return cfg, fmt.Errorf("config: store_authority is required")
	}
	if _, err := primitives.PubkeyFromBase58(cfg.StoreAuthority); err != nil {
		return cfg, fmt.Errorf("config: store_authority is invalid: %w", err)
	}
	cfg.ProgramID = strings.TrimSpace(cfg.ProgramID)
	if cfg.ProgramID == "" {
		cfg.ProgramID = defaultLicenseProgramID
	}
	if _, err := primitives.PubkeyFromBase58(cfg.ProgramID); err != nil {
		return cfg, fmt.Errorf("config: program_id is invalid: %w", err)
	}
	if cfg.DistDir == "" {
		cfg.DistDir = "dist-publish"
	}
	if cfg.CatalogRepoRoot == "" {
		cfg.CatalogRepoRoot = "."
	}
	writeCapable := strings.TrimSpace(cfg.BootIdentity.ShardsDir) != ""
	if writeCapable && strings.TrimSpace(cfg.PrivateStageDir) == "" {
		return cfg, fmt.Errorf("config: private_stage_dir is required when boot_identity.shards_dir is set")
	}
	if writeCapable && strings.TrimSpace(cfg.CatalogGenerationRoot) == "" {
		return cfg, fmt.Errorf("config: catalog_generation_root is required when boot_identity.shards_dir is set")
	}
	if writeCapable && strings.TrimSpace(cfg.CatalogMigrationStateDir) == "" {
		return cfg, fmt.Errorf("config: catalog_migration_state_dir is required when boot_identity.shards_dir is set")
	}
	if cfg.PrivateStageDir == "" {
		cfg.PrivateStageDir = filepath.Join(cfg.CatalogRepoRoot, ".melusina-private-stage")
	}
	if err := validateCatalogStorageRoots(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// validateCatalogStorageRoots performs lexical containment checks only. The
// write bootstrap performs filesystem/device checks after it owns writer.lock;
// doing those here would inspect bootstrap state before process exclusion.
func validateCatalogStorageRoots(cfg Config) error {
	type namedRoot struct {
		name string
		path string
	}
	roots := []namedRoot{
		{name: "dist_dir", path: cfg.DistDir},
		{name: "private_stage_dir", path: cfg.PrivateStageDir},
	}
	if cfg.CatalogGenerationRoot != "" {
		roots = append(roots, namedRoot{name: "catalog_generation_root", path: cfg.CatalogGenerationRoot})
	}
	if cfg.CatalogMigrationStateDir != "" {
		roots = append(roots, namedRoot{name: "catalog_migration_state_dir", path: cfg.CatalogMigrationStateDir})
	}

	for i := range roots {
		absolute, err := filepath.Abs(roots[i].path)
		if err != nil {
			return fmt.Errorf("config: resolve %s: %w", roots[i].name, err)
		}
		roots[i].path = filepath.Clean(absolute)
	}
	for i := 0; i < len(roots); i++ {
		for j := i + 1; j < len(roots); j++ {
			if pathsLexicallyOverlap(roots[i].path, roots[j].path) {
				return fmt.Errorf("config: %s and %s must be lexically disjoint", roots[i].name, roots[j].name)
			}
		}
	}
	return nil
}

func pathsLexicallyOverlap(a, b string) bool {
	return pathContains(a, b) || pathContains(b, a)
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}
