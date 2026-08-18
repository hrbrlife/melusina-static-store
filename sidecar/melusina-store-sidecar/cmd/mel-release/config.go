package main

// Env-only runtime configuration. No plaintext keys directory is ever read: the
// only signing material the CLI itself loads is the publisher ENVELOPE identity
// (via env:NAME or a path the operator points at), and every governed chain/store
// mutation is delegated to the signer provider (see signer.go). The seven names
// in fleet/bazaar-catalog.yaml are the canonical interface; the
// remaining MEL_RELEASE_* values below have safe defaults.

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// The license-registry program the store pins for release_v2 authority.
const defaultProgramID = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
const defaultBazaarStoreID = "melusina-os-root-store"

// Config is the fully-resolved, validated runtime configuration.
type Config struct {
	ConfigPath       string // MEL_RELEASE_CONFIG   — path to bazaar-catalog.yaml (required)
	RPCURL           string // MEL_RELEASE_RPC_URL   — Solana RPC (passed through to the signer provider)
	SquadsMultisig   string // MEL_RELEASE_SQUADS_MULTISIG
	SquadsVault      string // MEL_RELEASE_SQUADS_VAULT
	SignerProvider   string // MEL_RELEASE_SIGNER_PROVIDER — off-host governed command (required)
	StoreURL         string // MEL_RELEASE_STORE_URL — bare https origin (required)
	StorePubkey      string // MEL_RELEASE_STORE_PUBKEY — path to store operator identity.Public JSON (required)
	StoreLicenseMint string // MEL_RELEASE_STORE_LICENSE_MINT — Store license authority for signed stage/promote (required)

	// Additional env-only settings. The publisher envelope identity is required
	// for both halves: private staging is itself a signed store mutation, so
	// publish must fail before building if it cannot sign the stage request.
	StoreID       string // MEL_RELEASE_STORE_ID       (must be the default Bazaar Store)
	BundleOrigin  string // MEL_RELEASE_BUNDLE_ORIGIN  (must be the default Bazaar origin)
	Channel       string // MEL_RELEASE_CHANNEL        (default dev)
	ProgramID     string // MEL_RELEASE_PROGRAM_ID     (default defaultProgramID)
	StateDir      string // MEL_RELEASE_STATE_DIR      (default ~/.mel-release or /tmp fallback)
	PublisherKey  string // MEL_RELEASE_PUBLISHER_KEY  (env:NAME or path; required by publish and approve)
	OpTimeoutSecs int    // MEL_RELEASE_OP_TIMEOUT_SECS (default 480)
	// AllowGlobalReleaseRevoke is deliberately OFF by default. ReleaseEntry is
	// keyed by {master, appHash}, not by a store/install target, so automatically
	// revoking every other Active entry while publishing to one target would
	// mutate unrelated stores. Normal approval retains global release history and
	// lets the target's signed pointer select its desired release. A global
	// retirement needs an explicit, separately reviewed opt-in.
	AllowGlobalReleaseRevoke bool // MEL_RELEASE_ALLOW_GLOBAL_REVOKE=yes
}

func loadConfig() (Config, error) {
	c := Config{
		ConfigPath:       os.Getenv("MEL_RELEASE_CONFIG"),
		RPCURL:           os.Getenv("MEL_RELEASE_RPC_URL"),
		SquadsMultisig:   os.Getenv("MEL_RELEASE_SQUADS_MULTISIG"),
		SquadsVault:      os.Getenv("MEL_RELEASE_SQUADS_VAULT"),
		SignerProvider:   os.Getenv("MEL_RELEASE_SIGNER_PROVIDER"),
		StoreURL:         os.Getenv("MEL_RELEASE_STORE_URL"),
		StorePubkey:      os.Getenv("MEL_RELEASE_STORE_PUBKEY"),
		StoreLicenseMint: os.Getenv("MEL_RELEASE_STORE_LICENSE_MINT"),
		StoreID:          envOr("MEL_RELEASE_STORE_ID", defaultBazaarStoreID),
		Channel:          envOr("MEL_RELEASE_CHANNEL", "dev"),
		ProgramID:        envOr("MEL_RELEASE_PROGRAM_ID", defaultProgramID),
		PublisherKey:     os.Getenv("MEL_RELEASE_PUBLISHER_KEY"),
	}
	c.BundleOrigin = envOr("MEL_RELEASE_BUNDLE_ORIGIN", strings.TrimRight(c.StoreURL, "/"))
	c.OpTimeoutSecs = 480
	if revoke := strings.TrimSpace(os.Getenv("MEL_RELEASE_ALLOW_GLOBAL_REVOKE")); revoke != "" {
		if revoke != "yes" {
			return Config{}, errors.New("MEL_RELEASE_ALLOW_GLOBAL_REVOKE must be exactly 'yes' when set")
		}
		c.AllowGlobalReleaseRevoke = true
	}

	var missing []string
	for name, val := range map[string]string{
		"MEL_RELEASE_CONFIG":             c.ConfigPath,
		"MEL_RELEASE_SIGNER_PROVIDER":    c.SignerProvider,
		"MEL_RELEASE_STORE_URL":          c.StoreURL,
		"MEL_RELEASE_STORE_PUBKEY":       c.StorePubkey,
		"MEL_RELEASE_STORE_LICENSE_MINT": c.StoreLicenseMint,
		"MEL_RELEASE_PUBLISHER_KEY":      c.PublisherKey,
	} {
		if strings.TrimSpace(val) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		return Config{}, fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}
	if err := assertBareHTTPS(c.StoreURL); err != nil {
		return Config{}, fmt.Errorf("MEL_RELEASE_STORE_URL: %w", err)
	}
	c.StoreURL = strings.TrimRight(c.StoreURL, "/")
	if c.StoreURL != defaultBazaarOrigin {
		return Config{}, fmt.Errorf("MEL_RELEASE_STORE_URL must be %s", defaultBazaarOrigin)
	}
	if err := assertBareHTTPS(c.BundleOrigin); err != nil {
		return Config{}, fmt.Errorf("MEL_RELEASE_BUNDLE_ORIGIN: %w", err)
	}
	c.BundleOrigin = strings.TrimRight(c.BundleOrigin, "/")
	if c.BundleOrigin != defaultBazaarOrigin {
		return Config{}, fmt.Errorf("MEL_RELEASE_BUNDLE_ORIGIN must be %s", defaultBazaarOrigin)
	}
	if c.StoreID != defaultBazaarStoreID {
		return Config{}, fmt.Errorf("MEL_RELEASE_STORE_ID must be %s", defaultBazaarStoreID)
	}

	dir := os.Getenv("MEL_RELEASE_STATE_DIR")
	if strings.TrimSpace(dir) == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			dir = filepath.Join(os.TempDir(), "mel-release")
		} else {
			dir = filepath.Join(home, ".mel-release")
		}
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return Config{}, errors.New("MEL_RELEASE_STATE_DIR must be an absolute clean path")
	}
	c.StateDir = dir
	return c, nil
}

// appStateDir returns the per-app durable directory (WAL + immutable receipts),
// keyed on the immutable appId.
func (c Config) appStateDir(appID string) string {
	return filepath.Join(c.StateDir, "apps", appID)
}

func (c Config) walPath(appID string) string { return filepath.Join(c.appStateDir(appID), "wal.json") }
func (c Config) lockDir() string             { return filepath.Join(c.StateDir, "locks") }
func (c Config) candidatePath(appID string) string {
	return filepath.Join(c.appStateDir(appID), "candidate.json")
}
func (c Config) receiptPath(appID, name string) string {
	return filepath.Join(c.appStateDir(appID), name)
}

func envOr(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func assertBareHTTPS(value string) error {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be a bare https origin with no userinfo, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return errors.New("must not include a path")
	}
	return nil
}
