package main

// Env-only runtime configuration. No plaintext keys directory is ever read: the
// only signing material the CLI itself loads is the publisher ENVELOPE identity
// (via env:NAME or a path the operator points at), and every governed chain/store
// mutation is delegated to the signer provider (see signer.go).
//
// Every estate fact — the Store origin, domain and ID, the license-registry
// program, the master mint and the release Squads authority — comes from the
// owner-signed estate profile (MEL_RELEASE_ESTATE_PROFILE, pinned by
// MEL_RELEASE_ESTATE_PROFILE_SHA256; see estate.go). None has a compiled
// default: without a verified, pinned profile the CLI refuses before it reads
// the catalog. The older per-value variables (MEL_RELEASE_STORE_URL,
// MEL_RELEASE_PROGRAM_ID, ...) may still be set by a wrapper, but only to the
// profile's own value; a different value is refused, never preferred.

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const defaultReleaseOpTimeoutSecs = 480
const maxReleaseOpTimeoutSecs = 1800

// Config is the fully-resolved, validated runtime configuration.
type Config struct {
	ConfigPath string // MEL_RELEASE_CONFIG   — path to bazaar-catalog.yaml (required)
	RPCURL     string // MEL_RELEASE_RPC_URL   — Solana RPC (passed through to the signer provider)

	// EstateProfile and EstateProfileSHA256 name the owner-signed profile and
	// its reviewed digest (both required). Every estate field below is derived
	// from that profile by loadEstateBinding.
	EstateProfile       string // MEL_RELEASE_ESTATE_PROFILE
	EstateProfileSHA256 string // MEL_RELEASE_ESTATE_PROFILE_SHA256
	estate              estateBinding

	// These are read only to reject a caller override, then replaced by the
	// catalog authority once bindCatalog has proved it equals the profile's.
	SquadsMultisig    string // MEL_RELEASE_SQUADS_MULTISIG
	SquadsVault       string // MEL_RELEASE_SQUADS_VAULT
	SquadsProgramID   string // MEL_RELEASE_SQUADS_PROGRAM_ID
	SquadsThreshold   int    // MEL_RELEASE_SQUADS_THRESHOLD
	SquadsMemberCount int    // MEL_RELEASE_SQUADS_MEMBER_COUNT
	SignerProvider    string // MEL_RELEASE_SIGNER_PROVIDER — off-host governed command (required)
	StorePubkey       string // MEL_RELEASE_STORE_PUBKEY — path to store operator identity.Public JSON (required)
	StoreLicenseMint  string // MEL_RELEASE_STORE_LICENSE_MINT — Store license authority for signed stage/promote (required)

	// Estate-derived settings. A wrapper may repeat the profile's value in the
	// named variable; any other value is refused.
	StoreURL      string // "https://" + store.rootDomain       (MEL_RELEASE_STORE_URL)
	StoreDomain   string // store.rootDomain                    (MEL_RELEASE_STORE_DOMAIN)
	StoreID       string // store.storeId                       (MEL_RELEASE_STORE_ID)
	BundleOrigin  string // the Store origin                    (MEL_RELEASE_BUNDLE_ORIGIN)
	ProgramID     string // programs.license-registry.programId (MEL_RELEASE_PROGRAM_ID, MEL_PROGRAM_ID)
	MasterNftMint string // anchors.masterMint                  (MEL_RELEASE_MASTER_NFT_MINT)

	// Additional env-only settings. The publisher envelope identity is required
	// for both halves: private staging is itself a signed store mutation, so
	// publish must fail before building if it cannot sign the stage request.
	Channel       string // MEL_RELEASE_CHANNEL        (default dev)
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

// loadConfig is the existing mutation-capable configuration. Keep this strict
// default so adding a new command cannot accidentally inherit a less-privileged
// configuration mode.
func loadConfig() (Config, error) { return loadConfigForMutation(true) }

// loadPreflightConfig is the sole read-only configuration profile. Preflight
// verifies source/package facts and reads active releases, but it must not
// require a Store operator identity, a publisher envelope, or any Squads key.
// The configured provider receives the same absence: callers do not merely
// promise not to use credentials they happened to inherit.
func loadPreflightConfig() (Config, error) { return loadConfigForMutation(false) }

func loadConfigForMutation(needsMutationInputs bool) (Config, error) {
	c := Config{
		ConfigPath:          os.Getenv("MEL_RELEASE_CONFIG"),
		RPCURL:              os.Getenv("MEL_RELEASE_RPC_URL"),
		EstateProfile:       strings.TrimSpace(os.Getenv("MEL_RELEASE_ESTATE_PROFILE")),
		EstateProfileSHA256: strings.TrimSpace(os.Getenv("MEL_RELEASE_ESTATE_PROFILE_SHA256")),
		SquadsMultisig:      os.Getenv("MEL_RELEASE_SQUADS_MULTISIG"),
		SquadsVault:         os.Getenv("MEL_RELEASE_SQUADS_VAULT"),
		SquadsProgramID:     os.Getenv("MEL_RELEASE_SQUADS_PROGRAM_ID"),
		SignerProvider:      os.Getenv("MEL_RELEASE_SIGNER_PROVIDER"),
		StorePubkey:         os.Getenv("MEL_RELEASE_STORE_PUBKEY"),
		StoreLicenseMint:    os.Getenv("MEL_RELEASE_STORE_LICENSE_MINT"),
		Channel:             envOr("MEL_RELEASE_CHANNEL", "dev"),
		PublisherKey:        os.Getenv("MEL_RELEASE_PUBLISHER_KEY"),
	}
	for _, item := range []struct {
		name string
		dst  *int
	}{
		{"MEL_RELEASE_SQUADS_THRESHOLD", &c.SquadsThreshold},
		{"MEL_RELEASE_SQUADS_MEMBER_COUNT", &c.SquadsMemberCount},
	} {
		if raw := strings.TrimSpace(os.Getenv(item.name)); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 {
				return Config{}, fmt.Errorf("%s must be a positive integer when set", item.name)
			}
			*item.dst = value
		}
	}
	c.OpTimeoutSecs = defaultReleaseOpTimeoutSecs
	if raw := strings.TrimSpace(os.Getenv("MEL_RELEASE_OP_TIMEOUT_SECS")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < defaultReleaseOpTimeoutSecs || value > maxReleaseOpTimeoutSecs {
			return Config{}, fmt.Errorf("MEL_RELEASE_OP_TIMEOUT_SECS must be an integer in %d..%d when set", defaultReleaseOpTimeoutSecs, maxReleaseOpTimeoutSecs)
		}
		c.OpTimeoutSecs = value
	}
	if revoke := strings.TrimSpace(os.Getenv("MEL_RELEASE_ALLOW_GLOBAL_REVOKE")); revoke != "" {
		if revoke != "yes" {
			return Config{}, errors.New("MEL_RELEASE_ALLOW_GLOBAL_REVOKE must be exactly 'yes' when set")
		}
		c.AllowGlobalReleaseRevoke = true
	}

	var missing []string
	required := map[string]string{
		"MEL_RELEASE_CONFIG":                c.ConfigPath,
		"MEL_RELEASE_SIGNER_PROVIDER":       c.SignerProvider,
		"MEL_RELEASE_ESTATE_PROFILE":        c.EstateProfile,
		"MEL_RELEASE_ESTATE_PROFILE_SHA256": c.EstateProfileSHA256,
	}
	if needsMutationInputs {
		required["MEL_RELEASE_STORE_PUBKEY"] = c.StorePubkey
		required["MEL_RELEASE_STORE_LICENSE_MINT"] = c.StoreLicenseMint
		required["MEL_RELEASE_PUBLISHER_KEY"] = c.PublisherKey
	}
	for name, val := range required {
		if strings.TrimSpace(val) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return Config{}, fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}
	estate, err := loadEstateBinding(c.EstateProfile, c.EstateProfileSHA256)
	if err != nil {
		return Config{}, fmt.Errorf("MEL_RELEASE_ESTATE_PROFILE: %w", err)
	}
	if err := refuseEstateOverrides(estate); err != nil {
		return Config{}, err
	}
	c.estate = estate
	c.StoreURL = estate.StoreOrigin
	c.BundleOrigin = estate.StoreOrigin
	c.StoreDomain = estate.StoreDomain
	c.StoreID = estate.StoreID
	c.ProgramID = estate.ProgramID
	c.MasterNftMint = estate.MasterNftMint

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

// refuseEstateOverrides lets a wrapper repeat an estate value in its older
// variable, and refuses any other value by name: the profile is the only
// source, and a stale pin must stop the release rather than steer it.
func refuseEstateOverrides(estate estateBinding) error {
	for _, item := range []struct {
		name, want string
		origin     bool
	}{
		{name: "MEL_RELEASE_STORE_URL", want: estate.StoreOrigin, origin: true},
		{name: "MEL_RELEASE_BUNDLE_ORIGIN", want: estate.StoreOrigin, origin: true},
		{name: "MEL_RELEASE_STORE_DOMAIN", want: estate.StoreDomain},
		{name: "MEL_RELEASE_STORE_ID", want: estate.StoreID},
		{name: "MEL_RELEASE_PROGRAM_ID", want: estate.ProgramID},
		{name: "MEL_PROGRAM_ID", want: estate.ProgramID},
		{name: "MEL_RELEASE_MASTER_NFT_MINT", want: estate.MasterNftMint},
	} {
		supplied := strings.TrimSpace(os.Getenv(item.name))
		if item.origin {
			supplied = strings.TrimRight(supplied, "/")
		}
		if supplied != "" && supplied != item.want {
			return fmt.Errorf("%s=%q is not the estate profile's %q; it cannot override the owner-signed estate profile", item.name, supplied, item.want)
		}
	}
	return nil
}

// bindCatalog binds the catalog manifest to the estate. The manifest must
// describe the profile's Store (catalog_origin) and repeat the profile's
// release authority exactly; only then does it become the sole selector of
// the publisher authority. Per-app SPK keys still travel with each app's
// package; this concerns only the common Squads authority that authorizes
// releases.
func (c *Config) bindCatalog(catalog *Catalog) error {
	if catalog == nil || !wellFormedSquadsAuthority(catalog.ReleaseSquadsAuthority) {
		return errors.New("Bazaar catalog lacks a valid shared Squads authority")
	}
	if c.estate.StoreOrigin == "" || !wellFormedSquadsAuthority(c.estate.Squads) {
		return errors.New("no estate profile is bound; refusing to trust a catalog on its own")
	}
	if catalog.Origin != c.estate.StoreOrigin {
		return fmt.Errorf("Bazaar catalog catalog_origin %q is not the estate profile's Store %q; this catalog describes another Store", catalog.Origin, c.estate.StoreOrigin)
	}
	if catalog.ReleaseSquadsAuthority != c.estate.Squads {
		return fmt.Errorf("Bazaar catalog release_squads_authority %+v is not the estate profile's roles.store-release authority %+v", catalog.ReleaseSquadsAuthority, c.estate.Squads)
	}
	expected := catalog.ReleaseSquadsAuthority
	for _, item := range []struct {
		name, supplied, want string
	}{
		{"MEL_RELEASE_SQUADS_MULTISIG", c.SquadsMultisig, expected.Multisig},
		{"MEL_RELEASE_SQUADS_VAULT", c.SquadsVault, expected.Vault},
		{"MEL_RELEASE_SQUADS_PROGRAM_ID", c.SquadsProgramID, expected.ProgramID},
	} {
		if strings.TrimSpace(item.supplied) != "" && item.supplied != item.want {
			return fmt.Errorf("%s cannot override the catalog-pinned shared Squads authority", item.name)
		}
	}
	for _, item := range []struct {
		name     string
		supplied int
		want     int
	}{
		{"MEL_RELEASE_SQUADS_THRESHOLD", c.SquadsThreshold, expected.Threshold},
		{"MEL_RELEASE_SQUADS_MEMBER_COUNT", c.SquadsMemberCount, expected.MemberCount},
	} {
		if item.supplied != 0 && item.supplied != item.want {
			return fmt.Errorf("%s cannot override the catalog-pinned shared Squads authority", item.name)
		}
	}
	c.SquadsMultisig = expected.Multisig
	c.SquadsVault = expected.Vault
	c.SquadsProgramID = expected.ProgramID
	c.SquadsThreshold = expected.Threshold
	c.SquadsMemberCount = expected.MemberCount
	return nil
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
