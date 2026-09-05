package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/internal/hostupdate"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const controllerConfigSchema = "melusina-update-controller-config-v1"

const oneShotApplyPolicySchema = "melusina-one-shot-apply-policy-v1"

// maxControllerConfigBytes bounds the root-owned config file (small typed JSON).
const maxControllerConfigBytes = 1 << 20

// ControllerConfig is the ROOT-OWNED trust root for the host update controller.
// Unlike the shell-writable UpdatePolicy (which only decides whether/how often to
// apply), this file pins WHAT the controller will ever trust: the operator signing
// key, the destination store identity, the pinned bundle origin + generation URL,
// the component allowlist path, and the on-chain program/mint pins the chain gate
// enforces. It is loaded from a root-owned, <=0600, no-symlink file and strictly
// decoded (unknown/duplicate/trailing rejected) so nothing the controller trusts is
// silently widened.
type ControllerConfig struct {
	Schema string `json:"schema"`

	// Operator-preference half (mirrors UpdatePolicy; validated by the SAME rule).
	AutoApply              bool  `json:"autoApply"`
	PollIntervalSeconds    int64 `json:"pollIntervalSeconds"`
	DeepStableSeconds      int64 `json:"deepStableSeconds"`
	PromoteDeadlineSeconds int64 `json:"promoteDeadlineSeconds"`

	// Trust anchors — the controller NEVER reads these from the fetched document.
	OperatorPubkey  string `json:"operatorPubkey"`  // base58 ed25519; verifies the signed generation
	ExpectedStoreID string `json:"expectedStoreId"` // destination identity pin
	BundleOrigin    string `json:"bundleOrigin"`    // absolute https origin every bundleUrl must be under

	// Fetch surface.
	StoreGenerationURL string `json:"storeGenerationUrl"` // https .../update/generation.json

	// Host-action allowlist (root-owned) resolved via ResolveComponent.
	ComponentRegistryPath string `json:"componentRegistryPath"`

	// Chain-gate pins.
	ProgramID      string `json:"programId"`
	MasterNftMint  string `json:"masterNftMint"`
	LicenseNftMint string `json:"licenseNftMint"`
	SolanaRPCURL   string `json:"solanaRpcUrl"`
	// A single trusted endpoint is the shape that took the catalog to HTTP 503
	// when one key hit its quota (F-235/F-238). It is worse here: boot identity
	// turns any chain error into log.Fatalf under Restart=on-failure with no
	// start limit, so one exhausted endpoint crash-loops the controller.
	SolanaRPCFallbackURLs []string `json:"solanaRpcFallbackUrls,omitempty"`
	SolanaRPCAttempts     int      `json:"solanaRpcAttempts,omitempty"`

	// Persistent state.
	StateDir    string `json:"stateDir"`              // ControllerState + active WAL
	ReceiptDir  string `json:"receiptDir"`            // immutable terminal receipts
	StagingRoot string `json:"stagingRoot,omitempty"` // adapter download/stage root; default <stateDir>/staging

	// NotifyPath receives the admin-visible pending-update notification when
	// auto-apply is OFF. Default <stateDir>/pending-update.json.
	NotifyPath string `json:"notifyPath,omitempty"`

	// OneShotApply is an optional root-owned scope pin for the deliberately
	// narrow receipt-authorized Fineract migration path.  It is not a generic
	// override: when present it is valid only with AutoApply=false and an exact
	// singleton local registry for its named component.
	OneShotApply *OneShotApplyPolicy `json:"oneShotApply,omitempty"`
}

// OneShotApplyPolicy names the one controller identity and one local component
// that may be admitted through a Store-signed one-shot receipt.  The live
// migration is intentionally fixed to Fineract rather than becoming a reusable
// host-application backdoor.
type OneShotApplyPolicy struct {
	Schema       string `json:"schema"`
	ControllerID string `json:"controllerId"`
	ComponentID  string `json:"componentId"`
}

func safeOneShotToken(s string) bool {
	if s == "" || len(s) > 128 || strings.Contains(s, "..") || s[0] == '.' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

func (p OneShotApplyPolicy) validate() error {
	if p.Schema != oneShotApplyPolicySchema {
		return fmt.Errorf("oneShotApply schema mismatch: %q", p.Schema)
	}
	if !safeOneShotToken(p.ControllerID) || !safeOneShotToken(p.ComponentID) {
		return errors.New("oneShotApply controllerId and componentId must be safe identity tokens")
	}
	if p.ComponentID != "fineract-sidecar" {
		return fmt.Errorf("oneShotApply componentId %q is not the narrowly authorized fineract-sidecar", p.ComponentID)
	}
	return nil
}

// policy derives the shell-writable-equivalent UpdatePolicy from the config, using
// the package default as the base so the schema + any unset field stays canonical.
func (c ControllerConfig) policy() hostupdate.UpdatePolicy {
	p := hostupdate.DefaultUpdatePolicy()
	p.AutoApply = c.AutoApply
	p.PollIntervalSeconds = c.PollIntervalSeconds
	p.DeepStableSeconds = c.DeepStableSeconds
	p.PromoteDeadlineSeconds = c.PromoteDeadlineSeconds
	return p
}

func (c ControllerConfig) stagingRoot() string {
	if strings.TrimSpace(c.StagingRoot) != "" {
		return c.StagingRoot
	}
	return filepath.Join(c.StateDir, "staging")
}

func (c ControllerConfig) notifyPath() string {
	if strings.TrimSpace(c.NotifyPath) != "" {
		return c.NotifyPath
	}
	return filepath.Join(c.StateDir, "pending-update.json")
}

func (c ControllerConfig) operatorKey() (ed25519.PublicKey, error) {
	raw, err := primitives.DecodeBase58(c.OperatorPubkey)
	if err != nil {
		return nil, fmt.Errorf("operatorPubkey is not valid base58: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("operatorPubkey is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func (c ControllerConfig) validate() error {
	if c.Schema != controllerConfigSchema {
		return fmt.Errorf("config schema mismatch: %q (want %q)", c.Schema, controllerConfigSchema)
	}
	if err := c.policy().Validate(); err != nil {
		return fmt.Errorf("timing policy: %w", err)
	}
	if _, err := c.operatorKey(); err != nil {
		return err
	}
	// Refuse a malformed endpoint set at LOAD time. LoadConfig runs before
	// anything else in main, so a duplicate or an orphaned fallback list fails
	// visibly here instead of surfacing as a chain-read error later.
	if _, _, _, err := normalizeControllerRPCEndpoints(c.SolanaRPCURL, c.SolanaRPCFallbackURLs, c.SolanaRPCAttempts); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"expectedStoreId":       c.ExpectedStoreID,
		"programId":             c.ProgramID,
		"masterNftMint":         c.MasterNftMint,
		"licenseNftMint":        c.LicenseNftMint,
		"solanaRpcUrl":          c.SolanaRPCURL,
		"componentRegistryPath": c.ComponentRegistryPath,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("required config field %q is empty", name)
		}
	}
	for name, value := range map[string]string{
		"storeGenerationUrl": c.StoreGenerationURL,
		"bundleOrigin":       c.BundleOrigin,
	} {
		if !strings.HasPrefix(value, "https://") {
			return fmt.Errorf("config field %q must be an absolute https URL", name)
		}
	}
	for name, value := range map[string]string{
		"componentRegistryPath": c.ComponentRegistryPath,
		"stateDir":              c.StateDir,
		"receiptDir":            c.ReceiptDir,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("config field %q must be an absolute clean path", name)
		}
	}
	// The WAL is rooted at stateDir and derives <stateDir>/receipts; receiptDir must
	// name that exact location so the configured receipt path can't diverge from where
	// terminal receipts actually land.
	if c.ReceiptDir != filepath.Join(c.StateDir, "receipts") {
		return fmt.Errorf("receiptDir must be %q (the WAL's stateDir/receipts)", filepath.Join(c.StateDir, "receipts"))
	}
	if c.OneShotApply != nil {
		if c.AutoApply {
			return errors.New("oneShotApply requires autoApply=false")
		}
		if err := c.OneShotApply.validate(); err != nil {
			return err
		}
	}
	return nil
}

// LoadControllerConfig loads the production config: a root-owned (uid 0), <=0600,
// no-symlink regular file, strictly decoded.
func LoadControllerConfig(path string) (ControllerConfig, error) {
	return loadControllerConfigOwned(path, 0)
}

// loadControllerConfigOwned is the uid-parameterized loader so tests can assert the
// strict-decode + mode gates without being root.
func loadControllerConfigOwned(path string, expectedUID uint32) (ControllerConfig, error) {
	var cfg ControllerConfig
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return cfg, fmt.Errorf("open controller config: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return cfg, err
	}
	if !info.Mode().IsRegular() {
		return cfg, errors.New("controller config is not a regular file")
	}
	if info.Mode().Perm()&0o177 != 0 {
		return cfg, fmt.Errorf("controller config mode %04o is too permissive (want <=0600)", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return cfg, errors.New("controller config ownership metadata unavailable")
	}
	if stat.Uid != expectedUID {
		return cfg, fmt.Errorf("controller config owner uid %d != expected %d", stat.Uid, expectedUID)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxControllerConfigBytes+1))
	if err != nil {
		return cfg, err
	}
	if int64(len(raw)) > maxControllerConfigBytes {
		return cfg, errors.New("controller config exceeds bounded read limit")
	}
	if err := assertNoDuplicateTopLevelKeys(raw); err != nil {
		return cfg, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode controller config: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return cfg, errors.New("controller config has trailing data")
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// assertNoDuplicateTopLevelKeys retains its historical name, but scans every
// nested object too.  OneShotApply is a nested trust-root object; accepting a
// duplicate key there would make json.Decoder's last-wins behavior a policy
// widening primitive.
func assertNoDuplicateTopLevelKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("scan config tokens: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return errors.New("controller config must be a JSON object")
	}
	if err := scanJSONObjectKeys(dec); err != nil {
		return fmt.Errorf("scan config tokens: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("controller config has trailing data")
	}
	return nil
}

func scanJSONObjectKeys(dec *json.Decoder) error {
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := t.(string)
		if !ok {
			return errors.New("object key is not a string")
		}
		if seen[key] {
			return fmt.Errorf("controller config has duplicate key %q", key)
		}
		seen[key] = true
		if err := scanJSONValueKeys(dec); err != nil {
			return err
		}
	}
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != '}' {
		return errors.New("object did not terminate")
	}
	return nil
}

func scanJSONValueKeys(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		return scanJSONObjectKeys(dec)
	case '[':
		for dec.More() {
			if err := scanJSONValueKeys(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if endDelim, ok := end.(json.Delim); !ok || endDelim != ']' {
			return errors.New("array did not terminate")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}
