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

	// Persistent state.
	StateDir    string `json:"stateDir"`              // ControllerState + active WAL
	ReceiptDir  string `json:"receiptDir"`            // immutable terminal receipts
	StagingRoot string `json:"stagingRoot,omitempty"` // adapter download/stage root; default <stateDir>/staging

	// NotifyPath receives the admin-visible pending-update notification when
	// auto-apply is OFF. Default <stateDir>/pending-update.json.
	NotifyPath string `json:"notifyPath,omitempty"`
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

// assertNoDuplicateTopLevelKeys rejects a config object with a repeated top-level
// key (a decoy that json.Decode would silently last-wins).
func assertNoDuplicateTopLevelKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("scan config tokens: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return errors.New("controller config must be a JSON object")
	}
	seen := map[string]bool{}
	depth := 0
	for dec.More() || depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return fmt.Errorf("scan config tokens: %w", err)
		}
		switch v := t.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		case string:
			if depth == 0 {
				if seen[v] {
					return fmt.Errorf("controller config has duplicate key %q", v)
				}
				seen[v] = true
				// consume this key's value token/subtree
				if err := skipJSONValue(dec); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func skipJSONValue(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); ok && (delim == '{' || delim == '[') {
		depth := 1
		for depth > 0 {
			tt, err := dec.Token()
			if err != nil {
				return err
			}
			if d, ok := tt.(json.Delim); ok {
				switch d {
				case '{', '[':
					depth++
				case '}', ']':
					depth--
				}
			}
		}
	}
	return nil
}
