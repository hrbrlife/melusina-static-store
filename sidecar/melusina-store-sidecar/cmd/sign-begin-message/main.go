// Command sign-begin-message reconstructs the boot-identity operator (HgE1Xm4M)
// from the off-box shards and Ed25519-signs a RAW message (the adapter BEGIN
// signing message = BEGIN_AUTH_DOMAIN || canonical(intent), passed base64). It
// is the trivial "sign arbitrary bytes" variant of sign-deployment-root, for the
// Leg-B box-apply BEGIN authorization. NO chain, NO box; key derived transiently
// off-box (HT13). Output: JSON {sign_pubkey_b58, signature_b58}.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type config struct {
	Domain         string `json:"domain"`
	LicenseNFTMint string `json:"license_nft_mint"`
	ProgramID      string `json:"program_id"`
	BootIdentity   struct {
		ShardsDir          string `json:"shards_dir"`
		SidecarID          string `json:"sidecar_id"`
		ChainID            string `json:"chain_id"`
		KeyVersion         uint32 `json:"key_version"`
		OperatorKeyVersion uint32 `json:"operator_key_version"`
		OperatorDomain     string `json:"operator_domain"`
	} `json:"boot_identity"`
}

func main() {
	configPath := flag.String("config", "", "store config JSON with boot_identity")
	messageB64 := flag.String("message-b64", "", "base64 of the raw message to sign (signingMessageB64 from make-begin-intent)")
	flag.Parse()
	if err := run(*configPath, *messageB64, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "sign-begin-message: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath, messageB64 string, stdout io.Writer) error {
	if configPath == "" || messageB64 == "" {
		return errors.New("--config and --message-b64 are required")
	}
	message, err := base64.StdEncoding.DecodeString(strings.TrimSpace(messageB64))
	if err != nil {
		return fmt.Errorf("decode message-b64: %w", err)
	}
	operator, err := deriveOperator(configPath)
	if err != nil {
		return err
	}
	sig := operator.Sign(message)
	out := map[string]string{
		"sign_pubkey_b58": operator.Public().SignPubkeyB58,
		"signature_b58":   primitives.EncodeBase58(sig),
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func deriveOperator(configPath string) (*identity.Private, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	bi := cfg.BootIdentity
	if bi.ShardsDir == "" || bi.SidecarID == "" || bi.ChainID == "" {
		return nil, errors.New("publish-provisioned boot identity is required")
	}
	license, err := pda.FromBase58(cfg.LicenseNFTMint)
	if err != nil {
		return nil, fmt.Errorf("license_nft_mint: %w", err)
	}
	program, err := pda.FromBase58(cfg.ProgramID)
	if err != nil {
		return nil, fmt.Errorf("program_id: %w", err)
	}
	version := bi.OperatorKeyVersion
	if version == 0 {
		version = bi.KeyVersion
	}
	if version == 0 {
		version = 1
	}
	domain := strings.TrimSpace(bi.OperatorDomain)
	if domain == "" {
		domain = cfg.Domain
	}
	operatorPDA, _, err := pda.SidecarIdentity(license, bi.SidecarID, version, program)
	if err != nil {
		return nil, fmt.Errorf("derive operator PDA: %w", err)
	}
	shards, err := loadShards(bi.ShardsDir)
	if err != nil {
		return nil, err
	}
	ref := identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     bi.ChainID,
		ProgramID:   cfg.ProgramID,
		LicenseMint: cfg.LicenseNFTMint,
		Domain:      domain,
		PDA:         operatorPDA.Base58(),
		SidecarID:   bi.SidecarID,
		KeyVersion:  version,
	}
	operator, err := derive.DeriveSidecar(ref, shards)
	if err != nil {
		return nil, fmt.Errorf("derive operator identity: %w", err)
	}
	return operator, nil
}

func loadShards(dir string) (derive.SidecarShards, error) {
	var shards derive.SidecarShards
	for _, item := range []struct {
		name string
		dst  *[32]byte
	}{
		{"author.shard", &shards.AuthorShard},
		{"host-observation.shard", &shards.HostObservationShard},
		{"release.shard", &shards.ReleaseShard},
	} {
		raw, err := os.ReadFile(filepath.Join(dir, item.name))
		if err != nil {
			return shards, fmt.Errorf("read %s: %w", item.name, err)
		}
		value, err := parseShard(raw)
		if err != nil {
			return shards, fmt.Errorf("%s: %w", item.name, err)
		}
		*item.dst = value
	}
	return shards, nil
}

func parseShard(raw []byte) ([32]byte, error) {
	var out [32]byte
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 64 {
		value, err := hex.DecodeString(trimmed)
		if err != nil {
			return out, err
		}
		copy(out[:], value)
		return out, nil
	}
	if len(raw) == 32 {
		copy(out[:], raw)
		return out, nil
	}
	return out, fmt.Errorf("want 64 hex chars or 32 raw bytes, got %d bytes", len(raw))
}
