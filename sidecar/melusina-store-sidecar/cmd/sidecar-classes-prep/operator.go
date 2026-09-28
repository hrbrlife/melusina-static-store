package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// storeConfigEcho is the subset of the Store config this producer reads. It is
// deliberately a LOCAL echo (not the main package's Config): a producer that
// imports the serving process's whole config surface inherits its every
// validation turn; the producer needs only the boot-identity inputs and the
// store id, and it refuses when any is absent rather than defaulting it.
type storeConfigEcho struct {
	StoreID        string `json:"store_id"`
	LicenseNFTMint string `json:"license_nft_mint"`
	Domain         string `json:"domain"`
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

// resolveOperatorInputs builds the operator identity Ref from the Store
// config (or the explicit overrides), exactly the way Store startup does
// (boot_identity.go operatorIdentityRef): the same three shards under the
// same ref derive the same key, so the table the operator signs here is
// verifiable against the public half the Store config pins.
func resolveOperatorInputs(opts options) (identity.Ref, string, error) {
	var cfg storeConfigEcho
	shardsDir := strings.TrimSpace(opts.shardsDir)
	if strings.TrimSpace(opts.configPath) != "" {
		raw, err := os.ReadFile(opts.configPath)
		if err != nil {
			return identity.Ref{}, "", fmt.Errorf("read config: %w", err)
		}
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return identity.Ref{}, "", fmt.Errorf("parse config: %w", err)
		}
	}
	chainID := firstNonEmpty(opts.chainID, cfg.BootIdentity.ChainID)
	programID := firstNonEmpty(opts.programID, cfg.ProgramID)
	licenseMint := firstNonEmpty(opts.licenseMint, cfg.LicenseNFTMint)
	domain := firstNonEmpty(opts.domain, cfg.Domain)
	sidecarID := firstNonEmpty(opts.sidecarID, cfg.BootIdentity.SidecarID)
	if sidecarID == "" {
		sidecarID = "melusina-store-sidecar"
	}
	if strings.TrimSpace(opts.shardsDir) != "" {
		// explicit override wins
	} else {
		shardsDir = strings.TrimSpace(cfg.BootIdentity.ShardsDir)
	}
	if chainID == "" {
		return identity.Ref{}, "", errors.New("no chain id: -config boot_identity.chain_id or -chain-id is required (there is no default chain)")
	}
	if programID == "" {
		return identity.Ref{}, "", errors.New("no license-registry program id: -config program_id or -program-id is required")
	}
	if licenseMint == "" {
		return identity.Ref{}, "", errors.New("no license mint: -config license_nft_mint or -license-mint is required")
	}
	if domain == "" {
		return identity.Ref{}, "", errors.New("no domain: -config domain or -domain is required")
	}
	if shardsDir == "" {
		return identity.Ref{}, "", errors.New("no shards dir: -config boot_identity.shards_dir or -shards-dir is required (the operator key is the boot-identity key, never an ad-hoc one)")
	}
	keyVersion := cfg.BootIdentity.KeyVersion
	if keyVersion == 0 {
		keyVersion = 1
	}
	operatorVersion := cfg.BootIdentity.OperatorKeyVersion
	if operatorVersion == 0 {
		operatorVersion = keyVersion
	}
	mint, err := primitives.PubkeyFromBase58(licenseMint)
	if err != nil {
		return identity.Ref{}, "", fmt.Errorf("license mint: %w", err)
	}
	program, err := primitives.PubkeyFromBase58(programID)
	if err != nil {
		return identity.Ref{}, "", fmt.Errorf("program id: %w", err)
	}
	operatorPDA, _, err := pda.SidecarIdentity(mint, sidecarID, operatorVersion, program)
	if err != nil {
		return identity.Ref{}, "", fmt.Errorf("derive operator identity PDA: %w", err)
	}
	operatorDomain := firstNonEmpty(cfg.BootIdentity.OperatorDomain, opts.operatorDomain, domain)
	return identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     chainID,
		ProgramID:   program.Base58(),
		LicenseMint: mint.Base58(),
		Domain:      operatorDomain,
		PDA:         operatorPDA.Base58(),
		SidecarID:   sidecarID,
		KeyVersion:  operatorVersion,
	}, shardsDir, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// loadShardsForPrep mirrors the Store's loadSidecarShards: three hex-or-raw
// 32-byte shard files under the shards dir.
func loadShardsForPrep(dir string) (derive.SidecarShards, error) {
	var sh derive.SidecarShards
	for _, f := range []struct {
		name string
		dst  *[32]byte
	}{
		{"author.shard", &sh.AuthorShard},
		{"host-observation.shard", &sh.HostObservationShard},
		{"release.shard", &sh.ReleaseShard},
	} {
		raw, err := os.ReadFile(filepath.Join(dir, f.name))
		if err != nil {
			return sh, fmt.Errorf("read %s: %w", f.name, err)
		}
		trimmed := strings.TrimSpace(string(raw))
		var val [32]byte
		if len(trimmed) == 64 {
			b, err := hex.DecodeString(trimmed)
			if err != nil {
				return sh, fmt.Errorf("%s: not valid 32-byte hex: %w", f.name, err)
			}
			copy(val[:], b)
		} else if len(raw) == 32 {
			copy(val[:], raw)
		} else {
			return sh, fmt.Errorf("%s: want 64 hex chars or 32 raw bytes, got %d bytes", f.name, len(raw))
		}
		*f.dst = val
	}
	return sh, nil
}

// deriveSidecarOperatorForPrep derives the operator private identity from the
// ref and shards — the same derivation the Store process performs at startup,
// so the signing key here IS the Store's operator key, not a parallel one.
func deriveSidecarOperatorForPrep(ref identity.Ref, shards derive.SidecarShards) (*identity.Private, error) {
	operator, err := derive.DeriveSidecar(ref, shards)
	if err != nil {
		return nil, fmt.Errorf("derive operator: %w", err)
	}
	return operator, nil
}

// prepClockNow is the signing clock; split out so the producer's tests can pin
// determinism. signedAtUnix must be positive and current (the loader refuses
// a future-dated table through Verify's consumers).
func prepClockNow() int64 {
	return time.Now().UTC().Unix()
}

// readBoundedInput reads an operator input file, bounded and regular only.
func readBoundedInput(path, label string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file, not a symlink or device", label)
	}
	if info.Size() > 4<<20 {
		return nil, fmt.Errorf("%s exceeds 4 MiB", label)
	}
	return os.ReadFile(path)
}
