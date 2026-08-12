package main

import (
	"bytes"
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
)

const deploymentRootSchema = "melusina-deployment-root-v1"

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
	configPath := flag.String("config", "/etc/melusina/store.config.json", "store config JSON")
	inputPath := flag.String("input", "-", "unsigned deployment root JSON, or - for stdin")
	flag.Parse()
	if err := run(*configPath, *inputPath, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "sign-deployment-root: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath, inputPath string, stdin io.Reader, stdout io.Writer) error {
	operator, err := deriveOperator(configPath)
	if err != nil {
		return err
	}
	var input []byte
	if inputPath == "-" {
		input, err = io.ReadAll(stdin)
	} else {
		input, err = os.ReadFile(inputPath)
	}
	if err != nil {
		return fmt.Errorf("read deployment root: %w", err)
	}
	signed, err := signRoot(input, operator)
	if err != nil {
		return err
	}
	_, err = stdout.Write(signed)
	return err
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

func signRoot(raw []byte, operator *identity.Private) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("parse deployment root: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("deployment root contains trailing JSON")
	}
	if root["schema"] != deploymentRootSchema {
		return nil, fmt.Errorf("schema must be %s", deploymentRootSchema)
	}
	delete(root, "signature")
	public := operator.Public()
	if root["signingKey"] != public.SignPubkeyB58 {
		return nil, fmt.Errorf("signingKey does not match sealed operator %s", public.SignPubkeyB58)
	}
	canonical, err := json.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("canonicalize deployment root: %w", err)
	}
	root["signature"] = base64.StdEncoding.EncodeToString(operator.Sign(canonical))
	output, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(output, '\n'), nil
}
