package main

// Owner-run independent policy readback. It uses the same strict PDA and
// account-owner verifier as the private Store control route, but requires no
// Store Link client certificate and performs no Store write or listener start.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type storeControlPolicyReadback struct {
	Schema                 string    `json:"schema"`
	StoreID                string    `json:"storeId"`
	StorePolicy            string    `json:"storePolicy"`
	PolicyEpoch            uint64    `json:"policyEpoch"`
	PearlCommandPublicKey  string    `json:"pearlCommandPublicKey"`
	HumanApprovalPublicKey string    `json:"humanApprovalPublicKey"`
	ConfigSHA256           string    `json:"configSha256"`
	ObservedAt             time.Time `json:"observedAt"`
}

func currentStoreControlPolicyReadback(ctx context.Context, cfg Config, cr chainReader, configSHA string, now time.Time) (storeControlPolicyReadback, error) {
	if cr == nil || cfg.RPCURL == "" || cfg.StoreID == "" || len(configSHA) != 64 {
		return storeControlPolicyReadback{}, errors.New("configured chain reader and exact config pin required")
	}
	meta, err := fetchActiveStoreControlPolicy(ctx, cfg, cr)
	if err != nil {
		return storeControlPolicyReadback{}, err
	}
	return storeControlPolicyReadback{
		Schema: controlPolicySnapshotSchema, StoreID: cfg.StoreID,
		StorePolicy: meta.PDA, PolicyEpoch: meta.PolicyEpoch,
		PearlCommandPublicKey:  base64.RawURLEncoding.EncodeToString(meta.PearlCommandPublicKey[:]),
		HumanApprovalPublicKey: base64.RawURLEncoding.EncodeToString(meta.HumanApprovalPublicKey[:]),
		ConfigSHA256:           configSHA, ObservedAt: now.UTC(),
	}, nil
}

func runStoreControlPolicyReadbackSubcommand(args []string) {
	if err := storeControlPolicyReadbackCommand(args); err != nil {
		fmt.Fprintln(os.Stderr, "store-control-policy-readback:", err)
		os.Exit(1)
	}
}

func storeControlPolicyReadbackCommand(args []string) error {
	flags := flag.NewFlagSet("store-control-policy-readback", flag.ContinueOnError)
	configPath := flags.String("config", "", "exact signed Store configuration")
	expectedSHA := flags.String("expected-config-sha256", "", "independently pinned config SHA-256")
	outputPath := flags.String("output-file", "", "new owner-only readback JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("exact config, pin and output arguments required")
	}
	if !filepath.IsAbs(*configPath) || !filepath.IsAbs(*outputPath) || len(*expectedSHA) != 64 {
		return errors.New("absolute config/output paths and full config SHA-256 required")
	}
	info, err := os.Lstat(*configPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 1<<20 {
		return errors.New("signed Store config must be a bounded regular file")
	}
	configRaw, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	configSum := sha256.Sum256(configRaw)
	configSHA := hex.EncodeToString(configSum[:])
	if configSHA != strings.TrimSpace(*expectedSHA) {
		return errors.New("signed Store config SHA-256 differs")
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if cfg.RPCURL == "" || cfg.ProgramID == "" || cfg.StoreAuthority == "" || cfg.StoreID == "" {
		return errors.New("configured Store chain identity is incomplete")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	readback, err := currentStoreControlPolicyReadback(ctx, cfg, newConfiguredStoreRPCReader(cfg), configSHA, time.Now().UTC())
	if err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(*outputPath))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm() != 0o700 {
		return errors.New("readback output parent must be an owner-only directory")
	}
	file, err := os.OpenFile(*outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(*outputPath)
		}
	}()
	if err := json.NewEncoder(file).Encode(readback); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}
