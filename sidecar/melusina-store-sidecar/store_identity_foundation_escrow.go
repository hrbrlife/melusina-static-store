package main

// A foundation identity is generated before the Store can enroll. When the
// signed foundation was measured on a different rehearsal host, its original
// three shards must travel through the normal holder escrow and restore path.
// This producer admits only the exact shards and operator Ref that derive the
// owner-signed profile's Store key; it neither enrolls a Store nor starts one.

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/storerecovery"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type foundationEscrowOptions struct {
	profilePath, reportPath, shardsDir, recipientsPath, outDir string
}

type foundationIdentityReport struct {
	OperatorRef identity.Ref `json:"operator_identity_ref"`
	Shards      struct {
		Dir     string            `json:"dir"`
		Created bool              `json:"created"`
		Files   map[string]string `json:"files"`
	} `json:"shards"`
	Register struct {
		ProgramID           string `json:"program_id"`
		LicenseMint         string `json:"license_nft_mint"`
		SidecarID           string `json:"sidecar_id"`
		KeyVersion          uint32 `json:"key_version"`
		SigningPublicKey    string `json:"signing_pubkey_b58"`
		EncryptionPublicKey string `json:"encryption_pubkey_b58"`
	} `json:"register_sidecar_identity"`
}

func runStoreIdentityFoundationEscrowSealSubcommand(args []string) {
	fs := flag.NewFlagSet("store-identity-foundation-escrow-seal", flag.ExitOnError)
	var value foundationEscrowOptions
	fs.StringVar(&value.profilePath, "estate-profile", "", "verified owner-signed estate profile")
	fs.StringVar(&value.reportPath, "identity-report", "", "original boot-identity-prep report")
	fs.StringVar(&value.shardsDir, "shards-dir", "", "original mode-0700 shard directory")
	fs.StringVar(&value.recipientsPath, "recipients", "", "three disjoint enrolled holder recipients")
	fs.StringVar(&value.outDir, "out-dir", "", "new encrypted escrow output directory")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatal("store-identity-foundation-escrow-seal: positional input refused")
	}
	report, err := sealFoundationEscrow(value)
	if err != nil {
		log.Fatalf("store-identity-foundation-escrow-seal: %v", err)
	}
	printJSONReport("store-identity-foundation-escrow-seal", report)
}

func requireFoundationPrivateShards(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("foundation-escrow-shards-path-invalid")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("foundation-escrow-shards-dir-private-0700-required")
	}
	for _, name := range []string{"author.shard", "host-observation.shard", "release.shard"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return fmt.Errorf("foundation-escrow-shard-private-0600-required:%s", name)
		}
	}
	return nil
}

func sealFoundationEscrow(value foundationEscrowOptions) (map[string]any, error) {
	for _, path := range []string{value.profilePath, value.reportPath, value.recipientsPath, value.outDir} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("foundation-escrow-path-invalid")
		}
	}
	if err := requireFoundationPrivateShards(value.shardsDir); err != nil {
		return nil, err
	}
	profileRaw, err := readBoundedInput(value.profilePath, estateprofile.MaxProfileJSONBytes)
	if err != nil {
		return nil, err
	}
	profile, err := estateprofile.DecodeProfile(profileRaw)
	if err != nil {
		return nil, err
	}
	if _, err := estateprofile.VerifyProfile(profile); err != nil {
		return nil, err
	}
	if !profile.Store.IsRoot {
		return nil, errors.New("foundation-escrow-root-store-required")
	}
	productionReport, err := readBoundedInput(value.reportPath, maxStoreIdentityInputBytes)
	if err != nil {
		return nil, err
	}
	var source foundationIdentityReport
	if err := json.Unmarshal(productionReport, &source); err != nil {
		return nil, errors.New("foundation-escrow-identity-report-invalid")
	}
	ref := source.OperatorRef
	if ref.Validate() != nil || ref.Kind != identity.KindSidecar || ref.SidecarID != "store" ||
		ref.KeyVersion != 1 || ref.ChainID != "solana:"+profile.Network.Label ||
		ref.Domain != profile.Store.RootDomain {
		return nil, errors.New("foundation-escrow-identity-ref-profile-mismatch")
	}
	registry := ""
	for _, program := range profile.Programs {
		if program.Role == estateprofile.ProgramRoleLicenseRegistry {
			registry = program.ProgramID
		}
	}
	if registry == "" || ref.ProgramID != registry || source.Register.ProgramID != registry ||
		source.Register.LicenseMint != ref.LicenseMint || source.Register.SidecarID != ref.SidecarID ||
		source.Register.KeyVersion != ref.KeyVersion || source.Register.SigningPublicKey != profile.Store.OperatorKey {
		return nil, errors.New("foundation-escrow-identity-report-profile-mismatch")
	}
	if mint, err := primitives.PubkeyFromBase58(ref.LicenseMint); err != nil || mint.Base58() != ref.LicenseMint {
		return nil, errors.New("foundation-escrow-license-mint-invalid")
	}
	if !source.Shards.Created || source.Shards.Dir != value.shardsDir ||
		len(source.Shards.Files) != 3 ||
		source.Shards.Files["author"] != filepath.Join(value.shardsDir, "author.shard") ||
		source.Shards.Files["host_observation"] != filepath.Join(value.shardsDir, "host-observation.shard") ||
		source.Shards.Files["release"] != filepath.Join(value.shardsDir, "release.shard") {
		return nil, errors.New("foundation-escrow-shard-report-mismatch")
	}
	shards, err := loadSidecarShards(value.shardsDir)
	if err != nil {
		return nil, err
	}
	defer func() {
		clear(shards.AuthorShard[:])
		clear(shards.HostObservationShard[:])
		clear(shards.ReleaseShard[:])
	}()
	recipientsRaw, err := readBoundedInput(value.recipientsPath, maxStoreIdentityInputBytes)
	if err != nil {
		return nil, err
	}
	recipients, err := storerecovery.DecodeIdentityEscrowRecipients(recipientsRaw)
	if err != nil {
		return nil, err
	}
	escrow, err := storerecovery.SealIdentityEscrow(rand.Reader, profile.Store.StoreID, ref, shards, recipients, profile.Store.OperatorKey)
	if err != nil {
		return nil, err
	}
	manifest, _, err := storerecovery.VerifyIdentityEscrowManifest(escrow.Manifest, profile.Store.OperatorKey)
	if err != nil {
		return nil, err
	}
	if manifest.BoxKey != source.Register.EncryptionPublicKey {
		return nil, errors.New("foundation-escrow-box-key-report-mismatch")
	}
	if err := writeStoreIdentityEscrow(value.outDir, escrow); err != nil {
		return nil, err
	}
	return map[string]any{"schema": "melusina.store-foundation-escrow-report.v1", "storeId": manifest.StoreID,
		"operatorKey": manifest.OperatorKey, "boxKey": manifest.BoxKey,
		"manifestSha256": escrow.ManifestSHA256, "outDir": value.outDir}, nil
}
