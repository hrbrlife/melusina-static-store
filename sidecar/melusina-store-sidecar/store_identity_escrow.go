package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/storerecovery"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Store identity as a backup subject (M25): shard-wise escrow of the three
// attest shards the operator is derived from (internal/storerecovery).
//
//	store-identity-escrow-seal     Store host: seals each shard to its own
//	                               holders; gated by the estate enrollment.
//	store-recovery-keygen          anyone: a holder key or a restore session key.
//	store-identity-escrow-reseal   holder, offline: reseals one shard to a
//	                               replacement host's session key.
//	store-identity-restore         replacement host: rebuilds the shards,
//	                               proves they derive the kit's operator for
//	                               this configuration, writes shards_dir.
//
// The holders are the operator's input (a recipients file); the Store names
// none of its own and records no custody location (owner decision D-2).
const (
	refusalStoreIdentityRestoreConfigMismatch = "store-identity-restore-config-mismatch"

	storeIdentityEscrowManifestFile = "manifest.json"
)

func storeIdentityEscrowFile(role string) string { return "escrow-" + role + ".json" }

// sealStoreIdentityEscrow seals this Store's shards. verified is the identity
// the enrollment gate verified; the shards on disk must derive exactly it.
func sealStoreIdentityEscrow(cfg Config, verified *verifiedBootIdentity, state *storeEnrollmentState, recipients storerecovery.IdentityEscrowRecipientsV1) (storerecovery.IdentityEscrow, error) {
	if verified == nil || verified.operator == nil {
		return storerecovery.IdentityEscrow{}, storerecovery.Refuse(refusalStoreStateRequiresOperator, "")
	}
	if state == nil {
		return storerecovery.IdentityEscrow{}, storerecovery.Refuse(refusalStoreStateRequiresEnrollment, "")
	}
	operatorKey := verified.operator.Public().SignPubkeyB58
	if state.Enrollment.StoreOperatorKey != operatorKey {
		return storerecovery.IdentityEscrow{}, storerecovery.Refuse(refusalStoreStateEnrollmentOperator, state.Enrollment.StoreOperatorKey)
	}
	ref, err := storeOperatorRef(cfg, verified.sidecarID, verified.bindingKeyVersion)
	if err != nil {
		return storerecovery.IdentityEscrow{}, err
	}
	shards, err := loadSidecarShards(cfg.BootIdentity.ShardsDir)
	if err != nil {
		return storerecovery.IdentityEscrow{}, storerecovery.Refuse(storerecovery.RefusalIdentityOperatorMismatch, "load shards: "+err.Error())
	}
	defer func() {
		clear(shards.AuthorShard[:])
		clear(shards.HostObservationShard[:])
		clear(shards.ReleaseShard[:])
	}()
	return storerecovery.SealIdentityEscrow(rand.Reader, cfg.StoreID, ref, shards, recipients, operatorKey)
}

// storeOperatorRef is the identity Ref this configuration derives its
// operator under, exactly as the boot-identity ceremony does.
func storeOperatorRef(cfg Config, sidecarID string, bindingKeyVersion uint32) (identity.Ref, error) {
	licenseMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.LicenseNFTMint))
	if err != nil {
		return identity.Ref{}, storerecovery.Refuse(storerecovery.RefusalIdentityRefInvalid, "license_nft_mint")
	}
	ref, err := operatorIdentityRef(cfg, licenseMint, sidecarID, bindingKeyVersion)
	if err != nil {
		return identity.Ref{}, storerecovery.Refuse(storerecovery.RefusalIdentityRefInvalid, err.Error())
	}
	return ref, nil
}

// restoreStoreIdentity rebuilds the shards from three handoffs and writes
// them where cfg reads them, but only when the escrowed identity is exactly
// the one this configuration derives: a replacement host rendered with
// another mint, domain, chain, registry or key version would derive another
// operator from the same shards.
func restoreStoreIdentity(cfg Config, manifestRaw []byte, operatorKey string, sessionKeyPath string, handoffs [][]byte) error {
	manifest, _, err := storerecovery.VerifyIdentityEscrowManifest(manifestRaw, operatorKey)
	if err != nil {
		return err
	}
	if manifest.StoreID != cfg.StoreID {
		return storerecovery.Refuse(refusalStoreIdentityRestoreConfigMismatch, "store_id")
	}
	sidecarID := strings.TrimSpace(cfg.BootIdentity.SidecarID)
	bindingKeyVersion := cfg.BootIdentity.KeyVersion
	if bindingKeyVersion == 0 {
		bindingKeyVersion = 1
	}
	ref, err := storeOperatorRef(cfg, sidecarID, bindingKeyVersion)
	if err != nil {
		return err
	}
	if ref != manifest.OperatorRef {
		return storerecovery.Refuse(refusalStoreIdentityRestoreConfigMismatch, "this configuration derives the operator under another identity Ref")
	}
	session, err := storerecovery.ReadPrivateKeyFile(sessionKeyPath)
	if err != nil {
		return err
	}
	shards, err := storerecovery.RestoreIdentity(manifestRaw, operatorKey, session, handoffs)
	if err != nil {
		return err
	}
	defer func() {
		clear(shards.AuthorShard[:])
		clear(shards.HostObservationShard[:])
		clear(shards.ReleaseShard[:])
	}()
	if err := storerecovery.WriteShards(filepath.Clean(strings.TrimSpace(cfg.BootIdentity.ShardsDir)), shards); err != nil {
		return err
	}
	// The session key opened every handoff; with the shards written it has no
	// further use and is destroyed.
	if err := storerecovery.DestroyPrivateKeyFile(sessionKeyPath); err != nil {
		return fmt.Errorf("destroy the restore session key %s: %w", sessionKeyPath, err)
	}
	return nil
}

// writeStoreIdentityEscrow writes the public escrow documents into dir, which
// must not exist (its parent must).
func writeStoreIdentityEscrow(dir string, escrow storerecovery.IdentityEscrow) error {
	dir = filepath.Clean(dir)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return storerecovery.Refuse(refusalStoreStateOutputExists, dir+": "+err.Error())
	}
	files := map[string][]byte{storeIdentityEscrowManifestFile: escrow.Manifest}
	for role, raw := range escrow.Escrows {
		files[storeIdentityEscrowFile(role)] = raw
	}
	for name, raw := range files {
		if err := writeNewPublicFile(filepath.Join(dir, name), raw); err != nil {
			return err
		}
	}
	return publishNonceSyncDir(dir)
}

func writeNewPublicFile(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return storerecovery.Refuse(refusalStoreStateOutputExists, path+": "+err.Error())
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readBoundedInput(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("input exceeds its size limit")
	}
	return raw, nil
}

const maxStoreIdentityInputBytes = 256 << 10

func printJSONReport(action string, report any) {
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("%s: encode report: %v", action, err)
	}
	fmt.Println(string(encoded))
}

// runStoreIdentityEscrowSealSubcommand reads the shards with the operator's
// authority, so it passes the enrollment gate first; its first action beyond
// the gate is reading the recipients file.
func runStoreIdentityEscrowSealSubcommand(args []string) {
	fs := flag.NewFlagSet("store-identity-escrow-seal", flag.ExitOnError)
	configPath := fs.String("config", "store.config.json", "path to operator config (JSON)")
	recipientsPath := fs.String("recipients", "", "the "+storerecovery.IdentityEscrowRecipientsSchema+" document naming each shard's holders")
	outDir := fs.String("out-dir", "", "new directory for the manifest and the three escrow documents")
	_ = fs.Parse(args)
	if *recipientsPath == "" || *outDir == "" {
		log.Fatalf("store-identity-escrow-seal: -recipients and -out-dir are required")
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := setProgramIDFromConfig(cfg.ProgramID); err != nil {
		log.Fatalf("config: %v", err)
	}
	var cr chainReader
	if cfg.RPCURL != "" {
		cr = newConfiguredStoreRPCReader(cfg)
	}
	bootCtx, bootCancel := context.WithTimeout(context.Background(), 30*time.Second)
	verified, state, err := deriveEnrolledBootIdentity(bootCtx, cfg, *configPath, cr)
	bootCancel()
	if err != nil {
		log.Fatalf("store-identity-escrow-seal: %v", err)
	}
	raw, err := readBoundedInput(*recipientsPath, maxStoreIdentityInputBytes)
	if err != nil {
		log.Fatalf("store-identity-escrow-seal: read recipients: %v", err)
	}
	recipients, err := storerecovery.DecodeIdentityEscrowRecipients(raw)
	if err != nil {
		log.Fatalf("store-identity-escrow-seal: %v", err)
	}
	escrow, err := sealStoreIdentityEscrow(cfg, verified, state, recipients)
	if err != nil {
		log.Fatalf("store-identity-escrow-seal: %v", err)
	}
	if err := writeStoreIdentityEscrow(*outDir, escrow); err != nil {
		log.Fatalf("store-identity-escrow-seal: %v", err)
	}
	manifest, _, err := storerecovery.VerifyIdentityEscrowManifest(escrow.Manifest, verified.operator.Public().SignPubkeyB58)
	if err != nil {
		log.Fatalf("store-identity-escrow-seal: %v", err)
	}
	printJSONReport("store-identity-escrow-seal", map[string]any{
		"schema": "melusina.store-identity-escrow-report.v1", "storeId": manifest.StoreID,
		"operatorKey": manifest.OperatorKey, "boxKey": manifest.BoxKey,
		"manifestSha256": escrow.ManifestSHA256, "shards": manifest.Shards, "outDir": filepath.Clean(*outDir),
	})
}

// runStoreRecoveryKeygenSubcommand writes a new X25519 key file and prints
// its recipient: a holder key, or a replacement host's session key.
func runStoreRecoveryKeygenSubcommand(args []string) {
	fs := flag.NewFlagSet("store-recovery-keygen", flag.ExitOnError)
	outPath := fs.String("out", "", "new mode-0600 key file")
	_ = fs.Parse(args)
	if *outPath == "" {
		log.Fatalf("store-recovery-keygen: -out is required")
	}
	private, err := storerecovery.GenerateRecoveryKey(rand.Reader)
	if err != nil {
		log.Fatalf("store-recovery-keygen: %v", err)
	}
	if err := storerecovery.WritePrivateKeyFile(*outPath, private); err != nil {
		log.Fatalf("store-recovery-keygen: %v", err)
	}
	printJSONReport("store-recovery-keygen", map[string]string{"schema": "melusina.store-recovery-key-report.v1", "recipient": storerecovery.EncodeRecipient(private.PublicKey()), "keyFile": filepath.Clean(*outPath)})
}

// runStoreIdentityEscrowResealSubcommand is the holder's offline step.
func runStoreIdentityEscrowResealSubcommand(args []string) {
	fs := flag.NewFlagSet("store-identity-escrow-reseal", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "the escrow manifest")
	escrowPath := fs.String("escrow", "", "the escrow document of the holder's shard")
	holderKey := fs.String("holder-key", "", "the holder's mode-0600 key file")
	sessionRecipient := fs.String("session-recipient", "", "the replacement host's session recipient, received over an owner-authenticated channel")
	operatorKey := fs.String("operator-key", "", "base58 Store operator key the manifest must be signed by (the recovery kit's rootStore.operatorKey)")
	outPath := fs.String("out", "", "new file for the handoff")
	_ = fs.Parse(args)
	if *manifestPath == "" || *escrowPath == "" || *holderKey == "" || *sessionRecipient == "" || *operatorKey == "" || *outPath == "" {
		log.Fatalf("store-identity-escrow-reseal: -manifest, -escrow, -holder-key, -session-recipient, -operator-key and -out are required")
	}
	manifest, err := readBoundedInput(*manifestPath, maxStoreIdentityInputBytes)
	if err != nil {
		log.Fatalf("store-identity-escrow-reseal: read manifest: %v", err)
	}
	escrow, err := readBoundedInput(*escrowPath, maxStoreIdentityInputBytes)
	if err != nil {
		log.Fatalf("store-identity-escrow-reseal: read escrow: %v", err)
	}
	holder, err := storerecovery.ReadPrivateKeyFile(*holderKey)
	if err != nil {
		log.Fatalf("store-identity-escrow-reseal: %v", err)
	}
	handoff, role, err := storerecovery.ResealShard(rand.Reader, manifest, *operatorKey, escrow, holder, *sessionRecipient)
	if err != nil {
		log.Fatalf("store-identity-escrow-reseal: %v", err)
	}
	if err := writeNewPublicFile(*outPath, handoff); err != nil {
		log.Fatalf("store-identity-escrow-reseal: %v", err)
	}
	printJSONReport("store-identity-escrow-reseal", map[string]string{"schema": "melusina.store-identity-handoff-report.v1", "role": role, "sessionRecipient": *sessionRecipient, "handoff": filepath.Clean(*outPath)})
}

type repeatedFlag []string

func (r *repeatedFlag) String() string     { return strings.Join(*r, ",") }
func (r *repeatedFlag) Set(v string) error { *r = append(*r, v); return nil }

// runStoreIdentityRestoreSubcommand is the replacement host's step. It
// derives the operator only to prove the restored shards; it acts with no
// release authority, and the Store it prepares passes the startup gate.
func runStoreIdentityRestoreSubcommand(args []string) {
	fs := flag.NewFlagSet("store-identity-restore", flag.ExitOnError)
	configPath := fs.String("config", "store.config.json", "path to the replacement host's operator config (JSON); the shards are written to its boot_identity.shards_dir")
	manifestPath := fs.String("manifest", "", "the escrow manifest")
	sessionKey := fs.String("session-key", "", "this host's mode-0600 session key file; destroyed after the shards are written")
	operatorKey := fs.String("operator-key", "", "base58 Store operator key the manifest must be signed by (the recovery kit's rootStore.operatorKey)")
	var handoffPaths repeatedFlag
	fs.Var(&handoffPaths, "handoff", "one holder's handoff; give it once per shard")
	_ = fs.Parse(args)
	if *manifestPath == "" || *sessionKey == "" || *operatorKey == "" || len(handoffPaths) == 0 {
		log.Fatalf("store-identity-restore: -manifest, -session-key, -operator-key and -handoff are required")
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := setProgramIDFromConfig(cfg.ProgramID); err != nil {
		log.Fatalf("config: %v", err)
	}
	manifest, err := readBoundedInput(*manifestPath, maxStoreIdentityInputBytes)
	if err != nil {
		log.Fatalf("store-identity-restore: read manifest: %v", err)
	}
	var handoffs [][]byte
	for _, path := range handoffPaths {
		raw, err := readBoundedInput(path, maxStoreIdentityInputBytes)
		if err != nil {
			log.Fatalf("store-identity-restore: read handoff %s: %v", path, err)
		}
		handoffs = append(handoffs, raw)
	}
	if err := restoreStoreIdentity(cfg, manifest, *operatorKey, *sessionKey, handoffs); err != nil {
		log.Fatalf("store-identity-restore: %v", err)
	}
	printJSONReport("store-identity-restore", map[string]string{"schema": "melusina.store-identity-restore-report.v1", "storeId": cfg.StoreID, "operatorKey": *operatorKey, "shardsDir": filepath.Clean(cfg.BootIdentity.ShardsDir)})
}
