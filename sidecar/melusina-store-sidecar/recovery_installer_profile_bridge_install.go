package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// This subcommand is run inside the root Store container by the already
// enrolled StoreHost after it has accepted and journaled F1. It persists only
// the verified public authority, beside the owner-only enrollment state.
func runEstateEnrollRecoveryInstallerBridge(args []string) {
	fs := flag.NewFlagSet("estate-enroll-recovery-installer-bridge", flag.ExitOnError)
	config := fs.String("config", "store.config.json", "enrolled Store config")
	bridge := fs.String("bridge", "", "signed recovery bridge")
	admission := fs.String("admission", "", "dual-quorum admission")
	oldProfile := fs.String("old-profile", "", "owner-signed old building profile")
	successorProfile := fs.String("successor-profile", "", "owner-signed enrolled successor profile")
	f1 := fs.String("f1", "", "publisher-signed first successor set")
	f0 := fs.String("f0", "", "publisher-signed recovery foundation set")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || *bridge == "" || *admission == "" || *oldProfile == "" || *successorProfile == "" || *f0 == "" || *f1 == "" {
		log.Fatal("recovery-installer-profile-bridge-refused:arguments")
	}
	cfg, err := LoadConfig(*config)
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
	bootCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, _, err = deriveEnrolledBootIdentity(bootCtx, cfg, *config, cr)
	cancel()
	if err != nil {
		log.Fatalf("recovery-installer-profile-bridge: %v", err)
	}
	log.Print("recovery-installer-profile-bridge: enrolled gate complete")
	if err := installRecoveryInstallerBridge(*config, *bridge, *admission, *oldProfile, *successorProfile, *f0, *f1, time.Now().UTC()); err != nil {
		log.Fatalf("recovery-installer-profile-bridge: %v", err)
	}
	fmt.Println("recovery-installer-profile-bridge-enrolled")
}

func installRecoveryInstallerBridge(configPath, bridgePath, admissionPath, oldPath, successorPath, f0Path, f1Path string, now time.Time) error {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	path := recoveryBridgePath(cfg)
	if path == "" {
		return fmt.Errorf("%w:ordinary-store", errRecoveryBridge)
	}
	enrolled, err := readStoreEnrollmentState(cfg.EstateEnrollmentStatePath, uint32(os.Geteuid()))
	if err != nil {
		return fmt.Errorf("%w:enrollment", errRecoveryBridge)
	}
	if err := requireOwnedSecureDirectory(filepath.Dir(path), 0o700, uint32(os.Geteuid())); err != nil {
		return fmt.Errorf("%w:directory", errRecoveryBridge)
	}
	read := func(name string, limit int64) ([]byte, error) {
		if !filepath.IsAbs(name) || filepath.Clean(name) != name {
			return nil, fmt.Errorf("%w:path", errRecoveryBridge)
		}
		return readOwnedRegular(name, 0o600, uint32(os.Geteuid()), limit)
	}
	bridgeRaw, err := read(bridgePath, 64<<10)
	if err != nil {
		return err
	}
	admissionRaw, err := read(admissionPath, 2<<20)
	if err != nil {
		return err
	}
	oldRaw, err := read(oldPath, 64<<10)
	if err != nil {
		return err
	}
	successorRaw, err := read(successorPath, 64<<10)
	if err != nil {
		return err
	}
	f1Raw, err := read(f1Path, 8<<20)
	if err != nil {
		return err
	}
	f0Raw, err := read(f0Path, 8<<20)
	if err != nil {
		return err
	}
	var bridge recoveryInstallerBridge
	if assertNoDuplicateJSONKeys(bridgeRaw) != nil || decodeCatalogStrictJSON(bridgeRaw, &bridge) != nil {
		return fmt.Errorf("%w:bridge-json", errRecoveryBridge)
	}
	unsigned := bridge
	unsigned.OwnerSignatures, unsigned.CouncilSignatures = nil, nil
	preimage, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	state := recoveryBridgeState{Schema: recoveryBridgeStateSchema, BridgeRaw: bridgeRaw, AdmissionRaw: admissionRaw,
		AdmissionRawSHA256: recoverySHA(admissionRaw),
		OldProfileRaw:      oldRaw, SuccessorProfileRaw: successorRaw, F0Raw: f0Raw, F1Raw: f1Raw,
		BridgeSHA256: recoveryDigest(recoveryBridgeDomain, preimage), F0RawSHA256: recoverySHA(f0Raw), F1RawSHA256: recoverySHA(f1Raw)}
	_, f0Digest, err := verifySignedReleaseSet(f0Raw, enrolled.Profile.ReleaseTrust.PublisherKeys, enrolled.Profile.ReleaseTrust.Threshold)
	if err != nil {
		return fmt.Errorf("%w:f0-signature", errRecoveryBridge)
	}
	state.F0Digest = f0Digest
	_, f1Digest, err := verifySignedReleaseSet(f1Raw, enrolled.Profile.ReleaseTrust.PublisherKeys, enrolled.Profile.ReleaseTrust.Threshold)
	if err != nil {
		return fmt.Errorf("%w:f1-signature", errRecoveryBridge)
	}
	state.F1Digest = f1Digest
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if _, _, _, err := decodeRecoveryBridgeState(raw, &enrolled, now); err != nil {
		return err
	}
	measuredBinary, err := recoveryExecutableSHA()
	if err != nil || measuredBinary != bridge.StoreBinarySHA256 {
		return fmt.Errorf("%w:store-binary", errRecoveryBridge)
	}
	if existing, err := readOwnedRegular(path, 0o600, uint32(os.Geteuid()), 3<<20); err == nil {
		if bytes.Equal(existing, raw) {
			return nil
		}
		return fmt.Errorf("%w:replay", errRecoveryBridge)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, file, err := createStoreEnrollmentStateTemp(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		return fmt.Errorf("%w:one-use: %v", errRecoveryBridge, err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
