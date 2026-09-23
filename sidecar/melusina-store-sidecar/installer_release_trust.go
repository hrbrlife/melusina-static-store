package main

import (
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// bindInstallerReleaseTrust sets cfg's installer-release trust from the
// enrolled estate profile, the only source the Store has for which publisher
// keys the owners trust and which vault holds the master NFT. It must run
// after verifyConfiguredStoreEnrollment has verified state against this very
// config and before any handler is built from cfg. With no enrolled state the
// trust stays nil, and every InstallerReleaseEntry gate refuses by name.
func bindInstallerReleaseTrust(cfg *Config, state *storeEnrollmentState) error {
	cfg.installerReleaseTrust = nil
	if state == nil {
		return nil
	}
	trust, digest, err := installerrelease.TrustFromProfile(state.Profile)
	if err != nil {
		return fmt.Errorf("installer-release trust: %w", err)
	}
	if digest != state.ProfilePin.ProfileSHA256 {
		return fmt.Errorf("installer-release trust: %w: profile sha256 %s is not the enrolled pin %s", installerrelease.ErrProfile, digest, state.ProfilePin.ProfileSHA256)
	}
	masterB58 := strings.TrimSpace(cfg.ReleaseMasterNftMint)
	if masterB58 == "" {
		masterB58 = strings.TrimSpace(cfg.Mirror.RootMasterNftMint)
	}
	master, err := primitives.PubkeyFromBase58(masterB58)
	if err != nil || [32]byte(master) != trust.MasterNFTMint() {
		return fmt.Errorf("installer-release trust: %w:masterNftMint: the configured release master %q is not the enrolled profile's anchors.masterMint %s", installerrelease.ErrEstateMismatch, masterB58, state.Profile.Anchors.MasterMint)
	}
	cfg.installerReleaseTrust = trust
	return nil
}
