package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// errAppReleaseTrustProfile names an enrolled profile or configuration the
// app-release trust cannot be projected from.
var errAppReleaseTrustProfile = errors.New("app-release-trust-profile")

// bindAppReleaseTrust sets cfg's app-release trust from the enrolled estate
// profile, as bindInstallerReleaseTrust does for installer releases and as
// `mel-release` does for the same rule (cmd/mel-release/readback.go
// releaseEntryTrust): the profile's anchors.masterMint, the release custodian
// (roles.store-release's vault, the vault the Store already requires every
// served release to name) and releaseTrust's publisher keys and threshold.
// Each of the first two must also be what this Store's configuration names;
// a disagreement refuses startup by name. With no enrolled state the trust
// stays nil and the /publish admission applies its build's rule
// (unboundAppReleaseTrustRefusal).
func bindAppReleaseTrust(cfg *Config, state *storeEnrollmentState) error {
	cfg.appReleaseTrust = nil
	if state == nil {
		return nil
	}
	digest, err := estateprofile.VerifyProfile(state.Profile)
	if err != nil {
		return fmt.Errorf("%w: %v", errAppReleaseTrustProfile, err)
	}
	if digest != state.ProfilePin.ProfileSHA256 {
		return fmt.Errorf("%w: profile sha256 %s is not the enrolled pin %s", errAppReleaseTrustProfile, digest, state.ProfilePin.ProfileSHA256)
	}
	profile := state.Profile
	master, err := primitives.PubkeyFromBase58(profile.Anchors.MasterMint)
	if err != nil {
		return fmt.Errorf("%w: anchors.masterMint: %v", errAppReleaseTrustProfile, err)
	}
	configuredMaster := strings.TrimSpace(cfg.ReleaseMasterNftMint)
	if configuredMaster == "" {
		configuredMaster = strings.TrimSpace(cfg.Mirror.RootMasterNftMint)
	}
	if configured, err := primitives.PubkeyFromBase58(configuredMaster); err != nil || configured != master {
		return fmt.Errorf("%w:masterNftMint: the configured release master %q is not the enrolled profile's anchors.masterMint %s", errAppReleaseTrustProfile, configuredMaster, profile.Anchors.MasterMint)
	}
	role, ok := profileStoreReleaseRole(profile)
	if !ok {
		return fmt.Errorf("%w: roles.store-release is missing", errAppReleaseTrustProfile)
	}
	custodian, err := primitives.PubkeyFromBase58(role.Vault)
	if err != nil {
		return fmt.Errorf("%w: roles.store-release.vault: %v", errAppReleaseTrustProfile, err)
	}
	if strings.TrimSpace(cfg.ReleaseSquadsAuthority.Vault) != role.Vault {
		return fmt.Errorf("%w:releaseCustodian: release_squads_authority.vault %q is not the enrolled profile's roles.store-release vault %s", errAppReleaseTrustProfile, cfg.ReleaseSquadsAuthority.Vault, role.Vault)
	}
	keys := make([][32]byte, 0, len(profile.ReleaseTrust.PublisherKeys))
	for _, encoded := range profile.ReleaseTrust.PublisherKeys {
		raw, err := hex.DecodeString(encoded)
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("%w: releaseTrust.publisherKeys", errAppReleaseTrustProfile)
		}
		keys = append(keys, [32]byte(raw))
	}
	trust, err := releaseentry.NewTrust([32]byte(master), [32]byte(custodian), keys, profile.ReleaseTrust.Threshold)
	if err != nil {
		return fmt.Errorf("%w: %v", errAppReleaseTrustProfile, err)
	}
	cfg.appReleaseTrust = trust
	return nil
}

// admitReleaseEntryForPublish is the /publish admission of the ReleaseEntry
// meta (read at the PDA derived from rel's master mint and appHash, Active and
// pinning appHash, as verifyReleaseEntryHash already established). The Store
// is about to sign rel.ReleaseHash into its receipt and catalog pointer, and
// the tenant's authorization daemon refuses a receipt whose release hash or
// app is not the entry's (evalRelease: release-hash-mismatch,
// release-appid-mismatch). So the entry must attest exactly this release:
// app_hash, app_id = sha256(metadata appId), release_hash and version. With
// the enrolled estate's trust bound it is admitted in full, as `mel-release`
// admits it before every promote: the estate master mint, the release
// custodian, the recorded digest, a publisher key the owners enrolled in
// releaseTrust, the threshold and that key's signature. Every refusal names
// check=release_entry_admission and the releaseentry refusal.
func admitReleaseEntryForPublish(cfg Config, appHash [32]byte, meta releaseEntryMeta, rel ReleaseJSON, appIDText string) error {
	releaseHash, err := hash32FromHex(strings.ToLower(strings.TrimSpace(rel.ReleaseHash)))
	if err != nil {
		return fmt.Errorf("check=release_entry_admission: release.releaseHash is not 32-byte hex: %w", err)
	}
	want := releaseentry.Expectation{
		AppHash:     appHash,
		AppID:       releaseentry.AppIDHash(appIDText),
		ReleaseHash: releaseHash,
		Version:     strings.TrimSpace(rel.Version),
	}
	entry := meta.entry()
	if cfg.appReleaseTrust != nil {
		if err := cfg.appReleaseTrust.Admit(entry, want); err != nil {
			return fmt.Errorf("check=release_entry_admission: ReleaseEntry %s: %w", meta.PDA, err)
		}
		return nil
	}
	if err := unboundAppReleaseTrustRefusal(cfg); err != nil {
		return fmt.Errorf("check=release_entry_admission: ReleaseEntry %s: %w", meta.PDA, err)
	}
	if err := entry.Attests(want); err != nil {
		return fmt.Errorf("check=release_entry_admission: ReleaseEntry %s: %w", meta.PDA, err)
	}
	return nil
}
