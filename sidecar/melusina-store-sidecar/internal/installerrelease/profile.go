package installerrelease

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ErrProfile names every refusal of the estate profile a Trust is read from;
// ErrEstateMismatch a reader whose chain pins are another estate's.
var (
	ErrProfile        = errors.New("installer-release-trust-profile-invalid")
	ErrEstateMismatch = errors.New("installer-release-estate-mismatch")
)

// TrustFromProfile verifies the owner-signed profile and projects its
// installer-release trust: anchors.masterMint, the vault of the `core` role
// (the master NFT custodian the foundation ceremony establishes), and
// releaseTrust. It returns the profile's verified digest beside it. Nothing
// here is a default: a profile without one of these is refused.
func TrustFromProfile(profile estateprofile.EstateProfileV1) (*Trust, string, error) {
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrProfile, err)
	}
	master, err := primitives.PubkeyFromBase58(profile.Anchors.MasterMint)
	if err != nil {
		return nil, "", fmt.Errorf("%w: anchors.masterMint: %v", ErrProfile, err)
	}
	var custodianB58 string
	for _, role := range profile.Roles {
		if role.Role == estateprofile.AuthorityRoleCore {
			custodianB58 = role.Vault
		}
	}
	if custodianB58 == "" {
		return nil, "", fmt.Errorf("%w: roles.core is missing", ErrProfile)
	}
	custodian, err := primitives.PubkeyFromBase58(custodianB58)
	if err != nil {
		return nil, "", fmt.Errorf("%w: roles.core.vault: %v", ErrProfile, err)
	}
	keys := make([][32]byte, 0, len(profile.ReleaseTrust.PublisherKeys))
	for _, encoded := range profile.ReleaseTrust.PublisherKeys {
		raw, err := hex.DecodeString(encoded)
		if err != nil || len(raw) != 32 {
			return nil, "", fmt.Errorf("%w: releaseTrust.publisherKeys", ErrProfile)
		}
		keys = append(keys, [32]byte(raw))
	}
	trust, err := NewTrust(master, custodian, keys, profile.ReleaseTrust.Threshold)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrProfile, err)
	}
	return trust, digest, nil
}

// LoadProfileTrust reads the owner-signed profile at path, requires its
// verified digest to be the reviewed pin, and returns its Trust and the
// profile. A signed profile is not its own authority (anyone can sign one for
// an estate of their own making), so the pin comes from the caller's own
// root-owned configuration and is compared before any value is used.
func LoadProfileTrust(path, pin string) (*Trust, estateprofile.EstateProfileV1, error) {
	var zero estateprofile.EstateProfileV1
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, zero, fmt.Errorf("%w: profile path must be an absolute clean path", ErrProfile)
	}
	if len(pin) != 64 {
		return nil, zero, fmt.Errorf("%w: profile pin must be the 64-character lowercase profileSha256", ErrProfile)
	}
	if decoded, err := hex.DecodeString(pin); err != nil || hex.EncodeToString(decoded) != pin {
		return nil, zero, fmt.Errorf("%w: profile pin must be the 64-character lowercase profileSha256", ErrProfile)
	}
	raw, err := readRegularNoFollow(path, estateprofile.MaxProfileJSONBytes)
	if err != nil {
		return nil, zero, fmt.Errorf("%w: read: %v", ErrProfile, err)
	}
	profile, err := estateprofile.DecodeProfile(raw)
	if err != nil {
		return nil, zero, fmt.Errorf("%w: %v", ErrProfile, err)
	}
	trust, digest, err := TrustFromProfile(profile)
	if err != nil {
		return nil, zero, err
	}
	if digest != pin {
		return nil, zero, fmt.Errorf("%w: profile sha256 %s is not the pinned %s", ErrProfile, digest, pin)
	}
	return trust, profile, nil
}

// LoadBoundTrust is LoadProfileTrust for a reader that derives entries from
// its own program and master-mint pins: those pins must be the pinned
// profile's programs.license-registry and anchors.masterMint, because an
// entry admitted under one estate's publisher keys must come from the same
// estate's registry.
func LoadBoundTrust(path, pin string, program, masterMint [32]byte) (*Trust, error) {
	trust, profile, err := LoadProfileTrust(path, pin)
	if err != nil {
		return nil, err
	}
	programB58, ok := LicenseRegistryProgramID(profile)
	if !ok {
		return nil, fmt.Errorf("%w:programId: the profile names no programs.license-registry", ErrEstateMismatch)
	}
	profileProgram, err := primitives.PubkeyFromBase58(programB58)
	if err != nil || [32]byte(profileProgram) != program {
		return nil, fmt.Errorf("%w:programId: pinned program %s is not the profile's programs.license-registry %s", ErrEstateMismatch, primitives.Pubkey(program).Base58(), programB58)
	}
	if trust.MasterNFTMint() != masterMint {
		return nil, fmt.Errorf("%w:masterNftMint: pinned master %s is not the profile's anchors.masterMint %s", ErrEstateMismatch, primitives.Pubkey(masterMint).Base58(), profile.Anchors.MasterMint)
	}
	return trust, nil
}

// LicenseRegistryProgramID is the profile's programs.license-registry id.
func LicenseRegistryProgramID(profile estateprofile.EstateProfileV1) (string, bool) {
	for _, program := range profile.Programs {
		if program.Role == estateprofile.ProgramRoleLicenseRegistry {
			return program.ProgramID, true
		}
	}
	return "", false
}

func readRegularNoFollow(path string, limit int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("exceeds %d bytes", limit)
	}
	return raw, nil
}
