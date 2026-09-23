package main

// Estate binding. mel-release publishes into exactly one Store: the root Store
// of the estate named by an owner-signed EstateProfileV1, the same document the
// Store's own configuration is rendered from and checked against
// (`melusina-store-sidecar estate-store-config-render` and
// `estate-profile-check`). Nothing about a Store, its license registry, its
// master mint or its release authority is compiled into this CLI.
//
// A signed profile is not its own authority: anyone can sign a well-formed
// profile for an estate of their own making. The operator therefore names the
// reviewed digest separately (MEL_RELEASE_ESTATE_PROFILE_SHA256, the
// `profileSha256` that `melusina-store-sidecar estate-profile-review` prints
// and that the Store's render input already pins), and a profile whose
// verified digest differs is refused before any value is read from it.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// estateBinding is every estate fact mel-release and its provider use. Each
// field is a projection of the verified profile; none has a default.
type estateBinding struct {
	ProfileSHA256 string
	StoreOrigin   string          // "https://" + store.rootDomain
	StoreDomain   string          // store.rootDomain
	StoreID       string          // store.storeId
	ProgramID     string          // programs.license-registry.programId
	MasterNftMint string          // anchors.masterMint
	Squads        SquadsAuthority // roles.store-release + externalPrograms.squads-v4
}

// loadEstateBinding reads, verifies and pins the owner-signed profile, then
// derives the binding with the refusals the Store's own profile check applies
// (a root Store whose release role is a Squads store-release authority).
func loadEstateBinding(path, pin string) (estateBinding, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return estateBinding{}, errors.New("MEL_RELEASE_ESTATE_PROFILE must be an absolute clean path")
	}
	if !isLowerHex(pin, 64) {
		return estateBinding{}, errors.New("MEL_RELEASE_ESTATE_PROFILE_SHA256 must be the 64-character lowercase profileSha256 from estate-profile-review")
	}
	raw, err := readEstateProfile(path)
	if err != nil {
		return estateBinding{}, err
	}
	profile, err := estateprofile.DecodeProfile(raw)
	if err != nil {
		return estateBinding{}, fmt.Errorf("estate profile: %w", err)
	}
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		return estateBinding{}, fmt.Errorf("estate profile: %w", err)
	}
	if digest != pin {
		return estateBinding{}, fmt.Errorf("estate profile sha256 %s is not the reviewed MEL_RELEASE_ESTATE_PROFILE_SHA256 %s", digest, pin)
	}
	return estateBindingOf(profile, digest)
}

// requireEstateMasterMint refuses a build whose ReleaseEntry seed is not the
// estate's master mint. The provider names the mint it will register under;
// a mint from another estate would derive a ReleaseEntry the Store never reads.
func requireEstateMasterMint(c Config, b buildReceipt) error {
	if c.MasterNftMint == "" {
		return errors.New("no estate master mint is bound; refusing a build receipt")
	}
	if b.MasterNftMint != c.MasterNftMint {
		return fmt.Errorf("build receipt masterNftMint %s is not the estate profile's anchors.masterMint %s", b.MasterNftMint, c.MasterNftMint)
	}
	return nil
}

func readEstateProfile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("estate profile: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("estate profile must be a regular file, not a symlink or device")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("estate profile: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, estateprofile.MaxProfileJSONBytes+1))
	if err != nil {
		return nil, fmt.Errorf("estate profile: %w", err)
	}
	if len(raw) > estateprofile.MaxProfileJSONBytes {
		return nil, fmt.Errorf("estate profile exceeds %d bytes", estateprofile.MaxProfileJSONBytes)
	}
	return raw, nil
}

// estateBindingOf reads the binding out of a profile VerifyProfile has
// accepted, which has already refused a malformed domain, address, quorum or
// role vocabulary. What remains is the Store-specific shape.
func estateBindingOf(profile estateprofile.EstateProfileV1, digest string) (estateBinding, error) {
	if !profile.Store.IsRoot {
		return estateBinding{}, errors.New("estate profile store is not a root Store")
	}
	if profile.Store.ReleaseRole != estateprofile.AuthorityRoleStoreRelease {
		return estateBinding{}, fmt.Errorf("estate profile store.releaseRole %q is not %q", profile.Store.ReleaseRole, estateprofile.AuthorityRoleStoreRelease)
	}
	var (
		release       estateprofile.AuthorityRoleV1
		foundRelease  bool
		registry      string
		squadsProgram string
	)
	for _, role := range profile.Roles {
		if role.Role == estateprofile.AuthorityRoleStoreRelease {
			release, foundRelease = role, true
		}
	}
	if !foundRelease || release.Kind != estateprofile.AuthorityKindSquads {
		return estateBinding{}, fmt.Errorf("estate profile has no Squads roles.%s authority", estateprofile.AuthorityRoleStoreRelease)
	}
	for _, program := range profile.Programs {
		if program.Role == estateprofile.ProgramRoleLicenseRegistry {
			registry = program.ProgramID
		}
	}
	for _, program := range profile.ExternalPrograms {
		if program.Role == estateprofile.ExternalRoleSquadsV4 {
			squadsProgram = program.ProgramID
		}
	}
	if registry == "" {
		return estateBinding{}, fmt.Errorf("estate profile has no programs.%s", estateprofile.ProgramRoleLicenseRegistry)
	}
	if squadsProgram == "" {
		return estateBinding{}, fmt.Errorf("estate profile has no externalPrograms.%s", estateprofile.ExternalRoleSquadsV4)
	}
	binding := estateBinding{
		ProfileSHA256: digest,
		StoreOrigin:   "https://" + profile.Store.RootDomain,
		StoreDomain:   profile.Store.RootDomain,
		StoreID:       profile.Store.StoreID,
		ProgramID:     registry,
		MasterNftMint: profile.Anchors.MasterMint,
		Squads: SquadsAuthority{
			Multisig:    release.Multisig,
			Vault:       release.Vault,
			ProgramID:   squadsProgram,
			Threshold:   int(release.Threshold),
			MemberCount: int(release.MemberCount),
		},
	}
	return binding, nil
}
