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

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// estateBinding is every estate fact mel-release and its provider use. Each
// field is a projection of the verified profile; none has a default.
type estateBinding struct {
	ProfileSHA256    string
	EstateID         string          // estateId (immutable for the estate)
	StoreOrigin      string          // "https://" + store.rootDomain
	StoreDomain      string          // store.rootDomain
	StoreID          string          // store.storeId
	StoreOperatorKey string          // store.operatorKey
	ProgramID        string          // programs.license-registry.programId
	MasterNftMint    string          // anchors.masterMint
	Squads           SquadsAuthority // roles.store-release + externalPrograms.squads-v4
	// PublisherKeys and PublisherThreshold are releaseTrust: the publishers
	// the owners enrolled. approve admits a ReleaseEntry only when one of
	// these keys signed it (see releaseEntryTrust).
	PublisherKeys      []string // releaseTrust.publisherKeys (lowercase hex)
	PublisherThreshold uint32   // releaseTrust.threshold
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
// Every path that uses a build runs it: a fresh build (ensureBuilt,
// loadOrBuildPreflight), a cached preflight build, and a saved preflight
// receipt (verifyExistingPreflight). A publish resumed past INIT and a frozen
// candidate carry the build's mint instead; requireWALEstate and
// requireCandidateEstate check those.
func requireEstateMasterMint(c Config, b buildReceipt) error {
	if c.MasterNftMint == "" {
		return errors.New("no estate master mint is bound; refusing a build receipt")
	}
	if b.MasterNftMint != c.MasterNftMint {
		return fmt.Errorf("build receipt masterNftMint %s is not the estate profile's anchors.masterMint %s", b.MasterNftMint, c.MasterNftMint)
	}
	return nil
}

// requireWALEstate refuses to resume a release WAL whose build was seeded by
// another master mint. A WAL past INIT journals the mint its build receipt
// named, and a resume from BUILT goes straight to staging without reading the
// build again, so the check belongs to the WAL itself.
func requireWALEstate(c Config, rec walReceipt) error {
	if rec.State == stateInit && rec.MasterNftMint == "" {
		return nil
	}
	if c.MasterNftMint == "" {
		return errors.New("no estate master mint is bound; refusing to resume a release WAL")
	}
	if rec.MasterNftMint != c.MasterNftMint {
		return fmt.Errorf("%s WAL for app %s: masterNftMint %s is not the estate profile's anchors.masterMint %s; "+
			"it was built for another estate and cannot be resumed under this profile", rec.State, rec.AppID, rec.MasterNftMint, c.MasterNftMint)
	}
	return nil
}

// requireCandidateEstate refuses a frozen candidate that another estate
// produced: approve, reject-proposed and repair-catalog act on the release it
// names, so its ReleaseEntry seed and registry, its Store and its bundle
// origin must all be the bound estate's.
func requireCandidateEstate(c Config, rec walReceipt, cand candidateReceipt) error {
	if err := requireWALEstate(c, rec); err != nil {
		return err
	}
	for _, field := range []struct{ name, got, want, source string }{
		{"chain.masterNftMint", cand.Component.Chain.MasterNftMint, c.MasterNftMint, "anchors.masterMint"},
		{"chain.program", cand.Component.Chain.Program, c.ProgramID, "programs.license-registry"},
		{"storeId", cand.StoreID, c.StoreID, "store.storeId"},
		{"bundleOrigin", cand.BundleOrigin, c.BundleOrigin, "Store origin"},
	} {
		if field.want == "" {
			return fmt.Errorf("no estate %s is bound; refusing a frozen candidate", field.source)
		}
		if field.got != field.want {
			return fmt.Errorf("candidate for app %s: %s %s is not the estate profile's %s %s; it belongs to another estate",
				rec.AppID, field.name, field.got, field.source, field.want)
		}
	}
	return nil
}

// requireEstateStoreIdentity refuses a Store operator identity
// (MEL_RELEASE_STORE_PUBKEY, the destination submit seals every stage and
// promote request to) that is not the estate's Store. Its signing key must be
// the profile's store.operatorKey, the key the Store checks its own operator
// identity against (its store_authority is projected onto store.operatorKey),
// and it must be a sidecar identity derived under the estate's registry.
func requireEstateStoreIdentity(path string, estate estateBinding) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("must be an absolute clean path")
	}
	raw, err := readRegularFile(path, maxReceiptBytes)
	if err != nil {
		return err
	}
	public, err := identity.ParsePublicJSON(raw)
	if err != nil {
		return fmt.Errorf("store operator identity.Public: %w", err)
	}
	if public.Ref.Kind != identity.KindSidecar {
		return fmt.Errorf("ref.kind %q is not a Store sidecar identity", public.Ref.Kind)
	}
	if estate.StoreOperatorKey == "" || public.SignPubkeyB58 != estate.StoreOperatorKey {
		return fmt.Errorf("sign_pubkey_b58 %s is not the estate profile's store.operatorKey %s; this identity names another Store", public.SignPubkeyB58, estate.StoreOperatorKey)
	}
	if public.Ref.ProgramID != estate.ProgramID {
		return fmt.Errorf("ref.program_id %s is not the estate profile's programs.license-registry %s", public.Ref.ProgramID, estate.ProgramID)
	}
	return nil
}

func readEstateProfile(path string) ([]byte, error) {
	raw, err := readRegularFile(path, estateprofile.MaxProfileJSONBytes)
	if err != nil {
		return nil, fmt.Errorf("estate profile: %w", err)
	}
	return raw, nil
}

// readRegularFile reads a regular file (never a symlink or device) of at most
// limit bytes.
func readRegularFile(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("must be a regular file, not a symlink or device")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("exceeds %d bytes", limit)
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
		ProfileSHA256:    digest,
		EstateID:         profile.EstateID,
		StoreOrigin:      "https://" + profile.Store.RootDomain,
		StoreDomain:      profile.Store.RootDomain,
		StoreID:          profile.Store.StoreID,
		StoreOperatorKey: profile.Store.OperatorKey,
		ProgramID:        registry,
		MasterNftMint:    profile.Anchors.MasterMint,
		Squads: SquadsAuthority{
			Multisig:    release.Multisig,
			Vault:       release.Vault,
			ProgramID:   squadsProgram,
			Threshold:   int(release.Threshold),
			MemberCount: int(release.MemberCount),
		},
		PublisherKeys:      append([]string(nil), profile.ReleaseTrust.PublisherKeys...),
		PublisherThreshold: profile.ReleaseTrust.Threshold,
	}
	return binding, nil
}
