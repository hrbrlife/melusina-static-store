package estateprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// signUnchecked signs a profile's digest without validating it first, as a
// careless owner tool could, so a refusal below is the validator's own and
// never a missing or stale signature.
func signUnchecked(t *testing.T, profile EstateProfileV1, keyIDs ...string) EstateProfileV1 {
	t.Helper()
	profile.Signatures = nil
	profile.Signatures = signDigest(profile.OwnerPolicy, sha256Hex(profilePreimage(profile)), keyIDs...)
	return profile
}

// withRole returns profile with one role edited, on a copy of the role list.
func withRole(t *testing.T, profile EstateProfileV1, role string, edit func(*AuthorityRoleV1)) EstateProfileV1 {
	t.Helper()
	roles := append([]AuthorityRoleV1(nil), profile.Roles...)
	for index := range roles {
		if roles[index].Role == role {
			edit(&roles[index])
			profile.Roles = roles
			return profile
		}
	}
	t.Fatalf("the fixture has no %s role", role)
	return profile
}

// storeReleaseThresholdOne is the rehearsal profile with its Store release
// multisig at 1 of 3, signed by a threshold of its owners anyway.
func storeReleaseThresholdOne(t *testing.T) EstateProfileV1 {
	t.Helper()
	profile := withRole(t, newEstateProfile(t), AuthorityRoleStoreRelease, func(role *AuthorityRoleV1) { role.Threshold = 1 })
	return signUnchecked(t, profile, "owner-a", "owner-b")
}

// storeReleaseSingleKey is the rehearsal profile with its Store release role
// stated as one key, in the key kind's one closed shape, owner-signed.
func storeReleaseSingleKey(t *testing.T) EstateProfileV1 {
	t.Helper()
	profile := withRole(t, newEstateProfile(t), AuthorityRoleStoreRelease, func(role *AuthorityRoleV1) {
		*role = AuthorityRoleV1{
			Role: AuthorityRoleStoreRelease, Kind: AuthorityKindKey,
			Vault: role.Vault, Threshold: 1, MemberCount: 1, PermissionMasks: []uint32{},
		}
	})
	return signUnchecked(t, profile, "owner-a", "owner-b")
}

// An enrolled Store refuses a release authority below two and requires its
// configured threshold to equal roles.store-release exactly (Store
// squads_authority.go configuredEnrolledReleaseSquadsAuthorityPolicy and
// estate_profile_check.go verifyStoreEstateDeclaration), so a profile stating
// 1 of N is refused here, before owners can sign an estate whose root Store
// can never be configured. The owners' signatures do not change that.
func TestValidateRequiresAStoreReleaseQuorumOfTwo(t *testing.T) {
	// Positive control: the fixture's 2 of 3 is the least the Store accepts.
	accepted := newEstateProfile(t)
	if role := accepted.Roles[2]; role.Role != AuthorityRoleStoreRelease || role.Threshold != StoreReleaseMinThreshold {
		t.Fatalf("the fixture's store-release role is not at the minimum: %+v", role)
	}
	if _, err := DecodeProfile(marshalProfile(t, accepted)); err != nil {
		t.Fatalf("a 2-of-3 Store release role must decode: %v", err)
	}
	if _, err := VerifyProfile(accepted); err != nil {
		t.Fatalf("a 2-of-3 Store release role must verify: %v", err)
	}

	refused := storeReleaseThresholdOne(t)
	const want = RefusalFieldMalformed + ":roles." + AuthorityRoleStoreRelease + ".threshold"
	_, err := DecodeProfile(marshalProfile(t, refused))
	requireRefusal(t, err, want)
	_, err = VerifyProfile(refused)
	requireRefusal(t, err, want)
	_, err = ProfileSHA256(refused)
	requireRefusal(t, err, want)
}

// The minimum is the Store's, not every role's: a 1-of-N reseller multisig is
// still a profile, so the rule cannot have been widened to all Squads roles.
func TestValidateKeepsTheStoreReleaseMinimumToThatRole(t *testing.T) {
	profile := newEstateProfile(t)
	reseller := AuthorityRoleV1{
		Role: AuthorityRoleReseller, Kind: AuthorityKindSquads,
		Multisig: vectorAddress("rehearsal/reseller/multisig"), Vault: vectorAddress("rehearsal/reseller/vault"),
		Threshold: 1, MemberCount: 2, PermissionMasks: []uint32{7, 7},
		ConfigAuthority: "11111111111111111111111111111111",
	}
	profile.Roles = []AuthorityRoleV1{profile.Roles[0], reseller, profile.Roles[1], profile.Roles[2]}
	profile = signUnchecked(t, profile, "owner-a", "owner-b")
	if _, err := VerifyProfile(profile); err != nil {
		t.Fatalf("a 1-of-2 reseller role must still verify: %v", err)
	}
}

// Kind "key" is threshold one by definition and an enrolled Store refuses a
// release role that is not a multisig (store-estate-profile-release-role-not-
// squads), so roles.store-release is refused as a key by its kind. The root
// install admin, which is a key, stays accepted.
func TestValidateRefusesAStoreReleaseKey(t *testing.T) {
	accepted := newEstateProfile(t)
	if admin := accepted.Roles[1]; admin.Role != AuthorityRoleRootInstallAdmin || admin.Kind != AuthorityKindKey {
		t.Fatalf("the fixture's root install admin is not a key: %+v", admin)
	}
	if _, err := VerifyProfile(accepted); err != nil {
		t.Fatalf("a key root install admin must verify: %v", err)
	}

	refused := storeReleaseSingleKey(t)
	const want = RefusalFieldMalformed + ":roles." + AuthorityRoleStoreRelease + ".kind"
	_, err := DecodeProfile(marshalProfile(t, refused))
	requireRefusal(t, err, want)
	_, err = VerifyProfile(refused)
	requireRefusal(t, err, want)
}

// contractsCeremonyProfilePath is a byte copy of the contracts repository's
// scripts/estate/examples/example-estate.profile.json (blob c1df4a37, last
// changed in contracts c3c940b "master_registry leaves the foundation", read
// at contracts origin/main c3c940b): the document the chain foundation runs
// from, schema melusina.estate-profile/v1. A hand edit, or a copy of another
// revision, fails by name; re-copy it with `git show <commit>:<path>`.
const (
	contractsCeremonyProfilePath   = "../../testdata/contracts-example-estate.profile.json"
	contractsCeremonyProfileSHA256 = "29c66510a588c364d09b35ccb56ef20c58dfe400f0fa00dd5299122c5884c521"
)

func contractsCeremonyProfile(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(contractsCeremonyProfilePath)
	if err != nil {
		t.Fatalf("read %s: %v", contractsCeremonyProfilePath, err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != contractsCeremonyProfileSHA256 {
		t.Fatalf("CONTRACTS_CEREMONY_PROFILE_COPY_DRIFT: %s is %x, not the contracts bytes %s", contractsCeremonyProfilePath, sum, contractsCeremonyProfileSHA256)
	}
	return raw
}

// Seam audit #12: the real unsigned chain-foundation input, the contracts
// repository's own ceremony profile byte for byte, offered where an
// EstateProfileV1 is expected, is refused as the draft it is and not as a
// generic unsupported schema.
func TestTheContractsCeremonyProfileIsRefusedAsTheDraft(t *testing.T) {
	raw := contractsCeremonyProfile(t)
	var shape struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil || shape.Schema != FoundationCeremonyProfileSchema {
		t.Fatalf("the contracts ceremony profile names schema %q (%v), not %q", shape.Schema, err, FoundationCeremonyProfileSchema)
	}
	_, err := DecodeProfile(raw)
	requireRefusal(t, err, RefusalDraftNotEnrollable)
}

// longestStoreID is exactly MaxStoreIDLength characters.
const longestStoreID = "rehearsal-root-store-at-the-fifty-two-character-caps"

// remoteBakNamespaceName is the RemoteBak namespace name rule the Store's
// state namespace must satisfy: Store internal/storerecovery/namespace.go
// remoteBakNamespacePattern, the same as this module's
// internal/remotebakstore/store.go namespacePattern.
var remoteBakNamespaceName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// storeStateNamespace is the Store's StateNamespace naming, "store-" + id +
// "-g" + N, without its refusals.
func storeStateNamespace(storeID string, generation int) string {
	return "store-" + storeID + "-g" + strconv.Itoa(generation)
}

// withStoreID returns the rehearsal profile with store.storeId replaced,
// signed by a threshold of its owners without validating first.
func withStoreID(t *testing.T, storeID string) EstateProfileV1 {
	t.Helper()
	profile := newEstateProfile(t)
	profile.Store.StoreID = storeID
	return signUnchecked(t, profile, "owner-a", "owner-b")
}

// Seam audit #18: a storeId is fixed in the signed profile, and the Store's
// state backup refuses one whose namespace store-<storeId>-g<N> is longer
// than 63 characters. The profile therefore refuses at signing any id that
// could not be backed up through generation 999: 52 characters is accepted
// and its namespace at g999 is exactly 63, 53 characters is refused by name.
func TestValidateBoundsTheStoreIDToItsStateNamespace(t *testing.T) {
	if len(longestStoreID) != MaxStoreIDLength || MaxStoreIDLength != 52 {
		t.Fatalf("the longest store id is %d characters, the cap %d", len(longestStoreID), MaxStoreIDLength)
	}
	accepted := withStoreID(t, longestStoreID)
	if _, err := DecodeProfile(marshalProfile(t, accepted)); err != nil {
		t.Fatalf("a %d-character storeId must decode: %v", len(longestStoreID), err)
	}
	if _, err := VerifyProfile(accepted); err != nil {
		t.Fatalf("a %d-character storeId must verify: %v", len(longestStoreID), err)
	}
	if name := storeStateNamespace(longestStoreID, 999); len(name) != 63 || !remoteBakNamespaceName.MatchString(name) {
		t.Fatalf("the longest storeId's namespace at g999 is %q (%d characters), not a 63-character RemoteBak name", name, len(name))
	}
	if name := storeStateNamespace(longestStoreID, 1000); remoteBakNamespaceName.MatchString(name) {
		t.Fatalf("the horizon is g999, but %q is still a RemoteBak name", name)
	}

	tooLong := longestStoreID + "x"
	if name := storeStateNamespace(tooLong, 999); remoteBakNamespaceName.MatchString(name) {
		t.Fatalf("a %d-character storeId still fits at g999 (%q), so the cap is not the tightest", len(tooLong), name)
	}
	const want = RefusalFieldMalformed + ":store.storeId"
	refused := withStoreID(t, tooLong)
	_, err := DecodeProfile(marshalProfile(t, refused))
	requireRefusal(t, err, want)
	_, err = VerifyProfile(refused)
	requireRefusal(t, err, want)

	// The lower bound and the spelling are unchanged.
	for _, storeID := range []string{"ab", "rehearsal-root-store"} {
		if _, err := VerifyProfile(withStoreID(t, storeID)); err != nil {
			t.Fatalf("storeId %q must still verify: %v", storeID, err)
		}
	}
	for _, storeID := range []string{"a", "1abc", "Abc", "ab_c"} {
		_, err := VerifyProfile(withStoreID(t, storeID))
		requireRefusal(t, err, want)
	}
}
