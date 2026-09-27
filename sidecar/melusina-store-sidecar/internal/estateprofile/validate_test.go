package estateprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"sort"
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
// multisig at 1 of 4, signed by a threshold of its owners anyway.
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

// storeReleaseSeparateMultisig is the rehearsal profile with its Store
// release role as its own well-formed 2-of-3 Squads multisig - every per-role
// rule passes - owner-signed: what a founder declaring a separate
// store-release multisig would sign (K-CHN-03).
func storeReleaseSeparateMultisig(t *testing.T) EstateProfileV1 {
	t.Helper()
	profile := withRole(t, newEstateProfile(t), AuthorityRoleStoreRelease, func(role *AuthorityRoleV1) {
		*role = AuthorityRoleV1{
			Role: AuthorityRoleStoreRelease, Kind: AuthorityKindSquads,
			Multisig: vectorAddress("rehearsal/store-release/multisig"), Vault: vectorAddress("rehearsal/store-release/vault"),
			Threshold: 2, MemberCount: 3, PermissionMasks: []uint32{7, 7, 7},
			ConfigAuthority: "11111111111111111111111111111111",
		}
	})
	return signUnchecked(t, profile, "owner-a", "owner-b")
}

// K-CHN-03: the licence registry creates every app ReleaseEntry under the
// core vault and the Store serves an app only from roles.store-release's
// vault, so roles.store-release is core's authority by rule. The positive
// control is the fixture, whose store-release role is core's in every field;
// the negative controls change one field each, and a separate multisig, and
// every one is refused by the one name, by decode, verify and digest alike.
func TestValidateRequiresStoreReleaseToBeCore(t *testing.T) {
	accepted := newEstateProfile(t)
	core, release := accepted.Roles[0], accepted.Roles[2]
	if core.Role != AuthorityRoleCore || release.Role != AuthorityRoleStoreRelease || release.Multisig != core.Multisig || release.Vault != core.Vault {
		t.Fatalf("the fixture's store-release role is not core's authority: core %+v, store-release %+v", core, release)
	}
	if _, err := DecodeProfile(marshalProfile(t, accepted)); err != nil {
		t.Fatalf("a store-release role that is core must decode: %v", err)
	}
	if _, err := VerifyProfile(accepted); err != nil {
		t.Fatalf("a store-release role that is core must verify: %v", err)
	}

	cases := map[string]func(*AuthorityRoleV1){
		"separate-multisig": func(role *AuthorityRoleV1) {
			*role = storeReleaseSeparateMultisig(t).Roles[2]
		},
		"vault":     func(role *AuthorityRoleV1) { role.Vault = vectorAddress("rehearsal/store-release/vault") },
		"multisig":  func(role *AuthorityRoleV1) { role.Multisig = vectorAddress("rehearsal/store-release/multisig") },
		"threshold": func(role *AuthorityRoleV1) { role.Threshold = 2 },
		"member-count": func(role *AuthorityRoleV1) {
			role.MemberCount, role.PermissionMasks = 5, []uint32{7, 7, 7, 7, 7}
		},
		"permission-masks": func(role *AuthorityRoleV1) { role.PermissionMasks = []uint32{3, 7, 7, 7} },
		"config-authority": func(role *AuthorityRoleV1) { role.ConfigAuthority = vectorAddress("rehearsal/store-release/config") },
		"time-lock":        func(role *AuthorityRoleV1) { role.TimeLockSeconds = 60 },
	}
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			refused := signUnchecked(t, withRole(t, newEstateProfile(t), AuthorityRoleStoreRelease, cases[name]), "owner-a", "owner-b")
			_, err := DecodeProfile(marshalProfile(t, refused))
			requireRefusal(t, err, RefusalStoreReleaseNotCore)
			_, err = VerifyProfile(refused)
			requireRefusal(t, err, RefusalStoreReleaseNotCore)
			_, err = ProfileSHA256(refused)
			requireRefusal(t, err, RefusalStoreReleaseNotCore)
		})
	}

	// A profile with no store-release role is not refused by this rule: the
	// rule ties the role to core, it does not require the role.
	withoutRelease := newEstateProfile(t)
	withoutRelease.Roles = []AuthorityRoleV1{withoutRelease.Roles[0], withoutRelease.Roles[1]}
	withoutRelease.Store.ReleaseRole = AuthorityRoleCore
	if err := ValidateProfile(withoutRelease); err != nil {
		t.Fatalf("a profile with no store-release role is not this rule's refusal: %v", err)
	}
}

// An enrolled Store refuses a release authority below two and requires its
// configured threshold to equal roles.store-release exactly (Store
// squads_authority.go configuredEnrolledReleaseSquadsAuthorityPolicy and
// estate_profile_check.go verifyStoreEstateDeclaration), so a profile stating
// 1 of N is refused here, before owners can sign an estate whose root Store
// can never be configured. The owners' signatures do not change that. The
// per-role rule runs before the store-release-is-core rule, so this keeps
// its own name.
func TestValidateRequiresAStoreReleaseQuorumOfTwo(t *testing.T) {
	// Positive control: the fixture's store-release role, core's 3 of 4, is
	// at least the least the Store accepts.
	accepted := newEstateProfile(t)
	if role := accepted.Roles[2]; role.Role != AuthorityRoleStoreRelease || role.Threshold < StoreReleaseMinThreshold {
		t.Fatalf("the fixture's store-release role is below the minimum: %+v", role)
	}
	if _, err := DecodeProfile(marshalProfile(t, accepted)); err != nil {
		t.Fatalf("the fixture's Store release role must decode: %v", err)
	}
	if _, err := VerifyProfile(accepted); err != nil {
		t.Fatalf("the fixture's Store release role must verify: %v", err)
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

// WL-111 / S-21: the estate runner is a non-voting seat, and as a role it is
// a single machine key (kind "key"): no multisig, no threshold, no masks. A
// runner spelled as a squads multisig is refused by name; the key-kind seat
// verifies.
func TestValidateRefusesARunnerSeatThatCanVote(t *testing.T) {
	squadsKind := newEstateProfile(t)
	squadsKind.Roles = insertSortedRole(squadsKind.Roles, AuthorityRoleV1{
		Role: AuthorityRoleRunner, Kind: AuthorityKindSquads,
		Multisig: vectorAddress("rehearsal/runner/multisig"), Vault: vectorAddress("rehearsal/runner/vault"),
		Threshold: 0, MemberCount: 1, PermissionMasks: []uint32{7},
		ConfigAuthority: "11111111111111111111111111111111", TimeLockSeconds: 0,
	})
	squadsKind = signUnchecked(t, squadsKind, "owner-a", "owner-b")
	const want = RefusalFieldMalformed + ":roles." + AuthorityRoleRunner + ".kind"
	if err := refuseMatches(t, squadsKind, want); err != nil {
		t.Fatal(err)
	}

	// The key-kind runner seat — the machine's one address — verifies.
	seat := newEstateProfile(t)
	seat.Roles = insertSortedRole(seat.Roles, AuthorityRoleV1{
		Role: AuthorityRoleRunner, Kind: AuthorityKindKey,
		Vault: vectorAddress("rehearsal/runner/key"), Threshold: 1, MemberCount: 1,
		PermissionMasks: []uint32{},
	})
	seat = signUnchecked(t, seat, "owner-a", "owner-b")
	if _, err := VerifyProfile(seat); err != nil {
		t.Fatalf("a key-kind runner seat must verify: %v", err)
	}
}

// A squads-shaped runner seat is refused by its kind (the live refusal at
// validate.go: a runner is a single machine key, never a multisig with a
// threshold or voting masks). The former name described the since-deleted
// dead branch.
func TestValidateRefusesAMultisigShapedRunnerSeat(t *testing.T) {
	thresholded := newEstateProfile(t)
	thresholded.Roles = insertSortedRole(thresholded.Roles, AuthorityRoleV1{
		Role: AuthorityRoleRunner, Kind: AuthorityKindSquads,
		Multisig: vectorAddress("rehearsal/runner/multisig"), Vault: vectorAddress("rehearsal/runner/vault"),
		Threshold: 1, MemberCount: 1, PermissionMasks: []uint32{5},
		ConfigAuthority: "11111111111111111111111111111111", TimeLockSeconds: 0,
	})
	thresholded = signUnchecked(t, thresholded, "owner-a", "owner-b")
	const want = RefusalFieldMalformed + ":roles." + AuthorityRoleRunner + ".kind"
	if err := refuseMatches(t, thresholded, want); err != nil {
		t.Fatal(err)
	}
}

// A core config authority other than the all-zero sentinel is a standing key
// that can rewrite the core's own membership; only the sentinel verifies.
func TestValidateRefusesASetCoreConfigAuthority(t *testing.T) {
	standing := newEstateProfile(t)
	standing.Roles[0].ConfigAuthority = vectorAddress("rehearsal/core/configAuthority")
	standing = signUnchecked(t, standing, "owner-a", "owner-b")
	const want = RefusalCoreMultisigConfigAuthoritySet + ":roles." + AuthorityRoleCore + ".configAuthority"
	if err := refuseMatches(t, standing, want); err != nil {
		t.Fatal(err)
	}
}

// insertSortedRole inserts role keeping Roles sorted by role name (roles
// "core" < "estate-runner" < "program-upgrade" ...).
func insertSortedRole(roles []AuthorityRoleV1, role AuthorityRoleV1) []AuthorityRoleV1 {
	index := sort.Search(len(roles), func(i int) bool { return roles[i].Role > role.Role })
	roles = append(roles, AuthorityRoleV1{})
	copy(roles[index+1:], roles[index:])
	roles[index] = role
	return roles
}

// refuseMatches decodes and verifies profile and requires the exact refusal
// from both paths.
func refuseMatches(t *testing.T, profile EstateProfileV1, want string) error {
	t.Helper()
	_, err := DecodeProfile(marshalProfile(t, profile))
	requireRefusal(t, err, want)
	_, err = VerifyProfile(profile)
	requireRefusal(t, err, want)
	return nil
}

// contractsCeremonyProfilePath is a byte copy of the contracts repository's
// scripts/estate/examples/example-estate.profile.json, re-copied in the
// K-CHN-09 implementation worktree (contracts branch hermes/b01/K-CHN-09)
// after the example gained the estate-runner seat (core and tenant) and lost
// ceremony.coreApprovalRoles: the document the chain foundation runs from,
// schema melusina.estate-profile/v1. A hand edit, or a copy of another
// revision, fails by name; re-copy it with `git show <commit>:<path>`.
const (
	contractsCeremonyProfilePath   = "../../testdata/contracts-example-estate.profile.json"
	contractsCeremonyProfileSHA256 = "3b96ce8b05cf7ad0bc978cf25549b60eb05610acefdfadf8afe65b62ef1c6b8e"
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
