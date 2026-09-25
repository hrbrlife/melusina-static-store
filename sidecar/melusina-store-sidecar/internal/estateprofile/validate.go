package estateprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var (
	policyIDPattern = regexp.MustCompile(`^policy\.[a-z][a-z0-9.-]{1,95}\.v1$`)
	keyIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	labelPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	// storeIDPattern bounds a storeId at MaxStoreIDLength characters, so the
	// Store's state namespace "store-" + storeId + "-g" + N still fits a
	// 63-character RemoteBak namespace name at generation 999:
	// 6 + 52 + 2 + 3 = 63. A longer id would be signed into the profile and
	// then refused at the Store's first state backup.
	storeIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,51}$`)
	rootDomainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	reasonPattern     = regexp.MustCompile(`^[ -~]{1,200}$`)

	programRoles   = []string{ProgramRoleLicenseRegistry, ProgramRoleWitnessVerifier}
	externalRoles  = []string{ExternalRoleATA, ExternalRoleMemo, ExternalRoleSquadsV4, ExternalRoleToken, ExternalRoleToken2022, ExternalRoleTokenMetadata}
	authorityRoles = []string{AuthorityRoleCore, AuthorityRoleProgramUpgrade, AuthorityRoleReseller, AuthorityRoleRootInstallAdmin, AuthorityRoleStoreRelease}
)

// squadsPermissionVote is the Vote bit of a Squads v4 member permission mask
// (Initiate=1, Vote=2, Execute=4).
const squadsPermissionVote = 2

// ValidateProfile checks everything about a profile that needs no key
// operation: exact schema and kind, every field's closed spelling, sorted
// duplicate-free arrays, completeness, and the protocol refusal of the mainnet
// genesis. It accepts an unsigned profile, because owners compute the digest
// before they sign it. It proves neither identity nor authority.
func ValidateProfile(profile EstateProfileV1) error {
	if profile.Schema == DraftSchema {
		return refuse(RefusalDraftNotEnrollable)
	}
	if profile.Schema != ProfileSchema || profile.Kind != ProfileKind {
		return refuse(RefusalSchemaUnsupported)
	}
	if !validDigest(profile.EstateID) {
		return refuseSubject(RefusalFieldMalformed, "estateId")
	}
	if !validDigest(profile.EstateNonce) {
		return refuseSubject(RefusalFieldMalformed, "estateNonce")
	}
	if err := validateOwnerPolicy(profile.GenesisOwnerPolicy, "genesisOwnerPolicy"); err != nil {
		return err
	}
	if profile.Revision == 0 || profile.Revision > MaxSafeInteger {
		return refuseSubject(RefusalFieldMalformed, "revision")
	}
	if _, ok := parseIssuedAt(profile.IssuedAt); !ok {
		return refuseSubject(RefusalFieldMalformed, "issuedAt")
	}
	if err := validateOwnerPolicy(profile.OwnerPolicy, "ownerPolicy"); err != nil {
		return err
	}
	if err := validatePolicySuccessionShape(profile); err != nil {
		return err
	}
	if err := validateReleaseTrust(profile.ReleaseTrust); err != nil {
		return err
	}
	if err := validateNetwork(profile.Network); err != nil {
		return err
	}
	if err := validatePrograms(profile.Programs); err != nil {
		return err
	}
	if err := validateExternalPrograms(profile.ExternalPrograms); err != nil {
		return err
	}
	if err := validateAnchors(profile.Anchors); err != nil {
		return err
	}
	if err := validateRoles(profile.Roles); err != nil {
		return err
	}
	for _, role := range profile.Roles {
		if role.Kind == AuthorityKindSquads && !hasExternalRole(profile.ExternalPrograms, ExternalRoleSquadsV4) {
			return refuseSubject(RefusalIncomplete, "externalPrograms."+ExternalRoleSquadsV4)
		}
	}
	if err := validateStore(profile.Store, profile.Roles); err != nil {
		return err
	}
	if err := validateRecalls(profile.Recalls, "recalls"); err != nil {
		return err
	}
	if err := validatePrev(profile.Prev, profile.Revision); err != nil {
		return err
	}
	return validateSignatureShape(profile.Signatures, "signatures")
}

func validateOwnerPolicy(policy OwnerPolicyV1, field string) error {
	if !policyIDPattern.MatchString(policy.PolicyID) || strings.Contains(policy.PolicyID, "..") {
		return refuseSubject(RefusalFieldMalformed, field+".policyId")
	}
	if policy.Revision == 0 || policy.Revision > MaxSafeInteger {
		return refuseSubject(RefusalFieldMalformed, field+".revision")
	}
	if len(policy.Signers) < OwnerPolicyMinSigners || len(policy.Signers) > OwnerPolicyMaxSigners {
		return refuseSubject(RefusalFieldMalformed, field+".signers")
	}
	if policy.Threshold < OwnerPolicyMinThreshold || int(policy.Threshold) > len(policy.Signers) {
		return refuseSubject(RefusalFieldMalformed, field+".threshold")
	}
	if err := requireSorted(field+".signers", len(policy.Signers), func(index int) string { return policy.Signers[index].KeyID }); err != nil {
		return err
	}
	seenKeys := make(map[string]bool, len(policy.Signers))
	for _, signer := range policy.Signers {
		if !keyIDPattern.MatchString(signer.KeyID) {
			return refuseSubject(RefusalFieldMalformed, field+".signers.keyId")
		}
		if _, ok := decodeEd25519PublicKey(signer.Ed25519PublicKey); !ok {
			return refuseSubject(RefusalFieldMalformed, field+".signers."+signer.KeyID+".ed25519PublicKey")
		}
		if seenKeys[signer.Ed25519PublicKey] {
			return refuseSubject(RefusalArrayDuplicate, field+".signers.ed25519PublicKey")
		}
		seenKeys[signer.Ed25519PublicKey] = true
	}
	return nil
}

func validatePolicySuccessionShape(profile EstateProfileV1) error {
	if len(profile.PolicySuccession) > MaxPolicySuccessions {
		return refuseSubject(RefusalFieldMalformed, "policySuccession")
	}
	lastRevision := uint64(1)
	for index, step := range profile.PolicySuccession {
		field := fmt.Sprintf("policySuccession[%d]", index)
		if !validDigest(step.FromPolicySHA256) {
			return refuseSubject(RefusalFieldMalformed, field+".fromPolicySha256")
		}
		if err := validateOwnerPolicy(step.ToPolicy, field+".toPolicy"); err != nil {
			return err
		}
		// Revision 1 carries no succession, steps are strictly forward, and no
		// step is dated after the profile that carries it.
		if step.Revision < 2 || step.Revision > profile.Revision {
			return refuseSubject(RefusalFieldMalformed, field+".revision")
		}
		if index > 0 && step.Revision == lastRevision {
			return refuseSubject(RefusalArrayDuplicate, "policySuccession")
		}
		if index > 0 && step.Revision < lastRevision {
			return refuseSubject(RefusalArrayNotSorted, "policySuccession")
		}
		lastRevision = step.Revision
		if err := validateSignatureShape(step.Signatures, field+".signatures"); err != nil {
			return err
		}
	}
	return nil
}

func validateReleaseTrust(trust ReleaseTrustV1) error {
	if len(trust.PublisherKeys) == 0 {
		return refuseSubject(RefusalIncomplete, "releaseTrust.publisherKeys")
	}
	if len(trust.PublisherKeys) > MaxPublisherKeys {
		return refuseSubject(RefusalFieldMalformed, "releaseTrust.publisherKeys")
	}
	if err := requireSorted("releaseTrust.publisherKeys", len(trust.PublisherKeys), func(index int) string { return trust.PublisherKeys[index] }); err != nil {
		return err
	}
	for _, key := range trust.PublisherKeys {
		if _, ok := decodeEd25519PublicKey(key); !ok {
			return refuseSubject(RefusalFieldMalformed, "releaseTrust.publisherKeys")
		}
	}
	if trust.Threshold == 0 || int(trust.Threshold) > len(trust.PublisherKeys) {
		return refuseSubject(RefusalFieldMalformed, "releaseTrust.threshold")
	}
	return nil
}

func validateNetwork(network NetworkV1) error {
	if !labelPattern.MatchString(network.Label) {
		return refuseSubject(RefusalFieldMalformed, "network.label")
	}
	// The label is display only. The genesis hash IS the network, and the one
	// protocol constant refuses mainnet whatever the label says.
	if network.GenesisHash == MainnetBetaGenesisHash {
		return refuse(RefusalMainnetGenesis)
	}
	if !validAddress(network.GenesisHash) {
		return refuseSubject(RefusalFieldMalformed, "network.genesisHash")
	}
	if network.Commitment != NetworkCommitment {
		return refuseSubject(RefusalFieldMalformed, "network.commitment")
	}
	return nil
}

func validatePrograms(programs []ProgramV1) error {
	if err := requireSorted("programs", len(programs), func(index int) string { return programs[index].Role }); err != nil {
		return err
	}
	seenIDs := map[string]bool{}
	for _, program := range programs {
		if !contains(programRoles, program.Role) {
			return refuseSubject(RefusalFieldMalformed, "programs.role")
		}
		field := "programs." + program.Role
		if !validAddress(program.ProgramID) {
			return refuseSubject(RefusalFieldMalformed, field+".programId")
		}
		if seenIDs[program.ProgramID] {
			return refuseSubject(RefusalArrayDuplicate, "programs.programId")
		}
		seenIDs[program.ProgramID] = true
		if err := validateProgramAuthority(program, field); err != nil {
			return err
		}
		// Every estate-built fact comes from finalized read-back. An empty one
		// is a half-profile, which is a different refusal from a malformed one.
		for _, item := range []struct {
			name, value string
			valid       func(string) bool
		}{
			{"sourceCommit", program.SourceCommit, validSourceCommit},
			{"buildManifestSha256", program.BuildManifestSHA256, validDigest},
			{"executableSha256", program.ExecutableSHA256, validDigest},
			{"idlSha256", program.IDLSHA256, validDigest},
		} {
			if item.value == "" {
				return refuseSubject(RefusalIncomplete, field+"."+item.name)
			}
			if !item.valid(item.value) {
				return refuseSubject(RefusalFieldMalformed, field+"."+item.name)
			}
		}
	}
	for _, role := range programRoles {
		if !seenProgramRole(programs, role) {
			return refuseSubject(RefusalIncomplete, "programs."+role)
		}
	}
	return nil
}

// ProgramRoleIsFinal reports whether the program in role is deployed final:
// created and stripped of its upgrade authority in one transaction, so that
// finalized read-back finds no authority at all. The witness verifier is the
// one such role; the licence registry stays governed by the core vault. The
// set is closed and is the chain foundation's own (its FINAL_PROGRAM_NAMES):
// a role is final because of what it is, never because a profile says so.
func ProgramRoleIsFinal(role string) bool {
	return role == ProgramRoleWitnessVerifier
}

// validateProgramAuthority holds a program's stated upgrade authority to how
// its role is deployed. A final role must say final and name no authority -
// the empty string is the only truthful spelling of None - and a governed
// role must not say final and must name a real address. Each disagreement is
// refused by its own name, so "stated an authority the chain lacks" and
// "omitted the authority the chain has" are never the same failure.
func validateProgramAuthority(program ProgramV1, field string) error {
	if ProgramRoleIsFinal(program.Role) {
		if !program.Final {
			return refuseSubject(RefusalProgramMustBeFinal, field+".final")
		}
		if program.UpgradeAuthority != "" {
			return refuseSubject(RefusalProgramMustBeFinal, field+".upgradeAuthority")
		}
		return nil
	}
	if program.Final {
		return refuseSubject(RefusalProgramMustBeGoverned, field+".final")
	}
	if program.UpgradeAuthority == "" {
		return refuseSubject(RefusalIncomplete, field+".upgradeAuthority")
	}
	if !validAddress(program.UpgradeAuthority) {
		return refuseSubject(RefusalFieldMalformed, field+".upgradeAuthority")
	}
	return nil
}

func validateExternalPrograms(programs []ExternalProgramV1) error {
	if err := requireSorted("externalPrograms", len(programs), func(index int) string { return programs[index].Role }); err != nil {
		return err
	}
	for _, program := range programs {
		if !contains(externalRoles, program.Role) {
			return refuseSubject(RefusalFieldMalformed, "externalPrograms.role")
		}
		field := "externalPrograms." + program.Role
		if !validAddress(program.ProgramID) {
			return refuseSubject(RefusalFieldMalformed, field+".programId")
		}
		if program.ExecutableSHA256 == "" {
			return refuseSubject(RefusalIncomplete, field+".executableSha256")
		}
		if !validDigest(program.ExecutableSHA256) {
			return refuseSubject(RefusalFieldMalformed, field+".executableSha256")
		}
	}
	return nil
}

func validateAnchors(anchors AnchorsV1) error {
	for _, item := range []struct{ name, value string }{
		{"masterMint", anchors.MasterMint},
		{"resellerMint", anchors.ResellerMint},
		{"registryAuthority", anchors.RegistryAuthority},
		{"squadsProgramConfig", anchors.SquadsProgramConfig},
		{"squadsTreasury", anchors.SquadsTreasury},
	} {
		if item.value == "" {
			return refuseSubject(RefusalIncomplete, "anchors."+item.name)
		}
		if !validAddress(item.value) {
			return refuseSubject(RefusalFieldMalformed, "anchors."+item.name)
		}
	}
	return nil
}

func validateRoles(roles []AuthorityRoleV1) error {
	if err := requireSorted("roles", len(roles), func(index int) string { return roles[index].Role }); err != nil {
		return err
	}
	coreSeen := false
	for _, role := range roles {
		if !contains(authorityRoles, role.Role) {
			return refuseSubject(RefusalFieldMalformed, "roles.role")
		}
		coreSeen = coreSeen || role.Role == AuthorityRoleCore
		field := "roles." + role.Role
		if !validAddress(role.Vault) {
			return refuseSubject(RefusalFieldMalformed, field+".vault")
		}
		// The Store release authority is a multisig: a single key is
		// threshold one by definition, below StoreReleaseMinThreshold.
		if role.Role == AuthorityRoleStoreRelease && role.Kind != AuthorityKindSquads {
			return refuseSubject(RefusalFieldMalformed, field+".kind")
		}
		switch role.Kind {
		case AuthorityKindSquads:
			if !validAddress(role.Multisig) || role.Multisig == role.Vault {
				return refuseSubject(RefusalFieldMalformed, field+".multisig")
			}
			if role.MemberCount == 0 || role.MemberCount > MaxRoleMembers {
				return refuseSubject(RefusalFieldMalformed, field+".memberCount")
			}
			if len(role.PermissionMasks) != int(role.MemberCount) {
				return refuseSubject(RefusalFieldMalformed, field+".permissionMasks")
			}
			voters := uint32(0)
			for index, mask := range role.PermissionMasks {
				if mask == 0 || mask > 7 || (index > 0 && mask < role.PermissionMasks[index-1]) {
					return refuseSubject(RefusalFieldMalformed, field+".permissionMasks")
				}
				if mask&squadsPermissionVote != 0 {
					voters++
				}
			}
			// Squads itself refuses a threshold no set of voters can reach.
			if role.Threshold == 0 || role.Threshold > voters {
				return refuseSubject(RefusalFieldMalformed, field+".threshold")
			}
			if role.Role == AuthorityRoleStoreRelease && role.Threshold < StoreReleaseMinThreshold {
				return refuseSubject(RefusalFieldMalformed, field+".threshold")
			}
			if !validAddressOrDefault(role.ConfigAuthority) {
				return refuseSubject(RefusalFieldMalformed, field+".configAuthority")
			}
			if role.TimeLockSeconds > uint64(^uint32(0)) {
				return refuseSubject(RefusalFieldMalformed, field+".timeLockSeconds")
			}
		case AuthorityKindKey:
			if role.Multisig != "" || role.Threshold != 1 || role.MemberCount != 1 || len(role.PermissionMasks) != 0 || role.ConfigAuthority != "" || role.TimeLockSeconds != 0 {
				return refuseSubject(RefusalFieldMalformed, field+".kind")
			}
		default:
			return refuseSubject(RefusalFieldMalformed, field+".kind")
		}
	}
	if !coreSeen {
		return refuseSubject(RefusalIncomplete, "roles."+AuthorityRoleCore)
	}
	return nil
}

func validateStore(store StoreV1, roles []AuthorityRoleV1) error {
	if len(store.RootDomain) > 253 || !rootDomainPattern.MatchString(store.RootDomain) {
		return refuseSubject(RefusalFieldMalformed, "store.rootDomain")
	}
	// The registry stores this hash on chain; the profile states both so a
	// consumer compares either without re-deriving a spelling rule.
	sum := sha256.Sum256([]byte(store.RootDomain))
	if store.RootDomainSHA256 != hex.EncodeToString(sum[:]) {
		return refuseSubject(RefusalFieldMalformed, "store.rootDomainSha256")
	}
	if !storeIDPattern.MatchString(store.StoreID) {
		return refuseSubject(RefusalFieldMalformed, "store.storeId")
	}
	if !validAddress(store.OperatorKey) {
		return refuseSubject(RefusalFieldMalformed, "store.operatorKey")
	}
	for _, role := range roles {
		if role.Role == store.ReleaseRole {
			return nil
		}
	}
	return refuseSubject(RefusalFieldMalformed, "store.releaseRole")
}

func validateRecalls(recalls []RecallV1, field string) error {
	if len(recalls) > MaxRecalls {
		return refuseSubject(RefusalFieldMalformed, field)
	}
	if err := requireSorted(field, len(recalls), func(index int) string { return recalls[index].SHA256 }); err != nil {
		return err
	}
	for _, recall := range recalls {
		if !validDigest(recall.SHA256) {
			return refuseSubject(RefusalFieldMalformed, field+".sha256")
		}
		if !reasonPattern.MatchString(recall.Reason) {
			return refuseSubject(RefusalFieldMalformed, field+".reason")
		}
	}
	return nil
}

// validatePrev checks spelling only. Prev is informational: a missing
// intermediate record is not a defect, so no rule here or in Accept compares
// it with what a consumer has pinned.
func validatePrev(prev PrevV1, revision uint64) error {
	if prev.Revision == 0 && prev.SHA256 == "" {
		return nil
	}
	if revision == 1 || prev.Revision == 0 || prev.Revision >= revision || !validDigest(prev.SHA256) {
		return refuseSubject(RefusalFieldMalformed, "prev")
	}
	return nil
}

func validateSignatureShape(signatures []SignatureV1, field string) error {
	if len(signatures) > OwnerPolicyMaxSigners {
		return refuseSubject(RefusalFieldMalformed, field)
	}
	if err := requireSorted(field, len(signatures), func(index int) string { return signatures[index].KeyID }); err != nil {
		return err
	}
	for _, signature := range signatures {
		if !keyIDPattern.MatchString(signature.KeyID) {
			return refuseSubject(RefusalFieldMalformed, field+".keyId")
		}
		if _, ok := decodeSignature(signature.Signature); !ok {
			return refuseSubject(RefusalFieldMalformed, field+".signature")
		}
	}
	return nil
}

// requireSorted requires a strictly increasing key, naming an equal neighbour
// a duplicate and a smaller one an ordering fault.
func requireSorted(field string, count int, key func(index int) string) error {
	for index := 1; index < count; index++ {
		switch previous, current := key(index-1), key(index); {
		case previous == current:
			return refuseSubject(RefusalArrayDuplicate, field)
		case previous > current:
			return refuseSubject(RefusalArrayNotSorted, field)
		}
	}
	return nil
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func seenProgramRole(programs []ProgramV1, role string) bool {
	for _, program := range programs {
		if program.Role == role {
			return true
		}
	}
	return false
}

func hasExternalRole(programs []ExternalProgramV1, role string) bool {
	for _, program := range programs {
		if program.Role == role {
			return true
		}
	}
	return false
}
