package estateprofile

import "sort"

// Projection field names. A spec, challenge, config or installer declares its
// estate-bound values under exactly these keys, and every one of them must
// equal the enrolled profile's value. The set is closed: a key this estate
// does not define is unknown, and unknown stops.
const (
	FieldGenesisHash           = "network.genesisHash"
	FieldMasterMint            = "anchors.masterMint"
	FieldResellerMint          = "anchors.resellerMint"
	FieldRegistryAuthority     = "anchors.registryAuthority"
	FieldSquadsProgramConfig   = "anchors.squadsProgramConfig"
	FieldSquadsTreasury        = "anchors.squadsTreasury"
	FieldStoreRootDomain       = "store.rootDomain"
	FieldStoreRootDomainSHA256 = "store.rootDomainSha256"
	FieldStoreOperatorKey      = "store.operatorKey"
	FieldStoreID               = "store.storeId"

	// FieldSquadsV4ProgramID is the multisig programme this estate's
	// governance runs on. It is spelled here, beside the anchors, because it
	// is read the same way they are: an estate that deploys its own Squads
	// carries its own programme, and the two committed profiles already
	// disagree about it. A consumer takes it from the projection or refuses;
	// there is no compiled programme to fall back to.
	FieldSquadsV4ProgramID = "externalPrograms." + ExternalRoleSquadsV4 + ".programId"
)

// FieldProgramID is the projection key for one estate-built program's
// deployed program id, and FieldExternalProgramID the key for one external
// program's. The spelling of a projection key has exactly one home: a consumer
// that wants to declare "the licence registry program I was told to use" asks
// for the key rather than concatenating it, so a typo becomes a compile error
// in one place instead of an estate-projection-field-unknown at run time.
func FieldProgramID(role string) string { return "programs." + role + ".programId" }

// FieldExternalProgramID is the same for a program this estate did not build
// but does pin - Squads v4, the token programs, the ATA program.
func FieldExternalProgramID(role string) string { return "externalPrograms." + role + ".programId" }

// Projection is the flat set of estate-bound values the profile defines: the
// anchors, the network, the Store, one entry per estate-built and external
// program, and one vault and multisig per governance role. A consumer compares
// what it was told against this map and never against a compiled literal.
func Projection(profile EstateProfileV1) (map[string]string, error) {
	if err := ValidateProfile(profile); err != nil {
		return nil, err
	}
	projection := map[string]string{
		FieldGenesisHash:           profile.Network.GenesisHash,
		FieldMasterMint:            profile.Anchors.MasterMint,
		FieldResellerMint:          profile.Anchors.ResellerMint,
		FieldRegistryAuthority:     profile.Anchors.RegistryAuthority,
		FieldSquadsProgramConfig:   profile.Anchors.SquadsProgramConfig,
		FieldSquadsTreasury:        profile.Anchors.SquadsTreasury,
		FieldStoreRootDomain:       profile.Store.RootDomain,
		FieldStoreRootDomainSHA256: profile.Store.RootDomainSHA256,
		FieldStoreOperatorKey:      profile.Store.OperatorKey,
		FieldStoreID:               profile.Store.StoreID,
	}
	for _, program := range profile.Programs {
		projection[FieldProgramID(program.Role)] = program.ProgramID
		// A final program has no upgrade authority, so the estate defines no
		// value to compare one with: a declaration of it is unknown, never a
		// match against the empty string.
		if !program.Final {
			projection["programs."+program.Role+".upgradeAuthority"] = program.UpgradeAuthority
		}
		projection["programs."+program.Role+".executableSha256"] = program.ExecutableSHA256
	}
	for _, program := range profile.ExternalPrograms {
		projection[FieldExternalProgramID(program.Role)] = program.ProgramID
	}
	for _, role := range profile.Roles {
		projection["roles."+role.Role+".vault"] = role.Vault
		if role.Kind == AuthorityKindSquads {
			projection["roles."+role.Role+".multisig"] = role.Multisig
		}
	}
	return projection, nil
}

// RequireProjection refuses a declaration that this estate does not have.
// A key the estate does not define is estate-projection-field-unknown; a value
// that differs is estate-profile-anchor-mismatch, except for the genesis hash,
// which is the one identity and refuses with estate-genesis-mismatch. Keys are
// checked in sorted order, so the refusal names the same field every time.
func RequireProjection(profile EstateProfileV1, declared map[string]string) error {
	projection, err := Projection(profile)
	if err != nil {
		return err
	}
	fields := make([]string, 0, len(declared))
	for field := range declared {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		want, known := projection[field]
		if !known {
			return refuseSubject(RefusalProjectionFieldUnknown, field)
		}
		if declared[field] == want {
			continue
		}
		if field == FieldGenesisHash {
			return refuse(RefusalGenesisMismatch)
		}
		return refuseSubject(RefusalAnchorMismatch, field)
	}
	return nil
}

// RequireGenesis is the equality between the network a consumer is actually
// talking to — a getGenesisHash() read, never a label — and the network the
// profile names. The label is display only: a profile that says "devnet" and
// names some other genesis fails here against real devnet.
func RequireGenesis(profile EstateProfileV1, observedGenesisHash string) error {
	if observedGenesisHash == MainnetBetaGenesisHash {
		return refuse(RefusalMainnetGenesis)
	}
	if err := ValidateProfile(profile); err != nil {
		return err
	}
	if !validAddress(observedGenesisHash) {
		return refuseSubject(RefusalFieldMalformed, "observedGenesisHash")
	}
	if observedGenesisHash != profile.Network.GenesisHash {
		return refuse(RefusalGenesisMismatch)
	}
	return nil
}

// RequireProgramExecutable compares one deployed program's executable hash,
// read back from chain, with the hash the profile records for that role.
func RequireProgramExecutable(profile EstateProfileV1, role, executableSHA256 string) error {
	if err := ValidateProfile(profile); err != nil {
		return err
	}
	for _, program := range profile.Programs {
		if program.Role != role {
			continue
		}
		if !validDigest(executableSHA256) || executableSHA256 != program.ExecutableSHA256 {
			return refuseSubject(RefusalProgramExecutable, role)
		}
		return nil
	}
	return refuseSubject(RefusalProjectionFieldUnknown, "programs."+role)
}
