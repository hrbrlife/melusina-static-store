package estateprofile

import (
	"sort"
	"testing"
)

func TestProjectionIsTheClosedSetOfEstateBoundValues(t *testing.T) {
	profile := newEstateProfile(t)
	projection, err := Projection(profile)
	if err != nil {
		t.Fatalf("projection: %v", err)
	}
	want := map[string]string{
		FieldGenesisHash:                             profile.Network.GenesisHash,
		FieldMasterMint:                              profile.Anchors.MasterMint,
		FieldResellerMint:                            profile.Anchors.ResellerMint,
		FieldRegistryAuthority:                       profile.Anchors.RegistryAuthority,
		FieldSquadsProgramConfig:                     profile.Anchors.SquadsProgramConfig,
		FieldSquadsTreasury:                          profile.Anchors.SquadsTreasury,
		FieldStoreRootDomain:                         profile.Store.RootDomain,
		FieldStoreRootDomainSHA256:                   profile.Store.RootDomainSHA256,
		FieldStoreOperatorKey:                        profile.Store.OperatorKey,
		FieldStoreID:                                 profile.Store.StoreID,
		"programs.license-registry.programId":        profile.Programs[0].ProgramID,
		"programs.witness-verifier.programId":        profile.Programs[1].ProgramID,
		"externalPrograms.squads-v4.programId":       profile.ExternalPrograms[1].ProgramID,
		"roles.core.vault":                           profile.Roles[0].Vault,
		"roles.core.multisig":                        profile.Roles[0].Multisig,
		"roles.root-install-admin.vault":             profile.Roles[1].Vault,
		"roles.store-release.vault":                  profile.Roles[2].Vault,
		"roles.store-release.multisig":               profile.Roles[2].Multisig,
		"programs.license-registry.executableSha256": profile.Programs[0].ExecutableSHA256,
	}
	for field, value := range want {
		if projection[field] != value {
			t.Fatalf("projection[%s] is %q, want %q", field, projection[field], value)
		}
	}
	// A key-kind role has no multisig, so the projection must not invent one.
	if _, present := projection["roles.root-install-admin.multisig"]; present {
		t.Fatalf("the projection invented a multisig for a single-key role")
	}
	if err := RequireProjection(profile, want); err != nil {
		t.Fatalf("the profile's own projection must satisfy RequireProjection: %v", err)
	}
}

// foreign-anchor: a spec, challenge or installer that carries another estate's
// anchors is refused by the field it got wrong.
func TestRequireProjectionRefusesAForeignAnchor(t *testing.T) {
	profile := newEstateProfile(t)
	foreign := paypeDevnetProfile(t)
	for _, item := range []struct{ field, value string }{
		{FieldMasterMint, foreign.Anchors.MasterMint},
		{FieldRegistryAuthority, foreign.Anchors.RegistryAuthority},
		{FieldStoreRootDomainSHA256, foreign.Store.RootDomainSHA256},
		{FieldStoreOperatorKey, foreign.Store.OperatorKey},
		{"programs.license-registry.programId", foreign.Programs[0].ProgramID},
		{"roles.core.vault", foreign.Roles[0].Vault},
	} {
		t.Run(item.field, func(t *testing.T) {
			requireRefusal(t, RequireProjection(profile, map[string]string{item.field: item.value}), RefusalAnchorMismatch+":"+item.field)
		})
	}
}

func TestRequireProjectionNamesTheFirstFieldInSortedOrder(t *testing.T) {
	profile := newEstateProfile(t)
	declared := map[string]string{
		FieldStoreOperatorKey: "wrong",
		FieldMasterMint:       "wrong",
		FieldSquadsTreasury:   "wrong",
	}
	// Three wrong fields, one deterministic refusal: map order never decides
	// which defect gets reported.
	fields := make([]string, 0, len(declared))
	for field := range declared {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for attempt := 0; attempt < 8; attempt++ {
		requireRefusal(t, RequireProjection(profile, declared), RefusalAnchorMismatch+":"+fields[0])
	}
}

func TestRequireProjectionRefusesAnUnknownField(t *testing.T) {
	profile := newEstateProfile(t)
	requireRefusal(t, RequireProjection(profile, map[string]string{"anchors.legacyMasterMint": profile.Anchors.MasterMint}),
		RefusalProjectionFieldUnknown+":anchors.legacyMasterMint")
	// A role this estate does not define is unknown, not absent-and-fine.
	requireRefusal(t, RequireProjection(profile, map[string]string{"roles.reseller.vault": profile.Roles[0].Vault}),
		RefusalProjectionFieldUnknown+":roles.reseller.vault")
}

func TestRequireProjectionRefusesADeclaredGenesisThatIsNotTheEstates(t *testing.T) {
	profile := newEstateProfile(t)
	requireRefusal(t, RequireProjection(profile, map[string]string{FieldGenesisHash: paypeDevnetGenesisHash}), RefusalGenesisMismatch)
}

// relabelled-network: the label says devnet, the genesis says otherwise, and
// only the genesis is compared.
func TestRequireGenesisComparesTheGenesisAndNotTheLabel(t *testing.T) {
	profile := paypeDevnetProfile(t)
	if profile.Network.Label != "devnet" {
		t.Fatalf("the positive control must be labelled devnet")
	}
	if err := RequireGenesis(profile, paypeDevnetGenesisHash); err != nil {
		t.Fatalf("the real devnet genesis must satisfy the devnet profile: %v", err)
	}
	relabelled := newEstateProfile(t)
	relabelled.Network.Label = "devnet"
	relabelled = signProfile(t, relabelled, "owner-a", "owner-b")
	if _, err := VerifyProfile(relabelled); err != nil {
		t.Fatalf("the relabelled profile must otherwise be valid: %v", err)
	}
	requireRefusal(t, RequireGenesis(relabelled, paypeDevnetGenesisHash), RefusalGenesisMismatch)
}

// mainnet-genesis: one protocol constant, refused on both sides.
func TestMainnetGenesisIsRefusedOnBothSides(t *testing.T) {
	profile := newEstateProfile(t)
	requireRefusal(t, RequireGenesis(profile, MainnetBetaGenesisHash), RefusalMainnetGenesis)

	// A profile naming the mainnet genesis cannot even be digested, so it can
	// never be signed: the refusal precedes every key operation.
	named := newEstateProfile(t)
	named.Network.GenesisHash = MainnetBetaGenesisHash
	requireRefusal(t, ValidateProfile(named), RefusalMainnetGenesis)
	_, digestErr := ProfileSHA256(named)
	requireRefusal(t, digestErr, RefusalMainnetGenesis)
	_, err := VerifyProfile(named)
	requireRefusal(t, err, RefusalMainnetGenesis)
	_, err = DecodeProfile(marshalProfile(t, named))
	requireRefusal(t, err, RefusalMainnetGenesis)
	// The constant is the complete 44-character value, not a truncated one:
	// a truncation could never equal a getGenesisHash() result.
	if !validAddress(MainnetBetaGenesisHash) {
		t.Fatalf("the mainnet constant is not a canonical 32-byte base58 value")
	}
}

func TestRequireGenesisRefusesAMalformedObservation(t *testing.T) {
	profile := newEstateProfile(t)
	requireRefusal(t, RequireGenesis(profile, "devnet"), RefusalFieldMalformed+":observedGenesisHash")
	requireRefusal(t, RequireGenesis(profile, ""), RefusalFieldMalformed+":observedGenesisHash")
}

// program-bytes: the deployed executable hash is the profile's or it is not
// this estate's program.
func TestRequireProgramExecutable(t *testing.T) {
	profile := newEstateProfile(t)
	if err := RequireProgramExecutable(profile, ProgramRoleLicenseRegistry, profile.Programs[0].ExecutableSHA256); err != nil {
		t.Fatalf("the profile's own hash must pass: %v", err)
	}
	requireRefusal(t, RequireProgramExecutable(profile, ProgramRoleLicenseRegistry, profile.Programs[1].ExecutableSHA256),
		RefusalProgramExecutable+":"+ProgramRoleLicenseRegistry)
	requireRefusal(t, RequireProgramExecutable(profile, ProgramRoleWitnessVerifier, ""),
		RefusalProgramExecutable+":"+ProgramRoleWitnessVerifier)
	requireRefusal(t, RequireProgramExecutable(profile, "store-sidecar", profile.Programs[0].ExecutableSHA256),
		RefusalProjectionFieldUnknown+":programs.store-sidecar")
}

func TestProjectionRefusesAnInvalidProfileBeforeItProjectsAnything(t *testing.T) {
	profile := newEstateProfile(t)
	profile.Anchors.MasterMint = "not-an-address"
	if _, err := Projection(profile); err == nil {
		t.Fatalf("an invalid profile was projected")
	} else {
		requireRefusal(t, err, RefusalFieldMalformed+":anchors.masterMint")
	}
	requireRefusal(t, RequireProjection(profile, map[string]string{}), RefusalFieldMalformed+":anchors.masterMint")
	requireRefusal(t, RequireGenesis(profile, profile.Network.GenesisHash), RefusalFieldMalformed+":anchors.masterMint")
}
