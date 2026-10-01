package estateprofile

import (
	"encoding/json"
	"os"
	"testing"
)

func TestC1D12GeneratedExampleHasDerivedFeatureOnly(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/contracts-example-estate.profile.json")
	if err != nil {
		t.Fatal(err)
	}
	var example struct {
		Schema    string                     `json:"schema"`
		Estate    string                     `json:"estate"`
		Network   map[string]json.RawMessage `json:"network"`
		Hierarchy struct {
			Include bool `json:"include"`
		} `json:"hierarchy"`
		Programs     map[string]json.RawMessage `json:"programs"`
		ReleaseTrust struct {
			PublisherKeys []string `json:"publisherKeys"`
			Threshold     uint32   `json:"threshold"`
		} `json:"releaseTrust"`
		MasterNftMint   string `json:"masterNftMint"`
		ResellerNftMint string `json:"resellerNftMint"`
		RootStoreDomain string `json:"rootStoreDomain"`
		Squads          struct {
			Core struct {
				Threshold uint32 `json:"threshold"`
				Members   []struct {
					PublicKey string `json:"publicKey"`
				} `json:"members"`
			} `json:"core"`
		} `json:"squads"`
	}
	if err := json.Unmarshal(raw, &example); err != nil {
		t.Fatal(err)
	}
	if _, supplied := example.Network["licenseRegistryFeature"]; supplied {
		t.Fatal("D12_EXAMPLE_SUPPLIED_DERIVED_FEATURE")
	}
	if len(example.Network["genesisHash"]) == 0 {
		t.Fatal("D12_EXAMPLE_GENESIS_MISSING")
	}
	var genesis string
	if err := json.Unmarshal(example.Network["genesisHash"], &genesis); err != nil || !validAddress(genesis) || genesis == MainnetBetaGenesisHash {
		t.Fatalf("D12_EXAMPLE_GENESIS_INVALID: %s, %v", genesis, err)
	}
	var licenseProgram, witnessProgram string
	_ = json.Unmarshal(example.Programs["license_registry"], &licenseProgram)
	_ = json.Unmarshal(example.Programs["witness_verifier"], &witnessProgram)
	if example.Schema != FoundationCeremonyProfileSchema || example.Estate != "example-estate" ||
		len(example.Programs["license_registry"]) == 0 || len(example.Programs["witness_verifier"]) == 0 ||
		!validAddress(licenseProgram) || !validAddress(witnessProgram) ||
		!validAddress(example.MasterNftMint) || !validAddress(example.ResellerNftMint) ||
		example.RootStoreDomain == "" || example.Squads.Core.Threshold < 2 ||
		len(example.Squads.Core.Members) < int(example.Squads.Core.Threshold) ||
		len(example.ReleaseTrust.PublisherKeys) < int(example.ReleaseTrust.Threshold) || example.ReleaseTrust.Threshold == 0 {
		t.Fatal("D12_EXAMPLE_SHAPE_INCOMPLETE")
	}
	for _, key := range example.ReleaseTrust.PublisherKeys {
		if !validDigest(key) {
			t.Fatalf("D12_EXAMPLE_PUBLISHER_KEY_INVALID: %s", key)
		}
	}
	for _, member := range example.Squads.Core.Members {
		if !validAddress(member.PublicKey) {
			t.Fatalf("D12_EXAMPLE_CORE_MEMBER_INVALID: %s", member.PublicKey)
		}
	}
	if !example.Hierarchy.Include {
		for _, name := range []string{"level2_registry", "level3_registry", "level4_registry"} {
			if _, supplied := example.Programs[name]; supplied {
				t.Fatalf("D12_EXAMPLE_UNUSED_LEVEL_PROGRAM: %s", name)
			}
		}
	}
}

func TestC1D12PrivateGenesisAndCoreThreshold(t *testing.T) {
	base := newEstateProfile(t)
	// Store verifies the signed genesis. The feature is derived later from that
	// genesis by the ceremony reader, never supplied in an EstateProfileV1.
	private := base
	private.Network.GenesisHash = "DszkBgTZVoPkk9tDyXH85k4xs7HSjzxaCoLnPnuZNu6L"
	private = signProfile(t, private, "owner-a", "owner-b")
	if _, err := VerifyProfile(private); err != nil {
		t.Fatalf("D12_PRIVATE_GENESIS_REFUSED: %v", err)
	}
	// The signed 2-of-4 core authority is the minimum allowed foundation.
	two := base
	for i := range two.Roles {
		if two.Roles[i].Role == AuthorityRoleCore || two.Roles[i].Role == AuthorityRoleStoreRelease {
			two.Roles[i].Threshold = 2
		}
	}
	two = signProfile(t, two, "owner-a", "owner-b")
	if _, err := VerifyProfile(two); err != nil {
		t.Fatalf("D12_CORE_TWO_OF_FOUR_REFUSED: %v", err)
	}
}

func TestC1D12CoreThresholdOneRefused(t *testing.T) {
	profile := newEstateProfile(t)
	for i := range profile.Roles {
		if profile.Roles[i].Role == AuthorityRoleCore || profile.Roles[i].Role == AuthorityRoleStoreRelease {
			profile.Roles[i].Threshold = 1
		}
	}
	err := ValidateProfile(profile)
	if err == nil || (err.Error() != "estate-profile-field-malformed:roles.core.threshold" &&
		err.Error() != "estate-profile-field-malformed:roles.store-release.threshold") {
		t.Fatalf("D12_CORE_THRESHOLD_FLOOR: got %v; want a core/store-release threshold refusal", err)
	}
}

func TestC1D12MainnetRefused(t *testing.T) {
	profile := newEstateProfile(t)
	profile.Network.GenesisHash = MainnetBetaGenesisHash
	if err := ValidateProfile(profile); RefusalName(err) != RefusalMainnetGenesis {
		t.Fatalf("D12_MAINNET_REFUSAL: %v", err)
	}
}

func TestC1D12UnderivableGenesisRefused(t *testing.T) {
	base := newEstateProfile(t)
	for _, row := range []struct{ name, genesis string }{
		{"zero-genesis", "11111111111111111111111111111111"},
		{"malformed-genesis", "not-base58!"},
	} {
		t.Run(row.name, func(t *testing.T) {
			profile := base
			profile.Network.GenesisHash = row.genesis
			if err := ValidateProfile(profile); err == nil {
				t.Fatalf("D12_UNDERIVABLE_GENESIS_ACCEPTED: %s", row.name)
			}
		})
	}
}
