package estateprofile

import (
	"encoding/json"
	"os"
	"testing"
)

func c1NetworkFeatures(t *testing.T) []struct {
	Name        string `json:"name"`
	GenesisHash string `json:"genesisHash"`
	Feature     string `json:"feature"`
	Refusal     string `json:"refusal"`
} {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/contracts/C1-estate/C1-estate-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		NetworkFeatures []struct {
			Name        string `json:"name"`
			GenesisHash string `json:"genesisHash"`
			Feature     string `json:"feature"`
			Refusal     string `json:"refusal"`
		} `json:"networkFeatures"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.NetworkFeatures
}

func TestC1D12PrivateGenesisAndCoreThreshold(t *testing.T) {
	base := newEstateProfile(t)
	// Every derivable non-mainnet genesis in the shared vector is admissible.
	for _, row := range c1NetworkFeatures(t) {
		if row.Feature != "devnet" {
			continue
		}
		t.Run(row.Name, func(t *testing.T) {
			private := base
			private.Network.GenesisHash = row.GenesisHash
			private = signProfile(t, private, "owner-a", "owner-b")
			if _, err := VerifyProfile(private); err != nil {
				t.Fatalf("D12_PRIVATE_GENESIS_REFUSED: %v", err)
			}
		})
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
	var mainnet string
	for _, row := range c1NetworkFeatures(t) {
		if row.Name == "mainnet-beta" {
			mainnet = row.GenesisHash
		}
	}
	if mainnet == "" || mainnet != MainnetBetaGenesisHash {
		t.Fatal("D12_MAINNET_VECTOR_MISSING_OR_DRIFTED")
	}
	profile.Network.GenesisHash = mainnet
	if err := ValidateProfile(profile); RefusalName(err) != RefusalMainnetGenesis {
		t.Fatalf("D12_MAINNET_REFUSAL: %v", err)
	}
}

func TestC1D12UnderivableGenesisRefused(t *testing.T) {
	base := newEstateProfile(t)
	for _, row := range c1NetworkFeatures(t) {
		if row.Name != "zero-genesis" && row.Name != "malformed-genesis" {
			continue
		}
		t.Run(row.Name, func(t *testing.T) {
			profile := base
			profile.Network.GenesisHash = row.GenesisHash
			if err := ValidateProfile(profile); err == nil {
				t.Fatalf("D12_UNDERIVABLE_GENESIS_ACCEPTED: %s", row.Name)
			}
		})
	}
}
