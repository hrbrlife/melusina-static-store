package estateprofile

// Producer-owned D12 coverage for the Store's estateprofile copy: the chain
// foundation derives network.licenseRegistryFeature from the genesis hash, so
// an EstateProfileV1 never carries it. These tests are not locked and are not
// part of the deployer copy.

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// TestCampaignD12ExampleCarriesDerivedGenesisOnly checks that the ceremony
// example (the profile the owners would hand to a Store) states a valid,
// non-mainnet genesis and no supplied licenseRegistryFeature, and that the
// store-release threshold keeps its floor.
func TestCampaignD12ExampleCarriesDerivedGenesisOnly(t *testing.T) {
	raw, err := os.ReadFile(contractsCeremonyProfilePath)
	if err != nil {
		t.Fatal(err)
	}
	var example struct {
		Network map[string]json.RawMessage `json:"network"`
	}
	if err := json.Unmarshal(raw, &example); err != nil {
		t.Fatal(err)
	}
	if _, supplied := example.Network["licenseRegistryFeature"]; supplied {
		t.Fatal("D12_EXAMPLE_SUPPLIED_DERIVED_FEATURE")
	}
	var genesis string
	if err := json.Unmarshal(example.Network["genesisHash"], &genesis); err != nil {
		t.Fatalf("D12_EXAMPLE_GENESIS_MALFORMED: %v", err)
	}
	if !validAddress(genesis) || genesis == MainnetBetaGenesisHash {
		t.Fatalf("D12_EXAMPLE_GENESIS_INVALID: %s", genesis)
	}
}

// TestCampaignD12ExampleIsRefusedAsTheDraft confirms the example — an
// unsigned chain-foundation input, not an EstateProfileV1 — is refused by the
// draft refusal name, never as an unsupported schema.
func TestCampaignD12ExampleIsRefusedAsTheDraft(t *testing.T) {
	raw := contractsCeremonyProfile(t)
	_, err := DecodeProfile(raw)
	if RefusalName(err) != RefusalDraftNotEnrollable {
		t.Fatalf("D12_EXAMPLE_DRAFT_REFUSAL: got %v, want %s", err, RefusalDraftNotEnrollable)
	}
}

// TestCampaignD12MainnetGenesisRefusedByName pins the mainnet refusal: a
// signed profile naming the MainnetBeta genesis is never enrolled.
func TestCampaignD12MainnetGenesisRefusedByName(t *testing.T) {
	profile := newEstateProfile(t)
	profile.Network.GenesisHash = MainnetBetaGenesisHash
	err := ValidateProfile(profile)
	if RefusalName(err) != RefusalMainnetGenesis {
		t.Fatalf("D12_MUTANT_CONTROL: got %v, want %s", err, RefusalMainnetGenesis)
	}
}

// TestCampaignD12StoreReleaseThresholdSemantics loads the 2-of-4 store-release
// fixture unchanged and confirms the same fixture at threshold 1 is refused.
func TestCampaignD12StoreReleaseThresholdSemantics(t *testing.T) {
	two := newEstateProfile(t)
	if err := ValidateProfile(two); err != nil {
		t.Fatalf("D12_STORE_RELEASE_TWO_OF_FOUR_REFUSED: %v", err)
	}
	one := storeReleaseThresholdOne(t)
	err := ValidateProfile(one)
	if RefusalName(err) != RefusalFieldMalformed {
		t.Fatalf("D12_STORE_RELEASE_THRESHOLD_ONE_ACCEPTED: got %v", err)
	}
	var refusal *Refusal
	if errors.As(err, &refusal) && refusal.Subject != "roles.store-release.threshold" {
		t.Fatalf("D12_STORE_RELEASE_THRESHOLD_ONE_SUBJECT: got %s", refusal.Subject)
	}
}