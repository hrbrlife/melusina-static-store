package estateprofile

import "testing"

const (
	d12RealDevnetGenesis = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
	d12PrivateGenesis    = "DszkBgTZVoPkk9tDyXH85k4xs7HSjzxaCoLnPnuZNu6L"
)

// TestCampaignD12SignedCoreQuorumAndGenesis uses the existing fixture owner
// keys to sign each changed digest. These keys exist only in test code; a
// local signature is no claim about a deployed or authorized estate.
func TestCampaignD12SignedCoreQuorumAndGenesis(t *testing.T) {
	if d12RealDevnetGenesis == d12PrivateGenesis || d12RealDevnetGenesis == MainnetBetaGenesisHash || d12PrivateGenesis == MainnetBetaGenesisHash {
		t.Fatal("network controls are not distinct")
	}
	for _, item := range []struct{ name, genesis string }{
		{"real-devnet", d12RealDevnetGenesis},
		{"private-cluster", d12PrivateGenesis},
	} {
		t.Run(item.name, func(t *testing.T) {
			profile := newEstateProfile(t)
			profile.Network.GenesisHash = item.genesis
			for index := range profile.Roles {
				if profile.Roles[index].Role == AuthorityRoleCore || profile.Roles[index].Role == AuthorityRoleStoreRelease {
					profile.Roles[index].Threshold = 2
				}
			}
			profile = signUnchecked(t, profile, "owner-a", "owner-b")
			decoded, err := DecodeProfile(marshalProfile(t, profile))
			if err != nil {
				t.Fatalf("signed 2-of-4 profile was refused: %v", err)
			}
			if decoded.Network.GenesisHash != item.genesis {
				t.Fatalf("decoded genesis %q, want %q", decoded.Network.GenesisHash, item.genesis)
			}
			if _, err := VerifyProfile(decoded); err != nil {
				t.Fatalf("fixture owner signatures did not verify: %v", err)
			}
		})
	}
}

func TestCampaignD12SignedCoreThresholdOneRefused(t *testing.T) {
	profile := newEstateProfile(t)
	// Remove the Store release role so that only the core floor decides this
	// case, without the Store-release-is-core equality or Store quorum rule.
	roles := make([]AuthorityRoleV1, 0, len(profile.Roles))
	for _, role := range profile.Roles {
		if role.Role == AuthorityRoleStoreRelease {
			continue
		}
		if role.Role == AuthorityRoleCore {
			role.Threshold = 1
		}
		roles = append(roles, role)
	}
	profile.Roles = roles
	profile.Store.ReleaseRole = AuthorityRoleCore
	profile = signUnchecked(t, profile, "owner-a", "owner-b")
	want := RefusalFieldMalformed + ":roles.core.threshold"
	_, err := DecodeProfile(marshalProfile(t, profile))
	requireRefusal(t, err, want)
	_, err = VerifyProfile(profile)
	requireRefusal(t, err, want)
}

func TestCampaignD12SignedMainnetProfileRefused(t *testing.T) {
	profile := newEstateProfile(t)
	profile.Network.GenesisHash = MainnetBetaGenesisHash
	profile = signUnchecked(t, profile, "owner-a", "owner-b")
	_, err := DecodeProfile(marshalProfile(t, profile))
	requireRefusal(t, err, RefusalMainnetGenesis)
	_, err = VerifyProfile(profile)
	requireRefusal(t, err, RefusalMainnetGenesis)
}
