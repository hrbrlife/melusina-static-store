package estateprofile

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

func c1RunnerAddress(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/contracts/C1-estate/C1-estate-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Governance struct {
			Runner struct {
				PublicKey string `json:"publicKey"`
				Vote      bool   `json:"vote"`
			} `json:"runner"`
		} `json:"governance"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Governance.Runner.Vote {
		t.Fatal("D14_RUNNER_VOTE_FORBIDDEN: vector grants a vote")
	}
	return fixture.Governance.Runner.PublicKey
}

func TestC1D14NonVotingRunnerAndTwoVoterCore(t *testing.T) {
	profile := newEstateProfile(t)
	for i := range profile.Roles {
		if profile.Roles[i].Role == AuthorityRoleCore || profile.Roles[i].Role == AuthorityRoleStoreRelease {
			profile.Roles[i].Threshold = 2
			profile.Roles[i].PermissionMasks = []uint32{5, 5, 7, 7}
		}
	}
	profile.Roles = append(profile.Roles, AuthorityRoleV1{
		Role: AuthorityRoleRunner, Kind: AuthorityKindKey,
		Vault: c1RunnerAddress(t), Threshold: 1, MemberCount: 1,
		PermissionMasks: []uint32{},
	})
	sort.Slice(profile.Roles, func(i, j int) bool { return profile.Roles[i].Role < profile.Roles[j].Role })
	profile = signProfile(t, profile, "owner-a", "owner-b")
	if _, err := VerifyProfile(profile); err != nil {
		t.Fatalf("D14_NONVOTING_RUNNER_ACCEPTED: %v", err)
	}

	votingRunner := profile
	votingRunner.Roles = append([]AuthorityRoleV1(nil), profile.Roles...)
	for i := range votingRunner.Roles {
		if votingRunner.Roles[i].Role == AuthorityRoleRunner {
			votingRunner.Roles[i] = AuthorityRoleV1{
				Role: AuthorityRoleRunner, Kind: AuthorityKindSquads,
				Multisig: vectorAddress("C1/D14/voting-runner-multisig"),
				Vault:    c1RunnerAddress(t), Threshold: 1, MemberCount: 1,
				PermissionMasks: []uint32{7},
				ConfigAuthority: "11111111111111111111111111111111",
			}
		}
	}
	if err := ValidateProfile(votingRunner); err == nil || err.Error() != "estate-profile-field-malformed:roles.estate-runner.kind" {
		t.Fatalf("D14_VOTING_RUNNER_REFUSAL: got %v", err)
	}
}

func TestC1D14CoreCannotCountRunnerAsSecondVote(t *testing.T) {
	profile := newEstateProfile(t)
	for i := range profile.Roles {
		if profile.Roles[i].Role == AuthorityRoleCore || profile.Roles[i].Role == AuthorityRoleStoreRelease {
			profile.Roles[i].Threshold = 2
			profile.Roles[i].PermissionMasks = []uint32{5, 5, 5, 7}
		}
	}
	if err := ValidateProfile(profile); err == nil || err.Error() != "estate-profile-field-malformed:roles.core.threshold" {
		t.Fatalf("D14_RUNNER_NOT_THRESHOLD_VOTER: got %v", err)
	}
}
