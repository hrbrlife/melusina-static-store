package estateprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestC1D14SharedFixtureHelperPinned(t *testing.T) {
	raw, err := os.ReadFile("fixtures_test.go")
	if err != nil {
		t.Fatalf("C1_D14_SHARED_HELPER_MISSING:fixtures_test.go: %v", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != "1521f84fd3d50c7d6e912a3f3d6add99c8e98fb4d3123c0906949e99c0bf1432" {
		t.Fatalf("C1_D14_SHARED_HELPER_DRIFT:fixtures_test.go:%s", got)
	}
}

func TestC1D14CrossCopyParityRequired(t *testing.T) {
	contractsRoot := os.Getenv("C1_CONTRACTS_CHECKOUT")
	if contractsRoot == "" {
		contractsRoot = "../../../../../contracts"
	}
	deployerRoot := os.Getenv("C1_DEPLOYER_CHECKOUT")
	if deployerRoot == "" {
		deployerRoot = "../../../../../deployer"
	}
	for _, artifact := range []struct{ name, local, contracts, deployer, deployerStore string }{
		{"example", "../../testdata/contracts-example-estate.profile.json", filepath.Join(contractsRoot, "scripts/estate/examples/example-estate.profile.json"), filepath.Join(deployerRoot, "deploy-ui/testdata/contracts-example-estate.profile.json"), ""},
		{"profile-vectors", "../../testdata/estate-profile-vectors.json", filepath.Join(contractsRoot, "scripts/estate/testdata/estate-profile-vectors.json"), filepath.Join(deployerRoot, "deploy-ui/testdata/estate-profile-vectors.json"), filepath.Join(deployerRoot, "deploy-ui/testdata/store-estate-profile-vectors.json")},
	} {
		local, err := os.ReadFile(artifact.local)
		if err != nil {
			t.Fatalf("C1_D14_COPY_PARITY_MISSING:%s:store: %v", artifact.name, err)
		}
		peers := []struct{ name, path string }{{"contracts", artifact.contracts}, {"deployer", artifact.deployer}}
		if artifact.deployerStore != "" {
			peers = append(peers, struct{ name, path string }{"deployer-store", artifact.deployerStore})
		}
		for _, peer := range peers {
			copy, err := os.ReadFile(peer.path)
			if err != nil {
				t.Fatalf("C1_D14_COPY_PARITY_MISSING:%s:%s: %v", artifact.name, peer.name, err)
			}
			if !bytes.Equal(local, copy) {
				t.Fatalf("C1_D14_COPY_PARITY_DRIFT:%s:%s", artifact.name, peer.name)
			}
		}
	}
}

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
