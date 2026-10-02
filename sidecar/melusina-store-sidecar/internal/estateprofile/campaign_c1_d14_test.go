package estateprofile

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
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
	manifest, err := os.ReadFile("../../testdata/c1-rev3-digests.json")
	if err != nil {
		t.Fatalf("C1_D14_CANONICAL_DIGEST_MISSING: %v", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(manifest)); got != "32eee20c186b156829630becf5bfecc06ae0f4d96c0c82c4d0c5b488f8c273ef" {
		t.Fatalf("C1_D14_CANONICAL_DIGEST_DRIFT:manifest:%s", got)
	}
	var canonical struct {
		Schema string            `json:"schema"`
		SHA256 map[string]string `json:"sha256"`
	}
	if err := json.Unmarshal(manifest, &canonical); err != nil || canonical.Schema != "melusina.c1-estate.canonical-digests.v1" {
		t.Fatalf("C1_D14_CANONICAL_DIGEST_MALFORMED: %v", err)
	}
	for _, artifact := range []struct {
		name, path string
		normalized bool
	}{
		{"example", "../../testdata/contracts-example-estate.profile.json", false},
		{"profile", "../../testdata/estate-profile-vectors.json", true},
	} {
		local, err := os.ReadFile(artifact.path)
		if err != nil {
			t.Fatalf("C1_D14_COPY_PARITY_MISSING:%s: %v", artifact.name, err)
		}
		if artifact.normalized {
			var profile map[string]any
			if err := json.Unmarshal(local, &profile); err != nil {
				t.Fatalf("C1_D14_COPY_PARITY_MALFORMED:%s: %v", artifact.name, err)
			}
			delete(profile, "goSources")
			var compact bytes.Buffer
			encoder := json.NewEncoder(&compact)
			encoder.SetEscapeHTML(false)
			if err := encoder.Encode(profile); err != nil {
				t.Fatalf("C1_D14_COPY_PARITY_MALFORMED:%s: %v", artifact.name, err)
			}
			local = bytes.TrimSuffix(compact.Bytes(), []byte("\n"))
		}
		got := fmt.Sprintf("%x", sha256.Sum256(local))
		if canonical.SHA256[artifact.name] == "" || got != canonical.SHA256[artifact.name] {
			t.Fatalf("C1_D14_COPY_PARITY_DRIFT:%s: got %s want %s", artifact.name, got, canonical.SHA256[artifact.name])
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
