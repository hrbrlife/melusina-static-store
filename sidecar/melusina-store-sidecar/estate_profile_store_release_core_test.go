package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// K-CHN-03: this Store serves an app only from roles.store-release's vault,
// and the licence registry creates every app ReleaseEntry under the core
// vault, so the Store's own offline review (estate-profile-review) refuses an
// owner-signed profile whose store-release role is a multisig of its own, by
// the verifier's name, before any configuration is rendered from it. The
// positive control is the vector profile, whose store-release is core.
func TestEstateProfileReviewRefusesAStoreReleaseThatIsNotCore(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "estate-profile-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Profiles []struct {
			Name    string          `json:"name"`
			Profile json.RawMessage `json:"profile"`
		} `json:"profiles"`
		Decode []struct {
			Name     string `json:"name"`
			Document string `json:"document"`
		} `json:"decodeVectors"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	documents := map[string][]byte{}
	for _, profile := range vectors.Profiles {
		documents[profile.Name] = profile.Profile
	}
	for _, vector := range vectors.Decode {
		documents["decode:"+vector.Name] = []byte(vector.Document)
	}
	review := func(t *testing.T, document []byte) error {
		t.Helper()
		if len(document) == 0 {
			t.Fatal("the vectors carry no such document")
		}
		path := filepath.Join(t.TempDir(), "estate.json")
		if err := os.WriteFile(path, document, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := reviewStoreEstateProfile(path)
		return err
	}

	// Positive control: store-release is core's authority, and it reviews.
	accepted := documents["new-estate-revision-1"]
	var profile estateprofile.EstateProfileV1
	if err := json.Unmarshal(accepted, &profile); err != nil {
		t.Fatal(err)
	}
	role, ok := profileStoreReleaseRole(profile)
	if !ok || role.Multisig != profile.Roles[0].Multisig || role.Vault != profile.Roles[0].Vault || profile.Roles[0].Role != estateprofile.AuthorityRoleCore {
		t.Fatalf("the vector's store-release role is not core's authority: %+v", profile.Roles)
	}
	if err := review(t, accepted); err != nil {
		t.Fatalf("a profile whose store-release is core must review: %v", err)
	}

	// Negative control: the owner-signed separate 2-of-3 store-release.
	err = review(t, documents["decode:"+"store-release-not-core"])
	if err == nil || !strings.Contains(err.Error(), estateprofile.RefusalStoreReleaseNotCore) {
		t.Fatalf("a separate store-release multisig: %v, want %s", err, estateprofile.RefusalStoreReleaseNotCore)
	}
}
