package installerrelease

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The committed estate-profile vectors (owner keys derived from fixed labels;
// no authority anywhere).
func profileVector(t *testing.T, name string) (json.RawMessage, estateprofile.EstateProfileV1, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "estate-profile-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Profiles []struct {
			Name          string          `json:"name"`
			Profile       json.RawMessage `json:"profile"`
			ProfileSHA256 string          `json:"profileSha256"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors.Profiles {
		if v.Name == name {
			var profile estateprofile.EstateProfileV1
			if err := json.Unmarshal(v.Profile, &profile); err != nil {
				t.Fatal(err)
			}
			return v.Profile, profile, v.ProfileSHA256
		}
	}
	t.Fatalf("profile vector %s missing", name)
	return nil, estateprofile.EstateProfileV1{}, ""
}

func TestTrustFromProfileProjectsTheOwnersReleaseTrust(t *testing.T) {
	_, profile, digest := profileVector(t, "new-estate-revision-1")
	trust, got, err := TrustFromProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if got != digest {
		t.Fatalf("digest %s != vector %s", got, digest)
	}
	master, _ := primitives.PubkeyFromBase58(profile.Anchors.MasterMint)
	if trust.MasterNFTMint() != master || trust.masterNFTMint != master {
		t.Fatal("master is not anchors.masterMint")
	}
	var core string
	for _, role := range profile.Roles {
		if role.Role == estateprofile.AuthorityRoleCore {
			core = role.Vault
		}
	}
	if custodian, _ := primitives.PubkeyFromBase58(core); trust.custodian != custodian {
		t.Fatal("custodian is not roles.core.vault")
	}
	if len(trust.publishers) != len(profile.ReleaseTrust.PublisherKeys) || trust.threshold != profile.ReleaseTrust.Threshold {
		t.Fatalf("publishers %d threshold %d", len(trust.publishers), trust.threshold)
	}
	for _, key := range profile.ReleaseTrust.PublisherKeys {
		raw, _ := hex.DecodeString(key)
		if _, ok := trust.publishers[[32]byte(raw)]; !ok {
			t.Fatalf("publisher %s missing", key)
		}
	}
	// A profile edited after signing is refused, not projected.
	profile.ReleaseTrust.PublisherKeys = append([]string(nil), profile.ReleaseTrust.PublisherKeys[:1]...)
	profile.ReleaseTrust.Threshold = 1
	if _, _, err := TrustFromProfile(profile); !errors.Is(err, ErrProfile) {
		t.Fatalf("unsigned edit: %v", err)
	}
}

func TestLoadProfileTrustRequiresThePinnedProfile(t *testing.T) {
	raw, _, digest := profileVector(t, "new-estate-revision-1")
	path := filepath.Join(t.TempDir(), "estate-profile.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, profile, err := LoadProfileTrust(path, digest); err != nil || profile.EstateID == "" {
		t.Fatalf("pinned profile refused: %v", err)
	}
	_, _, other := profileVector(t, "new-estate-revision-2-migrate")
	for name, c := range map[string]struct{ path, pin, want string }{
		"another profile's pin": {path, other, "is not the pinned"},
		"uppercase pin":         {path, strings.ToUpper(digest), "lowercase profileSha256"},
		"relative path":         {"estate-profile.json", digest, "absolute clean path"},
		"absent file":           {path + ".absent", digest, "read"},
	} {
		if _, _, err := LoadProfileTrust(c.path, c.pin); !errors.Is(err, ErrProfile) || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadProfileTrust(link, digest); !errors.Is(err, ErrProfile) {
		t.Fatalf("symlink: %v", err)
	}
}
