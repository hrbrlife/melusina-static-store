package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

type c1D33Manifest struct {
	PublisherKeyset struct {
		Threshold uint32 `json:"threshold"`
		Keys      []struct {
			PublicKey string `json:"ed25519PublicKey"`
		} `json:"keys"`
	} `json:"publisherKeyset"`
}

// The D09 release-set vector is signed by test publishers. Build a matching
// owner-signed test estate using deterministic fixture owner keys, then require
// the typed release-tools front door to reach provider selection without any
// MEL_RELEASE_* environment setup. This test never executes a provider.
func c1D33FixtureProfile(t *testing.T, manifestPath string) string {
	t.Helper()
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest c1D33Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.PublisherKeyset.Threshold != 3 || len(manifest.PublisherKeyset.Keys) != 4 {
		t.Fatal("D33_SIGNED_MANIFEST_FIXTURE_DRIFT")
	}
	vectorsRaw, err := os.ReadFile("../../testdata/estate-profile-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Profiles []struct {
			Name    string          `json:"name"`
			Profile json.RawMessage `json:"profile"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(vectorsRaw, &vectors); err != nil {
		t.Fatal(err)
	}
	var profile estateprofile.EstateProfileV1
	for _, row := range vectors.Profiles {
		if row.Name == "new-estate-revision-1" {
			if err := json.Unmarshal(row.Profile, &profile); err != nil {
				t.Fatal(err)
			}
		}
	}
	if profile.Schema == "" {
		t.Fatal("D33_ESTATE_PROFILE_FIXTURE_MISSING")
	}
	profile.ReleaseTrust.PublisherKeys = nil
	for _, key := range manifest.PublisherKeyset.Keys {
		profile.ReleaseTrust.PublisherKeys = append(profile.ReleaseTrust.PublisherKeys, key.PublicKey)
	}
	sort.Strings(profile.ReleaseTrust.PublisherKeys)
	profile.ReleaseTrust.Threshold = manifest.PublisherKeyset.Threshold
	profile.Signatures = nil
	digest, err := estateprofile.ProfileSHA256(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyID := range []string{"owner-a", "owner-b"} {
		seed := sha256.Sum256([]byte("melusina-estate-profile-vector-key:" + profile.OwnerPolicy.PolicyID + "/" + keyID))
		signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), []byte(digest))
		profile.Signatures = append(profile.Signatures, estateprofile.SignatureV1{
			KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(signature),
		})
	}
	if _, err := estateprofile.VerifyProfile(profile); err != nil {
		t.Fatalf("D33_SIGNED_PROFILE_FIXTURE_INVALID: %v", err)
	}
	profileRaw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "estate-profile.json")
	if err := os.WriteFile(path, profileRaw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func c1D33ClearLegacyEnv(t *testing.T) {
	t.Helper()
	for _, pair := range os.Environ() {
		name, _, _ := strings.Cut(pair, "=")
		if strings.HasPrefix(name, "MEL_RELEASE_") {
			t.Setenv(name, "")
		}
	}
}

func TestC1D33SignedFixtureProfileBindsPublisherDevice(t *testing.T) {
	manifest, err := filepath.Abs("../../testdata/contracts/C1-estate/d33-signed-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	device, err := filepath.Abs("../../testdata/contracts/C1-estate/d33-publisher-device.json")
	if err != nil {
		t.Fatal(err)
	}
	profilePath := c1D33FixtureProfile(t, manifest)
	profileRaw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := estateprofile.DecodeProfile(profileRaw)
	if err != nil {
		t.Fatalf("D33_FIXTURE_PROFILE_DECODE: %v", err)
	}
	var reference struct {
		SignerKind string `json:"signerKind"`
		PublicKey  string `json:"publicKey"`
	}
	deviceRaw, err := os.ReadFile(device)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(deviceRaw, &reference); err != nil {
		t.Fatal(err)
	}
	if reference.SignerKind != "wallet" || !slicesContains(profile.ReleaseTrust.PublisherKeys, reference.PublicKey) {
		t.Fatalf("D33_PUBLISHER_DEVICE_NOT_IN_SIGNED_PROFILE: %s", reference.PublicKey)
	}
}

func slicesContains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestC1D33TypedFrontDoorRefusesUnpinnedProvider(t *testing.T) {
	c1D33ClearLegacyEnv(t)
	manifest, err := filepath.Abs("../../testdata/contracts/C1-estate/d33-signed-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	device, err := filepath.Abs("../../testdata/contracts/C1-estate/d33-publisher-device.json")
	if err != nil {
		t.Fatal(err)
	}
	profile := c1D33FixtureProfile(t, manifest)
	originalDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(originalDir)
	for _, name := range []string{"operator-one", "operator-two"} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), name)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chdir(dir); err != nil {
				t.Fatal(err)
			}
			defer os.Chdir(originalDir)
			err := run([]string{"preflight", "--profile", profile, "--manifest", manifest, "--device", device})
			if err == nil || !strings.Contains(err.Error(), "RELEASE_PROVIDER_UNPINNED") {
				t.Fatalf("D33_RELEASE_PROVIDER_UNPINNED: got %v", err)
			}
			missingProfile := filepath.Join(t.TempDir(), "missing-estate-profile.json")
			err = run([]string{"preflight", "--profile", missingProfile, "--manifest", manifest, "--device", device})
			if err == nil || strings.Contains(err.Error(), "RELEASE_PROVIDER_UNPINNED") {
				t.Fatalf("D33_MISSING_PROFILE_PRECEDES_PROVIDER: got %v", err)
			}
		})
	}
}

func TestC1D33LegacyOverrideCannotReplaceProfile(t *testing.T) {
	c1D33ClearLegacyEnv(t)
	manifest, err := filepath.Abs("../../testdata/contracts/C1-estate/d33-signed-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	device, err := filepath.Abs("../../testdata/contracts/C1-estate/d33-publisher-device.json")
	if err != nil {
		t.Fatal(err)
	}
	profile := c1D33FixtureProfile(t, manifest)
	err = run([]string{"preflight", "--profile", profile, "--manifest", manifest, "--device", device})
	if err == nil || !strings.Contains(err.Error(), "RELEASE_PROVIDER_UNPINNED") {
		t.Fatalf("D33_VALID_PROFILE_REACHES_PROVIDER_SELECTION: got %v", err)
	}
	t.Setenv("MEL_RELEASE_STORE_DOMAIN", "us.paype.cc")
	err = run([]string{"preflight", "--profile", profile, "--manifest", manifest, "--device", device})
	if err == nil || !strings.Contains(err.Error(), "PROFILE_PROJECTION_MISMATCH") {
		t.Fatalf("D33_PROFILE_PROJECTION_MISMATCH: got %v", err)
	}
}
