package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// The fictitious new estate of testdata/estate-profile-vectors.json. These
// constants stand in for it in catalog fixtures;
// TestEstateFixtureConstantsAreTheVector keeps them equal to the vector.
const (
	estateVectorsPath    = "../../testdata/estate-profile-vectors.json"
	newEstateVector      = "new-estate-revision-1"
	testStoreOrigin      = "https://bazaar.rehearsal.invalid"
	testProgramID        = "7DNxWEbxfLQTCcNKnouxcSTNk2Z3SSua1mt5YxEf1nKD"
	testSquadsMultisig   = "3D1TFuixe17WNQGBGUc1c8BKEAfspARX34Ak9yP77wkD"
	testSquadsVault      = "QLCZ39GVSyJn89pN4HUe4yFrVXXu2NVKKdbxvfFNbn4"
	testSquadsProgramID  = "8bDkdukaQiH73C7Z6wdVgtXEJQwZsHD8f7iAnBGqBuLb"
	testSquadsThreshold  = 2
	testSquadsMembers    = 3
	testEstateMasterMint = "Arum4b6QykqtkcKpfxbHSU1TTiHjxVDCxL1EPg9ka7sz"
)

func testSquadsAuthority() SquadsAuthority {
	return SquadsAuthority{
		Multisig: testSquadsMultisig, Vault: testSquadsVault, ProgramID: testSquadsProgramID,
		Threshold: testSquadsThreshold, MemberCount: testSquadsMembers,
	}
}

// estateVector returns one committed vector's raw profile JSON and its
// recorded digest.
func estateVector(t *testing.T, name string) (json.RawMessage, string) {
	t.Helper()
	raw, err := os.ReadFile(estateVectorsPath)
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
	for _, vector := range vectors.Profiles {
		if vector.Name == name {
			return vector.Profile, vector.ProfileSHA256
		}
	}
	t.Fatalf("vector %s missing", name)
	return nil, ""
}

// writeEstateProfile writes the new-estate profile to a private file and
// returns its path and verified digest. mutate, when set, edits the profile,
// which is then re-signed by two of its owners: the owner keys of the vectors
// are derived from fixed labels (internal/estateprofile/fixtures_test.go) and
// hold no authority anywhere.
func writeEstateProfile(t *testing.T, mutate func(*estateprofile.EstateProfileV1)) (string, string) {
	t.Helper()
	raw, digest := estateVector(t, newEstateVector)
	if mutate != nil {
		var profile estateprofile.EstateProfileV1
		if err := json.Unmarshal(raw, &profile); err != nil {
			t.Fatal(err)
		}
		mutate(&profile)
		profile = resignEstateProfile(t, profile)
		var err error
		if raw, err = json.Marshal(profile); err != nil {
			t.Fatal(err)
		}
		if digest, err = estateprofile.ProfileSHA256(profile); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "estate-profile.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, digest
}

func resignEstateProfile(t *testing.T, profile estateprofile.EstateProfileV1) estateprofile.EstateProfileV1 {
	t.Helper()
	profile.Signatures = nil
	digest, err := estateprofile.ProfileSHA256(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyID := range []string{"owner-a", "owner-b"} {
		seed := sha256.Sum256([]byte("melusina-estate-profile-vector-key:" + profile.OwnerPolicy.PolicyID + "/" + keyID))
		profile.Signatures = append(profile.Signatures, estateprofile.SignatureV1{
			KeyID:     keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), []byte(digest))),
		})
	}
	return profile
}

// estateOverrideNames are the older per-value variables a wrapper may still
// set. Tests clear them so an operator's shell cannot decide an outcome.
var estateOverrideNames = []string{
	"MEL_RELEASE_STORE_URL", "MEL_RELEASE_BUNDLE_ORIGIN", "MEL_RELEASE_STORE_DOMAIN",
	"MEL_RELEASE_STORE_ID", "MEL_RELEASE_PROGRAM_ID", "MEL_PROGRAM_ID", "MEL_RELEASE_MASTER_NFT_MINT",
	"MEL_RELEASE_SQUADS_MULTISIG", "MEL_RELEASE_SQUADS_VAULT", "MEL_RELEASE_SQUADS_PROGRAM_ID",
	"MEL_RELEASE_SQUADS_THRESHOLD", "MEL_RELEASE_SQUADS_MEMBER_COUNT",
}

// setReleaseEnv sets a complete mutation configuration bound to the given
// profile, including a Store operator identity for that profile's Store.
func setReleaseEnv(t *testing.T, profilePath, profileSHA256 string) {
	t.Helper()
	for _, name := range estateOverrideNames {
		t.Setenv(name, "")
	}
	operatorKey, registry := testEstateStoreFacts(profilePath)
	for key, value := range map[string]string{
		"MEL_RELEASE_CONFIG":                "/tmp/bazaar-catalog.yaml",
		"MEL_RELEASE_SIGNER_PROVIDER":       "provider",
		"MEL_RELEASE_STORE_PUBKEY":          writeStoreIdentity(t, operatorKey, registry, func(*identity.Public) {}),
		"MEL_RELEASE_STORE_LICENSE_MINT":    "store-license-mint",
		"MEL_RELEASE_PUBLISHER_KEY":         "/tmp/publisher.key",
		"MEL_RELEASE_ESTATE_PROFILE":        profilePath,
		"MEL_RELEASE_ESTATE_PROFILE_SHA256": profileSHA256,
		"MEL_RELEASE_OP_TIMEOUT_SECS":       "",
	} {
		t.Setenv(key, value)
	}
}

// testEstateStoreFacts reads the Store operator key and registry a profile
// file names, or placeholders when it names none (a test of a profile that
// must be refused).
func testEstateStoreFacts(profilePath string) (string, string) {
	operatorKey, registry := "11111111111111111111111111111111", testProgramID
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		return operatorKey, registry
	}
	var profile estateprofile.EstateProfileV1
	if json.Unmarshal(raw, &profile) != nil {
		return operatorKey, registry
	}
	if profile.Store.OperatorKey != "" {
		operatorKey = profile.Store.OperatorKey
	}
	for _, program := range profile.Programs {
		if program.Role == estateprofile.ProgramRoleLicenseRegistry {
			registry = program.ProgramID
		}
	}
	return operatorKey, registry
}

// writeStoreIdentity writes a Store operator identity.Public whose signing key
// is operatorKey, derived under registry; mutate edits it first.
func writeStoreIdentity(t *testing.T, operatorKey, registry string, mutate func(*identity.Public)) string {
	t.Helper()
	public := identity.Public{
		Version: identity.CurrentVersion,
		Ref: identity.Ref{
			Kind:        identity.KindSidecar,
			ChainID:     "solana:devnet",
			ProgramID:   registry,
			LicenseMint: "11111111111111111111111111111111",
			Domain:      strings.TrimPrefix(testStoreOrigin, "https://"),
			PDA:         "11111111111111111111111111111111",
			SidecarID:   "rehearsal-root-store-v2",
			KeyVersion:  1,
		},
		SignPubkeyB58: operatorKey,
		BoxPubkeyB58:  "11111111111111111111111111111111",
	}
	mutate(&public)
	raw, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "store-operator.public.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// setNewEstateReleaseEnv binds a complete configuration to the unmodified
// new-estate profile.
func setNewEstateReleaseEnv(t *testing.T) {
	t.Helper()
	path, digest := writeEstateProfile(t, nil)
	setReleaseEnv(t, path, digest)
}

func TestEstateFixtureConstantsAreTheVector(t *testing.T) {
	raw, _ := estateVector(t, newEstateVector)
	var profile estateprofile.EstateProfileV1
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	binding, err := estateBindingOf(profile, "")
	if err != nil {
		t.Fatal(err)
	}
	if binding.StoreOrigin != testStoreOrigin || binding.ProgramID != testProgramID || binding.MasterNftMint != testEstateMasterMint || binding.Squads != testSquadsAuthority() {
		t.Fatalf("fixture constants drifted from the %s vector: %+v", newEstateVector, binding)
	}
}

// Every estate value comes out of the signed profile. The expectation is read
// from the vector's raw JSON by field name, not through the binding code, so a
// value taken from the wrong place (the reseller mint for the master, the core
// vault for the release vault) fails by the field it names.
func TestLoadConfigDerivesEveryEstateValueFromTheSignedProfile(t *testing.T) {
	path, digest := writeEstateProfile(t, nil)
	setReleaseEnv(t, path, digest)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig(): %v", err)
	}

	raw, recorded := estateVector(t, newEstateVector)
	if digest != recorded {
		t.Fatalf("written profile digest %s is not the vector's %s", digest, recorded)
	}
	var doc struct {
		Store struct {
			RootDomain string `json:"rootDomain"`
			StoreID    string `json:"storeId"`
		} `json:"store"`
		Anchors struct {
			MasterMint   string `json:"masterMint"`
			ResellerMint string `json:"resellerMint"`
		} `json:"anchors"`
		Programs []struct {
			Role      string `json:"role"`
			ProgramID string `json:"programId"`
		} `json:"programs"`
		ExternalPrograms []struct {
			Role      string `json:"role"`
			ProgramID string `json:"programId"`
		} `json:"externalPrograms"`
		Roles []struct {
			Role        string `json:"role"`
			Multisig    string `json:"multisig"`
			Vault       string `json:"vault"`
			Threshold   int    `json:"threshold"`
			MemberCount int    `json:"memberCount"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"storeOrigin": "https://" + doc.Store.RootDomain, "storeDomain": doc.Store.RootDomain, "storeId": doc.Store.StoreID, "masterMint": doc.Anchors.MasterMint}
	for _, program := range doc.Programs {
		if program.Role == "license-registry" {
			want["registry"] = program.ProgramID
		}
	}
	for _, program := range doc.ExternalPrograms {
		if program.Role == "squads-v4" {
			want["squadsProgram"] = program.ProgramID
		}
	}
	for _, role := range doc.Roles {
		if role.Role == "store-release" {
			want["multisig"], want["vault"] = role.Multisig, role.Vault
			want["threshold"], want["memberCount"] = strconv.Itoa(role.Threshold), strconv.Itoa(role.MemberCount)
		}
	}
	got := map[string]string{
		"storeOrigin": cfg.StoreURL, "storeDomain": cfg.StoreDomain, "storeId": cfg.StoreID, "masterMint": cfg.MasterNftMint,
		"registry": cfg.ProgramID, "squadsProgram": cfg.estate.Squads.ProgramID,
		"multisig": cfg.estate.Squads.Multisig, "vault": cfg.estate.Squads.Vault,
		"threshold": strconv.Itoa(cfg.estate.Squads.Threshold), "memberCount": strconv.Itoa(cfg.estate.Squads.MemberCount),
	}
	for field, value := range want {
		if value == "" || got[field] != value {
			t.Errorf("%s = %q, want the profile's %q", field, got[field], value)
		}
	}
	if cfg.BundleOrigin != cfg.StoreURL || cfg.MasterNftMint == doc.Anchors.ResellerMint {
		t.Errorf("bundle origin %q / master mint %q not bound to the estate Store", cfg.BundleOrigin, cfg.MasterNftMint)
	}
	if len(want) != len(got) {
		t.Fatalf("expected %d profile fields, compared %d", len(got), len(want))
	}
}

// Without a verified profile whose digest is the reviewed pin there is no
// estate, and every configuration refuses by name before it can fall back to
// anything.
func TestLoadConfigRefusesWithoutAVerifiedPinnedProfile(t *testing.T) {
	path, digest := writeEstateProfile(t, nil)
	_, otherDigest := estateVector(t, "new-estate-revision-2-migrate")
	symlink := filepath.Join(t.TempDir(), "estate-profile.json")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	unsigned := filepath.Join(t.TempDir(), "estate-profile.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), "rehearsal-root-store", "tampered-root-store", 1)
	if tampered == string(raw) {
		t.Fatal("tamper control did not change the profile")
	}
	if err := os.WriteFile(unsigned, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	// A profile signed by keys outside its owner policy, pinned to its own
	// digest: only signature verification can refuse it.
	var forged estateprofile.EstateProfileV1
	if err := json.Unmarshal(raw, &forged); err != nil {
		t.Fatal(err)
	}
	forged.Store.StoreID = "forged-root-store"
	forged.Signatures = nil
	forgedDigest, err := estateprofile.ProfileSHA256(forged)
	if err != nil {
		t.Fatal(err)
	}
	for _, keyID := range []string{"owner-a", "owner-b"} {
		seed := sha256.Sum256([]byte("not-an-owner-of-this-estate/" + keyID))
		forged.Signatures = append(forged.Signatures, estateprofile.SignatureV1{
			KeyID:     keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), []byte(forgedDigest))),
		})
	}
	forgedRaw, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	forgedPath := filepath.Join(t.TempDir(), "estate-profile.json")
	if err := os.WriteFile(forgedPath, forgedRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		path, digest, want string
	}{
		"no profile":        {path: "", digest: digest, want: "missing required env: MEL_RELEASE_ESTATE_PROFILE"},
		"no pin":            {path: path, digest: "", want: "missing required env: MEL_RELEASE_ESTATE_PROFILE_SHA256"},
		"malformed pin":     {path: path, digest: strings.ToUpper(digest), want: "MEL_RELEASE_ESTATE_PROFILE_SHA256 must be"},
		"another profile":   {path: path, digest: otherDigest, want: "is not the reviewed MEL_RELEASE_ESTATE_PROFILE_SHA256"},
		"relative path":     {path: "estate-profile.json", digest: digest, want: "absolute clean path"},
		"symlink":           {path: symlink, digest: digest, want: "must be a regular file"},
		"unsigned edit":     {path: unsigned, digest: digest, want: "estate profile:"},
		"forged signatures": {path: forgedPath, digest: forgedDigest, want: "estate profile:"},
		"missing file":      {path: filepath.Join(t.TempDir(), "absent.json"), digest: digest, want: "estate profile:"},
	} {
		t.Run(name, func(t *testing.T) {
			setReleaseEnv(t, tc.path, tc.digest)
			for _, load := range []func() (Config, error){loadConfig, loadPreflightConfig} {
				if _, err := load(); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error = %v, want %q", err, tc.want)
				}
			}
		})
	}
	// Positive control: the same inputs with the right pin load.
	setReleaseEnv(t, path, digest)
	if _, err := loadConfig(); err != nil {
		t.Fatalf("control: verified pinned profile refused: %v", err)
	}
}

// A profile that verifies but does not describe a root Store released by a
// Squads store-release authority is not one mel-release can publish into.
func TestEstateBindingRefusesAProfileThatIsNotARootSquadsReleasedStore(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*estateprofile.EstateProfileV1)
		want   string
	}{
		"not root": {
			mutate: func(p *estateprofile.EstateProfileV1) { p.Store.IsRoot = false },
			want:   "not a root Store",
		},
		"released by another role": {
			mutate: func(p *estateprofile.EstateProfileV1) { p.Store.ReleaseRole = estateprofile.AuthorityRoleCore },
			want:   "store.releaseRole",
		},
	} {
		t.Run(name, func(t *testing.T) {
			path, digest := writeEstateProfile(t, tc.mutate)
			setReleaseEnv(t, path, digest)
			if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	// Positive control: a re-signed profile with an unrelated edit binds, so
	// the refusals above are about the Store shape, not the re-signing.
	path, digest := writeEstateProfile(t, func(p *estateprofile.EstateProfileV1) { p.IssuedAt = "2026-09-21T00:00:00Z" })
	setReleaseEnv(t, path, digest)
	if _, err := loadConfig(); err != nil {
		t.Fatalf("control: re-signed root profile refused: %v", err)
	}
}

// A wrapper may repeat a profile value in its older variable; any other value
// is refused by name rather than preferred.
func TestLoadConfigRefusesAnEstateOverride(t *testing.T) {
	path, digest := writeEstateProfile(t, nil)
	for name, same := range map[string]string{
		"MEL_RELEASE_STORE_URL":       testStoreOrigin + "/",
		"MEL_RELEASE_BUNDLE_ORIGIN":   testStoreOrigin,
		"MEL_RELEASE_STORE_DOMAIN":    strings.TrimPrefix(testStoreOrigin, "https://"),
		"MEL_RELEASE_STORE_ID":        "rehearsal-root-store",
		"MEL_RELEASE_PROGRAM_ID":      testProgramID,
		"MEL_PROGRAM_ID":              testProgramID,
		"MEL_RELEASE_MASTER_NFT_MINT": testEstateMasterMint,
	} {
		t.Run(name, func(t *testing.T) {
			setReleaseEnv(t, path, digest)
			t.Setenv(name, same)
			if _, err := loadConfig(); err != nil {
				t.Fatalf("%s repeating the profile value refused: %v", name, err)
			}
			other := "https://store.example.test"
			if !strings.HasSuffix(name, "_URL") && !strings.HasSuffix(name, "_ORIGIN") {
				other = "11111111111111111111111111111111"
			}
			t.Setenv(name, other)
			if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), name+"=") || !strings.Contains(err.Error(), "cannot override the owner-signed estate profile") {
				t.Fatalf("%s=%s: error = %v, want a refusal naming it", name, other, err)
			}
		})
	}
}

// The catalog becomes the release selector only when it describes the
// profile's Store and repeats the profile's release authority exactly.
func TestBindCatalogRequiresTheEstateStoreAndAuthority(t *testing.T) {
	path, digest := writeEstateProfile(t, nil)
	setReleaseEnv(t, path, digest)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	good := &Catalog{Origin: testStoreOrigin, ReleaseSquadsAuthority: testSquadsAuthority()}
	bound := cfg
	if err := bound.bindCatalog(good); err != nil {
		t.Fatalf("bindCatalog(estate catalog): %v", err)
	}
	if bound.SquadsMultisig != testSquadsMultisig || bound.SquadsVault != testSquadsVault || bound.SquadsProgramID != testSquadsProgramID || bound.SquadsThreshold != testSquadsThreshold || bound.SquadsMemberCount != testSquadsMembers {
		t.Fatalf("bound authority = %+v", bound)
	}

	other := func(change func(*SquadsAuthority)) *Catalog {
		authority := testSquadsAuthority()
		change(&authority)
		return &Catalog{Origin: testStoreOrigin, ReleaseSquadsAuthority: authority}
	}
	for name, tc := range map[string]struct {
		catalog *Catalog
		want    string
	}{
		"another Store":  {&Catalog{Origin: "https://store.example.test", ReleaseSquadsAuthority: testSquadsAuthority()}, "describes another Store"},
		"multisig":       {other(func(a *SquadsAuthority) { a.Multisig = testSquadsVault }), "roles.store-release authority"},
		"vault":          {other(func(a *SquadsAuthority) { a.Vault = testSquadsMultisig }), "roles.store-release authority"},
		"squads program": {other(func(a *SquadsAuthority) { a.ProgramID = testProgramID }), "roles.store-release authority"},
		"threshold":      {other(func(a *SquadsAuthority) { a.Threshold = 3 }), "roles.store-release authority"},
		"member count":   {other(func(a *SquadsAuthority) { a.MemberCount = 4 }), "roles.store-release authority"},
		"malformed":      {other(func(a *SquadsAuthority) { a.Vault = "" }), "valid shared Squads authority"},
	} {
		t.Run(name, func(t *testing.T) {
			attempt := cfg
			if err := attempt.bindCatalog(tc.catalog); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	if err := (&Config{}).bindCatalog(good); err == nil || !strings.Contains(err.Error(), "no estate profile is bound") {
		t.Fatalf("catalog bound with no estate: %v", err)
	}

	withOverride := cfg
	withOverride.SquadsVault = testSquadsMultisig
	if err := withOverride.bindCatalog(good); err == nil || !strings.Contains(err.Error(), "cannot override") {
		t.Fatalf("Squads override error = %v", err)
	}
}

// The provider sees exactly the estate binding, whatever the caller's
// environment held.
func TestExecProviderCarriesTheEstateBinding(t *testing.T) {
	path, digest := writeEstateProfile(t, nil)
	setReleaseEnv(t, path, digest)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.bindCatalog(&Catalog{Origin: testStoreOrigin, ReleaseSquadsAuthority: testSquadsAuthority()}); err != nil {
		t.Fatal(err)
	}
	env := newExecProvider(cfg).env
	for name, want := range map[string]string{
		"MEL_RELEASE_STORE_URL":           testStoreOrigin,
		"MEL_RELEASE_STORE_DOMAIN":        strings.TrimPrefix(testStoreOrigin, "https://"),
		"MEL_PROGRAM_ID":                  testProgramID,
		"MEL_RELEASE_MASTER_NFT_MINT":     testEstateMasterMint,
		"MEL_RELEASE_SQUADS_MULTISIG":     testSquadsMultisig,
		"MEL_RELEASE_SQUADS_VAULT":        testSquadsVault,
		"MEL_RELEASE_SQUADS_PROGRAM_ID":   testSquadsProgramID,
		"MEL_RELEASE_SQUADS_THRESHOLD":    strconv.Itoa(testSquadsThreshold),
		"MEL_RELEASE_SQUADS_MEMBER_COUNT": strconv.Itoa(testSquadsMembers),
	} {
		if env[name] != want {
			t.Errorf("provider %s = %q, want %q", name, env[name], want)
		}
	}
	merged := strings.Join(mergedEnvironment([]string{"MEL_PROGRAM_ID=11111111111111111111111111111111", "MEL_RELEASE_STORE_DOMAIN=store.example.test"}, env), "\n")
	if !strings.Contains(merged, "MEL_PROGRAM_ID="+testProgramID) || !strings.Contains(merged, "MEL_RELEASE_STORE_DOMAIN=bazaar.rehearsal.invalid") {
		t.Fatalf("an inherited estate value survived the provider environment:\n%s", merged)
	}
}

// The provider names the master mint the ReleaseEntry is seeded by; a mint
// that is not the estate's would register a release the Store never reads.
func TestPublishRefusesABuildSeededByAnotherMasterMint(t *testing.T) {
	h := newHarness(t)
	h.cfg.MasterNftMint = testEstateMasterMint
	err := h.publish("1.0.2")
	if err == nil || !strings.Contains(err.Error(), "is not the estate profile's anchors.masterMint "+testEstateMasterMint) {
		t.Fatalf("publish with a foreign master mint: %v", err)
	}
	if countOp(h.callOps(), "stage") != 0 || countOp(h.callOps(), "propose-register") != 0 {
		t.Fatalf("a build for another estate reached the Store or the chain: %v", h.callOps())
	}

	fresh := newHarness(t)
	fresh.cfg.MasterNftMint = testEstateMasterMint
	if _, err := fresh.preflight("1.0.1"); err == nil || !strings.Contains(err.Error(), "is not the estate profile's anchors.masterMint") {
		t.Fatalf("preflight with a foreign master mint: %v", err)
	}
	// Positive control: the harness's own estate mint publishes.
	control := newHarness(t)
	if err := control.publish("1.0.2"); err != nil {
		t.Fatalf("control publish with the estate master mint: %v", err)
	}
}
