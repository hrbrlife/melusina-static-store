package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

type storeEstateProfileVectors struct {
	Profiles []struct {
		Name    string                        `json:"name"`
		Profile estateprofile.EstateProfileV1 `json:"profile"`
	} `json:"profiles"`
}

func storeEstateProfileFixture(t *testing.T) estateprofile.EstateProfileV1 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "estate-profile-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors storeEstateProfileVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors.Profiles {
		if vector.Name == "new-estate-revision-1" {
			if _, err := estateprofile.VerifyProfile(vector.Profile); err != nil {
				t.Fatalf("profile vector invalid: %v", err)
			}
			return vector.Profile
		}
	}
	t.Fatal("new-estate-revision-1 profile vector missing")
	return estateprofile.EstateProfileV1{}
}

func storeEstateDeclarationForProfile(t *testing.T, profile estateprofile.EstateProfileV1) storeEstateDeclaration {
	t.Helper()
	releaseRole, ok := profileStoreReleaseRole(profile)
	if !ok {
		t.Fatal("profile has no Store release role")
	}
	licenseRegistryProgramID := profileProgramID(t, profile, estateprofile.ProgramRoleLicenseRegistry)
	squadsProgramID := profileExternalProgramID(t, profile, estateprofile.ExternalRoleSquadsV4)
	return storeEstateDeclaration{
		// The profile deliberately does not contain a tenant operating licence.
		// This valid public key is only used to test that the preflight calls the
		// missing binding out rather than silently pretending it checked it.
		LicenseNFTMint:       profile.Anchors.MasterMint,
		StoreAuthority:       profile.Store.OperatorKey,
		ProgramID:            licenseRegistryProgramID,
		Domain:               profile.Store.RootDomain,
		StoreID:              profile.Store.StoreID,
		ResellerNFTMint:      profile.Anchors.ResellerMint,
		ReleaseMasterNFTMint: profile.Anchors.MasterMint,
		ReleaseSquadsAuthority: ReleaseSquadsAuthority{
			Multisig: releaseRole.Multisig, Vault: releaseRole.Vault,
			ProgramID: squadsProgramID,
			Threshold: int(releaseRole.Threshold), MemberCount: int(releaseRole.MemberCount),
		},
	}
}

func profileProgramID(t *testing.T, profile estateprofile.EstateProfileV1, role string) string {
	t.Helper()
	for _, program := range profile.Programs {
		if program.Role == role {
			return program.ProgramID
		}
	}
	t.Fatalf("profile program %q missing", role)
	return ""
}

func profileExternalProgramID(t *testing.T, profile estateprofile.EstateProfileV1, role string) string {
	t.Helper()
	for _, program := range profile.ExternalPrograms {
		if program.Role == role {
			return program.ProgramID
		}
	}
	t.Fatalf("profile external program %q missing", role)
	return ""
}

func TestStoreEstateProfileCheckAcceptsExactProjection(t *testing.T) {
	profile := storeEstateProfileFixture(t)
	declaration := storeEstateDeclarationForProfile(t, profile)
	digest, err := verifyStoreEstateDeclaration(declaration, profile)
	if err != nil {
		t.Fatalf("exact profile projection rejected: %v", err)
	}
	wantDigest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if digest != wantDigest {
		t.Fatalf("digest = %q, want %q", digest, wantDigest)
	}
}

func TestStoreEstateProfileCheckRefusesAConfigAnchorFromAnotherEstate(t *testing.T) {
	profile := storeEstateProfileFixture(t)
	declaration := storeEstateDeclarationForProfile(t, profile)
	declaration.ProgramID = profileProgramID(t, profile, estateprofile.ProgramRoleWitnessVerifier)
	_, err := verifyStoreEstateDeclaration(declaration, profile)
	if err == nil || !strings.Contains(err.Error(), "store-estate-profile-config-mismatch: estate-profile-anchor-mismatch:programs.license-registry.programId") {
		t.Fatalf("foreign program declaration error = %v", err)
	}
}

func TestStoreEstateProfileCheckRefusesAChangedReleaseQuorum(t *testing.T) {
	profile := storeEstateProfileFixture(t)
	declaration := storeEstateDeclarationForProfile(t, profile)
	declaration.ReleaseSquadsAuthority.Threshold++
	_, err := verifyStoreEstateDeclaration(declaration, profile)
	if err == nil || !strings.Contains(err.Error(), "store-estate-profile-config-mismatch: roles.store-release.threshold") {
		t.Fatalf("changed quorum error = %v", err)
	}
}

func TestStoreEstateProfileCheckLoadsOnlyAnExplicitCompleteDeclaration(t *testing.T) {
	profile := storeEstateProfileFixture(t)
	declaration := storeEstateDeclarationForProfile(t, profile)
	profileRaw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"license_nft_mint":        declaration.LicenseNFTMint,
		"store_authority":         declaration.StoreAuthority,
		"program_id":              declaration.ProgramID,
		"domain":                  declaration.Domain,
		"store_id":                declaration.StoreID,
		"reseller_nft_mint":       declaration.ResellerNFTMint,
		"release_master_nft_mint": declaration.ReleaseMasterNFTMint,
		"release_squads_authority": map[string]any{
			"multisig":     declaration.ReleaseSquadsAuthority.Multisig,
			"vault":        declaration.ReleaseSquadsAuthority.Vault,
			"program_id":   declaration.ReleaseSquadsAuthority.ProgramID,
			"threshold":    declaration.ReleaseSquadsAuthority.Threshold,
			"member_count": declaration.ReleaseSquadsAuthority.MemberCount,
		},
	}
	configRaw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	configPath := filepath.Join(root, "store.config.json")
	profilePath := filepath.Join(root, "estate.json")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, profileRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := checkStoreEstateProfile(estateProfileCheckOptions{configPath: configPath, profilePath: profilePath})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if report.Status != "profile-config-projection-verified" || report.EstateID != profile.EstateID || len(report.UnboundConfigInputs) != 1 || report.UnboundConfigInputs[0] != "license_nft_mint" {
		t.Fatalf("report = %+v", report)
	}

	delete(config, "store_authority")
	configRaw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = checkStoreEstateProfile(estateProfileCheckOptions{configPath: configPath, profilePath: profilePath})
	if err == nil || !strings.Contains(err.Error(), "store-estate-profile-config-missing:store_authority") {
		t.Fatalf("implicit Store authority accepted: %v", err)
	}
}

func TestStoreEstateProfileCheckRefusesDuplicateConfigurationKeys(t *testing.T) {
	_, err := decodeUniqueJSONObject([]byte(`{"domain":"one.invalid","domain":"two.invalid"}`))
	if err == nil || !strings.Contains(err.Error(), `JSON has duplicate key "domain"`) {
		t.Fatalf("duplicate config key error = %v", err)
	}
}

func TestStoreEstateProfileCheckRefusesNestedDuplicateConfigurationKeys(t *testing.T) {
	_, err := decodeUniqueJSONObject([]byte(`{"release_squads_authority":{"multisig":"one","multisig":"two"}}`))
	if err == nil || !strings.Contains(err.Error(), `JSON has duplicate key "multisig"`) {
		t.Fatalf("nested duplicate config key error = %v", err)
	}
}
