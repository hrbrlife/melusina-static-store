package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/storesecurity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func newStoreConfigRenderFixture(t *testing.T) (estateprofile.EstateProfileV1, string, string, string, map[string]any) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := storeEstateProfileFixture(t)
	profileRaw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "estate-profile.json")
	if err := os.WriteFile(profilePath, profileRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]any{
		"schema":          storeConfigRenderInputSchema,
		"kind":            storeConfigRenderInputKind,
		"profileSha256":   digest,
		"licenseNftMint":  profile.Anchors.MasterMint,
		"rpcUrl":          "https://rpc.rehearsal.invalid/v1",
		"rpcFallbackUrls": []string{"https://rpc-fallback.rehearsal.invalid/v1"},
		"rpcAttempts":     2,
		"chainId":         "solana:rehearsal",
		"operatorDomain":  "operator.rehearsal.invalid",
		"securityProfile": signedStoreSecurityFixture(t, profile, digest),
	}
	return profile, profilePath, filepath.Join(dir, "store-render-input.json"), filepath.Join(dir, "store.config.json"), input
}

func signedStoreSecurityFixture(t *testing.T, profile estateprofile.EstateProfileV1, profileDigest string) storesecurity.Profile {
	t.Helper()
	scanner := sha256.Sum256([]byte("store-security-rehearsal-scanner"))
	storeLinkCert := sha256.Sum256([]byte("store-security-rehearsal-store-link-cert"))
	p := storesecurity.Profile{
		Schema: storesecurity.Schema, EstateProfileSHA256: profileDigest, StoreID: profile.Store.StoreID,
		ControlListenAddr: "127.0.0.1:9444", StoreLinkClientCertSHA256: hex.EncodeToString(storeLinkCert[:]),
		ScannerEd25519PublicKey: hex.EncodeToString(ed25519.NewKeyFromSeed(scanner[:]).Public().(ed25519.PublicKey)),
	}
	ownerKeys := map[string]ed25519.PrivateKey{}
	for _, signer := range profile.OwnerPolicy.Signers[:profile.OwnerPolicy.Threshold] {
		seed := sha256.Sum256([]byte("melusina-estate-profile-vector-key:" + profile.OwnerPolicy.PolicyID + "/" + signer.KeyID))
		ownerKeys[signer.KeyID] = ed25519.NewKeyFromSeed(seed[:])
	}
	signed, err := storesecurity.SignOwnerThreshold(p, profile, profileDigest, ownerKeys)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func writeStoreConfigRenderInput(t *testing.T, path string, input map[string]any) {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEstateProfileReviewReturnsTheCanonicalSignedProfilePin(t *testing.T) {
	profile, profilePath, _, _, _ := newStoreConfigRenderFixture(t)
	report, err := reviewStoreEstateProfile(profilePath)
	if err != nil {
		t.Fatalf("review profile: %v", err)
	}
	wantDigest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != storeEstateProfileReviewSchema || report.Status != "owner-signed-estate-profile-verified" || report.EstateID != profile.EstateID || report.ProfileSHA256 != wantDigest || report.ProfileRevision != profile.Revision || report.NetworkGenesisHash != profile.Network.GenesisHash || report.ReleaseTrustThreshold != profile.ReleaseTrust.Threshold {
		t.Fatalf("profile review report = %#v", report)
	}
}

func TestH09_1_12StoreConfigRejectsFoundationDraft(t *testing.T) {
	_, profilePath, _, _, _ := newStoreConfigRenderFixture(t)
	if _, digest, err := loadVerifiedStoreConfigRenderProfile(profilePath); err != nil || digest == "" {
		t.Fatalf("1.12::title-claim: signed estate profile refused: digest=%q err=%v", digest, err)
	}
	if err := os.WriteFile(profilePath, []byte(`{"schema":"melusina.estate-profile/v1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadVerifiedStoreConfigRenderProfile(profilePath); err == nil ||
		!strings.Contains(err.Error(), "1.12::title-claim") || !strings.Contains(err.Error(), estateprofile.RefusalDraftNotEnrollable) {
		t.Fatalf("1.12::title-claim: Store config admitted foundation draft: %v", err)
	}
}

func TestH09_1_5StoreAcceptsFinalWitnessWithoutAuthority(t *testing.T) {
	profile, profilePath, _, _, _ := newStoreConfigRenderFixture(t)
	if _, digest, err := loadVerifiedStoreConfigRenderProfile(profilePath); err != nil || digest == "" {
		t.Fatalf("1.5::title-claim: final witness profile refused: digest=%q err=%v", digest, err)
	}
	profile.Programs[1].UpgradeAuthority = profile.Programs[0].UpgradeAuthority
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadVerifiedStoreConfigRenderProfile(profilePath); err == nil ||
		!strings.Contains(err.Error(), "1.5::title-claim") || !strings.Contains(err.Error(), estateprofile.RefusalProgramMustBeFinal) {
		t.Fatalf("1.5::title-claim: Store accepted witness upgrade authority: %v", err)
	}
}

func TestH09_1_8StoreRepresentsFinalWitness(t *testing.T) {
	profile, profilePath, _, _, _ := newStoreConfigRenderFixture(t)
	if _, digest, err := loadVerifiedStoreConfigRenderProfile(profilePath); err != nil || digest == "" {
		t.Fatalf("1.8::title-claim: final witness profile refused: digest=%q err=%v", digest, err)
	}
	profile.Programs[1].Final = false
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadVerifiedStoreConfigRenderProfile(profilePath); err == nil ||
		!strings.Contains(err.Error(), "1.8::title-claim") || !strings.Contains(err.Error(), estateprofile.RefusalProgramMustBeFinal) {
		t.Fatalf("1.8::title-claim: Store accepted final witness stated governed: %v", err)
	}
}

func TestH09_1_4StoreReleaseNeedsTwoVoters(t *testing.T) {
	profile, profilePath, _, _, _ := newStoreConfigRenderFixture(t)
	if profile.Roles[2].Role != estateprofile.AuthorityRoleStoreRelease || profile.Roles[2].Threshold < estateprofile.StoreReleaseMinThreshold {
		t.Fatalf("1.4::title-claim: fixture has no valid Store release role: %+v", profile.Roles[2])
	}
	if _, digest, err := loadVerifiedStoreConfigRenderProfile(profilePath); err != nil || digest == "" {
		t.Fatalf("1.4::title-claim: signed 2-of-N Store release profile refused: digest=%q err=%v", digest, err)
	}
	profile.Roles[2].Threshold = 1
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadVerifiedStoreConfigRenderProfile(profilePath); err == nil ||
		!strings.Contains(err.Error(), "1.4::title-claim") || !strings.Contains(err.Error(), ":roles.store-release.threshold") {
		t.Fatalf("1.4::title-claim: 1-of-N Store release profile was not refused by name: %v", err)
	}
}

func TestH09_1_18StoreStateNamespaceFits(t *testing.T) {
	profile, profilePath, _, _, _ := newStoreConfigRenderFixture(t)
	if _, digest, err := loadVerifiedStoreConfigRenderProfile(profilePath); err != nil || digest == "" {
		t.Fatalf("1.18::title-claim: valid signed Store ID refused: digest=%q err=%v", digest, err)
	}
	profile.Store.StoreID = strings.Repeat("a", estateprofile.MaxStoreIDLength+1)
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadVerifiedStoreConfigRenderProfile(profilePath); err == nil ||
		!strings.Contains(err.Error(), "1.18::title-claim") || !strings.Contains(err.Error(), ":store.storeId") {
		t.Fatalf("1.18::title-claim: overlong Store ID was not refused by name: %v", err)
	}
}

func TestEstateStoreConfigRenderWritesValidatedProfileBoundCandidate(t *testing.T) {
	profile, profilePath, inputPath, outputPath, input := newStoreConfigRenderFixture(t)
	writeStoreConfigRenderInput(t, inputPath, input)

	report, err := renderEstateStoreConfig(estateStoreConfigRenderOptions{
		profilePath: profilePath,
		inputPath:   inputPath,
		outputPath:  outputPath,
	})
	if err != nil {
		t.Fatalf("render candidate: %v", err)
	}
	if report.Schema != storeConfigRenderReportSchema || report.Status != "profile-bound-store-config-candidate-written" {
		t.Fatalf("report identity = %#v", report)
	}
	if report.EstateID != profile.EstateID || report.ProfileRevision != profile.Revision || report.ReleaseTrustThreshold != profile.ReleaseTrust.Threshold {
		t.Fatalf("report profile = %#v", report)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest := sha256.Sum256(raw)
	if report.ConfigSHA256 != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("config digest = %q, want %x", report.ConfigSHA256, wantDigest)
	}
	info, err := os.Lstat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode = %v, want regular 0600", info.Mode())
	}
	// The rendered bytes themselves carry the profile's registry and root
	// origin: the loader has no compiled value that could stand in for either.
	var rendered struct {
		ProgramID    *string `json:"program_id"`
		RootStoreURL *string `json:"root_store_url"`
	}
	if err := json.Unmarshal(raw, &rendered); err != nil {
		t.Fatal(err)
	}
	if rendered.ProgramID == nil || *rendered.ProgramID != profileProgramID(t, profile, estateprofile.ProgramRoleLicenseRegistry) {
		t.Fatalf("rendered program_id = %v, want the profile's license-registry program", rendered.ProgramID)
	}
	if *rendered.ProgramID == testLicenseProgramID {
		t.Fatal("fixture profile shares the test registry pin, so this check could not see a fallback")
	}
	if rendered.RootStoreURL == nil || *rendered.RootStoreURL != "https://"+profile.Store.RootDomain {
		t.Fatalf("rendered root_store_url = %v, want the profile root Store origin", rendered.RootStoreURL)
	}

	cfg, err := LoadConfig(outputPath)
	if err != nil {
		t.Fatalf("normal config loader refused rendered candidate: %v", err)
	}
	if cfg.Domain != profile.Store.RootDomain || cfg.StoreID != profile.Store.StoreID || cfg.StoreAuthority != profile.Store.OperatorKey {
		t.Fatalf("Store identity = domain %q id %q authority %q", cfg.Domain, cfg.StoreID, cfg.StoreAuthority)
	}
	security := input["securityProfile"].(storesecurity.Profile)
	if cfg.StoreLinkControlMTLS.ListenAddr != security.ControlListenAddr || cfg.StoreLinkControlMTLS.StoreLinkClientCertSHA256 != security.StoreLinkClientCertSHA256 || !cfg.Policy.RequirePearlControlForAppPublish || cfg.ListingSignerSocket == "" {
		t.Fatalf("rendered-governed-store-link-control-missing: control=%+v policy=%+v signer=%q", cfg.StoreLinkControlMTLS, cfg.Policy, cfg.ListingSignerSocket)
	}
	if err := requireServingControlMTLS(cfg); err != nil {
		t.Fatalf("rendered-governed-store-link-control-refused: %v", err)
	}
	if cfg.ProgramID != profileProgramID(t, profile, estateprofile.ProgramRoleLicenseRegistry) {
		t.Fatalf("program ID = %q", cfg.ProgramID)
	}
	if cfg.ReleaseMasterNftMint != profile.Anchors.MasterMint || cfg.ResellerNFTMint != profile.Anchors.ResellerMint {
		t.Fatalf("mint anchors = master %q reseller %q", cfg.ReleaseMasterNftMint, cfg.ResellerNFTMint)
	}
	role, ok := profileStoreReleaseRole(profile)
	if !ok {
		t.Fatal("missing Store release role")
	}
	if cfg.ReleaseSquadsAuthority.Multisig != role.Multisig || cfg.ReleaseSquadsAuthority.Vault != role.Vault || cfg.ReleaseSquadsAuthority.Threshold != int(role.Threshold) || cfg.ReleaseSquadsAuthority.MemberCount != int(role.MemberCount) {
		t.Fatalf("release authority = %#v, profile role = %#v", cfg.ReleaseSquadsAuthority, role)
	}
	if cfg.ReleaseSquadsAuthority.ProgramID != profileExternalProgramID(t, profile, estateprofile.ExternalRoleSquadsV4) {
		t.Fatalf("release squads program = %q", cfg.ReleaseSquadsAuthority.ProgramID)
	}
	// The gated routes' snapshots are rendered explicitly, as a dedicated
	// directory under the state root that holds dist_dir.
	if cfg.ServedSnapshotDir != "/var/lib/melusina-store/served-snapshots" || filepath.Dir(cfg.ServedSnapshotDir) != filepath.Dir(cfg.DistDir) {
		t.Fatalf("rendered-served-snapshot-dir-not-under-state-root: %q, state root %q", cfg.ServedSnapshotDir, filepath.Dir(cfg.DistDir))
	}
	if cfg.EstateEnrollmentStatePath != storeConfigRenderStatePath || cfg.BootIdentity.OperatorDomain != "operator.rehearsal.invalid" || cfg.BootIdentity.ChainID != "solana:rehearsal" {
		t.Fatalf("unbound config inputs were not preserved: %#v", cfg)
	}
	wantPublishers := make([]string, 0, len(profile.ReleaseTrust.PublisherKeys))
	for _, key := range profile.ReleaseTrust.PublisherKeys {
		decoded, err := hex.DecodeString(key)
		if err != nil {
			t.Fatal(err)
		}
		wantPublishers = append(wantPublishers, primitives.EncodeBase58(decoded))
	}
	sort.Strings(wantPublishers)
	if !reflect.DeepEqual(cfg.Policy.AcceptPublishers, wantPublishers) {
		t.Fatalf("accept publishers = %q, want %q", cfg.Policy.AcceptPublishers, wantPublishers)
	}
	if _, err := checkStoreEstateProfile(estateProfileCheckOptions{configPath: outputPath, profilePath: profilePath}); err != nil {
		t.Fatalf("profile checker refused rendered config: %v", err)
	}
	reportRaw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reportRaw), "rpc.rehearsal.invalid") {
		t.Fatal("public render report disclosed the RPC endpoint")
	}
}

func TestEstateStoreConfigRenderRefusesUnboundOrInvalidInputsBeforeOutput(t *testing.T) {
	_, profilePath, inputPath, outputPath, input := newStoreConfigRenderFixture(t)
	cases := []struct {
		name      string
		mutate    func(map[string]any)
		wantError string
	}{
		{
			name: "profile digest mismatch",
			mutate: func(doc map[string]any) {
				doc["profileSha256"] = strings.Repeat("0", 64)
			},
			wantError: "store-config-render-profile-sha256-mismatch",
		},
		{
			name: "profile derived domain override",
			mutate: func(doc map[string]any) {
				doc["domain"] = "foreign.invalid"
			},
			wantError: "store-config-render-input-unknown-field:domain",
		},
		{
			name: "insecure rpc scheme",
			mutate: func(doc map[string]any) {
				doc["rpcUrl"] = "http://rpc.rehearsal.invalid/v1"
			},
			wantError: "store-config-render-input-rpc-must-use-https",
		},
		{
			name: "duplicate rpc endpoint",
			mutate: func(doc map[string]any) {
				doc["rpcFallbackUrls"] = []string{doc["rpcUrl"].(string)}
			},
			wantError: "duplicate endpoint",
		},
		{
			name: "malformed rpc endpoint",
			mutate: func(doc map[string]any) {
				doc["rpcUrl"] = "not an endpoint"
			},
			wantError: "endpoint must be an absolute HTTP(S) URL",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := map[string]any{}
			for key, value := range input {
				doc[key] = value
			}
			tc.mutate(doc)
			writeStoreConfigRenderInput(t, inputPath, doc)
			_, err := renderEstateStoreConfig(estateStoreConfigRenderOptions{profilePath: profilePath, inputPath: inputPath, outputPath: outputPath})
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error = %v, want %q", err, tc.wantError)
			}
			if _, statErr := os.Lstat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("output exists after refusal: %v", statErr)
			}
		})
	}
}

func TestEstateStoreConfigRenderRefusesDuplicateInputKeysAndInsecureInputMode(t *testing.T) {
	_, profilePath, inputPath, outputPath, input := newStoreConfigRenderFixture(t)
	writeStoreConfigRenderInput(t, inputPath, input)
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append([]byte(`{"schema":"`+storeConfigRenderInputSchema+`","schema":"`+storeConfigRenderInputSchema+`",`), raw[1:]...)
	if err := os.WriteFile(inputPath, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = renderEstateStoreConfig(estateStoreConfigRenderOptions{profilePath: profilePath, inputPath: inputPath, outputPath: outputPath})
	if err == nil || !strings.Contains(err.Error(), `JSON has duplicate key "schema"`) {
		t.Fatalf("duplicate input error = %v", err)
	}
	writeStoreConfigRenderInput(t, inputPath, input)
	if err := os.Chmod(inputPath, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = renderEstateStoreConfig(estateStoreConfigRenderOptions{profilePath: profilePath, inputPath: inputPath, outputPath: outputPath})
	if err == nil || !strings.Contains(err.Error(), "must be owned mode 0600") {
		t.Fatalf("insecure input mode error = %v", err)
	}
}

func TestEstateStoreConfigRenderNeverOverwritesAndProfileCheckCatchesQuorumDrift(t *testing.T) {
	_, profilePath, inputPath, outputPath, input := newStoreConfigRenderFixture(t)
	writeStoreConfigRenderInput(t, inputPath, input)
	if err := os.WriteFile(outputPath, []byte("existing candidate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := renderEstateStoreConfig(estateStoreConfigRenderOptions{profilePath: profilePath, inputPath: inputPath, outputPath: outputPath})
	if !errors.Is(err, errStoreConfigRenderOutputExists) {
		t.Fatalf("overwrite error = %v", err)
	}
	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "existing candidate\n" {
		t.Fatalf("existing output changed to %q", got)
	}
	if err := os.Remove(outputPath); err != nil {
		t.Fatal(err)
	}
	symlinkTarget := filepath.Join(filepath.Dir(outputPath), "existing-target.json")
	if err := os.WriteFile(symlinkTarget, []byte("symlink target\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(symlinkTarget, outputPath); err != nil {
		t.Fatal(err)
	}
	_, err = renderEstateStoreConfig(estateStoreConfigRenderOptions{profilePath: profilePath, inputPath: inputPath, outputPath: outputPath})
	if !errors.Is(err, errStoreConfigRenderOutputExists) {
		t.Fatalf("symlink overwrite error = %v", err)
	}
	got, err = os.ReadFile(symlinkTarget)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "symlink target\n" {
		t.Fatalf("symlink target changed to %q", got)
	}
	if err := os.Remove(outputPath); err != nil {
		t.Fatal(err)
	}
	if _, err := renderEstateStoreConfig(estateStoreConfigRenderOptions{profilePath: profilePath, inputPath: inputPath, outputPath: outputPath}); err != nil {
		t.Fatalf("render candidate: %v", err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	authority := doc["release_squads_authority"].(map[string]any)
	// The profile's release role is core's 3 of 4 (K-CHN-03); 2 is drift.
	authority["threshold"] = float64(2)
	driftedRaw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	driftedPath := filepath.Join(filepath.Dir(outputPath), "drifted-store.config.json")
	if err := os.WriteFile(driftedPath, driftedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = checkStoreEstateProfile(estateProfileCheckOptions{configPath: driftedPath, profilePath: profilePath})
	if err == nil || !strings.Contains(err.Error(), "store-estate-profile-config-mismatch: roles.store-release.threshold") {
		t.Fatalf("quorum drift error = %v", err)
	}
	if _, err := LoadConfig(driftedPath); err != nil {
		t.Fatalf("drifted config should remain structurally valid before profile check: %v", err)
	}
}
