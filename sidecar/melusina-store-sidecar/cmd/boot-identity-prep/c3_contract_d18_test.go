package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

type c3D18Spec struct {
	Schema            string `json:"schema"`
	EstateID          string `json:"estateId"`
	HostMachineIDHash string `json:"hostMachineIdHash"`
	RootStoreHostname string `json:"rootStoreHostname"`
	PlacementKind     string `json:"placementKind"`
	StoragePool       string `json:"storagePool"`
	Bridge            struct {
		Name        string `json:"name"`
		IPv4Address string `json:"ipv4Address"`
		IPv4NAT     bool   `json:"ipv4Nat"`
	} `json:"bridge"`
	Profile   string `json:"profile"`
	Container struct {
		Name             string `json:"name"`
		ImageFingerprint string `json:"imageFingerprint"`
	} `json:"container"`
	BackendAddress string `json:"backendAddress"`
	Identity       struct {
		LicenseNFTMint string `json:"licenseNftMint"`
		Domain         string `json:"domain"`
		ChainID        string `json:"chainId"`
		ProgramID      string `json:"programId"`
		TLSCertPath    string `json:"tlsCertPath"`
		SidecarID      string `json:"sidecarId"`
	} `json:"identity"`
}

func TestC3D18TwoPassBootIdentityUsesOneLicenseAndShards(t *testing.T) {
	c3D18PinSharedHelper(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "contracts", "C3-release-and-store-host", "C3-release-and-store-host.json"))
	if err != nil {
		t.Fatalf("C3-D18-vector-unreadable: %v", err)
	}
	var vector struct {
		ReleaseSet struct {
			NeutralF0CanonicalSHA256 string `json:"neutralF0CanonicalSha256"`
			NeutralF0                struct {
				Sequence  uint64 `json:"sequence"`
				Artifacts []struct {
					Role         string `json:"role"`
					SHA256       string `json:"sha256"`
					SourceCommit string `json:"sourceCommit"`
				} `json:"artifacts"`
			} `json:"neutralF0"`
		} `json:"releaseSet"`
		StoreHost struct {
			PassOne struct {
				RawSpec                   string          `json:"rawSpec"`
				SpecSHA256                string          `json:"specSha256"`
				StoreBootstrapVersion     string          `json:"storeBootstrapVersion"`
				SignedAuthorization       json.RawMessage `json:"signedAuthorization"`
				SignedAuthorizationSHA256 string          `json:"signedAuthorizationSha256"`
				Spec                      c3D18Spec       `json:"spec"`
				IdentityInputs            struct {
					LicenseNFTMint string `json:"licenseNftMint"`
					Domain         string `json:"domain"`
					ChainID        string `json:"chainId"`
					ProgramID      string `json:"programId"`
					TLSCertPath    string `json:"tlsCertPath"`
				} `json:"identityInputs"`
				AuthorizationClaims struct {
					RootStoreLicenseMint string `json:"rootStoreLicenseMint"`
					EstateID             string `json:"estateId"`
				} `json:"authorizationClaims"`
			} `json:"passOne"`
			PassTwo struct {
				EstateID                 string          `json:"estateId"`
				SameRootStoreLicenseMint string          `json:"sameRootStoreLicenseMint"`
				SignedFinalProfile       json.RawMessage `json:"signedFinalProfile"`
				SignedFinalProfileSHA256 string          `json:"signedFinalProfileSha256"`
			} `json:"passTwo"`
		} `json:"storeHost"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatalf("C3-D18-vector-invalid: %v", err)
	}
	first := vector.StoreHost.PassOne
	var measuredSpec c3D18Spec
	specDecoder := json.NewDecoder(strings.NewReader(first.RawSpec))
	specDecoder.DisallowUnknownFields()
	if err := specDecoder.Decode(&measuredSpec); err != nil || !reflect.DeepEqual(measuredSpec, first.Spec) {
		t.Fatalf("C3-D18-raw-spec-differs-from-reviewed-spec: err=%v", err)
	}
	var trailing any
	if err := specDecoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("C3-D18-raw-spec-has-trailing-data: %v", err)
	}
	if strings.Contains(first.RawSpec, "signedFinalProfile") || strings.Contains(first.RawSpec, "masterMint") {
		t.Fatal("C3-D18-pass-one-has-circular-estate-fact")
	}
	if first.Spec.EstateID == "" || first.Spec.EstateID != vector.StoreHost.PassTwo.EstateID || first.Spec.EstateID != first.AuthorizationClaims.EstateID {
		t.Fatal("C3-D18-estate-id-not-derived-before-profile")
	}
	sum := sha256.Sum256([]byte(first.RawSpec))
	if hex.EncodeToString(sum[:]) != first.SpecSHA256 {
		t.Fatal("C3-D18-pass-one-spec-digest-mismatch")
	}
	license := first.IdentityInputs.LicenseNFTMint
	if license == "" || license != first.AuthorizationClaims.RootStoreLicenseMint || license != vector.StoreHost.PassTwo.SameRootStoreLicenseMint {
		t.Fatalf("C3-D18-license-mint-changed-between-passes: %q != %q", license, vector.StoreHost.PassTwo.SameRootStoreLicenseMint)
	}
	if first.IdentityInputs.Domain != first.Spec.RootStoreHostname {
		t.Fatalf("C3-D18-identity-domain-substituted: %q", first.IdentityInputs.Domain)
	}
	if first.Spec.Identity.LicenseNFTMint != license || first.Spec.Identity.Domain != first.IdentityInputs.Domain || first.Spec.Identity.ChainID != first.IdentityInputs.ChainID || first.Spec.Identity.ProgramID != first.IdentityInputs.ProgramID || first.Spec.Identity.TLSCertPath != first.IdentityInputs.TLSCertPath || first.Spec.Identity.SidecarID != "store" {
		t.Fatalf("C3-D18-spec-identity-facts-drift: %+v", first.Spec.Identity)
	}

	dir := t.TempDir()
	shards := filepath.Join(dir, "shards")
	binary := filepath.Join(dir, "sidecar")
	if err := os.WriteFile(binary, []byte("C3 D18 local sidecar fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	identityCert, _ := writeTestCert(t, dir, first.Spec.RootStoreHostname)
	profile := filepath.Join(dir, "signed-final-profile.json")
	if err := os.WriteFile(profile, vector.StoreHost.PassTwo.SignedFinalProfile, 0o600); err != nil {
		t.Fatal(err)
	}
	decodedProfile, err := estateprofile.DecodeProfile(vector.StoreHost.PassTwo.SignedFinalProfile)
	if err != nil {
		t.Fatalf("C3-D18-signed-profile-invalid: %v", err)
	}
	profileDigest, err := estateprofile.VerifyProfile(decodedProfile)
	if err != nil || profileDigest != vector.StoreHost.PassTwo.SignedFinalProfileSHA256 || decodedProfile.EstateID != first.Spec.EstateID {
		t.Fatalf("C3-D18-signed-profile-not-same-estate: digest=%q estate=%q err=%v", profileDigest, decodedProfile.EstateID, err)
	}
	if decodedProfile.Store.RootDomain != first.Spec.RootStoreHostname || decodedProfile.Store.RootDomain != first.IdentityInputs.Domain {
		t.Fatalf("C3-D18-signed-profile-domain-drift: signed=%q spec=%q identity=%q", decodedProfile.Store.RootDomain, first.Spec.RootStoreHostname, first.IdentityInputs.Domain)
	}
	authorization, err := estateprofile.DecodeStoreHostAuthorization(first.SignedAuthorization)
	if err != nil {
		t.Fatalf("C3-D18-signed-host-authorization-invalid: %v", err)
	}
	var bootstrapSHA, bootstrapCommit string
	bootstrapCount := 0
	for _, artifact := range vector.ReleaseSet.NeutralF0.Artifacts {
		if artifact.Role == "store-bootstrap" {
			bootstrapSHA, bootstrapCommit = artifact.SHA256, artifact.SourceCommit
			bootstrapCount++
		}
	}
	if bootstrapCount != 1 || first.StoreBootstrapVersion == "" {
		t.Fatal("C3-D18-store-bootstrap-measurement-missing")
	}
	release := estateprofile.StoreHostRelease{
		ReleaseSetSequence:         vector.ReleaseSet.NeutralF0.Sequence,
		ReleaseSetSHA256:           vector.ReleaseSet.NeutralF0CanonicalSHA256,
		StoreBootstrapSHA256:       bootstrapSHA,
		StoreBootstrapVersion:      first.StoreBootstrapVersion,
		StoreBootstrapSourceCommit: bootstrapCommit,
		StoreHostSpecSHA256:        first.SpecSHA256,
	}
	placement := estateprofile.StoreHostPlacement{
		HostMachineIDHash: measuredSpec.HostMachineIDHash,
		RootStoreHostname: measuredSpec.RootStoreHostname,
		PlacementKind:     measuredSpec.PlacementKind,
		ContainerName:     measuredSpec.Container.Name,
		BridgeName:        measuredSpec.Bridge.Name,
		BackendAddress:    measuredSpec.BackendAddress,
	}
	verificationTime := time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)
	authorizationDigest, err := estateprofile.RequireStoreHostAuthorization(decodedProfile.GenesisOwnerPolicy, authorization, release, placement, verificationTime)
	if err != nil || authorizationDigest != first.SignedAuthorizationSHA256 {
		t.Fatalf("C3-D18-owner-authorization-not-bound-to-spec-and-F0: digest=%q err=%v", authorizationDigest, err)
	}
	for _, control := range []struct {
		name            string
		changeRelease   func(*estateprofile.StoreHostRelease)
		changePlacement func(*estateprofile.StoreHostPlacement)
		field           string
	}{
		{"f0", func(value *estateprofile.StoreHostRelease) { value.ReleaseSetSHA256 = strings.Repeat("0", 64) }, nil, "releaseSetSha256"},
		{"bootstrap", func(value *estateprofile.StoreHostRelease) { value.StoreBootstrapSHA256 = strings.Repeat("0", 64) }, nil, "storeBootstrapSha256"},
		{"raw-spec", func(value *estateprofile.StoreHostRelease) { value.StoreHostSpecSHA256 = strings.Repeat("0", 64) }, nil, "storeHostSpecSha256"},
		{"host-placement", nil, func(value *estateprofile.StoreHostPlacement) { value.HostMachineIDHash = strings.Repeat("0", 64) }, "hostMachineIdHash"},
		{"hostname", nil, func(value *estateprofile.StoreHostPlacement) { value.RootStoreHostname = "store.other.example.test" }, "rootStoreHostname"},
	} {
		t.Run(control.name, func(t *testing.T) {
			changedRelease, changedPlacement := release, placement
			if control.changeRelease != nil {
				control.changeRelease(&changedRelease)
			}
			if control.changePlacement != nil {
				control.changePlacement(&changedPlacement)
			}
			_, err := estateprofile.RequireStoreHostAuthorization(decodedProfile.GenesisOwnerPolicy, authorization, changedRelease, changedPlacement, verificationTime)
			want := estateprofile.RefusalStoreHostAuthorizationInputMismatch + ":" + control.field
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("C3-D18-signed-host-authorization-%s-mismatch-accepted: %v", control.field, err)
			}
		})
	}
	chain, program, err := chainIDFromProfile(profile)
	if err != nil || chain != first.IdentityInputs.ChainID || program != first.IdentityInputs.ProgramID {
		t.Fatalf("C3-D18-registry-or-chain-substituted: chain=%q program=%q err=%v", chain, program, err)
	}
	args := []string{
		"-shards-dir", shards, "-license-mint", license, "-domain", first.Spec.RootStoreHostname,
		"-sidecar-id", "store", "-program-id", program, "-binary", binary, "-tls-cert", identityCert,
	}
	var before bytes.Buffer
	if err := run(append(append([]string{}, args...), "-chain-id", first.IdentityInputs.ChainID), &before); err != nil {
		t.Fatalf("C3-D18-pass-one-preparation: %v", err)
	}
	var after bytes.Buffer
	if err := run(append(append([]string{}, args...), "-profile", profile), &after); err != nil {
		t.Fatalf("C3-D18-pass-two-remeasurement: %v", err)
	}
	var a, b ceremonyReport
	if err := json.Unmarshal(before.Bytes(), &a); err != nil {
		t.Fatalf("C3-D18-pass-one-report-empty-or-invalid: %v", err)
	}
	if err := json.Unmarshal(after.Bytes(), &b); err != nil {
		t.Fatalf("C3-D18-pass-two-report-empty-or-invalid: %v", err)
	}
	if !a.Shards.Created || b.Shards.Created || a.SidecarIdentityPDA != b.SidecarIdentityPDA || a.RegisterSidecarInput.SigningPubkeyBase58 != b.RegisterSidecarInput.SigningPubkeyBase58 || a.RegisterSidecarInput.TLSCertFingerprintHex != b.RegisterSidecarInput.TLSCertFingerprintHex {
		t.Fatalf("C3-D18-identity-regenerated-on-spec-rebuild: first=%+v second=%+v", a, b)
	}
	if b.RegisterSidecarInput.LicenseNFTMint != license || b.RegisterSidecarInput.LicenseNFTMint == "" {
		t.Fatalf("C3-D18-root-store-license-mint-substituted: %q", b.RegisterSidecarInput.LicenseNFTMint)
	}
	if a.IdentityRef.ChainID != b.IdentityRef.ChainID || a.IdentityRef.Domain != b.IdentityRef.Domain {
		t.Fatal("C3-D18-pass-two-identity-reference-drift")
	}
	identityPEM, err := os.ReadFile(identityCert)
	if err != nil {
		t.Fatal(err)
	}
	identityBlock, _ := pem.Decode(identityPEM)
	if identityBlock == nil || identityBlock.Type != "CERTIFICATE" {
		t.Fatal("C3-D18-self-signature-control-no-leaf")
	}
	originalLeaf, err := x509.ParseCertificate(identityBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := originalLeaf.CheckSignature(originalLeaf.SignatureAlgorithm, originalLeaf.RawTBSCertificate, originalLeaf.Signature); err != nil {
		t.Fatalf("C3-D18-test-identity-leaf-not-self-signed: %v", err)
	}
	brokenDER := append([]byte{}, identityBlock.Bytes...)
	brokenDER[len(brokenDER)-1] ^= 1
	brokenLeaf, err := x509.ParseCertificate(brokenDER)
	if err != nil {
		t.Fatalf("C3-D18-self-signature-control-not-parseable: %v", err)
	}
	if err := brokenLeaf.CheckSignature(brokenLeaf.SignatureAlgorithm, brokenLeaf.RawTBSCertificate, brokenLeaf.Signature); err == nil {
		t.Fatal("C3-D18-self-signature-control-still-valid")
	}
	brokenPath := filepath.Join(dir, "bad-self-signature.pem")
	if err := os.WriteFile(brokenPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: brokenDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	brokenArgs := append([]string{}, args...)
	for i := 0; i < len(brokenArgs)-1; i++ {
		switch brokenArgs[i] {
		case "-tls-cert":
			brokenArgs[i+1] = brokenPath
		case "-shards-dir":
			brokenArgs[i+1] = filepath.Join(t.TempDir(), "fresh-shards")
		}
	}
	if err := run(append(brokenArgs, "-chain-id", first.IdentityInputs.ChainID), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "identity-leaf-self-signature-invalid") {
		t.Fatalf("C3-D18-identity-leaf-self-signature-invalid: %v", err)
	}

	// A partial shard set must refuse rather than combine old and new custody.
	other := filepath.Join(t.TempDir(), "partial-shards")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "author.shard"), []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	partialArgs := append(append([]string{}, args...), "-chain-id", first.IdentityInputs.ChainID)
	for i := 0; i < len(partialArgs)-1; i++ {
		if partialArgs[i] == "-shards-dir" {
			partialArgs[i+1] = other
			break
		}
	}
	if err := run(partialArgs, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "partial shard set") {
		t.Fatalf("C3-D18-partial-shards-overwritten: %v", err)
	}
}

func c3D18PinSharedHelper(t *testing.T) {
	t.Helper()
	const path = "main_test.go"
	const want = "c90937d0dfc624c54f6ca5e5f8303a49ed3fa419d8f8797459d220a192c8d162"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("C3-D18-shared-helper-pin: %s: %v", path, err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("C3-D18-shared-helper-pin: %s is %s, pinned %s", path, got, want)
	}
}
