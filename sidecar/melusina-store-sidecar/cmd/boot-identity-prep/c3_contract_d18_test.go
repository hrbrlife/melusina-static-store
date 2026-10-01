package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

func TestC3D18TwoPassBootIdentityUsesOneLicenseAndShards(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "testdata", "contracts", "C3-release-and-store-host", "C3-release-and-store-host.json"))
	if err != nil {
		t.Fatalf("C3-D18-vector-unreadable: %v", err)
	}
	var vector struct {
		StoreHost struct {
			PassOne struct {
				RawSpec    string `json:"rawSpec"`
				SpecSHA256 string `json:"specSha256"`
				Spec       struct {
					EstateID          string `json:"estateId"`
					RootStoreHostname string `json:"rootStoreHostname"`
				} `json:"spec"`
				IdentityInputs struct {
					LicenseNFTMint string `json:"licenseNftMint"`
					Domain         string `json:"domain"`
					ChainID        string `json:"chainId"`
					ProgramID      string `json:"programId"`
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
		t.Fatal(err)
	}
	if err := json.Unmarshal(after.Bytes(), &b); err != nil {
		t.Fatal(err)
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
