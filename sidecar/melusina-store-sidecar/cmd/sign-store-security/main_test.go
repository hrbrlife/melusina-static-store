package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/storesecurity"
)

func TestOwnerThresholdProducerPinsStoreSecurityProfile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "estate-profile-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Profiles []struct {
			Name    string                        `json:"name"`
			Profile estateprofile.EstateProfileV1 `json:"profile"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	var estate estateprofile.EstateProfileV1
	for _, vector := range vectors.Profiles {
		if vector.Name == "new-estate-revision-1" {
			estate = vector.Profile
			break
		}
	}
	profileSHA256, err := estateprofile.VerifyProfile(estate)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	estatePath := filepath.Join(dir, "estate.json")
	if err := os.WriteFile(estatePath, mustJSON(t, estate), 0o600); err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256([]byte("test Store Link certificate"))
	scannerSeed := sha256.Sum256([]byte("test scanner authority"))
	security := storesecurity.Profile{Schema: storesecurity.Schema, EstateProfileSHA256: profileSHA256, StoreID: estate.Store.StoreID, ControlListenAddr: "127.0.0.1:9443", StoreLinkClientCertSHA256: hex.EncodeToString(pin[:]), ScannerEd25519PublicKey: hex.EncodeToString(ed25519.NewKeyFromSeed(scannerSeed[:]).Public().(ed25519.PublicKey))}
	securityPath := filepath.Join(dir, "security-input.json")
	if err := os.WriteFile(securityPath, mustJSON(t, security), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--estate-profile", estatePath, "--security-profile", securityPath, "--out", filepath.Join(dir, "security-signed.json")}
	for _, signer := range estate.OwnerPolicy.Signers[:estate.OwnerPolicy.Threshold] {
		seed := sha256.Sum256([]byte("melusina-estate-profile-vector-key:" + estate.OwnerPolicy.PolicyID + "/" + signer.KeyID))
		path := filepath.Join(dir, signer.KeyID+".seed")
		if err := os.WriteFile(path, seed[:], 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--owner-key", signer.KeyID+"="+path)
	}
	if err := run(args); err != nil {
		t.Fatalf("owner-threshold-producer-positive: %v", err)
	}
	output, err := os.ReadFile(filepath.Join(dir, "security-signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := storesecurity.Decode(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := storesecurity.Verify(signed, estate, profileSHA256); err != nil {
		t.Fatalf("signed-profile-consumer-positive: %v", err)
	}
	signed.StoreLinkClientCertSHA256 = hex.EncodeToString(scannerSeed[:])
	if err := storesecurity.Verify(signed, estate, profileSHA256); err == nil {
		t.Fatal("owner-signed-store-link-pin-required")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
