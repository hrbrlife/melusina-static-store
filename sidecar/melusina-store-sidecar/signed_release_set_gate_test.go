package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
)

func TestH09_3_1PublisherSignedSetBindsInstallerReleaseBytes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "C3-release-and-store-host", "C3-release-and-store-host.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		ReleaseSet struct {
			SignedEstateStages []struct {
				Deployable json.RawMessage `json:"deployable"`
			} `json:"signedEstateStages"`
		} `json:"releaseSet"`
		StoreHost struct {
			PassTwo struct {
				SignedFinalProfile json.RawMessage `json:"signedFinalProfile"`
			} `json:"passTwo"`
		} `json:"storeHost"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	var profile struct {
		ReleaseTrust struct {
			PublisherKeys []string `json:"publisherKeys"`
			Threshold     uint32   `json:"threshold"`
		} `json:"releaseTrust"`
	}
	if err := json.Unmarshal(vector.StoreHost.PassTwo.SignedFinalProfile, &profile); err != nil {
		t.Fatal(err)
	}
	if len(vector.ReleaseSet.SignedEstateStages) == 0 {
		t.Fatal("signed deployable release set absent")
	}
	set, digest, err := verifySignedReleaseSet(vector.ReleaseSet.SignedEstateStages[0].Deployable, profile.ReleaseTrust.PublisherKeys, profile.ReleaseTrust.Threshold)
	if err != nil || len(digest) != 64 {
		t.Fatalf("signed set refused: %s: %v", digest, err)
	}
	var shell struct {
		Role, File, SHA256 string
		SizeBytes          int64
	}
	for _, artifact := range set.Artifacts {
		if artifact.Role == "shell-bundle" {
			shell.Role, shell.File, shell.SHA256, shell.SizeBytes = artifact.Role, artifact.Name, artifact.SHA256, artifact.SizeBytes
		}
	}
	if shell.File == "" {
		t.Fatal("signed shell artifact absent")
	}
	if err := requireSignedSetArtifact(set, "shell", shell.File, shell.SHA256, shell.SizeBytes); err != nil {
		t.Fatalf("publisher signed shell refused: %v", err)
	}
	for _, negative := range []struct {
		label, hash string
		size       int64
		want       string
	}{
		{"different hash", strings.Repeat("0", 64), shell.SizeBytes, "release-set-artifact-mismatch"},
		{"different size", shell.SHA256, shell.SizeBytes + 1, "release-set-artifact-mismatch"},
	} {
		if err := requireSignedSetArtifact(set, "shell", shell.File, negative.hash, negative.size); err == nil || !strings.Contains(err.Error(), negative.want) {
			t.Fatalf("3.1::title-claim: %s: want %s, got %v", negative.label, negative.want, err)
		}
	}
	var changed map[string]any
	if err := json.Unmarshal(vector.ReleaseSet.SignedEstateStages[0].Deployable, &changed); err != nil {
		t.Fatal(err)
	}
	signatures := changed["signatures"].([]any)
	first := signatures[0].(map[string]any)
	first["signature"] = "0" + first["signature"].(string)
	mutated, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifySignedReleaseSet(mutated, profile.ReleaseTrust.PublisherKeys, profile.ReleaseTrust.Threshold); err == nil || !strings.Contains(err.Error(), "release-set-signature-invalid") {
		t.Fatalf("mutated signature not refused by name: %v", err)
	}
}

func TestH09_3_1EnrolledStoreServesOnlyHighestSignedSetArtifact(t *testing.T) {
	profile, enrollment := validStoreEnrollmentStateInput(t)
	state, err := newStoreEnrollmentState(profile, enrollment, storeEnrollmentStateNow)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(root, "enrollment.json")
	if err := writeStoreEnrollmentStateNew(statePath, state, uint32(os.Geteuid())); err != nil {
		t.Fatal(err)
	}
	setDir := filepath.Join(root, "sets")
	if err := os.Mkdir(setDir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("publisher pinned shell bytes")
	hash := sha256.Sum256(body)
	name := "shell-rehearsal.tar.xz"
	keys := []map[string]any{}
	for index, key := range profile.ReleaseTrust.PublisherKeys {
		keys = append(keys, map[string]any{"keyId": "publisher-" + string(rune('a'+index)), "ed25519PublicKey": key})
	}
	value := map[string]any{
		"schema": "melusina.bootstrap-release-set.v2", "stage": "deployable", "sequence": uint64(19),
		"createdAt": "2026-09-20T01:00:00Z", "foundation": map[string]any{"sequence": uint64(1), "sha256": strings.Repeat("0", 64)},
		"publisherKeyset": map[string]any{"threshold": profile.ReleaseTrust.Threshold, "keys": keys},
		"recalls":         []any{}, "phaseEndpoints": map[string]any{}, "artifacts": []any{map[string]any{
			"role": "shell-bundle", "name": name, "sha256": hex.EncodeToString(hash[:]), "sizeBytes": int64(len(body)),
			"sourceRepo": "rehearsal", "sourceCommit": strings.Repeat("1", 40), "toolchain": "rehearsal", "origins": []any{}, "phase": "p0-verify"}},
		"completeness": "complete", "declaredAbsent": []any{}, "signatures": []any{},
	}
	unsigned, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var set servedReleaseSet
	if err := json.Unmarshal(unsigned, &set); err != nil {
		t.Fatal(err)
	}
	digest, err := signedSetDigest(set)
	if err != nil {
		t.Fatal(err)
	}
	sigs := []any{}
	for _, label := range []string{"rehearsal/publisher-1", "rehearsal/publisher-2"} {
		private := releasetest.VectorKey(label)
		public := hex.EncodeToString(private.Public().(ed25519.PublicKey))
		for _, key := range keys {
			if key["ed25519PublicKey"] == public {
				sigs = append(sigs, map[string]any{"keyId": key["keyId"], "signature": hex.EncodeToString(ed25519.Sign(private, []byte(digest)))})
			}
		}
	}
	if len(sigs) < int(profile.ReleaseTrust.Threshold) {
		t.Fatal("published fixture lacks threshold signers")
	}
	value["signatures"] = sigs
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(setDir, "release-set-"+digest+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{EstateEnrollmentStatePath: statePath, ReleaseMasterNftMint: profile.Anchors.MasterMint, releaseSetDir: setDir}
	if err := bindInstallerReleaseTrust(&cfg, &state); err != nil {
		t.Fatal(err)
	}
	cfg.releaseSetDir = setDir
	if err := verifyServedReleaseSet(cfg, "shell", name, hex.EncodeToString(hash[:]), int64(len(body))); err != nil {
		t.Fatalf("signed serve refused: %v", err)
	}
	if err := verifyServedReleaseSet(cfg, "shell", name, strings.Repeat("0", 64), int64(len(body))); err == nil || !strings.Contains(err.Error(), "release-set-artifact-mismatch") {
		t.Fatalf("3.1::title-claim: changed bytes not refused by name: %v", err)
	}
	if err := verifyServedReleaseSet(cfg, "shell", "foreign.tar.xz", hex.EncodeToString(hash[:]), int64(len(body))); err == nil || !strings.Contains(err.Error(), "release-set-artifact-absent") {
		t.Fatalf("3.1::title-claim: foreign name not refused by name: %v", err)
	}
	// A later accepted set replaces the serving authority. An older signed
	// artifact cannot remain servable just because its earlier file remains.
	newName := "successor-shell.tar.xz"
	value["sequence"] = uint64(20)
	value["artifacts"].([]any)[0].(map[string]any)["name"] = newName
	unsigned, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(unsigned, &set); err != nil {
		t.Fatal(err)
	}
	newDigest, err := signedSetDigest(set)
	if err != nil {
		t.Fatal(err)
	}
	newSignatures := []any{}
	for _, label := range []string{"rehearsal/publisher-1", "rehearsal/publisher-2"} {
		private := releasetest.VectorKey(label)
		public := hex.EncodeToString(private.Public().(ed25519.PublicKey))
		for _, key := range keys {
			if key["ed25519PublicKey"] == public {
				newSignatures = append(newSignatures, map[string]any{"keyId": key["keyId"], "signature": hex.EncodeToString(ed25519.Sign(private, []byte(newDigest)))})
			}
		}
	}
	value["signatures"] = newSignatures
	raw, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(setDir, "release-set-"+newDigest+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyServedReleaseSet(cfg, "shell", newName, hex.EncodeToString(hash[:]), int64(len(body))); err != nil {
		t.Fatalf("signed successor refused: %v", err)
	}
	if err := verifyServedReleaseSet(cfg, "shell", name, hex.EncodeToString(hash[:]), int64(len(body))); err == nil || !strings.Contains(err.Error(), "release-set-artifact-absent") {
		t.Fatalf("3.1::title-claim: superseded shell still served: %v", err)
	}
}
