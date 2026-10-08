package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These bytes were cut by the production Foundation release producer for a
// disposable local estate. The keys are separately pinned by its signed estate
// profile; no key or digest from the release set selects its own verifier.
func TestEnrolledReleaseGateAcceptsSignedExtensionsAndRecalls(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "signed-foundation-v2-migrate-extensions.json"))
	if err != nil {
		t.Fatal(err)
	}
	trusted := []string{
		"2d1054ec74cb3fe57a051aa41694734c9a5c9c967535068b4a6d59ae6bdb78cc",
		"c15c7f72f4bafdae9d8a0033ee6a0c51bf14379be715b1060b075a1b206ce9fb",
		"cb991b63b5937f537ddadb650b266e6f29c96012f91194af9f8cd1c922b347ef",
	}
	set, digest, err := verifySignedReleaseSet(raw, trusted, 2)
	if err != nil || digest != "a87928b82a5d82aa463144657ccdfa6f98c90ddae756948839ad60ed5f6b703f" {
		t.Fatalf("signed-extension-release-set-positive: digest=%s err=%v", digest, err)
	}
	if len(set.Recalls) != 3 {
		t.Fatal("signed-extension-release-set-recalls-missing")
	}
	for _, artifact := range set.Artifacts {
		if artifact.Role != "shell-bundle" {
			continue
		}
		if err := requireSignedSetArtifact(set, "shell", artifact.Name, artifact.SHA256, artifact.SizeBytes); err != nil {
			t.Fatalf("signed-extension-shell-artifact-positive: %v", err)
		}
	}
	mutate := func(name string, change func(map[string]any)) {
		t.Run(name, func(t *testing.T) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			change(doc)
			changed, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := verifySignedReleaseSet(changed, trusted, 2); err == nil || !strings.Contains(err.Error(), "release-set-signature-invalid") {
				t.Fatalf("signed-extension-%s-mutation-refused: %v", name, err)
			}
		})
	}
	mutate("incus-fingerprint", func(doc map[string]any) {
		for _, value := range doc["artifacts"].([]any) {
			artifact := value.(map[string]any)
			if artifact["incusFingerprint"] != nil {
				artifact["incusFingerprint"] = strings.Repeat("0", 64)
				return
			}
		}
		t.Fatal("extension fixture lacks incus fingerprint")
	})
	mutate("recall-digest", func(doc map[string]any) {
		doc["recalls"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64)
	})
	var nullable map[string]any
	if err := json.Unmarshal(raw, &nullable); err != nil {
		t.Fatal(err)
	}
	for _, value := range nullable["artifacts"].([]any) {
		artifact := value.(map[string]any)
		if artifact["incusFingerprint"] != nil {
			artifact["incusFingerprint"] = nil
			break
		}
	}
	nullRaw, err := json.Marshal(nullable)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifySignedReleaseSet(nullRaw, trusted, 2); err == nil || !strings.Contains(err.Error(), "release-set-json-invalid: null incusFingerprint extension") {
		t.Fatalf("signed-extension-null-mutation-refused: %v", err)
	}
}
