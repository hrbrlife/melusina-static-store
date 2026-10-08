package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
)

// The expected digest was made by the Foundation release producer's canonical
// preimage, independent of this Store verifier. The publisher signer is the
// repository's published, test-only estate vector key.
func TestEnrolledReleaseGateAcceptsSignedExtensionsAndRecalls(t *testing.T) {
	unsigned, err := os.ReadFile(filepath.Join("testdata", "release-set-c3-extensions-unsigned.json"))
	if err != nil {
		t.Fatal(err)
	}
	trusted := []string{
		"754a25111a91dffda7231bb434335bdd7b34ebff63d899cec0eaa9da9a66e6bf",
		"7e9547415856eed6c1fa510a7a641e7037173979220ab4522c0d4941d4510c41",
	}
	const expected = "1ed96229c9cb7dab9c6028b70498b4e0eb9041b46cee03f38cebe28982201483"
	private := releasetest.TrustedPublisher()
	if got := hex.EncodeToString(private.Public().(ed25519.PublicKey)); got != trusted[1] {
		t.Fatalf("signed-extension-publisher-pin-mismatch: %s", got)
	}
	var document map[string]any
	if err := json.Unmarshal(unsigned, &document); err != nil {
		t.Fatal(err)
	}
	document["signatures"] = []any{map[string]any{
		"keyId": "publisher-b", "signature": hex.EncodeToString(ed25519.Sign(private, []byte(expected))),
	}}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	set, digest, err := verifySignedReleaseSet(raw, trusted, 1)
	if err != nil || digest != expected {
		t.Fatalf("signed-extension-release-set-positive: digest=%s err=%v", digest, err)
	}
	if len(set.Recalls) != 1 || len(set.DeclaredAbsent) != 1 {
		t.Fatal("signed-extension-release-set-recalls-or-absence-missing")
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
			if _, _, err := verifySignedReleaseSet(changed, trusted, 1); err == nil || !strings.Contains(err.Error(), "release-set-signature-invalid") {
				t.Fatalf("signed-extension-%s-mutation-refused: %v", name, err)
			}
		})
	}
	mutate("incus-fingerprint", func(doc map[string]any) {
		doc["artifacts"].([]any)[0].(map[string]any)["incusFingerprint"] = strings.Repeat("0", 64)
	})
	mutate("recall-digest", func(doc map[string]any) {
		doc["recalls"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64)
	})
	var nullable map[string]any
	if err := json.Unmarshal(raw, &nullable); err != nil {
		t.Fatal(err)
	}
	nullable["artifacts"].([]any)[0].(map[string]any)["incusFingerprint"] = nil
	nullRaw, err := json.Marshal(nullable)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifySignedReleaseSet(nullRaw, trusted, 1); err == nil || !strings.Contains(err.Error(), "release-set-json-invalid: null incusFingerprint extension") {
		t.Fatalf("signed-extension-null-mutation-refused: %v", err)
	}
}
