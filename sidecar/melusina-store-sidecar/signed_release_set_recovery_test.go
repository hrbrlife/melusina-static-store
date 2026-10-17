package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The signed bytes and canonical digest are produced by the deployer and
// independently checked by the contracts release-set implementation.
func TestRecoveryContinuityIsBoundAtTheStoreServeGate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "recovery-signed-release-set.json"))
	if err != nil {
		t.Fatal(err)
	}
	var claim servedReleaseSet
	if err := json.Unmarshal(raw, &claim); err != nil {
		t.Fatal(err)
	}
	trusted := make([]string, 0, len(claim.PublisherKeyset.Keys))
	for _, key := range claim.PublisherKeyset.Keys {
		trusted = append(trusted, key.Ed25519PublicKey)
	}
	const expected = "6ab01a5984a221c50415c57766a08184602e20263156f7ca894f004c6b358689"
	verified, digest, err := verifySignedReleaseSet(raw, trusted, 2)
	if err != nil || digest != expected || verified.Continuity == nil || verified.Continuity.Kind != "lost-predecessor" {
		t.Fatalf("recovery-signed-set-positive: digest=%s err=%v", digest, err)
	}
	mutate := func(name string, change func(map[string]any), refusal string) {
		t.Run(name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			change(document)
			changed, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := verifySignedReleaseSet(changed, trusted, 2); err == nil || !strings.Contains(err.Error(), refusal) {
				t.Fatalf("%s accepted: %v", name, err)
			}
		})
	}
	mutate("recovery-digest", func(d map[string]any) { d["continuity"].(map[string]any)["admissionSha256"] = strings.Repeat("0", 64) }, "release-set-signature-invalid")
	mutate("recovery-operator", func(d map[string]any) { d["continuity"].(map[string]any)["operator"] = "foreign" }, "release-set-signature-invalid")
	mutate("recovery-sequence-rewind", func(d map[string]any) { d["sequence"] = float64(105) }, "release-set-continuity-invalid")
	mutate("recovery-null", func(d map[string]any) { d["continuity"] = nil }, "release-set-json-invalid: null continuity")
}
