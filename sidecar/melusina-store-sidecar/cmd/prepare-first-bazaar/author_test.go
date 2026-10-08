package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This is the retained public original-author preparation, not a fabricated
// Core vote, proposal, execution or Store receipt. No private key is included.
func TestActualFirstAuthorPreparationRequiresOriginalCoreAndExactCandidate(t *testing.T) {
	raw, err := os.ReadFile("testdata/first-bazaar-author-preparation.json")
	if err != nil {
		t.Fatal(err)
	}
	appHash := "a3172ddafb512da90139f225ba225e70536360fc0e07934930b36b18b6c335c3"
	runtimeHash := "e9badc3858ff3a971f3399e14d90a86a0da43089dd110989667cb91e2b465e46"
	state, release, err := firstAuthorRelease(raw, appHash, runtimeHash)
	if err != nil {
		t.Fatal(err)
	}
	var r map[string]any
	if err := json.Unmarshal(release, &r); err != nil {
		t.Fatal(err)
	}
	if r["signedAtUnix"] != float64(state.CreatedAtUnix) || r["releaseEntryPda"] != "4iFmchVJiwbKc5a23xjVwcNGAPGYYjUbZ4hPPwQcCVBo" || r["runtimeContractSha256"] != runtimeHash || state.TransactionIndex != 1986 || !state.DryRun {
		t.Fatal("actual preparation lost original signature, locator or provisional-time semantics")
	}
	// The author's payload signature intentionally does not sign the stated
	// quorum threshold. The fixed first-app boundary must still enforce 3-of-4.
	for _, mutated := range []string{strings.Replace(string(raw), "\"threshold\": 3", "\"threshold\": 2", 1), strings.Replace(string(raw), "\"memberCount\": 4", "\"memberCount\": 5", 1), strings.Replace(string(raw), "\"appHash\":", "\"AppHash\":", 1), strings.Replace(string(raw), "TOLQ2dJ9SuSe", "UOLQ2dJ9SuSe", 1)} {
		if _, _, err := firstAuthorRelease([]byte(mutated), appHash, runtimeHash); err == nil {
			t.Fatal("changed authority or signature accepted")
		}
	}
	if _, _, err := firstAuthorRelease(raw, strings.Repeat("a", 64), runtimeHash); err == nil {
		t.Fatal("author output for another package accepted")
	}
	if _, _, err := firstAuthorRelease(raw, appHash, ""); err == nil {
		t.Fatal("missing runtime binding accepted")
	}
}

func TestPublicPreparationInputNeverFollowsSymlinkOrSharedPrivateFile(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "state.json")
	if err := os.WriteFile(name, []byte("public"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublicPreparation(name, 128); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublicPreparation(link, 128); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Link(name, filepath.Join(dir, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublicPreparation(name, 128); err == nil {
		t.Fatal("shared file accepted")
	}
	if _, err := readPublicPreparation(name, 1); err == nil {
		t.Fatal("oversized file accepted")
	}
}
