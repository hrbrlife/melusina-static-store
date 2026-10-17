package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/recoveryprofilebridge"
)

func TestRecoveryBridgeOnlyThreeF1HashesAndExactSizes(t *testing.T) {
	const one = "7cbadcadd22318691dea0862127fe3167880e8c15d6d735fdb1845b0cb17218d"
	const two = "832d4bb11fa176c734cd8be10aad16fdc7c5e4aec711e2e6c82dd466e8cdb810"
	const three = "c2b047bcf9f5dcb8de02e1598fa347b68aef32f19309c6a3b28da4aa352c31aa"
	bridge := recoveryprofilebridge.Signed{Statement: recoveryprofilebridge.Statement{F1Sequence: 107,
		Members: []recoveryprofilebridge.Member{{Role: "installer", ArtifactSHA256: one, ArtifactSize: 11},
			{Role: "shell-bundle", ArtifactSHA256: two, ArtifactSize: 22},
			{Role: "update-controller", ArtifactSHA256: three, ArtifactSize: 33}}}}
	var set servedReleaseSet
	if err := json.Unmarshal([]byte(`{"stage":"foundation","sequence":107,"artifacts":[{"role":"installer","sha256":"`+one+`","sizeBytes":11},{"role":"shell-bundle","sha256":"`+two+`","sizeBytes":22},{"role":"update-controller","sha256":"`+three+`","sizeBytes":33}]}`), &set); err != nil {
		t.Fatal(err)
	}
	if err := requireBridgeSetMembers(set, bridge); err != nil {
		t.Fatal(err)
	}
	set.Artifacts[2].SizeBytes++
	if err := requireBridgeSetMembers(set, bridge); err == nil || !strings.Contains(err.Error(), "member-refused") {
		t.Fatalf("changed signed F1 member size admitted: %v", err)
	}
	set.Artifacts[2].SizeBytes--
	runtime := recoveryBridgeRuntime{signed: bridge}
	var member [32]byte
	member[0] = 7
	if runtime.member(member) {
		t.Fatal("foreign fourth hash admitted")
	}
}

func TestRecoveryBridgeRootFilesRefuseSymlinkAndLooseMode(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryRootFile(dir, "good.json", 1024); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(good, filepath.Join(dir, "alias.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryRootFile(dir, "alias.json", 1024); err == nil {
		t.Fatal("root bridge symlink admitted")
	}
	if err := os.Chmod(good, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecoveryRootFile(dir, "good.json", 1024); err == nil || !strings.Contains(err.Error(), "recovery-profile-bridge-state-refused") {
		t.Fatal("world-readable bridge file admitted")
	}
}

func TestRecoveryBridgeServeRefusesAlteredPersistedStateBeforeRPC(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ name, raw string }{
		{recoveryBridgeLeaf, "altered"},
		{recoveryOldProfileLeaf, "old"},
		{recoverySuccessorProfileLeaf, "successor"},
	} {
		if err := os.WriteFile(filepath.Join(dir, item.name), []byte(item.raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runtime := recoveryBridgeRuntime{bridgeRaw: []byte("original"), oldRaw: []byte("old"),
		successorRaw: []byte("successor")}
	if err := runtime.verify(context.Background(), Config{releaseSetDir: dir}); err == nil ||
		!strings.Contains(err.Error(), "recovery-profile-bridge-state-refused") {
		t.Fatalf("RECOVERY_PROFILE_BRIDGE_SERVE_STATE_MUTANT_ACCEPTED: %v", err)
	}
}
