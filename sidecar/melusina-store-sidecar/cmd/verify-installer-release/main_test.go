package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The chain half of this command is proven live (an Active InstallerReleaseEntry
// for the installed controller; refusals for an unauthorized artifact, for a
// sidecar binary whose authority class is sidecar_identity rather than
// installer_release, and for a symlink). These cover the offline refusals, which
// must fail BEFORE any network call so a malformed ceremony never touches RPC.
func TestRunRefusesRelativePaths(t *testing.T) {
	if err := run("etc/config.json", "/abs/artifact"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative config accepted: %v", err)
	}
	if err := run("/etc/config.json", "artifact"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative artifact accepted: %v", err)
	}
}

func TestRunRefusesConfigMissingChainPins(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	// a syntactically valid controller config that omits the pins this ceremony
	// needs must refuse by name, never fall back to a default program or RPC.
	if err := os.WriteFile(cfg, []byte(`{"schema":"melusina-update-controller-config-v1","autoApply":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	art := filepath.Join(dir, "artifact")
	if err := os.WriteFile(art, []byte("bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := run(cfg, art)
	if err == nil || !strings.Contains(err.Error(), "masterNftMint") {
		t.Fatalf("config without chain pins accepted: %v", err)
	}
}

func TestHashNoFollowRefusesSymlinkAndDirectory(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("controller"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hashNoFollow(link); err == nil {
		t.Fatal("symlinked artifact accepted — the ceremony could attest to bytes other than those installed")
	}
	if _, _, err := hashNoFollow(dir); err == nil {
		t.Fatal("directory accepted as an artifact")
	}
	sum, size, err := hashNoFollow(real)
	if err != nil {
		t.Fatalf("regular file rejected: %v", err)
	}
	if size != int64(len("controller")) || sum == [32]byte{} {
		t.Fatalf("unexpected hash result: size=%d sum=%x", size, sum)
	}
}
