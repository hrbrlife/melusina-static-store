package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readOnlyArgs(output string) []string {
	return []string{
		"--store", "https://store.sbr-coop.org", "--store-id", "melusina-os-root-store",
		"--store-pubkey", "/tmp/operator.json", "--private-route", "/tmp/route.json",
		"--estate-profile", "/tmp/profile.json", "--estate-profile-sha256", strings.Repeat("a", 64),
		"--read-current-generation-out", output,
	}
}

func TestReadCurrentGenerationModeRejectsSignerAndMutableFlags(t *testing.T) {
	output := filepath.Join(t.TempDir(), "generation.json")
	got, err := parseFlags(readOnlyArgs(output))
	if err != nil || got.readCurrentOut != output {
		t.Fatalf("read-only mode refused: %#v %v", got, err)
	}
	for _, extra := range [][]string{{"--request", "/tmp/request.json"}, {"--publisher-key", "/tmp/key.json"},
		{"--program-id", "11111111111111111111111111111111"}, {"--envelope-out", "/tmp/signed.json"},
		{"--connect-address", "10.1.1.1:18443"}, {"--carry-forward"}, {"--verified-slot", "123"}} {
		if _, err := parseFlags(append(readOnlyArgs(output), extra...)); err == nil || !strings.Contains(err.Error(), "read-current-generation product mode") {
			t.Errorf("accepted mutable/signer argument %v: %v", extra, err)
		}
	}
	if _, err := parseFlags(readOnlyArgs("relative.json")); err == nil {
		t.Fatal("accepted relative output")
	}
}

func TestReadCurrentGenerationOutputIsExclusiveOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "generation.json")
	raw := []byte(`{"schema":"melusina-desired-generation-v1"}`)
	if err := writeNewCurrentGeneration(out, raw); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || string(got) != string(raw) {
		t.Fatalf("output drift: %q %v", got, err)
	}
	info, err := os.Stat(out)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode drift: %v %v", info, err)
	}
	if err := writeNewCurrentGeneration(out, raw); err == nil {
		t.Fatal("replaced existing readback")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := writeNewCurrentGeneration(filepath.Join(link, "generation.json"), raw); err == nil {
		t.Fatal("accepted symlink parent")
	}
}
