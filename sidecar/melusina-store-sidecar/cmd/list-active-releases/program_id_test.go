package main

import (
	"strings"
	"testing"
)

// testProgramID is sha256("store-test-fixture: estate registry"), a synthetic
// key that is no estate's program.
const testProgramID = "AYftHM3kVLbKa6KqTiahVDGALQiA5EyMmTxM2J6SP73f"

// The lister compiles no license registry: it enumerates only the registry the
// caller names, and refuses by name when none, a malformed one or the System
// Program is supplied.
func TestParseArgsRequireTheEstateRegistry(t *testing.T) {
	base := []string{"-rpc-url", "https://rpc.example", "-app-id", "021x360jnqz798taefscu7r69a0xvvqyhfwfjadq8g2f9wuqm5h0"}
	got, err := parseArgs(append(append([]string{}, base...), "-program-id", testProgramID))
	if err != nil {
		t.Fatalf("complete arguments rejected: %v", err)
	}
	if got.programID != testProgramID {
		t.Fatalf("programID = %q, want %q", got.programID, testProgramID)
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"absent":         {base, "-program-id is required"},
		"malformed":      {append(append([]string{}, base...), "-program-id", "not-a-program"), "-program-id must be the canonical base58 license-registry program"},
		"system program": {append(append([]string{}, base...), "-program-id", systemProgramID), "not the System Program"},
		"no app":         {[]string{"-rpc-url", "https://rpc.example", "-program-id", testProgramID}, "usage:"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseArgs(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
