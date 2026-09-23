package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test fixtures only: the client compiles no license registry. Each is
// sha256 of a fixture label, not any estate's program.
const (
	testProgramID      = "AYftHM3kVLbKa6KqTiahVDGALQiA5EyMmTxM2J6SP73f" // "store-test-fixture: estate registry"
	otherTestProgramID = "AuJTDa1HUfxzQG7apn8Hd3cjR6Kih9mwYQ3TcgbRsnH7" // "store-test-fixture: another license registry"
)

func completeFlags() []string {
	return []string{
		"--store", "https://store.example", "--class", "deployer", "--name", "deployer.tar.xz",
		"--artifact", "artifact.tar.xz", "--publisher-key", "publisher.json", "--store-pubkey", "store.json",
	}
}

// The installer client names the estate's registry in its chain evidence only
// because the caller supplied it; an absent, malformed or System Program
// registry is refused by name.
func TestParseFlagsRequireTheEstateRegistry(t *testing.T) {
	got, err := parseFlags(append(completeFlags(), "--program-id", testProgramID))
	if err != nil {
		t.Fatalf("complete flags rejected: %v", err)
	}
	if got.programID != testProgramID {
		t.Fatalf("programID = %q, want %q", got.programID, testProgramID)
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"absent":         {completeFlags(), "missing required flag(s): --program-id"},
		"malformed":      {append(completeFlags(), "--program-id", "not-a-program"), "--program-id must be the canonical base58 license-registry program"},
		"system program": {append(completeFlags(), "--program-id", systemProgramID), "not the System Program"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFlags(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// A publisher key minted under another registry belongs to another estate;
// it is refused before anything is uploaded instead of its program winning.
func TestPublisherKeyBoundToAnotherRegistryIsRefused(t *testing.T) {
	publisher, signSeed, boxSeed := testPrivate(t, "publisher")
	operator, _, _ := testPrivate(t, "store")
	foreign := publisher.Public().Ref
	foreign.ProgramID = otherTestProgramID
	contacted := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { contacted = true }))
	defer server.Close()

	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact.tar.xz")
	publisherPath := filepath.Join(dir, "publisher.json")
	operatorPath := filepath.Join(dir, "operator.json")
	if err := os.WriteFile(artifactPath, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	publisherJSON, _ := json.Marshal(publisherKeyFile{Ref: foreign, SignSeed: hex.EncodeToString(signSeed[:]), BoxSeed: hex.EncodeToString(boxSeed[:])})
	if err := os.WriteFile(publisherPath, publisherJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	operatorJSON, _ := json.Marshal(operator.Public())
	if err := os.WriteFile(operatorPath, operatorJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{
		"--store", server.URL, "--class", "deployer", "--name", "deployer.tar.xz", "--artifact", artifactPath,
		"--publisher-key", publisherPath, "--store-pubkey", operatorPath, "--program-id", testProgramID,
	}, new(strings.Builder))
	if err == nil || !strings.Contains(err.Error(), "check=program_id: publisher key is bound to license-registry program "+otherTestProgramID) {
		t.Fatalf("publisher key under another registry: error = %v", err)
	}
	if contacted {
		t.Fatal("the store was contacted for a refused publisher key")
	}
}
