package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
)

// Test fixtures only: the client compiles no license registry. Each is
// sha256 of a fixture label, not any estate's program.
const (
	testProgramID      = "AYftHM3kVLbKa6KqTiahVDGALQiA5EyMmTxM2J6SP73f" // "store-test-fixture: estate registry"
	otherTestProgramID = "AuJTDa1HUfxzQG7apn8Hd3cjR6Kih9mwYQ3TcgbRsnH7" // "store-test-fixture: another license registry"
)

func completeFlags() []string {
	return []string{
		"--store", "https://store.example", "--store-id", "store-1", "--request", "request.json",
		"--publisher-key", "publisher.json", "--store-pubkey", "store.json",
	}
}

// The promote client names the estate's registry in its chain evidence only
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
// it is refused before anything is signed instead of its program winning.
func TestPublisherKeyBoundToAnotherRegistryIsRefused(t *testing.T) {
	tmp := t.TempDir()
	var sign, box [32]byte
	for i := range sign {
		sign[i], box[i] = 0x51, 0x62
	}
	ref := identity.Ref{
		Kind: identity.KindPearl, ChainID: defaultChainID, ProgramID: otherTestProgramID,
		LicenseMint: "publisher-license", Domain: "publisher.example", PDA: "publisher-pda",
		PearlIDHash: strings.Repeat("a", 64), KeyVersion: 1,
	}
	publisherPath := filepath.Join(tmp, "publisher.json")
	raw, err := json.Marshal(publisherKeyFile{Ref: ref, SignSeed: hex.EncodeToString(sign[:]), BoxSeed: hex.EncodeToString(box[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publisherPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	storeRef := ref
	storeRef.Kind, storeRef.PearlIDHash, storeRef.SidecarID, storeRef.ProgramID = identity.KindSidecar, "", "store-1", testProgramID
	store, err := identity.NewPrivate(storeRef, box, sign)
	if err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(tmp, "store.json")
	storeRaw, err := json.Marshal(store.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storePath, storeRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(tmp, "request.json")
	if err := os.WriteFile(requestPath, []byte(`{"schema":"melusina-generation-promote-v1","channel":"stable","expectedCurrentGeneration":0,"components":[{}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	envelopePath := filepath.Join(tmp, "signed.json")
	err = run([]string{
		"--store", "https://127.0.0.1:1", "--store-id", "store-1", "--request", requestPath,
		"--publisher-key", publisherPath, "--store-pubkey", storePath, "--envelope-out", envelopePath,
		"--program-id", testProgramID,
	}, new(strings.Builder))
	if err == nil || !strings.Contains(err.Error(), "check=program_id: publisher key is bound to license-registry program "+otherTestProgramID) {
		t.Fatalf("publisher key under another registry: error = %v", err)
	}
	if _, statErr := os.Stat(envelopePath); !os.IsNotExist(statErr) {
		t.Fatalf("an envelope was written for a refused publisher key: %v", statErr)
	}
}
