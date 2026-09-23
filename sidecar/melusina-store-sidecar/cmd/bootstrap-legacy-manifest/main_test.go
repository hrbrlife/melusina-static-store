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

// Test fixtures only: the command compiles no license registry. Each is
// sha256 of a fixture label, not any estate's program.
const (
	testProgramID      = "AYftHM3kVLbKa6KqTiahVDGALQiA5EyMmTxM2J6SP73f" // "store-test-fixture: estate registry"
	otherTestProgramID = "AuJTDa1HUfxzQG7apn8Hd3cjR6Kih9mwYQ3TcgbRsnH7" // "store-test-fixture: another license registry"
)

// writeIdentities writes a publisher key bound to publisherProgram and the
// store operator's public identity, returning their paths.
func writeIdentities(t *testing.T, publisherProgram string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	var sign, box [32]byte
	for i := range sign {
		sign[i], box[i] = 0x13, 0x24
	}
	ref := identity.Ref{
		Kind: identity.KindPearl, ChainID: "solana:devnet", ProgramID: publisherProgram,
		LicenseMint: "publisher-license", Domain: "publisher.example", PDA: "publisher-pda",
		PearlIDHash: strings.Repeat("b", 64), KeyVersion: 1,
	}
	raw, err := json.Marshal(publisherKeyFile{Ref: ref, SignSeed: hex.EncodeToString(sign[:]), BoxSeed: hex.EncodeToString(box[:])})
	if err != nil {
		t.Fatal(err)
	}
	publisherPath := filepath.Join(dir, "publisher.json")
	if err := os.WriteFile(publisherPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	operator, err := identity.NewPrivate(identity.Ref{
		Kind: identity.KindSidecar, ChainID: "solana:devnet", ProgramID: testProgramID,
		LicenseMint: "store-license", Domain: "store.example", PDA: "store-pda", SidecarID: "store", KeyVersion: 1,
	}, box, sign)
	if err != nil {
		t.Fatal(err)
	}
	opRaw, err := json.Marshal(operator.Public())
	if err != nil {
		t.Fatal(err)
	}
	operatorPath := filepath.Join(dir, "store.json")
	if err := os.WriteFile(operatorPath, opRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	return publisherPath, operatorPath
}

func bootstrapArgs(publisherPath, operatorPath, envelopePath string) []string {
	return []string{
		"--store", "https://127.0.0.1:1", "--store-pubkey", operatorPath, "--publisher-key", publisherPath,
		"--generation", "7", "--verified-slot", "9", "--envelope-out", envelopePath,
	}
}

// The signed bootstrap request names the estate's registry only because the
// caller supplied it; nothing falls back to a compiled registry.
func TestBootstrapEnvelopeNamesTheSuppliedRegistry(t *testing.T) {
	publisherPath, operatorPath := writeIdentities(t, testProgramID)
	envelopePath := filepath.Join(t.TempDir(), "signed.json")
	var out strings.Builder
	if err := run(append(bootstrapArgs(publisherPath, operatorPath, envelopePath), "--program-id", testProgramID), &out); err != nil {
		t.Fatalf("complete request refused: %v", err)
	}
	raw, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	var body bootstrapBody
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if got := body.Envelope.Payload.ChainEvidence.ProgramID; got != testProgramID {
		t.Fatalf("chain evidence names program %q, want the supplied %q", got, testProgramID)
	}
	if !strings.Contains(out.String(), "SIGNED_LEGACY_MANIFEST_BOOTSTRAP_OK") {
		t.Fatalf("unexpected output %q", out.String())
	}
}

func TestBootstrapRefusesAMissingOrForeignRegistry(t *testing.T) {
	publisherPath, operatorPath := writeIdentities(t, testProgramID)
	foreignPublisher, _ := writeIdentities(t, otherTestProgramID)
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"absent":         {bootstrapArgs(publisherPath, operatorPath, filepath.Join(t.TempDir(), "a.json")), "--program-id is required"},
		"malformed":      {append(bootstrapArgs(publisherPath, operatorPath, filepath.Join(t.TempDir(), "b.json")), "--program-id", "not-a-program"), "--program-id must be the canonical base58 license-registry program"},
		"system program": {append(bootstrapArgs(publisherPath, operatorPath, filepath.Join(t.TempDir(), "c.json")), "--program-id", systemProgramID), "not the System Program"},
		"foreign key":    {append(bootstrapArgs(foreignPublisher, operatorPath, filepath.Join(t.TempDir(), "d.json")), "--program-id", testProgramID), "check=program_id: publisher key is bound to license-registry program " + otherTestProgramID},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(tc.args, new(strings.Builder)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
