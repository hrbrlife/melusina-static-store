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

// Test fixtures only: the emitter compiles no license registry. Each is
// sha256 of a fixture label, not any estate's program or mint.
const (
	testProgramID      = "AYftHM3kVLbKa6KqTiahVDGALQiA5EyMmTxM2J6SP73f" // "store-test-fixture: estate registry"
	otherTestProgramID = "AuJTDa1HUfxzQG7apn8Hd3cjR6Kih9mwYQ3TcgbRsnH7" // "store-test-fixture: another license registry"
	testLicenseMint    = "G4Ps7fo3cud6NxSWoJS78fozqCWtCmAT9ZdoM3t4vHWb"
)

func testConfig(programID string) storeConfigFile {
	var cfg storeConfigFile
	cfg.LicenseNFTMint = testLicenseMint
	cfg.ProgramID = programID
	cfg.Domain = "store.example.org"
	cfg.BootIdentity.SidecarID = "store"
	cfg.BootIdentity.ChainID = "solana:devnet"
	return cfg
}

// The operator identity is derived under the registry the Store config names;
// a config without one is refused by name instead of falling back to a
// compiled registry.
func TestOperatorRefTakesTheRegistryFromConfigOnly(t *testing.T) {
	ref, err := operatorRef(testConfig(testProgramID))
	if err != nil {
		t.Fatalf("complete config refused: %v", err)
	}
	if ref.ProgramID != testProgramID {
		t.Fatalf("operator ref program = %q, want the config's %q", ref.ProgramID, testProgramID)
	}
	for name, tc := range map[string]struct {
		program string
		want    string
	}{
		"absent":         {"", "config: program_id is required"},
		"malformed":      {"not-a-program", "config: program_id must be the canonical base58 license-registry program"},
		"system program": {systemProgramID, "not the System Program"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := operatorRef(testConfig(tc.program)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// sign names only the supplied registry, and refuses an operator identity or
// publisher key minted under another one before any artifact is read.
func TestSignRequiresTheOperatorsRegistry(t *testing.T) {
	dir := t.TempDir()
	var sign, box [32]byte
	for i := range sign {
		sign[i], box[i] = 0x35, 0x46
	}
	write := func(name string, value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	operatorFor := func(program string) string {
		ref, err := operatorRef(testConfig(program))
		if err != nil {
			t.Fatal(err)
		}
		op, err := identity.NewPrivate(ref, sign, box)
		if err != nil {
			t.Fatal(err)
		}
		return write("operator-"+program+".json", op.Public())
	}
	publisherFor := func(program string) string {
		ref := identity.Ref{
			Kind: identity.KindPearl, ChainID: "solana:devnet", ProgramID: program,
			LicenseMint: testLicenseMint, Domain: "publisher.example", PDA: "publisher-pda",
			PearlIDHash: strings.Repeat("c", 64), KeyVersion: 1,
		}
		return write("publisher-"+program+".json", publisherKeyFile{Ref: ref, SignSeed: hex.EncodeToString(box[:]), BoxSeed: hex.EncodeToString(sign[:])})
	}
	args := func(operator, publisher string, extra ...string) []string {
		return append([]string{
			"--operator-public", operator, "--publisher-identity", publisher,
			"--release", filepath.Join(dir, "absent-RELEASE.json"), "--spk", filepath.Join(dir, "absent.spk"),
			"--metadata", filepath.Join(dir, "absent-metadata.json"), "--release-entry-pda", "release-pda",
			"--verified-slot", "5", "--stage-nonce", "stage", "--promote-nonce", "promote",
			"--txid", "tx", "--wal-digest", "wal", "--out-fixture", filepath.Join(dir, "fixture.json"),
		}, extra...)
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"absent":           {args(operatorFor(testProgramID), publisherFor(testProgramID)), "--program-id is required"},
		"malformed":        {args(operatorFor(testProgramID), publisherFor(testProgramID), "--program-id", "not-a-program"), "--program-id must be the canonical base58 license-registry program"},
		"foreign operator": {args(operatorFor(otherTestProgramID), publisherFor(testProgramID), "--program-id", testProgramID), "check=program_id: operator identity is bound to license-registry program " + otherTestProgramID},
		"foreign key":      {args(operatorFor(testProgramID), publisherFor(otherTestProgramID), "--program-id", testProgramID), "check=program_id: publisher key is bound to license-registry program " + otherTestProgramID},
		// Positive control: with a matching registry the command gets past
		// every registry check and fails only on the absent release bytes.
		"matching": {args(operatorFor(testProgramID), publisherFor(testProgramID), "--program-id", testProgramID), "absent-RELEASE.json"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := runSign(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
