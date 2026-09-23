package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Test fixtures only: keygen compiles no estate's values. The program is
// sha256("store-test-fixture: estate registry"); the rest are synthetic.
const (
	testProgramID   = "AYftHM3kVLbKa6KqTiahVDGALQiA5EyMmTxM2J6SP73f"
	testLicenseMint = "G4Ps7fo3cud6NxSWoJS78fozqCWtCmAT9ZdoM3t4vHWb"
	testPDA         = "7DNxWEbxfLQTCcNKnouxcSTNk2Z3SSua1mt5YxEf1nKD"
)

func storePubkeyArgs() map[string]string {
	sign := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x07}, 32)).Public().(ed25519.PublicKey)
	return map[string]string{
		"--sign-pubkey-b58": primitives.EncodeBase58(sign),
		"--box-pubkey-b58":  primitives.EncodeBase58(bytes.Repeat([]byte{0x09}, 32)),
		"--license-mint":    testLicenseMint,
		"--domain":          "store.example.org",
		"--program-id":      testProgramID,
		"--pda":             testPDA,
		"--sidecar-id":      "store",
	}
}

func flagsOf(values map[string]string, drop string) []string {
	var out []string
	for name, value := range values {
		if name != drop {
			out = append(out, name, value)
		}
	}
	return out
}

// store-pubkey builds the operator identity only from the facts the caller
// supplies, and refuses by name when any estate fact is left out.
func TestStorePubkeyTakesEveryEstateFactFromFlags(t *testing.T) {
	values := storePubkeyArgs()
	var out bytes.Buffer
	if err := run(append([]string{"store-pubkey"}, flagsOf(values, "")...), &out, new(bytes.Buffer)); err != nil {
		t.Fatalf("complete flags refused: %v", err)
	}
	var pub identity.Public
	if err := json.Unmarshal(out.Bytes(), &pub); err != nil {
		t.Fatal(err)
	}
	if pub.Ref.ProgramID != testProgramID || pub.Ref.LicenseMint != testLicenseMint || pub.Ref.PDA != testPDA ||
		pub.Ref.SidecarID != "store" || pub.Ref.Domain != "store.example.org" || pub.SignPubkeyB58 != values["--sign-pubkey-b58"] {
		t.Fatalf("identity does not carry exactly the supplied facts: %+v", pub)
	}
	for name := range values {
		t.Run("without "+name, func(t *testing.T) {
			err := run(append([]string{"store-pubkey"}, flagsOf(values, name)...), new(bytes.Buffer), new(bytes.Buffer))
			if err == nil || !strings.Contains(err.Error(), "missing required flag(s): "+name) {
				t.Fatalf("error = %v, want a refusal naming %s", err, name)
			}
		})
	}
	bad := storePubkeyArgs()
	bad["--program-id"] = systemProgramID
	if err := run(append([]string{"store-pubkey"}, flagsOf(bad, "")...), new(bytes.Buffer), new(bytes.Buffer)); err == nil || !strings.Contains(err.Error(), "not the System Program") {
		t.Fatalf("System Program registry: error = %v", err)
	}
}

// publisher mints a key only under the registry, mint and domain supplied.
func TestPublisherTakesEveryEstateFactFromFlags(t *testing.T) {
	seed := bytes.Repeat([]byte{0x05}, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	// The Solana CLI keypair format is a JSON number array, not base64.
	var numbers []int
	for _, b := range append(append([]byte{}, seed...), priv.Public().(ed25519.PublicKey)...) {
		numbers = append(numbers, int(b))
	}
	keypair, err := json.Marshal(numbers)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "keypair.json")
	if err := os.WriteFile(path, keypair, 0o600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"--license-mint": testLicenseMint, "--domain": "store.example.org", "--program-id": testProgramID}
	var out bytes.Buffer
	if err := run(append(append([]string{"publisher"}, flagsOf(values, "")...), path), &out, new(bytes.Buffer)); err != nil {
		t.Fatalf("complete flags refused: %v", err)
	}
	var key publisherKeyFile
	if err := json.Unmarshal(out.Bytes(), &key); err != nil {
		t.Fatal(err)
	}
	if key.Ref.ProgramID != testProgramID || key.Ref.LicenseMint != testLicenseMint || key.Ref.Domain != "store.example.org" {
		t.Fatalf("publisher ref does not carry exactly the supplied facts: %+v", key.Ref)
	}
	for name := range values {
		t.Run("without "+name, func(t *testing.T) {
			err := run(append(append([]string{"publisher"}, flagsOf(values, name)...), path), new(bytes.Buffer), new(bytes.Buffer))
			if err == nil || !strings.Contains(err.Error(), "missing required flag(s): "+name) {
				t.Fatalf("error = %v, want a refusal naming %s", err, name)
			}
		})
	}
}
