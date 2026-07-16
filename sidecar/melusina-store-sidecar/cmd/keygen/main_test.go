package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	keygenTestProgram = "BSENx6t1GVPzhnnd4yiojxWk7HjKZiiRQEkriHg6Mpix"
	keygenTestGenesis = "11111111111111111111111111111111"
)

func TestPublisherRequiresAndPersistsFreshChainBinding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "publisher.json")
	if raw, err := json.Marshal([]byte(priv)); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(keyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	license := randomBase58Key(t)
	var stdout, stderr bytes.Buffer
	err = run([]string{
		"publisher", "--license-mint", license, "--domain", "store.example.org",
		"--program-id", keygenTestProgram, "--cluster-genesis-hash", keygenTestGenesis,
		keyPath,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	var key publisherKeyFile
	if err := json.Unmarshal(stdout.Bytes(), &key); err != nil {
		t.Fatal(err)
	}
	if key.Ref.ProgramID != keygenTestProgram || key.ClusterGenesisHash != keygenTestGenesis || key.Ref.LicenseMint != license || key.Ref.PDA != primitives.EncodeBase58(pub) {
		t.Fatalf("publisher key is not exactly fresh-deployment-bound: %+v", key)
	}

	if err := run([]string{"publisher", keyPath}, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "--license-mint and --domain are required") {
		t.Fatalf("implicit publisher identity inputs accepted: %v", err)
	}
}

func TestStorePublicRequiresDerivedFreshProgramPDA(t *testing.T) {
	licenseText := randomBase58Key(t)
	license, _ := primitives.PubkeyFromBase58(licenseText)
	program, _ := primitives.PubkeyFromBase58(keygenTestProgram)
	wantPDA, _, err := pda.SidecarIdentity(license, "store", 1, program)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{
		"store-pubkey",
		"--sign-pubkey-b58", randomBase58Key(t), "--box-pubkey-b58", randomBase58Key(t),
		"--license-mint", licenseText, "--domain", "store.example.org",
		"--program-id", keygenTestProgram, "--cluster-genesis-hash", keygenTestGenesis,
		"--pda", wantPDA.Base58(), "--sidecar-id", "store", "--key-version", "1",
	}
	var stdout, stderr bytes.Buffer
	if err := run(args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var got identity.Public
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Ref.ProgramID != keygenTestProgram || got.Ref.PDA != wantPDA.Base58() || !strings.Contains(stderr.String(), keygenTestGenesis) {
		t.Fatalf("store public identity binding drift: %+v stderr=%q", got.Ref, stderr.String())
	}

	wrong := append([]string(nil), args...)
	for i := range wrong {
		if wrong[i] == wantPDA.Base58() {
			wrong[i] = randomBase58Key(t)
			break
		}
	}
	if err := run(wrong, &stdout, &stderr); err == nil || !strings.Contains(err.Error(), "derived fresh-program PDA") {
		t.Fatalf("wrong PDA accepted: %v", err)
	}
}

func TestFreshChainValidationRefusesLegacyAndMissing(t *testing.T) {
	if err := validateFreshChain("", ""); err == nil {
		t.Fatal("missing program/genesis accepted")
	}
	if err := validateFreshChain(legacyProgramID, keygenTestGenesis); err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("legacy program accepted: %v", err)
	}
}

func randomBase58Key(t *testing.T) string {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return primitives.EncodeBase58(raw[:])
}
