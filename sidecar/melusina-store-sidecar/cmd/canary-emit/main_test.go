package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
)

func TestSignRequiresValidRuntimeContractAndEmitsExactBytes(t *testing.T) {
	dir := t.TempDir()
	license := "11111111111111111111111111111111"
	operator, _ := canaryTestIdentity(t, "operator", license, 0x11)
	publisher, publisherSeed := canaryTestIdentity(t, "publisher", license, 0x22)
	operatorPath := filepath.Join(dir, "operator.json")
	publisherPath := filepath.Join(dir, "publisher.json")
	writeCanaryJSON(t, operatorPath, operator.Public())
	writeCanaryJSON(t, publisherPath, publisherKeyFile{
		Ref: publisher.Public().Ref, SignSeed: hex.EncodeToString(publisherSeed[:]), BoxSeed: strings.Repeat("33", 32),
	})

	spk := []byte("exact canary spk")
	metadata := []byte(`{"appId":"canary-app","version":"1.0.0"}`)
	appHash := strings.Repeat("a", 64)
	spkDigest := sha256.Sum256(spk)
	contract, err := json.Marshal(runtimecontract.Contract{
		SchemaURL: runtimecontract.SchemaURL, Schema: runtimecontract.Schema,
		App:      runtimecontract.App{AppID: "canary-app", Version: "1.0.0", SPKSHA256: hex.EncodeToString(spkDigest[:]), AppHash: appHash},
		Sidecars: []runtimecontract.Sidecar{},
		LaunchProbe: runtimecontract.VisibleProbe{
			Kind:           "visible-ui",
			Steps:          []runtimecontract.ProbeStep{{Action: "Open the app screen.", ExpectedResult: "The app screen renders."}},
			ExpectedResult: "The app opens without a launch error.",
		},
		Fixtures: []runtimecontract.Fixture{}, Cleanup: runtimecontract.Cleanup{Steps: []string{"No test data remains."}},
	})
	if err != nil {
		t.Fatal(err)
	}
	contractDigest := sha256.Sum256(contract)
	release := []byte(`{"appHash":"` + appHash + `","version":"1.0.0","runtimeContractSchema":"` + runtimecontract.Schema + `","runtimeContractSha256":"` + hex.EncodeToString(contractDigest[:]) + `"}`)
	paths := map[string][]byte{
		"release.json": release, "app.spk": spk, "metadata.json": metadata, "RUNTIME-CONTRACT.json": contract,
	}
	for name, body := range paths {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "fixture.json")
	args := []string{
		"--operator-public", operatorPath, "--publisher-identity", publisherPath,
		"--release", filepath.Join(dir, "release.json"), "--spk", filepath.Join(dir, "app.spk"),
		"--metadata", filepath.Join(dir, "metadata.json"), "--runtime-contract", filepath.Join(dir, "RUNTIME-CONTRACT.json"),
		"--release-entry-pda", "11111111111111111111111111111111", "--verified-slot", "123",
		"--stage-nonce", strings.Repeat("1", 64), "--promote-nonce", strings.Repeat("2", 64),
		"--txid", "canary-runtime-contract-test", "--wal-digest", strings.Repeat("4", 64), "--out-fixture", out,
	}
	if err := runSign(args); err != nil {
		t.Fatal(err)
	}
	var fixture map[string]json.RawMessage
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	var encoded string
	if err := json.Unmarshal(fixture["runtime_contract_b64"], &encoded); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, contract) {
		t.Fatal("canary fixture did not preserve exact runtime-contract bytes")
	}

	tampered := append([]byte(nil), contract...)
	tampered[len(tampered)-1] ^= 1
	if err := validateRuntimeMaterial(release, spk, metadata, tampered); err == nil {
		t.Fatal("canary emitter accepted a tampered runtime contract")
	}
}

func canaryTestIdentity(t *testing.T, sidecarID, license string, tag byte) (*identity.Private, [32]byte) {
	t.Helper()
	var signSeed, boxSeed [32]byte
	for i := range signSeed {
		signSeed[i] = tag
		boxSeed[i] = tag ^ byte(i)
	}
	ref := identity.Ref{
		Kind: identity.KindSidecar, ChainID: defaultChainID, ProgramID: defaultProgramIDB58,
		LicenseMint: license, Domain: "store.example.org", PDA: "11111111111111111111111111111111",
		SidecarID: sidecarID, KeyVersion: 1,
	}
	priv, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		t.Fatal(err)
	}
	return priv, signSeed
}

func writeCanaryJSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
