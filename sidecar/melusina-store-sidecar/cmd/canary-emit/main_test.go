package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	canaryTestProgram = "BSENx6t1GVPzhnnd4yiojxWk7HjKZiiRQEkriHg6Mpix"
	canaryTestGenesis = "11111111111111111111111111111111"
)

func TestCanaryConfigRequiresAndVerifiesFreshChain(t *testing.T) {
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": canaryTestGenesis})
	}))
	defer rpc.Close()
	cfg := storeConfigFile{
		LicenseNFTMint: randomCanaryKey(t), ProgramID: canaryTestProgram,
		ClusterGenesisHash: canaryTestGenesis, RPCURL: rpc.URL, Domain: "store.example.org",
	}
	cfg.BootIdentity.SidecarID = "store"
	cfg.BootIdentity.ChainID = defaultChainID
	cfg.BootIdentity.KeyVersion = 1
	path := filepath.Join(t.TempDir(), "store.json")
	writeCanaryJSON(t, path, cfg, 0o600)
	loaded, err := loadStoreConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCanaryConfigGenesis(loaded); err != nil {
		t.Fatalf("exact genesis rejected: %v", err)
	}
	loaded.ClusterGenesisHash = canaryTestProgram
	if err := verifyCanaryConfigGenesis(loaded); err == nil || !strings.Contains(err.Error(), "cluster genesis mismatch") {
		t.Fatalf("wrong genesis accepted: %v", err)
	}

	cfg.ProgramID = legacyProgramIDB58
	writeCanaryJSON(t, path, cfg, 0o600)
	if _, err := loadStoreConfig(path); err == nil || !strings.Contains(err.Error(), "legacy program_id is refused") {
		t.Fatalf("legacy config accepted: %v", err)
	}
}

func TestRunSignBindsFreshProgramGenesisIdentitiesAndReleasePDA(t *testing.T) {
	dir := t.TempDir()
	license := randomCanaryKey(t)
	operator, _, _ := canaryIdentity(t, "operator", license)
	publisher, publisherSign, publisherBox := canaryIdentity(t, "publisher", license)
	operatorPath := filepath.Join(dir, "operator.json")
	publisherPath := filepath.Join(dir, "publisher.json")
	writeCanaryJSON(t, operatorPath, operator.Public(), 0o600)
	writeCanaryJSON(t, publisherPath, publisherKeyFile{
		Ref: publisher.Public().Ref, ClusterGenesisHash: canaryTestGenesis,
		SignSeed: hex.EncodeToString(publisherSign[:]), BoxSeed: hex.EncodeToString(publisherBox[:]),
	}, 0o600)

	masterText := randomCanaryKey(t)
	master, _ := primitives.PubkeyFromBase58(masterText)
	program, _ := primitives.PubkeyFromBase58(canaryTestProgram)
	appHash := sha256.Sum256([]byte("fresh app hash"))
	releasePDA, _, err := pda.Release(master, appHash, program)
	if err != nil {
		t.Fatal(err)
	}
	releasePath := filepath.Join(dir, "RELEASE.json")
	spkPath := filepath.Join(dir, "app.spk")
	metadataPath := filepath.Join(dir, "metadata.json")
	writeCanaryJSON(t, releasePath, map[string]any{
		"appHash": hex.EncodeToString(appHash[:]), "masterNftMint": masterText,
	}, 0o600)
	if err := os.WriteFile(spkPath, []byte("fresh app spk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, []byte(`{"appId":"fresh-app"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fixturePath := filepath.Join(dir, "fixture.json")
	args := []string{
		"--operator-public", operatorPath, "--publisher-identity", publisherPath,
		"--release", releasePath, "--spk", spkPath, "--metadata", metadataPath,
		"--release-entry-pda", releasePDA.Base58(), "--verified-slot", "123",
		"--program-id", canaryTestProgram, "--cluster-genesis-hash", canaryTestGenesis,
		"--stage-nonce", strings.Repeat("a", 32), "--promote-nonce", strings.Repeat("b", 32),
		"--txid", "tx-fresh", "--wal-digest", strings.Repeat("c", 64),
		"--out-fixture", fixturePath,
	}
	if err := runSign(args); err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ProgramID          string          `json:"program_id"`
		ClusterGenesisHash string          `json:"cluster_genesis_hash"`
		StageWire          envelope.Signed `json:"stage_wire"`
		PromoteWire        envelope.Signed `json:"promote_wire"`
	}
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.ProgramID != canaryTestProgram || fixture.ClusterGenesisHash != canaryTestGenesis ||
		fixture.StageWire.Payload.ChainEvidence.ProgramID != canaryTestProgram ||
		fixture.StageWire.Payload.ChainEvidence.ReleaseEntryPDA != releasePDA.Base58() ||
		fixture.PromoteWire.Payload.ChainEvidence.ProgramID != canaryTestProgram {
		t.Fatalf("canary fixture fresh-deployment binding drift: %+v", fixture)
	}

	wrong := append([]string(nil), args...)
	for i := range wrong {
		if wrong[i] == releasePDA.Base58() {
			wrong[i] = randomCanaryKey(t)
			break
		}
	}
	if err := runSign(wrong); err == nil || !strings.Contains(err.Error(), "fresh-program derived") {
		t.Fatalf("wrong ReleaseEntry PDA accepted: %v", err)
	}
}

func TestCanaryFreshChainRefusesMissingAndLegacy(t *testing.T) {
	if err := validateCanaryFreshChain("", ""); err == nil {
		t.Fatal("missing program/genesis accepted")
	}
	if err := validateCanaryFreshChain(legacyProgramIDB58, canaryTestGenesis); err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("legacy program accepted: %v", err)
	}
}

func canaryIdentity(t *testing.T, sidecarID, license string) (*identity.Private, [32]byte, [32]byte) {
	t.Helper()
	var signSeed, boxSeed [32]byte
	if _, err := rand.Read(signSeed[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(boxSeed[:]); err != nil {
		t.Fatal(err)
	}
	priv, err := identity.NewPrivate(identity.Ref{
		Kind: identity.KindSidecar, ChainID: defaultChainID, ProgramID: canaryTestProgram,
		LicenseMint: license, Domain: "store.example.org", PDA: randomCanaryKey(t),
		SidecarID: sidecarID, KeyVersion: 1,
	}, signSeed, boxSeed)
	if err != nil {
		t.Fatal(err)
	}
	return priv, signSeed, boxSeed
}

func randomCanaryKey(t *testing.T) string {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return primitives.EncodeBase58(raw[:])
}

func writeCanaryJSON(t *testing.T, path string, value any, mode os.FileMode) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
}
