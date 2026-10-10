package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerpublish"
)

func TestInstallerCLIToProductionRouterAndRestartReadback(t *testing.T) {
	cfg, chain, _, artifact, _, pda, class, name := releaseSetup(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	pinRootStoreOperator(t, cfg, chain, op)
	chain.installerEntry[pda] = mockInstallerEntry{installerHash: sha256.Sum256(artifact), version: "1.0.0", status: verify.AttestationStatusActive}
	if err := os.Remove(filepath.Join(cfg.DistDir, "releases", class, name)); err != nil {
		t.Fatal(err)
	}
	svc := newTestService(t, cfg, chain, op)
	var signSeed, boxSeed [32]byte
	if _, err := rand.Read(signSeed[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(boxSeed[:]); err != nil {
		t.Fatal(err)
	}
	ref := op.Public().Ref
	ref.SidecarID = "cli-publisher"
	ref.Domain = "publisher.example.org"
	publisher, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		t.Fatal(err)
	}
	svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	// Keep the package containing the production signer in this test's import
	// graph; the command below calls the same signer before it posts.
	digest := sha256.Sum256(artifact)
	if _, err := installerpublish.Digest(class, name, hex.EncodeToString(digest[:]), svc.cfg.StoreID, svc.cfg.Domain, svc.cfg.LicenseNFTMint, svc.cfg.ProgramID); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(newPublicRouterWithService(svc.cfg, op, chain, nil, catalogRuntime{}, svc, false))
	defer server.Close()
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "artifact")
	publisherPath := filepath.Join(dir, "publisher.json")
	operatorPath := filepath.Join(dir, "operator.json")
	if err := os.WriteFile(artifactPath, artifact, 0600); err != nil {
		t.Fatal(err)
	}
	publisherJSON, err := json.Marshal(struct {
		Ref      identity.Ref `json:"ref"`
		SignSeed string       `json:"sign_seed_hex"`
		BoxSeed  string       `json:"box_seed_hex"`
	}{ref, hex.EncodeToString(signSeed[:]), hex.EncodeToString(boxSeed[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publisherPath, publisherJSON, 0600); err != nil {
		t.Fatal(err)
	}
	operatorJSON, err := json.Marshal(op.Public())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(operatorPath, operatorJSON, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "run", "./cmd/submit-installer",
		"--store", server.URL, "--class", class, "--name", name,
		"--artifact", artifactPath, "--publisher-key", publisherPath, "--store-pubkey", operatorPath,
		"--store-id", svc.cfg.StoreID, "--store-domain", svc.cfg.Domain,
		"--license-mint", svc.cfg.LicenseNFTMint, "--program-id", svc.cfg.ProgramID)
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "PUBLISH INSTALLER OK") {
		t.Fatalf("installer-cli-production-router-positive: %v %s", err, output)
	}
	reopened, err := openPublishNonceLedger(filepath.Join(svc.cfg.PrivateStageDir, publishNonceLedgerDirName), testPublishNonceLedgerID, defaultPublishNonceLedgerOptions())
	if err != nil {
		t.Fatal(err)
	}
	restarted := restartPublishServiceForTest(svc)
	restarted.appNonces = reopened
	after := httptest.NewServer(newPublicRouterWithService(restarted.cfg, op, chain, nil, catalogRuntime{}, restarted, false))
	defer after.Close()
	response, err := http.Get(after.URL + "/releases/" + class + "/" + name)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Store-Gate") != "verified" {
		t.Fatalf("installer-restart-intended-readback: %d", response.StatusCode)
	}
	response, err = http.Get(after.URL + "/releases/data/" + name)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("installer-restart-wrong-class-served")
	}
}
