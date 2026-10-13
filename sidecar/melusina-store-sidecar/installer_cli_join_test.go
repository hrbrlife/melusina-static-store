package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerpublish"
	"github.com/hrbrlife/melusina-store-sidecar/internal/publishclient"
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
	server := httptest.NewTLSServer(newPublicRouterWithService(svc.cfg, op, chain, nil, catalogRuntime{}, svc, false))
	defer server.Close()
	dir := t.TempDir()
	leafPath := filepath.Join(dir, "store-leaf.pem")
	if err := os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
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
		"--store", server.URL, "--store-tls-leaf", leafPath, "--class", class, "--name", name,
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
	after := httptest.NewTLSServer(newPublicRouterWithService(restarted.cfg, op, chain, nil, catalogRuntime{}, restarted, false))
	defer after.Close()
	afterLeaf := filepath.Join(dir, "restarted-leaf.pem")
	if err := os.WriteFile(afterLeaf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: after.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	afterClient, err := publishclient.NewClient(after.URL, "", afterLeaf, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	response, err := afterClient.Get(after.URL + "/releases/" + class + "/" + name)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Store-Gate") != "verified" {
		t.Fatalf("installer-restart-intended-readback: %d", response.StatusCode)
	}
	response, err = afterClient.Get(after.URL + "/releases/data/" + name)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("installer-restart-wrong-class-served")
	}
}
