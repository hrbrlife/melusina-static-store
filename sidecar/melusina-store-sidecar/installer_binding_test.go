package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerpublish"
)

type installerRestartProbe struct {
	LedgerRoot   string          `json:"ledger_root"`
	Signed       envelope.Signed `json:"signed"`
	Signer       string          `json:"signer"`
	Destination  identity.Public `json:"destination"`
	ArtifactHash string          `json:"artifact_hash"`
}

func checkInstallerReplayInRestartedProcess(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var probe installerRestartProbe
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	ledger, err := openPublishNonceLedger(probe.LedgerRoot, testPublishNonceLedgerID, defaultPublishNonceLedgerOptions())
	if err != nil {
		t.Fatalf("installer-publish-real-process-restart-ledger: %v", err)
	}
	svc := &publishService{appNonces: ledger}
	err = svc.verifyDurableEnvelope(probe.Signed, envelope.VerifyOptions{
		ExpectedKind: envelope.KindPublishRequest, ExpectedSignerPubkeyB58: probe.Signer,
		ExpectedDestination: &probe.Destination, ExpectedRequestHash: probe.ArtifactHash,
	})
	if err == nil || !strings.Contains(err.Error(), "publish nonce already consumed") {
		t.Fatalf("installer-publish-real-process-restart-replay: expected durable replay refusal, got %v", err)
	}
}

func TestInstallerPublishExactBindingAndRestartReplay(t *testing.T) {
	if path := os.Getenv("MELUSINA_INSTALLER_RESTART_PROBE"); path != "" {
		checkInstallerReplayInRestartedProcess(t, path)
		return
	}
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	chain := newMockChainReader()
	bindTestInstallerReleaseEstate(t, chain, &cfg)
	pinRootStoreOperator(t, cfg, chain, op)
	artifact := []byte("exact installer binding")
	pinInstallerEntry(t, cfg, chain, artifact, "1.0.0", verify.AttestationStatusActive)
	svc := newTestService(t, cfg, chain, op)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	sign := func(class, name, method, target, storeID string) envelope.Signed {
		t.Helper()
		hash := sha256.Sum256(artifact)
		if method == http.MethodPost && target == installerpublish.Target {
			signed, err := installerpublish.Sign(pub, op.Public(), class, name, hex.EncodeToString(hash[:]),
				storeID, svc.cfg.Domain, svc.cfg.LicenseNFTMint, svc.cfg.ProgramID, 12345, 5*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			return signed
		}
		binding, err := installerpublish.Digest(class, name, hex.EncodeToString(hash[:]),
			storeID, svc.cfg.Domain, svc.cfg.LicenseNFTMint, svc.cfg.ProgramID)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := envelope.Sign(envelope.KindPublishRequest, pub, op.Public(), envelope.SignOptions{
			RequestHash: hex.EncodeToString(hash[:]), BodyHash: binding,
			Method: method, Target: target, TTL: 5 * time.Minute,
			Chain: envelope.ChainEvidence{ChainID: pub.Public().Ref.ChainID,
				ProgramID: svc.cfg.ProgramID, VerifiedSlot: 12345},
		})
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	for _, tc := range []struct {
		name, signedClass, signedName, requestClass, requestName, method, target, storeID string
	}{
		{"installer-publish-wrong-class", "shell", "sandstorm-42.tar.xz", "data", "sandstorm-42.tar.xz", http.MethodPost, installerpublish.Target, svc.cfg.StoreID},
		{"installer-publish-wrong-name", "shell", "sandstorm-42.tar.xz", "shell", "other.tar.xz", http.MethodPost, installerpublish.Target, svc.cfg.StoreID},
		{"installer-publish-wrong-target", "shell", "sandstorm-42.tar.xz", "shell", "sandstorm-42.tar.xz", http.MethodPost, "/publish/other", svc.cfg.StoreID},
		{"installer-publish-wrong-estate", "shell", "sandstorm-42.tar.xz", "shell", "sandstorm-42.tar.xz", http.MethodPost, installerpublish.Target, "other-store"},
		{"installer-publish-wrong-method", "shell", "sandstorm-42.tar.xz", "shell", "sandstorm-42.tar.xz", http.MethodPut, installerpublish.Target, svc.cfg.StoreID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signed := sign(tc.signedClass, tc.signedName, tc.method, tc.target, tc.storeID)
			response := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, signed, tc.requestClass, tc.requestName, artifact))
			if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "check=installer_binding") {
				t.Fatalf("%s: status=%d body=%s", tc.name, response.Code, response.Body.String())
			}
		})
	}
	signed := sign("shell", "sandstorm-42.tar.xz", http.MethodPost, installerpublish.Target, svc.cfg.StoreID)
	response := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, signed, "shell", "sandstorm-42.tar.xz", artifact))
	if response.Code != http.StatusOK {
		t.Fatalf("installer-publish-bound-positive: status=%d body=%s", response.Code, response.Body.String())
	}
	reopened, err := openPublishNonceLedger(filepath.Join(svc.cfg.PrivateStageDir, publishNonceLedgerDirName),
		testPublishNonceLedgerID, defaultPublishNonceLedgerOptions())
	if err != nil {
		t.Fatal(err)
	}
	restarted := restartPublishServiceForTest(svc)
	restarted.appNonces = reopened
	replay := doPublishInstaller(t, restarted, jsonInstallerPublishBody(t, signed, "shell", "sandstorm-42.tar.xz", artifact))
	if replay.Code != http.StatusUnauthorized || !strings.Contains(replay.Body.String(), "nonce_ledger") {
		t.Fatalf("installer-publish-restart-replay: status=%d body=%s", replay.Code, replay.Body.String())
	}
	artifactDigest := sha256.Sum256(artifact)
	probe := installerRestartProbe{
		LedgerRoot: filepath.Join(svc.cfg.PrivateStageDir, publishNonceLedgerDirName),
		Signed:     signed, Signer: pub.Public().SignPubkeyB58, Destination: op.Public(),
		ArtifactHash: hex.EncodeToString(artifactDigest[:]),
	}
	probePath := filepath.Join(t.TempDir(), "installer-restart-probe.json")
	raw, err := json.Marshal(probe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(probePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInstallerPublishExactBindingAndRestartReplay$", "-test.v")
	cmd.Env = append(os.Environ(), "MELUSINA_INSTALLER_RESTART_PROBE="+probePath)
	output, err := cmd.CombinedOutput()
	if err != nil || ctx.Err() != nil || !strings.Contains(string(output), "PASS: TestInstallerPublishExactBindingAndRestartReplay") {
		t.Fatalf("installer-publish-real-process-restart-replay: %v, context=%v, child=%s", err, ctx.Err(), output)
	}
}
