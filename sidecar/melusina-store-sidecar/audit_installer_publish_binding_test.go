package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// The real signed publisher and installer handler form the positive path.
// The second call identifies the missing class binding and process-local nonce.
func TestAuditInstallerPublishBindingAndRestartNonce(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	op := newTestIdentity(t, "audit-store-operator", cfg.LicenseNFTMint, cfg.Domain)
	chain := newMockChainReader()
	bindTestInstallerReleaseEstate(t, chain, &cfg)
	pinRootStoreOperator(t, cfg, chain, op)
	artifact := []byte("audit release bytes for binding check")
	pinInstallerEntry(t, cfg, chain, artifact, "1.0.0", verify.AttestationStatusActive)
	pub := newTestIdentity(t, "audit-installer-publisher", randPubkeyB58(t), "publisher.example.org")
	svc := newTestService(t, cfg, chain, op)
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	signed := signInstallerPublish(t, pub, op.Public(), artifact)

	first := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, signed, "shell", "audit-shell.tar.xz", artifact))
	if first.Code != http.StatusOK {
		t.Fatalf("production publisher to installer handler = %d: %s", first.Code, first.Body.String())
	}
	if _, err := os.Stat(filepath.Join(cfg.DistDir, "releases", "shell", "audit-shell.tar.xz")); err != nil {
		t.Fatalf("signed shell artifact not written: %v", err)
	}
	sameProcess := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, signed, "sidecar", "audit-sidecar.bin", artifact))
	if sameProcess.Code != http.StatusUnauthorized || !strings.Contains(sameProcess.Body.String(), "nonce replay") {
		t.Fatalf("same-process nonce should refuse by name, got %d: %s", sameProcess.Code, sameProcess.Body.String())
	}
	// A restarted public service reconstructs only its memory nonce cache; the
	// release directory, chain reader and accepted-publisher policy are held.
	restarted := &publishService{
		cfg: svc.cfg, cr: chain, operator: op, nonces: envelope.NewMemoryNonceCache(),
	}
	otherClass := doPublishInstaller(t, restarted, jsonInstallerPublishBody(t, signed, "sidecar", "audit-sidecar.bin", artifact))
	if otherClass.Code != http.StatusOK {
		t.Fatalf("same signed envelope after nonce reset across class = %d: %s", otherClass.Code, otherClass.Body.String())
	}
	if _, err := os.Stat(filepath.Join(cfg.DistDir, "releases", "sidecar", "audit-sidecar.bin")); err != nil {
		t.Fatalf("cross-class artifact not written: %v", err)
	}
	otherName := &publishService{
		cfg: svc.cfg, cr: chain, operator: op, nonces: envelope.NewMemoryNonceCache(),
	}
	renamed := doPublishInstaller(t, otherName, jsonInstallerPublishBody(t, signed, "shell", "renamed-shell.tar.xz", artifact))
	if renamed.Code != http.StatusOK {
		t.Fatalf("same signed envelope after nonce reset across name = %d: %s", renamed.Code, renamed.Body.String())
	}
}

func TestAuditRenderedAppPublishSwitch(t *testing.T) {
	_, profilePath, inputPath, outputPath, input := newStoreConfigRenderFixture(t)
	writeStoreConfigRenderInput(t, inputPath, input)
	if _, err := renderEstateStoreConfig(estateStoreConfigRenderOptions{
		profilePath: profilePath, inputPath: inputPath, outputPath: outputPath,
	}); err != nil {
		t.Fatalf("signed profile config render: %v", err)
	}
	cfg, err := LoadConfig(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policy.RequirePearlControlForAppPublish {
		t.Fatal("rendered config unexpectedly retires direct app publishing")
	}
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	request := httptest.NewRequest(http.MethodPost, "/publish", nil)
	response := httptest.NewRecorder()
	newRouter(cfg, nil, nil, nil).ServeHTTP(response, request)
	if response.Code == http.StatusGone {
		t.Fatalf("direct app publish route retired despite rendered switch: %s", response.Body.String())
	}
}

func TestAuditScanReportPolicyGate(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.Policy.RequireScanReport = true
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "scan-policy-store-operator", cfg.LicenseNFTMint, cfg.Domain)
	master := randPubkeyB58(t)
	fixture := buildValidFixture(t, cfg, master)
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "scan-policy-repo", "scan-policy-app", fixture.metadata)
	chain := newMockChainReader()
	fixture.pinAccept(chain, operatorSignPub32(t, op))
	svc := newTestService(t, cfg, chain, op)
	pub := newTestIdentity(t, "scan-policy-publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	release := mustJSON(t, fixture.rel)
	stageSig := signPublishForRoute(t, pub, op.Public(), fixture.spk, release,
		"/publish/stage", time.Now().UTC(), 5*time.Minute, "")
	stage := doStagePublish(t, svc, jsonPublishBody(t, stageSig, release, fixture.spk, fixture.metadata))
	if stage.Code != http.StatusOK {
		t.Fatalf("scan-report policy stage = %d: %s", stage.Code, stage.Body.String())
	}
	publishSig := signPublish(t, pub, op.Public(), fixture.spk, release)
	published := doPublish(t, svc, jsonPublishBody(t, publishSig, release, fixture.spk, fixture.metadata))
	if published.Code != http.StatusOK {
		t.Fatalf("scan-report policy publish = %d: %s", published.Code, published.Body.String())
	}
}
