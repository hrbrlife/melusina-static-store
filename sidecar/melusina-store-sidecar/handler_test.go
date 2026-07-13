package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

var enc = base64.StdEncoding

// stubAssembler gives each handler test an isolated in-process read surface.
func stubAssembler(t *testing.T) *CatalogAssembler {
	t.Helper()
	return &CatalogAssembler{DistDir: t.TempDir()}
}

// newTestService builds a publishService with the given mock reader + operator
// and a stub assembler.
func newTestService(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private) *publishService {
	t.Helper()
	if cfg.PrivateStageDir == "" {
		cfg.PrivateStageDir = t.TempDir()
	}
	if err := os.Chmod(cfg.PrivateStageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if cfg.DistDir == "" {
		cfg.DistDir = t.TempDir()
	}
	if err := os.Mkdir(filepath.Join(cfg.PrivateStageDir, "rollouts"), 0o700); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(cfg.DistDir, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.DistDir, "apps", "index.json")); os.IsNotExist(err) {
		if err := os.WriteFile(filepath.Join(cfg.DistDir, "apps", "index.json"), []byte("{\"apps\":[]}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	nonceRoot := filepath.Join(cfg.PrivateStageDir, publishNonceLedgerDirName)
	if err := initializePublishNonceLedger(nonceRoot, testPublishNonceLedgerID, defaultPublishNonceLedgerOptions()); err != nil {
		t.Fatalf("initialize app nonce ledger: %v", err)
	}
	appNonces, err := openPublishNonceLedger(nonceRoot, testPublishNonceLedgerID, defaultPublishNonceLedgerOptions())
	if err != nil {
		t.Fatalf("open app nonce ledger: %v", err)
	}
	if cfg.CatalogGenerationRoot == "" {
		cfg.CatalogGenerationRoot = t.TempDir()
	}
	t.Cleanup(func() {
		_ = filepath.Walk(cfg.CatalogGenerationRoot, func(path string, info os.FileInfo, err error) error {
			if err == nil && info != nil {
				if info.IsDir() {
					_ = os.Chmod(path, 0o755)
				} else {
					_ = os.Chmod(path, 0o644)
				}
			}
			return nil
		})
	})
	generations := AppCatalogGenerationStore{Root: cfg.CatalogGenerationRoot, Barrier: &sync.RWMutex{}}
	if _, err := generations.BootstrapFromFlat(cfg.DistDir, nil); err != nil {
		t.Fatalf("bootstrap app catalog generation: %v", err)
	}
	return &publishService{
		cfg:                cfg,
		cr:                 m,
		operator:           op,
		assembler:          &CatalogAssembler{DistDir: cfg.DistDir},
		nonces:             envelope.NewMemoryNonceCache(),
		appNonces:          appNonces,
		catalogGenerations: generations,
		catalogExpectedUID: uint32(os.Getuid()),
		catalogExpectedGID: uint32(os.Getgid()),
	}
}

// signPublish builds a valid signed artifact envelope from the publisher,
// addressed to the operator, binding RequestHash=sha256(spk) and Body=release.
func signPublish(t *testing.T, publisher *identity.Private, operatorPub identity.Public, spk, release []byte) envelope.Signed {
	return signPublishForRoute(t, publisher, operatorPub, spk, release, "/publish", time.Now().UTC(), 5*time.Minute, "")
}

func signPublishForRoute(t *testing.T, publisher *identity.Private, operatorPub identity.Public, spk, release []byte, route string, now time.Time, ttl time.Duration, nonce string) envelope.Signed {
	t.Helper()
	spkSum := sha256.Sum256(spk)
	sig, err := envelope.Sign(envelope.KindArtifact, publisher, operatorPub, envelope.SignOptions{
		Body:        release,
		RequestHash: hex.EncodeToString(spkSum[:]),
		Method:      http.MethodPost,
		Target:      route,
		Now:         now,
		TTL:         ttl,
		Nonce:       nonce,
		Chain: envelope.ChainEvidence{
			ChainID:      "solana:devnet",
			ProgramID:    "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
			VerifiedSlot: 12345,
		},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sig
}

func signInstallerPublish(t *testing.T, publisher *identity.Private, operatorPub identity.Public, artifact []byte) envelope.Signed {
	t.Helper()
	artifactSum := sha256.Sum256(artifact)
	sig, err := envelope.Sign(envelope.KindArtifact, publisher, operatorPub, envelope.SignOptions{
		RequestHash: hex.EncodeToString(artifactSum[:]),
		TTL:         5 * time.Minute,
		Chain: envelope.ChainEvidence{
			ChainID:      "solana:devnet",
			ProgramID:    "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
			VerifiedSlot: 12345,
		},
	})
	if err != nil {
		t.Fatalf("Sign installer: %v", err)
	}
	return sig
}

// jsonPublishBody assembles the JSON wire form for POST /publish.
func jsonPublishBody(t *testing.T, sig envelope.Signed, release, spk, metadata []byte) *bytes.Buffer {
	t.Helper()
	req := publishRequest{
		Envelope:    sig,
		ReleaseB64:  b64(release),
		SPKB64:      b64(spk),
		MetadataB64: b64(metadata),
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewBuffer(b)
}

func b64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return enc.EncodeToString(b)
}

func doPublish(t *testing.T, svc *publishService, body *bytes.Buffer) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/publish", body)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	svc.handlePublish(w, r)
	return w
}

func doStagePublish(t *testing.T, svc *publishService, body *bytes.Buffer) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/publish/stage", body)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	svc.handleStagePublish(w, r)
	return w
}

func stageThenPromote(t *testing.T, svc *publishService, publisher *identity.Private, operator identity.Public, spk, release []byte, body func(envelope.Signed) *bytes.Buffer) *httptest.ResponseRecorder {
	t.Helper()
	stage := doStagePublish(t, svc, body(signPublishForRoute(t, publisher, operator, spk, release, "/publish/stage", time.Now().UTC(), 5*time.Minute, "")))
	if stage.Code != http.StatusOK {
		t.Fatalf("stage expected 200, got %d: %s", stage.Code, stage.Body.String())
	}
	return doPublish(t, svc, body(signPublish(t, publisher, operator, spk, release)))
}

func jsonInstallerPublishBody(t *testing.T, sig envelope.Signed, class, name string, artifact []byte) *bytes.Buffer {
	t.Helper()
	req := installerPublishRequest{
		Envelope:    sig,
		Class:       class,
		Name:        name,
		ArtifactB64: b64(artifact),
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewBuffer(b)
}

func doPublishInstaller(t *testing.T, svc *publishService, body *bytes.Buffer) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/publish/installer", body)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	svc.handlePublishInstaller(w, r)
	return w
}

func TestPublishBodyLimitsAreEndpointSpecific(t *testing.T) {
	appRequest := httptest.NewRequest(http.MethodPost, "/publish", http.NoBody)
	appRequest.Header.Set("Content-Type", "application/json")
	appRequest.ContentLength = maxAppPublishBody + 1
	if _, _, _, _, _, err := parsePublishBody(appRequest); err == nil ||
		!strings.Contains(err.Error(), "limit is") {
		t.Fatalf("app publish did not reject a body above its limit: %v", err)
	}

	installerRequest := httptest.NewRequest(http.MethodPost, "/publish/installer", http.NoBody)
	installerRequest.Header.Set("Content-Type", "application/json")
	installerRequest.ContentLength = maxAppPublishBody + 1
	if _, _, _, _, err := parseInstallerPublishBody(installerRequest); err == nil ||
		strings.Contains(err.Error(), "limit is") {
		t.Fatalf("installer endpoint incorrectly reused the app limit: %v", err)
	}

	oversizedInstaller := httptest.NewRequest(http.MethodPost, "/publish/installer", http.NoBody)
	oversizedInstaller.Header.Set("Content-Type", "application/json")
	oversizedInstaller.ContentLength = maxInstallerPublishBody + 1
	if _, _, _, _, err := parseInstallerPublishBody(oversizedInstaller); err == nil ||
		!strings.Contains(err.Error(), "limit is") {
		t.Fatalf("installer publish did not reject a body above its limit: %v", err)
	}
}

func pinRootStoreOperator(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private) {
	t.Helper()
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	f.pinAccept(m, operatorPub)
	authz := m.storeAuthz[f.authzPDA]
	authz.isRoot = true
	m.storeAuthz[f.authzPDA] = authz
}

func TestHandlePublish_Accept(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)

	f := buildValidFixture(t, cfg, master)
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	stageSig := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", time.Now().UTC(), 5*time.Minute, "")
	stage := doStagePublish(t, svc, jsonPublishBody(t, stageSig, release, f.spk, f.metadata))
	if stage.Code != http.StatusOK {
		t.Fatalf("stage expected 200, got %d: %s", stage.Code, stage.Body.String())
	}
	var stageReceipt StageReceipt
	if err := json.Unmarshal(stage.Body.Bytes(), &stageReceipt); err != nil {
		t.Fatalf("decode stage receipt: %v", err)
	}
	operatorKey, err := op.Public().SignPublicKey()
	if err != nil {
		t.Fatalf("operator public key: %v", err)
	}
	if err := verifyStageReceipt(ed25519.PublicKey(operatorKey), stageReceipt); err != nil {
		t.Fatalf("verify stage receipt: %v", err)
	}

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var rc Receipt
	if err := json.Unmarshal(w.Body.Bytes(), &rc); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if rc.AppHash != strings.ToLower(f.rel.AppHash) {
		t.Errorf("receipt appHash %s != %s", rc.AppHash, f.rel.AppHash)
	}
	if rc.OperatorSignature == "" {
		t.Error("receipt missing operator signature")
	}
	if rc.Catalog == nil || rc.Catalog.AppID != metadataAppID(f.metadata) || rc.Catalog.PackageID != metadataPackageID(f.metadata) {
		t.Fatalf("receipt missing exact signed catalog pointer: %+v", rc.Catalog)
	}
	if err := verifyAppCatalogPointer(ed25519.PublicKey(operatorKey), *rc.Catalog); err != nil {
		t.Fatalf("verify catalog pointer: %v", err)
	}
}

func TestAppPublishPurposeRefusalDoesNotConsumeAcrossRoutes(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)
	clock := time.Now().UTC().Add(time.Second)
	svc.now = func() time.Time { return clock }
	pub := newTestIdentity(t, "purpose-publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	release := mustJSON(t, f.rel)

	stageEnvelope := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", clock, 5*time.Minute, "purpose-stage")
	wrongPromote := doPublish(t, svc, jsonPublishBody(t, stageEnvelope, release, f.spk, f.metadata))
	if wrongPromote.Code != http.StatusUnauthorized || !strings.Contains(wrongPromote.Body.String(), "check=envelope_purpose") {
		t.Fatalf("stage envelope on promote route = %d %s", wrongPromote.Code, wrongPromote.Body.String())
	}
	stage := doStagePublish(t, svc, jsonPublishBody(t, stageEnvelope, release, f.spk, f.metadata))
	if stage.Code != http.StatusOK {
		t.Fatalf("wrong-route refusal consumed stage envelope: %d %s", stage.Code, stage.Body.String())
	}

	promoteEnvelope := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish", clock, 5*time.Minute, "purpose-promote")
	wrongStage := doStagePublish(t, svc, jsonPublishBody(t, promoteEnvelope, release, f.spk, f.metadata))
	if wrongStage.Code != http.StatusUnauthorized || !strings.Contains(wrongStage.Body.String(), "check=envelope_purpose") {
		t.Fatalf("promote envelope on stage route = %d %s", wrongStage.Code, wrongStage.Body.String())
	}
	promote := doPublish(t, svc, jsonPublishBody(t, promoteEnvelope, release, f.spk, f.metadata))
	if promote.Code != http.StatusOK {
		t.Fatalf("wrong-route refusal consumed promote envelope: %d %s", promote.Code, promote.Body.String())
	}

	// Re-open the durable ledger as a restarted service. Both route nonces stay
	// consumed across the process boundary even though installer replay state is
	// intentionally a separate in-memory cache.
	opts := defaultPublishNonceLedgerOptions()
	opts.Now = func() time.Time { return clock }
	reopened, err := openPublishNonceLedger(filepath.Join(svc.cfg.PrivateStageDir, publishNonceLedgerDirName), testPublishNonceLedgerID, opts)
	if err != nil {
		t.Fatalf("reopen app nonce ledger: %v", err)
	}
	restarted := &publishService{
		cfg:                svc.cfg,
		cr:                 svc.cr,
		operator:           svc.operator,
		assembler:          svc.assembler,
		nonces:             envelope.NewMemoryNonceCache(),
		appNonces:          reopened,
		catalogGenerations: svc.catalogGenerations,
		now:                svc.now,
	}
	stageReplay := doStagePublish(t, restarted, jsonPublishBody(t, stageEnvelope, release, f.spk, f.metadata))
	if stageReplay.Code != http.StatusUnauthorized || !strings.Contains(stageReplay.Body.String(), "nonce already consumed") {
		t.Fatalf("stage replay after restart = %d %s", stageReplay.Code, stageReplay.Body.String())
	}
	promoteReplay := doPublish(t, restarted, jsonPublishBody(t, promoteEnvelope, release, f.spk, f.metadata))
	if promoteReplay.Code != http.StatusUnauthorized || !strings.Contains(promoteReplay.Body.String(), "nonce already consumed") {
		t.Fatalf("promote replay after restart = %d %s", promoteReplay.Code, promoteReplay.Body.String())
	}
}

func TestAppPublishEveryPostClaimBoundaryIsRetryableWithFreshEnvelope(t *testing.T) {
	for _, step := range []string{
		"after-source-persist",
		"after-generation-commit",
		"after-rollout-commit",
		"after-current-switch",
	} {
		t.Run(step, func(t *testing.T) {
			cfg, _ := testConfig(t)
			cfg.CatalogRepoRoot = t.TempDir()
			op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
			fixture := buildValidFixture(t, cfg, randPubkeyB58(t))
			seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "fault-retry", "app", fixture.metadata)
			chain := newMockChainReader()
			fixture.pinAccept(chain, operatorSignPub32(t, op))
			svc := newTestService(t, cfg, chain, op)
			publisher := newTestIdentity(t, "fault-retry-publisher", randPubkeyB58(t), "publisher.example.org")
			svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
			release := mustJSON(t, fixture.rel)
			now := time.Now().UTC().Add(time.Second)
			svc.now = func() time.Time { return now }

			stageEnvelope := signPublishForRoute(t, publisher, op.Public(), fixture.spk, release, "/publish/stage", now, 5*time.Minute, "fault-stage-"+step)
			stage := doStagePublish(t, svc, jsonPublishBody(t, stageEnvelope, release, fixture.spk, fixture.metadata))
			if stage.Code != http.StatusOK {
				t.Fatalf("stage = %d: %s", stage.Code, stage.Body.String())
			}
			fired := false
			svc.afterAppMutation = func(got string) error {
				if got == step && !fired {
					fired = true
					return errors.New("injected post-claim exit")
				}
				return nil
			}
			firstEnvelope := signPublishForRoute(t, publisher, op.Public(), fixture.spk, release, "/publish", now, 5*time.Minute, "fault-first-"+step)
			first := doPublish(t, svc, jsonPublishBody(t, firstEnvelope, release, fixture.spk, fixture.metadata))
			if first.Code != http.StatusInternalServerError || !fired {
				t.Fatalf("faulted promote = %d fired=%v: %s", first.Code, fired, first.Body.String())
			}

			// Simulate a real process exit: discard the service and its mutex/cache,
			// reopen the durable ledger, run the same cold recovery selection used
			// before listener startup, and construct a fresh service instance.
			ledgerOpts := defaultPublishNonceLedgerOptions()
			ledgerOpts.Now = func() time.Time { return now }
			reopened, err := openPublishNonceLedger(filepath.Join(svc.cfg.PrivateStageDir, publishNonceLedgerDirName), testPublishNonceLedgerID, ledgerOpts)
			if err != nil {
				t.Fatalf("restart ledger: %v", err)
			}
			rollouts, err := exactRolloutStates(svc.cfg)
			if err != nil {
				t.Fatalf("restart rollout validation: %v", err)
			}
			operatorKey, err := op.Public().SignPublicKey()
			if err != nil {
				t.Fatal(err)
			}
			domainHash := primitives.StoreDomainHash(svc.cfg.Domain)
			if _, err := svc.catalogGenerations.RecoverCurrent(rollouts, ed25519.PublicKey(operatorKey), hex.EncodeToString(domainHash[:]), svc.cfg.PrivateStageDir, uint32(os.Getuid()), uint32(os.Getgid())); err != nil {
				t.Fatalf("restart generation recovery: %v", err)
			}
			restarted := &publishService{
				cfg:                svc.cfg,
				cr:                 chain,
				operator:           op,
				assembler:          NewCatalogAssembler(svc.cfg.CatalogRepoRoot, svc.cfg.DistDir),
				nonces:             envelope.NewMemoryNonceCache(),
				appNonces:          reopened,
				catalogGenerations: svc.catalogGenerations,
				catalogExpectedUID: uint32(os.Getuid()),
				catalogExpectedGID: uint32(os.Getgid()),
				now:                func() time.Time { return now },
			}
			retryEnvelope := signPublishForRoute(t, publisher, op.Public(), fixture.spk, release, "/publish", now, 5*time.Minute, "fault-retry-"+step)
			retry := doPublish(t, restarted, jsonPublishBody(t, retryEnvelope, release, fixture.spk, fixture.metadata))
			if retry.Code != http.StatusOK {
				t.Fatalf("fresh-envelope retry = %d: %s", retry.Code, retry.Body.String())
			}
		})
	}
}

func TestAppPublishRunsPostSuccessRetention(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "retention-store-operator", cfg.LicenseNFTMint, cfg.Domain)
	fixture := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "retention", "app", fixture.metadata)
	chain := newMockChainReader()
	fixture.pinAccept(chain, operatorSignPub32(t, op))
	svc := newTestService(t, cfg, chain, op)
	publisher := newTestIdentity(t, "retention-publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	now := time.Now().UTC().Add(time.Second)
	svc.now = func() time.Time { return now }
	old := persistRetentionStage(t, svc.cfg.PrivateStageDir, "unreferenced-old", now.Add(-8*24*time.Hour))
	release := mustJSON(t, fixture.rel)
	stageEnvelope := signPublishForRoute(t, publisher, op.Public(), fixture.spk, release, "/publish/stage", now, 5*time.Minute, "retention-stage")
	if got := doStagePublish(t, svc, jsonPublishBody(t, stageEnvelope, release, fixture.spk, fixture.metadata)); got.Code != http.StatusOK {
		t.Fatalf("stage = %d: %s", got.Code, got.Body.String())
	}
	promoteEnvelope := signPublishForRoute(t, publisher, op.Public(), fixture.spk, release, "/publish", now, 5*time.Minute, "retention-promote")
	if got := doPublish(t, svc, jsonPublishBody(t, promoteEnvelope, release, fixture.spk, fixture.metadata)); got.Code != http.StatusOK {
		t.Fatalf("promote = %d: %s", got.Code, got.Body.String())
	}
	if _, err := os.Stat(filepath.Join(svc.cfg.PrivateStageDir, old.StageID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-success retention did not delete old unreferenced stage: %v", err)
	}
}

func TestAppPublishTightExpiryExactAndPlusOneMillisecond(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)
	pub := newTestIdentity(t, "expiry-publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	release := mustJSON(t, f.rel)
	signedAt := time.Now().UTC().Add(time.Second).Truncate(time.Millisecond)
	expiresAt := signedAt.Add(time.Second)
	clock := expiresAt
	svc.now = func() time.Time { return clock }

	exact := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", signedAt, time.Second, "expiry-exact")
	accepted := doStagePublish(t, svc, jsonPublishBody(t, exact, release, f.spk, f.metadata))
	if accepted.Code != http.StatusOK {
		t.Fatalf("exact raw expiry must be accepted: %d %s", accepted.Code, accepted.Body.String())
	}
	clock = expiresAt.Add(time.Millisecond)
	after := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", signedAt, time.Second, "expiry-after")
	refused := doStagePublish(t, svc, jsonPublishBody(t, after, release, f.spk, f.metadata))
	if refused.Code != http.StatusUnauthorized || !strings.Contains(refused.Body.String(), "check=envelope_expiry") {
		t.Fatalf("raw expiry +1ms must refuse: %d %s", refused.Code, refused.Body.String())
	}
}

func TestAppPublishPDAOnlyAllowlistRefusesWithoutNonceAllocation(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)
	pub := newTestIdentity(t, "unlisted-publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{f.rel.ReleaseEntryPda}
	release := mustJSON(t, f.rel)
	sig := signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", time.Now().UTC(), 5*time.Minute, "pda-only")

	refused := doStagePublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
	if refused.Code != http.StatusForbidden || !strings.Contains(refused.Body.String(), "check=accept_publishers") {
		t.Fatalf("PDA-only allowlist = %d %s", refused.Code, refused.Body.String())
	}
	entries, err := os.ReadDir(filepath.Join(svc.cfg.PrivateStageDir, publishNonceLedgerDirName, publishNonceClaimsDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("PDA-only refusal allocated %d durable nonce markers", len(entries))
	}
}

func TestHandlePublish_RequiresPrivateStage(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	release := mustJSON(t, f.rel)

	w := doPublish(t, svc, jsonPublishBody(t, signPublish(t, pub, op.Public(), f.spk, release), release, f.spk, f.metadata))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "check=stage") {
		t.Fatalf("expected unstaged promotion to fail 409 at stage gate, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlePublish_AllowsOlderActiveReleaseDuringRollout(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	f.rel.Version = "2.0.0"
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: f.appHashBytes, appID: f.appID, version: f.rel.Version, status: verify.AttestationStatusActive, registeredAt: f.rel.SignedAtUnix}
	pinOtherActiveRelease(t, m, &f, "1.0.0")
	svc := newTestService(t, cfg, m, op)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}
	release := mustJSON(t, f.rel)

	stage := doStagePublish(t, svc, jsonPublishBody(t, signPublishForRoute(t, pub, op.Public(), f.spk, release, "/publish/stage", time.Now().UTC(), 5*time.Minute, ""), release, f.spk, f.metadata))
	if stage.Code != http.StatusOK {
		t.Fatalf("stage expected 200, got %d: %s", stage.Code, stage.Body.String())
	}
	promote := doPublish(t, svc, jsonPublishBody(t, signPublish(t, pub, op.Public(), f.spk, release), release, f.spk, f.metadata))
	if promote.Code != http.StatusOK {
		t.Fatalf("overlap promotion expected 200, got %d: %s", promote.Code, promote.Body.String())
	}
}

func TestHandlePublish_PromotesFinalizedReleaseFromProvisionalStage(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	writeServedReleaseClaim(t, cfg.DistDir, metadataAppID(f.metadata), f.rel.SignedAtUnix-1000)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}

	provisional := f.rel
	provisional.SignedAtUnix = 0
	provisional.ReleaseEntryPda = ""
	provisional.AuthorSig = ""
	provisional.QuorumPolicy = QuorumPolicy{}
	provisionalBytes := mustJSON(t, provisional)
	stage := doStagePublish(t, svc, jsonPublishBody(t,
		signPublishForRoute(t, pub, op.Public(), f.spk, provisionalBytes, "/publish/stage", time.Now().UTC(), 5*time.Minute, ""), provisionalBytes, f.spk, f.metadata))
	if stage.Code != http.StatusOK {
		t.Fatalf("provisional stage expected 200, got %d: %s", stage.Code, stage.Body.String())
	}

	finalBytes := mustJSON(t, f.rel)
	promote := doPublish(t, svc, jsonPublishBody(t,
		signPublish(t, pub, op.Public(), f.spk, finalBytes), finalBytes, f.spk, f.metadata))
	if promote.Code != http.StatusOK {
		t.Fatalf("finalized promotion expected 200, got %d: %s", promote.Code, promote.Body.String())
	}
}

func TestHandlePublishInstaller_Accept(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	m := newMockChainReader()
	pinRootStoreOperator(t, cfg, m, op)

	artifact := []byte("prebuilt sandstorm release bytes")
	hash := sha256.Sum256(artifact)
	pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
	m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, version: "1.0.0", status: verify.AttestationStatusActive}
	svc := newTestService(t, cfg, m, op)
	pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signInstallerPublish(t, pub, op.Public(), artifact)
	svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}

	w := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, sig, "shell", "sandstorm-42.tar.xz", artifact))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(cfg.DistDir, "releases", "shell", "sandstorm-42.tar.xz"))
	if err != nil {
		t.Fatalf("artifact not written: %v", err)
	}
	if !bytes.Equal(got, artifact) {
		t.Fatalf("written artifact bytes changed")
	}
	if !strings.Contains(w.Body.String(), hex.EncodeToString(hash[:])) {
		t.Fatalf("response does not include installer hash: %s", w.Body.String())
	}
}

func TestHandlePublishInstaller_Rejects(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte)
		class    string
		fileName string
		wantCode int
		wantBody string
	}{
		{
			name: "installer_release_missing",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				pinRootStoreOperator(t, cfg, m, op)
			},
			class:    "shell",
			fileName: "sandstorm-42.tar.xz",
			wantCode: http.StatusForbidden,
			wantBody: "check=installer_release",
		},
		{
			name: "installer_release_revoked",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				pinRootStoreOperator(t, cfg, m, op)
				hash := sha256.Sum256(artifact)
				pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
				m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, version: "1.0.0", status: verify.AttestationStatusRevoked}
			},
			class:    "shell",
			fileName: "sandstorm-42.tar.xz",
			wantCode: http.StatusForbidden,
			wantBody: "check=installer_release",
		},
		{
			name: "installer_release_superseded",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				pinRootStoreOperator(t, cfg, m, op)
				hash := sha256.Sum256(artifact)
				pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
				m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, version: "1.0.0", status: verify.AttestationStatusSuperseded}
			},
			class:    "shell",
			fileName: "sandstorm-42.tar.xz",
			wantCode: http.StatusForbidden,
			wantBody: "check=installer_release",
		},
		{
			name: "installer_hash_mismatch",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				pinRootStoreOperator(t, cfg, m, op)
				hash := sha256.Sum256(artifact)
				pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
				otherHash := sha256.Sum256([]byte("different installer bytes"))
				m.installerEntry[pda] = mockInstallerEntry{installerHash: otherHash, version: "1.0.0", status: verify.AttestationStatusActive}
			},
			class:    "shell",
			fileName: "sandstorm-42.tar.xz",
			wantCode: http.StatusForbidden,
			wantBody: "check=installer_release",
		},
		{
			name: "non_root_store_operator",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				operatorPub := operatorSignPub32(t, op)
				f := buildValidFixture(t, cfg, randPubkeyB58(t))
				f.pinAccept(m, operatorPub) // isRoot=false
				hash := sha256.Sum256(artifact)
				pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
				m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, version: "1.0.0", status: verify.AttestationStatusActive}
			},
			class:    "sidecar",
			fileName: "store-sidecar",
			wantCode: http.StatusForbidden,
			wantBody: "is_root=false",
		},
		{
			name: "invalid_path_segment",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				pinRootStoreOperator(t, cfg, m, op)
			},
			class:    "shell",
			fileName: "nested/artifact",
			wantCode: http.StatusBadRequest,
			wantBody: "name must be a single safe path segment",
		},
		{
			name: "missing_master_mint_config",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) {
				pinRootStoreOperator(t, cfg, m, op)
			},
			class:    "shell",
			fileName: "sandstorm-42.tar.xz",
			wantCode: http.StatusServiceUnavailable,
			wantBody: "release_master_nft_mint is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := testConfig(t)
			cfg.DistDir = t.TempDir()
			cfg.ReleaseMasterNftMint = randPubkeyB58(t)
			if tc.name == "missing_master_mint_config" {
				cfg.ReleaseMasterNftMint = ""
			}
			op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
			m := newMockChainReader()
			artifact := []byte("installer artifact " + tc.name)
			tc.setup(t, cfg, m, op, artifact)
			svc := newTestService(t, cfg, m, op)
			pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
			sig := signInstallerPublish(t, pub, op.Public(), artifact)
			svc.cfg.Policy.AcceptPublishers = []string{pub.Public().SignPubkeyB58}

			w := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, sig, tc.class, tc.fileName, artifact))
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("body %q does not name %q", w.Body.String(), tc.wantBody)
			}
			if _, err := os.Stat(filepath.Join(cfg.DistDir, "releases", tc.class, tc.fileName)); err == nil {
				t.Fatalf("rejected installer artifact was written")
			}
		})
	}
}

func TestHandlePublishInstaller_AuthorAndVersionMatrix(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed
		wantCode   int
		wantBody   string
		wantNoFile bool
	}{
		{
			name: "no_envelope",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "1.0.0", verify.AttestationStatusActive)
				return envelope.Signed{}
			},
			wantCode:   http.StatusUnauthorized,
			wantBody:   "check=envelope",
			wantNoFile: true,
		},
		{
			name: "bad_envelope_signature",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "1.0.0", verify.AttestationStatusActive)
				pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
				sig := signInstallerPublish(t, pub, op.Public(), artifact)
				sig.SignatureB58 = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
				return sig
			},
			wantCode:   http.StatusUnauthorized,
			wantBody:   "check=envelope",
			wantNoFile: true,
		},
		{
			name: "publisher_not_allowed",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "1.0.0", verify.AttestationStatusActive)
				pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
				return signInstallerPublish(t, pub, op.Public(), artifact)
			},
			wantCode:   http.StatusForbidden,
			wantBody:   "check=accept_publishers",
			wantNoFile: true,
		},
		{
			name: "current_version_equal",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "1.0.0", verify.AttestationStatusActive)
				old := []byte("old installer artifact")
				writeCurrentInstaller(t, cfg, "shell", "sandstorm-42.tar.xz", old)
				pinInstallerEntry(t, cfg, m, old, "1.0.0", verify.AttestationStatusActive)
				pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
				return signInstallerPublish(t, pub, op.Public(), artifact)
			},
			wantCode: http.StatusConflict,
			wantBody: "check=installer_version",
		},
		{
			name: "current_version_lower",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "1.0.0", verify.AttestationStatusActive)
				old := []byte("old installer artifact")
				writeCurrentInstaller(t, cfg, "shell", "sandstorm-42.tar.xz", old)
				pinInstallerEntry(t, cfg, m, old, "2.0.0", verify.AttestationStatusActive)
				pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
				return signInstallerPublish(t, pub, op.Public(), artifact)
			},
			wantCode: http.StatusConflict,
			wantBody: "check=installer_version",
		},
		{
			name: "current_active_not_superseded",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "2.0.0", verify.AttestationStatusActive)
				old := []byte("old installer artifact")
				writeCurrentInstaller(t, cfg, "shell", "sandstorm-42.tar.xz", old)
				pinInstallerEntry(t, cfg, m, old, "1.0.0", verify.AttestationStatusActive)
				pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
				return signInstallerPublish(t, pub, op.Public(), artifact)
			},
			wantCode: http.StatusConflict,
			wantBody: "check=installer_supersede",
		},
		{
			name: "version_bumped_signed_witnessed",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, artifact []byte) envelope.Signed {
				pinRootStoreOperator(t, cfg, m, op)
				pinInstallerEntry(t, cfg, m, artifact, "2.0.0", verify.AttestationStatusActive)
				old := []byte("old installer artifact")
				writeCurrentInstaller(t, cfg, "shell", "sandstorm-42.tar.xz", old)
				pinInstallerEntry(t, cfg, m, old, "1.0.0", verify.AttestationStatusSuperseded)
				pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
				return signInstallerPublish(t, pub, op.Public(), artifact)
			},
			wantCode: http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := testConfig(t)
			cfg.DistDir = t.TempDir()
			cfg.ReleaseMasterNftMint = randPubkeyB58(t)
			op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
			m := newMockChainReader()
			artifact := []byte("new installer artifact " + tc.name)
			sig := tc.setup(t, cfg, m, op, artifact)
			svc := newTestService(t, cfg, m, op)
			if tc.name == "publisher_not_allowed" {
				svc.cfg.Policy.AcceptPublishers = []string{"not-the-publisher"}
			} else if sig.Payload.Source.SignPubkeyB58 != "" {
				svc.cfg.Policy.AcceptPublishers = []string{sig.Payload.Source.SignPubkeyB58}
			}

			w := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, sig, "shell", "sandstorm-42.tar.xz", artifact))
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			if tc.wantBody != "" && !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("body %q does not name %q", w.Body.String(), tc.wantBody)
			}
			got, err := os.ReadFile(filepath.Join(cfg.DistDir, "releases", "shell", "sandstorm-42.tar.xz"))
			if tc.wantCode == http.StatusOK {
				if err != nil {
					t.Fatalf("expected artifact written: %v", err)
				}
				if !bytes.Equal(got, artifact) {
					t.Fatalf("written artifact mismatch")
				}
				return
			}
			if tc.wantNoFile {
				if err == nil {
					t.Fatalf("rejected installer artifact was written")
				}
			} else if err == nil && bytes.Equal(got, artifact) {
				t.Fatalf("rejected installer artifact replaced current file")
			}
		})
	}
}

func pinInstallerEntry(t *testing.T, cfg Config, m *mockChainReader, artifact []byte, version string, status verify.AttestationStatus) string {
	t.Helper()
	hash := sha256.Sum256(artifact)
	pda := installerReleasePDA(t, cfg.ReleaseMasterNftMint, hash)
	m.installerEntry[pda] = mockInstallerEntry{installerHash: hash, version: version, status: status}
	return pda
}

func writeCurrentInstaller(t *testing.T, cfg Config, class, name string, artifact []byte) {
	t.Helper()
	dir := filepath.Join(cfg.DistDir, "releases", class)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), artifact, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHandlePublishInstaller_NoOperatorFailsClosed(t *testing.T) {
	cfg, _ := testConfig(t)
	svc := &publishService{cfg: cfg, cr: nil, operator: nil, assembler: stubAssembler(t), nonces: envelope.NewMemoryNonceCache()}
	w := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, envelope.Signed{}, "shell", "sandstorm-42.tar.xz", []byte("artifact")))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlePublish_Rejects(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) (release, spk []byte, sig envelope.Signed)
		wantCode int
		wantBody string
	}{
		{
			name: "no_envelope",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				release := mustJSON(t, f.rel)
				return release, f.spk, envelope.Signed{}
			},
			wantCode: http.StatusUnauthorized,
			wantBody: "check=envelope",
		},
		{
			name: "apphash_mismatch",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				// Tamper the SPK AFTER signing so the envelope RequestHash binds the
				// tampered bytes (envelope passes) but the recomputed tree-hash !=
				// appHash.
				release := mustJSON(t, f.rel)
				tampered := append(append([]byte{}, f.spk...), 0x00)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				sig := signPublish(t, pub, op.Public(), tampered, release)
				return release, tampered, sig
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=app_hash",
		},
		{
			name: "release_entry_missing",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				delete(m.releaseEntry, f.relPDA)
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "release_entry_revoked",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: f.appHashBytes, appID: f.appID, version: "1.0.0", status: verify.AttestationStatusRevoked}
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "release_entry_superseded",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: f.appHashBytes, appID: f.appID, version: "1.0.0", status: verify.AttestationStatusSuperseded}
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "release_entry_hash_mismatch",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				otherHash := sha256.Sum256([]byte("different app bytes"))
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: otherHash, appID: f.appID, version: "1.0.0", status: verify.AttestationStatusActive}
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=release_entry",
		},
		{
			name: "version_equal_to_active",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				pinOtherActiveRelease(t, m, f, "1.0.0")
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusConflict,
			wantBody: "check=release_version",
		},
		{
			name: "version_lower_than_active",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				pinOtherActiveRelease(t, m, f, "2.0.0")
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusConflict,
			wantBody: "check=release_version",
		},
		{
			name: "blacklisted",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				m.blacklist[f.blAppPDA] = mockBlacklist{present: true, entryType: 1}
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				return release, f.spk, signPublish(t, pub, op.Public(), f.spk, release)
			},
			wantCode: http.StatusForbidden,
			wantBody: "check=blacklist",
		},
		{
			name: "bad_envelope_signature",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				sig := signPublish(t, pub, op.Public(), f.spk, release)
				sig.SignatureB58 = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111" // corrupt
				return release, f.spk, sig
			},
			wantCode: http.StatusUnauthorized,
			wantBody: "check=envelope",
		},
		{
			name: "request_hash_not_spk",
			setup: func(t *testing.T, cfg Config, m *mockChainReader, op *identity.Private, f *publishFixture, opPub [32]byte) ([]byte, []byte, envelope.Signed) {
				release := mustJSON(t, f.rel)
				pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
				// Sign binding a DIFFERENT spk, then submit the real spk.
				other := []byte("a different package")
				sig := signPublish(t, pub, op.Public(), other, release)
				return release, f.spk, sig
			},
			wantCode: http.StatusUnauthorized,
			wantBody: "check=envelope",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := testConfig(t)
			op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
			operatorPub := operatorSignPub32(t, op)
			master := randPubkeyB58(t)
			f := buildValidFixture(t, cfg, master)
			m := newMockChainReader()
			f.pinAccept(m, operatorPub)
			svc := newTestService(t, cfg, m, op)
			svc.cfg.Policy.AcceptPublishers = []string{f.rel.ReleaseEntryPda}

			release, spk, sig := tc.setup(t, cfg, m, op, &f, operatorPub)
			if sig.Payload.Source.SignPubkeyB58 != "" {
				svc.cfg.Policy.AcceptPublishers = []string{sig.Payload.Source.SignPubkeyB58}
			}
			w := doPublish(t, svc, jsonPublishBody(t, sig, release, spk, f.metadata))
			if w.Code != tc.wantCode {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.wantCode, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("body %q does not name %q", w.Body.String(), tc.wantBody)
			}
		})
	}
}

func TestHandlePublish_AcceptPublishersPolicy(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)
	svc.cfg.Policy.AcceptPublishers = []string{"not-" + f.rel.ReleaseEntryPda}

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=accept_publishers") {
		t.Fatalf("body %q does not name accept_publishers", w.Body.String())
	}
}

func TestHandlePublish_AcceptPublishersRequired(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	svc := newTestService(t, cfg, m, op)

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=accept_publishers") {
		t.Fatalf("body %q does not name accept_publishers", w.Body.String())
	}
}

func TestHandlePublishInstaller_AcceptPublishersRequired(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	m := newMockChainReader()
	pinRootStoreOperator(t, cfg, m, op)

	artifact := []byte("installer publish requires an allowlisted publisher")
	pinInstallerEntry(t, cfg, m, artifact, "1.0.0", verify.AttestationStatusActive)
	svc := newTestService(t, cfg, m, op)
	pub := newTestIdentity(t, "installer-publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signInstallerPublish(t, pub, op.Public(), artifact)

	w := doPublishInstaller(t, svc, jsonInstallerPublishBody(t, sig, "shell", "sandstorm-42.tar.xz", artifact))
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=accept_publishers") {
		t.Fatalf("body %q does not name accept_publishers", w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(cfg.DistDir, "releases", "shell", "sandstorm-42.tar.xz")); err == nil {
		t.Fatalf("rejected installer artifact was written")
	}
}

func pinOtherActiveRelease(t *testing.T, m *mockChainReader, f *publishFixture, version string) string {
	t.Helper()
	otherHash := sha256.Sum256([]byte("other release " + version))
	relPDA, _, err := pda.Release(f.masterMint, otherHash, programID)
	if err != nil {
		t.Fatal(err)
	}
	addr := relPDA.Base58()
	m.releaseEntry[addr] = mockReleaseEntry{appHash: otherHash, appID: f.appID, version: version, status: verify.AttestationStatusActive}
	return addr
}

// TestHandlePublish_NoOperatorFailsClosed asserts that when boot has not wired
// an operator identity / chain reader, /publish fails closed with 503 — it never
// accepts an unverified upload.
func TestHandlePublish_NoOperatorFailsClosed(t *testing.T) {
	cfg, _ := testConfig(t)
	svc := &publishService{cfg: cfg, cr: nil, operator: nil, assembler: stubAssembler(t), nonces: envelope.NewMemoryNonceCache()}
	w := doPublish(t, svc, bytes.NewBufferString("{}"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandlePublish_EnvBypassRejected asserts the dev-only offline/skip/scan
// escape hatches are rejected on the receive path (spec §5 S7).
func TestHandlePublish_EnvBypassRejected(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	m := newMockChainReader()
	svc := newTestService(t, cfg, m, op)

	for _, env := range []string{"MELUSINA_ATTEST_OFFLINE", "SKIP_STEPS", "MELUSINA_SCAN_NOOP"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "1")
			w := doPublish(t, svc, bytes.NewBufferString("{}"))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for %s, got %d", env, w.Code)
			}
			if !strings.Contains(w.Body.String(), "bypass is disabled") {
				t.Fatalf("expected bypass-disabled message, got %q", w.Body.String())
			}
		})
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
