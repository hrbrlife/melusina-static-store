package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func appendControlKey(dst []byte, key [32]byte) []byte { return append(dst, key[:]...) }

func controlPolicyBlob(license, domain, authority, authz, pearlKey, humanKey [32]byte, epoch uint64) []byte {
	b := append([]byte{}, accountDiscriminator("StoreControlPolicy")...)
	b = appendControlKey(b, license)
	b = appendControlKey(b, domain)
	b = appendControlKey(b, authority)
	b = appendControlKey(b, authz)
	b = appendControlKey(b, pearlKey)
	b = appendControlKey(b, humanKey)
	b = appendControlU64(b, epoch)
	b = append(b, storePolicyStatusActive)
	b = appendControlFixed(b, 1, 32)
	b = appendControlU64(b, 1)
	b = appendControlFixed(b, 2, 32)
	b = appendControlU64(b, 1)
	b = append(b, 0) // retired_at None
	b = append(b, 1) // bump
	return b
}

func controlGrantBlob(policy, appID, vault, publisherKey [32]byte, actions uint16, epoch uint64, now time.Time) []byte {
	b := append([]byte{}, accountDiscriminator("StorePublisherGrant")...)
	b = appendControlKey(b, policy)
	b = appendControlKey(b, appID)
	b = appendControlKey(b, vault)
	b = appendControlKey(b, publisherKey)
	b = appendControlU16(b, actions)
	b = appendControlU64(b, uint64(now.Add(-time.Minute).Unix()))
	b = appendControlU64(b, uint64(now.Add(time.Hour).Unix()))
	b = appendControlU64(b, epoch)
	b = append(b, storeGrantStatusActive)
	b = append(b, 0) // previous_grant None
	b = appendControlFixed(b, 3, 32)
	b = appendControlU64(b, 1)
	b = appendControlFixed(b, 4, 32)
	b = appendControlU64(b, 1)
	b = append(b, 0) // revoked_at None
	b = append(b, 0) // revoked_by None
	b = append(b, 1) // bump
	return b
}

func controlHeader(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func newControlCommand(t *testing.T, now time.Time, dossierID string, preflight appPublishPreflight, policy, grant, action string) (controlCommand, pearlCommandSignature, offlineControlApproval, ed25519.PublicKey, ed25519.PublicKey) {
	t.Helper()
	stage, err := buildStagedAppManifestWithRuntimeContract(preflight.spk, preflight.metadata, preflight.releaseBytes, preflight.runtimeContract, preflight.release, preflight.hint, now)
	if err != nil {
		t.Fatal(err)
	}
	route := controlPublishPathPrefix + dossierID + controlPublishPathSuffix
	if action == controlCommandActionPrepare {
		route = controlPublishPathPrefix + dossierID + controlPreparePathSuffix
	}
	command := controlCommand{
		Schema: controlCommandSchema, CommandID: "0123456789abcdef01234567", DossierID: dossierID,
		Action: action, Route: route, Method: http.MethodPost,
		StorePolicy: policy, PolicyEpoch: 7, PublisherGrant: grant, GrantEpoch: 3,
		PublisherIntentHash: strings.ToLower(preflight.sig.PayloadHash), AppID: stage.AppID, Version: stage.Version,
		ArtifactSHA256: stage.SPKSHA256, AppHash: stage.AppHash, ReleaseHash: stage.ReleaseHash, StageID: stage.StageID,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute), Nonce: "89abcdef0123456789abcdef",
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := pearlCommandSignature{
		Schema: pearlCommandSignatureSchema, CommandDigest: command.Digest(),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, pearlCommandSignaturePayload(command))), SignedAt: now,
	}
	humanPublic, humanPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approval := offlineControlApproval{
		Schema: offlineApprovalSchema, CommandDigest: command.Digest(),
		SignerPublicKey: base64.RawURLEncoding.EncodeToString(humanPublic),
		Signature:       base64.RawURLEncoding.EncodeToString(ed25519.Sign(humanPrivate, []byte(command.HumanSigningText()))), SignedAt: now,
	}
	return command, signature, approval, public, humanPublic
}

func stageControlCandidate(t *testing.T, svc *publishService, publisher *identity.Private, operator identity.Public, f publishFixture, now time.Time) appPublishPreflight {
	t.Helper()
	release := mustJSON(t, f.rel)
	stageSig := signPublishForRoute(t, publisher, operator, f.spk, release, "/publish/stage", now, 5*time.Minute, "")
	stage := doStagePublish(t, svc, jsonPublishBody(t, stageSig, release, f.spk, f.metadata))
	if stage.Code != http.StatusOK {
		t.Fatalf("stage candidate: got %d: %s", stage.Code, stage.Body.String())
	}
	controlRoute := controlPublishPathPrefix + "dossier-1" + controlPublishPathSuffix
	controlSig := signPublishForRoute(t, publisher, operator, f.spk, release, controlRoute, now, 5*time.Minute, "control-nonce")
	return appPublishPreflight{sig: controlSig, releaseBytes: release, spk: f.spk, metadata: f.metadata, runtimeContract: f.runtimeContract, release: f.rel}
}

// buildValidFixture predates the real Sandstorm identity constraint and uses a
// 53-character test id. The control path intentionally refuses that shape, so
// this adapter keeps the broad legacy fixture untouched while deriving a fully
// consistent, production-shaped release for the control-route tests.
func controlFixture(t *testing.T, f publishFixture) publishFixture {
	t.Helper()
	appText := strings.Repeat("a", 52)
	f.metadata = []byte(strings.Replace(string(f.metadata), metadataAppID(f.metadata), appText, 1))
	appHashText, err := apphash.Canonical(bytes.NewReader(f.spk), f.metadata)
	if err != nil {
		t.Fatal(err)
	}
	f.appHashBytes, err = hash32FromHex(appHashText)
	if err != nil {
		t.Fatal(err)
	}
	f.rel.AppHash = appHashText
	relPDA, _, err := pda.Release(f.masterMint, f.appHashBytes, programID)
	if err != nil {
		t.Fatal(err)
	}
	f.relPDA, f.rel.ReleaseEntryPda = relPDA.Base58(), relPDA.Base58()
	f.appID = sha256.Sum256([]byte(appText))
	f.runtimeContract = runtimeContractForTest(t, f.spk, f.metadata, f.rel)
	runtimeHash := sha256.Sum256(f.runtimeContract)
	f.rel.RuntimeContractSHA256 = fmt.Sprintf("%x", runtimeHash[:])
	return f
}

func TestControlPublishRunsTheOrdinaryGateOnlyAfterExactGrantCommand(t *testing.T) {
	clock := time.Now().UTC().Add(time.Second).Truncate(time.Millisecond)
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	cfg.ProgramID = programID.Base58()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	f := controlFixture(t, buildValidFixture(t, cfg, randPubkeyB58(t)))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorSignPub32(t, op))
	appID, err := controlSandstormAppID(metadataAppID(f.metadata))
	if err != nil {
		t.Fatal(err)
	}
	releaseMeta := m.releaseEntry[f.relPDA]
	releaseMeta.appID = appID
	m.releaseEntry[f.relPDA] = releaseMeta
	svc := newTestService(t, cfg, m, op)
	svc.now = func() time.Time { return clock }
	publisher := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	preflight := stageControlCandidate(t, svc, publisher, op.Public(), f, clock)

	license, err := primitives.PubkeyFromBase58(cfg.LicenseNFTMint)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := primitives.PubkeyFromBase58(cfg.StoreAuthority)
	if err != nil {
		t.Fatal(err)
	}
	authz, err := primitives.PubkeyFromBase58(f.authzPDA)
	if err != nil {
		t.Fatal(err)
	}
	policyPDA, err := deriveStoreControlPolicy(license, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	publisherKey, err := primitives.PubkeyFromBase58(publisher.Public().SignPubkeyB58)
	if err != nil {
		t.Fatal(err)
	}
	grantPDA, err := deriveStorePublisherGrant(policyPDA, appID, publisherKey, programID)
	if err != nil {
		t.Fatal(err)
	}
	command, pearlSignature, offlineApproval, pearlKey, humanKey := newControlCommand(t, clock, "dossier-1", preflight, policyPDA.Base58(), grantPDA.Base58(), controlCommandActionPublish)
	var pearlRaw [32]byte
	copy(pearlRaw[:], pearlKey)
	var humanRaw [32]byte
	copy(humanRaw[:], humanKey)
	m.rawAccounts[policyPDA.Base58()] = controlPolicyBlob(license, primitives.StoreDomainHash(cfg.Domain), authority, authz, pearlRaw, humanRaw, 7)
	m.rawAccounts[grantPDA.Base58()] = controlGrantBlob(policyPDA, appID, releaseMeta.publisherSquadsVault, publisherKey, storePublisherActionPublishRelease, 3, clock)

	body := jsonPublishBody(t, preflight.sig, preflight.releaseBytes, preflight.spk, preflight.metadata)
	req := httptest.NewRequest(http.MethodPost, command.Route, bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(controlCommandHeader, controlHeader(t, command))
	req.Header.Set(controlPearlSignatureHeader, controlHeader(t, pearlSignature))
	req.Header.Set(controlOfflineApprovalHeader, controlHeader(t, offlineApproval))
	w := httptest.NewRecorder()
	svc.handleControlRelease(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("control publish got %d: %s", w.Code, w.Body.String())
	}
	// The response could be lost after the sidecar has switched the catalog.
	// An exact command retry must return its durable receipt before it attempts
	// to parse a body or claim the publisher envelope nonce again.
	retry := httptest.NewRequest(http.MethodPost, command.Route, nil)
	retry.Header.Set(controlCommandHeader, controlHeader(t, command))
	retry.Header.Set(controlPearlSignatureHeader, controlHeader(t, pearlSignature))
	retry.Header.Set(controlOfflineApprovalHeader, controlHeader(t, offlineApproval))
	w = httptest.NewRecorder()
	svc.handleControlRelease(w, retry)
	if w.Code != http.StatusOK {
		t.Fatalf("completed control publish retry got %d: %s", w.Code, w.Body.String())
	}
}

func TestControlPrepareStagesOnlyWithPearlCommandAndPrepareGrant(t *testing.T) {
	clock := time.Now().UTC().Add(time.Second).Truncate(time.Millisecond)
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	cfg.ProgramID = programID.Base58()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	f := controlFixture(t, buildValidFixture(t, cfg, randPubkeyB58(t)))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorSignPub32(t, op))
	svc := newTestService(t, cfg, m, op)
	svc.now = func() time.Time { return clock }
	// The legacy migration allowlist is empty: this proves the Pearl route gets
	// its publisher authority only from the governed app-scoped grant.
	svc.cfg.Policy.AcceptPublishers = nil
	publisher := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	release := mustJSON(t, f.rel)
	prepareRoute := controlPublishPathPrefix + "dossier-prepare" + controlPreparePathSuffix
	prepareEnvelope := signPublishForRoute(t, publisher, op.Public(), f.spk, release, prepareRoute, clock, 5*time.Minute, "prepare-nonce")
	preflight := appPublishPreflight{sig: prepareEnvelope, releaseBytes: release, spk: f.spk, metadata: f.metadata, runtimeContract: f.runtimeContract, release: f.rel}

	appID, err := controlSandstormAppID(metadataAppID(f.metadata))
	if err != nil {
		t.Fatal(err)
	}
	license, err := primitives.PubkeyFromBase58(cfg.LicenseNFTMint)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := primitives.PubkeyFromBase58(cfg.StoreAuthority)
	if err != nil {
		t.Fatal(err)
	}
	authz, err := primitives.PubkeyFromBase58(f.authzPDA)
	if err != nil {
		t.Fatal(err)
	}
	policyPDA, err := deriveStoreControlPolicy(license, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	publisherKey, err := primitives.PubkeyFromBase58(publisher.Public().SignPubkeyB58)
	if err != nil {
		t.Fatal(err)
	}
	grantPDA, err := deriveStorePublisherGrant(policyPDA, appID, publisherKey, programID)
	if err != nil {
		t.Fatal(err)
	}
	command, pearlSignature, _, pearlKey, humanKey := newControlCommand(t, clock, "dossier-prepare", preflight, policyPDA.Base58(), grantPDA.Base58(), controlCommandActionPrepare)
	var pearlRaw [32]byte
	copy(pearlRaw[:], pearlKey)
	var humanRaw [32]byte
	copy(humanRaw[:], humanKey)
	releaseMeta := m.releaseEntry[f.relPDA]
	publisherVault, err := primitives.PubkeyFromBase58(f.rel.LicenseSquadsVault)
	if err != nil || publisherVault != releaseMeta.publisherSquadsVault {
		t.Fatalf("fixture release does not bind the expected publisher vault: %v", err)
	}
	m.rawAccounts[policyPDA.Base58()] = controlPolicyBlob(license, primitives.StoreDomainHash(cfg.Domain), authority, authz, pearlRaw, humanRaw, 7)
	// This grant deliberately has PREPARE and not PUBLISH. If the control path
	// accidentally used the publish bit, this positive control must fail.
	m.rawAccounts[grantPDA.Base58()] = controlGrantBlob(policyPDA, appID, publisherVault, publisherKey, storePublisherActionPrepareRelease, 3, clock)

	body := jsonPublishBody(t, prepareEnvelope, release, f.spk, f.metadata)
	req := httptest.NewRequest(http.MethodPost, command.Route, bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(controlCommandHeader, controlHeader(t, command))
	req.Header.Set(controlPearlSignatureHeader, controlHeader(t, pearlSignature))
	// There is intentionally no offline-approval header. Preparation cannot
	// publish and must not make an operator sign a mere private stage.
	w := httptest.NewRecorder()
	svc.handleControlRelease(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("control prepare got %d: %s", w.Code, w.Body.String())
	}
	var receipt StageReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.StageID != command.StageID {
		t.Fatalf("prepare receipt stage = %s, want %s", receipt.StageID, command.StageID)
	}
	if _, _, _, _, _, err := loadStagedAppWithRuntimeContract(svc.cfg.PrivateStageDir, command.StageID); err != nil {
		t.Fatalf("control prepare did not durably stage the candidate: %v", err)
	}
	// A response-loss retry does not need the large body or a fresh publisher
	// nonce. The journal returns the signed durable stage receipt directly.
	retry := httptest.NewRequest(http.MethodPost, command.Route, nil)
	retry.Header.Set(controlCommandHeader, controlHeader(t, command))
	retry.Header.Set(controlPearlSignatureHeader, controlHeader(t, pearlSignature))
	w = httptest.NewRecorder()
	svc.handleControlRelease(w, retry)
	if w.Code != http.StatusOK {
		t.Fatalf("completed control prepare retry got %d: %s", w.Code, w.Body.String())
	}

	// The old transport cannot use that publisher merely because the Pearl
	// command succeeded: its static migration allowlist is empty.
	legacyEnvelope := signPublishForRoute(t, publisher, op.Public(), f.spk, release, "/publish/stage", clock, 5*time.Minute, "legacy-nonce")
	legacy := doStagePublish(t, svc, jsonPublishBody(t, legacyEnvelope, release, f.spk, f.metadata))
	if legacy.Code != http.StatusForbidden || !strings.Contains(legacy.Body.String(), "accept_publishers") {
		t.Fatalf("legacy route bypassed the empty migration allowlist: %d: %s", legacy.Code, legacy.Body.String())
	}
}

func TestControlPublishRefusesChangedCandidateAndStalePredecessor(t *testing.T) {
	clock := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	command := testControlCommand(clock)
	command.DossierID = "dossier-1"
	command.Route = controlPublishPathPrefix + command.DossierID + controlPublishPathSuffix
	command.AppID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	preflight := appPublishPreflight{sig: envelopeSignedForControl(t), metadata: []byte(`{"appId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`), spk: []byte("spk"), releaseBytes: []byte(`{}`), release: ReleaseJSON{}}
	stage := stagedAppManifest{AppID: command.AppID, Version: command.Version, SPKSHA256: command.ArtifactSHA256, AppHash: command.AppHash, ReleaseHash: command.ReleaseHash, StageID: command.StageID}
	preflight.sig.PayloadHash = command.PublisherIntentHash
	if err := commandMatchesCandidate(command, preflight, stage); err != nil {
		t.Fatalf("control candidate unexpectedly refused: %v", err)
	}
	command.ArtifactSHA256 = strings.Repeat("f", 64)
	if err := commandMatchesCandidate(command, preflight, stage); err == nil {
		t.Fatal("changed candidate was accepted")
	}
}

// envelopeSignedForControl supplies only the canonical payload hash needed by
// the pure candidate-binding test above; signature verification is exercised by
// TestControlPublishRunsTheOrdinaryGateOnlyAfterExactGrantCommand.
func envelopeSignedForControl(t *testing.T) envelope.Signed {
	t.Helper()
	return envelope.Signed{PayloadHash: strings.Repeat("a", 64)}
}

func TestControlPublishHeaderAndRouteAreStrict(t *testing.T) {
	if _, _, err := controlPublishRoute("/control/v1/releases/../publish"); err == nil {
		t.Fatal("unsafe route accepted")
	}
	if _, _, err := controlPrepareRoute("/control/v1/releases/../prepare"); err == nil {
		t.Fatal("unsafe prepare route accepted")
	}
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set(controlCommandHeader, "not-base64")
	if _, _, _, _, err := parsePearlControlHeaders(request); err == nil {
		t.Fatal("malformed control header accepted")
	}
	request.Header.Set(controlCommandHeader, base64.RawURLEncoding.EncodeToString([]byte(`{} trailing`)))
	if _, _, _, _, err := parsePearlControlHeaders(request); err == nil {
		t.Fatal("control header with trailing JSON was accepted")
	}
}

func TestControlCriticalRecheckRefusesBeforeNonceOrCatalogMutation(t *testing.T) {
	clock := time.Now().UTC().Add(time.Second).Truncate(time.Millisecond)
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorSignPub32(t, op))
	svc := newTestService(t, cfg, m, op)
	svc.now = func() time.Time { return clock }
	publisher := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	release := mustJSON(t, f.rel)
	stage := doStagePublish(t, svc, jsonPublishBody(t, signPublishForRoute(t, publisher, op.Public(), f.spk, release, "/publish/stage", clock, 5*time.Minute, ""), release, f.spk, f.metadata))
	if stage.Code != http.StatusOK {
		t.Fatalf("stage candidate: got %d: %s", stage.Code, stage.Body.String())
	}
	sig := signPublishForRoute(t, publisher, op.Public(), f.spk, release, "/publish", clock, 5*time.Minute, "control-critical")
	body := jsonPublishBody(t, sig, release, f.spk, f.metadata)
	req := httptest.NewRequest(http.MethodPost, "/publish", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	svc.handleAppPublish(w, req, "/publish", func(_ appPublishPreflight, claimed identity.Public) (string, error) {
		return claimed.SignPubkeyB58, nil
	}, func(appPublishPreflight, time.Time) error {
		return errors.New("publisher grant became suspended")
	}, nil, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "publisher grant became suspended") {
		t.Fatalf("critical recheck got %d: %s", w.Code, w.Body.String())
	}
	// The control re-check sits before VerifyPublish and the durable envelope
	// claim. A retry with the same envelope must therefore still reach it rather
	// than being reported as a consumed command.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/publish", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	svc.handleAppPublish(w, req, "/publish", func(_ appPublishPreflight, claimed identity.Public) (string, error) {
		return claimed.SignPubkeyB58, nil
	}, func(appPublishPreflight, time.Time) error {
		return errors.New("publisher grant became suspended")
	}, nil, nil)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "nonce") {
		t.Fatalf("critical refusal consumed the envelope: %d: %s", w.Code, w.Body.String())
	}
}
