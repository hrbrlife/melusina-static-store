package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/appscan"
	"github.com/hrbrlife/melusina-store-sidecar/internal/controltlsissue"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/publisherenvelope"
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

func newControlCommand(t *testing.T, now time.Time, dossierID string, preflight appPublishPreflight, policy, grant, action string) (controlCommand, pearlCommandSignature, offlineControlApproval, ed25519.PublicKey, ed25519.PublicKey, ed25519.PrivateKey) {
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
	return command, signature, approval, public, humanPublic, private
}

func TestControlPublishRunsTheOrdinaryGateOnlyAfterExactGrantCommand(t *testing.T) {
	cfg, _ := testConfig(t)
	profile := storeEstateProfileFixture(t)
	profileDigest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	bundle, clientPin, err := controltlsissue.Issue("127.0.0.1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	controlIdentityDir := t.TempDir()
	serverCertPath := filepath.Join(controlIdentityDir, "server.crt")
	serverKeyPath := filepath.Join(controlIdentityDir, "server.key")
	clientCAPath := filepath.Join(controlIdentityDir, "client-ca.crt")
	for path, content := range map[string]string{serverCertPath: bundle.ServerCertPEM, serverKeyPath: bundle.ServerKeyPEM, clientCAPath: bundle.ClientCAPEM} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	security := signedStoreSecurityFixture(t, profile, profileDigest, clientPin)
	cfg.StoreID = profile.Store.StoreID
	cfg.CatalogRepoRoot = t.TempDir()
	cfg.ProgramID = programID.Base58()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = op.Public().SignPubkeyB58
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "test-repo", "test-app", f.metadata)
	m := newMockChainReader()
	f.pinAccept(m, operatorSignPub32(t, op))
	f.pinServeListingActive(m)
	appID, err := controlSandstormAppID(metadataAppID(f.metadata))
	if err != nil {
		t.Fatal(err)
	}
	releaseMeta := m.releaseEntry[f.relPDA]
	releaseMeta.appID = appID
	m.releaseEntry[f.relPDA] = releaseMeta
	svc := newTestService(t, cfg, m, op)
	// The nonce ledger sets its high-water during service construction. Capture
	// this test's fixed clock afterwards so farm load cannot put it behind that
	// durable value.
	clock := time.Now().UTC().Add(time.Second).Truncate(time.Millisecond)
	svc.now = func() time.Time { return clock }
	publisherRef := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org").Public().Ref
	var publisherSignSeed, publisherBoxSeed [32]byte
	if _, err := rand.Read(publisherSignSeed[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(publisherBoxSeed[:]); err != nil {
		t.Fatal(err)
	}
	publisher, err := identity.NewPrivate(publisherRef, publisherSignSeed, publisherBoxSeed)
	if err != nil {
		t.Fatal(err)
	}
	svc.cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	release := mustJSON(t, f.rel)
	dossierID := "0123456789abcdef01234567"
	stage, err := buildStagedAppManifestWithRuntimeContract(f.spk, f.metadata, release, f.runtimeContract, f.rel, slotHint{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp(os.TempDir(), "pps")
	if err != nil {
		t.Fatal(err)
	}
	publisherPath := filepath.Join(socketDir, "publisher.json")
	storePath := filepath.Join(socketDir, "store.json")
	publisherFile, err := json.Marshal(map[string]any{"ref": publisherRef, "sign_seed_hex": hex.EncodeToString(publisherSignSeed[:]), "box_seed_hex": hex.EncodeToString(publisherBoxSeed[:])})
	if err != nil {
		t.Fatal(err)
	}
	storeFile, err := json.Marshal(op.Public())
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{publisherPath: publisherFile, storePath: storeFile} {
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	socketPath := filepath.Join(socketDir, "s")
	signer, err := publisherenvelope.Load(publisherenvelope.Config{SocketPath: socketPath, PublisherIdentityPath: publisherPath, StoreIdentityPath: storePath, StoreID: cfg.StoreID, AllowedUID: uint32(os.Geteuid())})
	if err != nil {
		t.Fatalf("bazaar-publisher-envelope-producer-positive: %v", err)
	}
	signerContext, stopSigner := context.WithCancel(context.Background())
	signerDone := make(chan error, 1)
	go func() { signerDone <- publisherenvelope.Serve(signerContext, socketPath, signer) }()
	t.Cleanup(func() {
		stopSigner()
		select {
		case <-signerDone:
		case <-time.After(2 * time.Second):
			t.Error("bazaar-publisher-envelope-producer-positive: signer did not stop")
		}
		if err := os.RemoveAll(socketDir); err != nil {
			t.Error(err)
		}
	})
	for deadline := time.Now().Add(2 * time.Second); ; {
		if info, err := os.Lstat(socketPath); err == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bazaar-publisher-envelope-producer-positive: signer socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}
	clientSigner, err := publisherenvelope.NewClient(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	signedResponse, err := clientSigner.Sign(context.Background(), publisherenvelope.Request{Schema: publisherenvelope.RequestSchema,
		DossierID: dossierID, StoreID: cfg.StoreID, AppID: stage.AppID, Version: stage.Version,
		ArtifactSHA256: stage.SPKSHA256, AppHash: stage.AppHash, ReleaseHash: stage.ReleaseHash,
		ReleaseB64: base64.StdEncoding.EncodeToString(release), ReleaseEntryPDA: f.rel.ReleaseEntryPda, VerifiedSlot: 12345})
	if err != nil {
		t.Fatalf("bazaar-publisher-envelope-producer-positive: %v", err)
	}
	signedRaw, err := base64.RawURLEncoding.DecodeString(signedResponse.EnvelopeB64)
	if err != nil {
		t.Fatal(err)
	}
	var controlSig envelope.Signed
	if err := json.Unmarshal(signedRaw, &controlSig); err != nil {
		t.Fatal(err)
	}
	if controlSig.Payload.Method != http.MethodPost || controlSig.Payload.Target != controlPublishPathPrefix+dossierID+controlPublishPathSuffix {
		t.Fatal("bazaar-publisher-envelope-producer-positive: signer did not bind the governed publish method and target")
	}
	preflight := appPublishPreflight{sig: controlSig, releaseBytes: release, spk: f.spk, metadata: f.metadata, runtimeContract: f.runtimeContract, release: f.rel}
	svc.cfg.EstateProfile = &profile
	svc.cfg.StoreSecurityProfile = &security
	svc.cfg.StoreLinkControlMTLS = StoreLinkControlMTLSConfig{ListenAddr: security.ControlListenAddr, CertPath: serverCertPath, KeyPath: serverKeyPath, ClientCAPath: clientCAPath, StoreLinkClientCertSHA256: security.StoreLinkClientCertSHA256}
	svc.cfg.Policy.RequirePearlControlForAppPublish = true
	svc.cfg.Policy.RequireScanReport = true
	svc.cfg.Policy.ScannerEd25519PublicKey = security.ScannerEd25519PublicKey
	if err := requireServingControlMTLS(svc.cfg); err != nil {
		t.Fatalf("control-publish-signed-security-setup: %v", err)
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
	command, pearlSignature, offlineApproval, pearlKey, humanKey, pearlPrivate := newControlCommand(t, clock, dossierID, preflight, policyPDA.Base58(), grantPDA.Base58(), controlCommandActionPublish)
	var pearlRaw [32]byte
	copy(pearlRaw[:], pearlKey)
	var humanRaw [32]byte
	copy(humanRaw[:], humanKey)
	m.rawAccounts[policyPDA.Base58()] = controlPolicyBlob(license, primitives.StoreDomainHash(cfg.Domain), authority, authz, pearlRaw, humanRaw, 7)
	m.rawAccounts[grantPDA.Base58()] = controlGrantBlob(policyPDA, appID, releaseMeta.publisherSquadsVault, publisherKey, storePublisherActionPrepareRelease, 3, clock)
	privateRouter := newControlReleaseRouter(svc)
	privateServer, err := newStoreLinkControlServer(svc.cfg.StoreLinkControlMTLS, privateRouter)
	if err != nil {
		t.Fatalf("control-private-mtls-publish-positive: %v", err)
	}
	listener := httptest.NewUnstartedServer(privateServer.Handler)
	listener.TLS = privateServer.TLSConfig
	listener.StartTLS()
	defer listener.Close()
	clientIdentity, err := tls.X509KeyPair([]byte(bundle.ClientCertPEM), []byte(bundle.ClientKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(bundle.ClientCAPEM)) {
		t.Fatal("control-private-mtls-publish-positive: client CA missing")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{clientIdentity}}}}
	prepareRoute := controlPublishPathPrefix + "dossier-prepare" + controlPreparePathSuffix
	prepareSig := signPublishForRoute(t, publisher, op.Public(), f.spk, release, prepareRoute, clock, 5*time.Minute, "prepare-nonce")
	preparePreflight := preflight
	preparePreflight.sig = prepareSig
	prepareCommand, _, _, _, _, _ := newControlCommand(t, clock, "dossier-prepare", preparePreflight, policyPDA.Base58(), grantPDA.Base58(), controlCommandActionPrepare)
	prepareCommand.CommandID = "fedcba9876543210fedcba98"
	prepareCommand.Nonce = "fedcba9876543210fedcba98"
	prepareSignature := pearlCommandSignature{Schema: pearlCommandSignatureSchema, CommandDigest: prepareCommand.Digest(),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(pearlPrivate, pearlCommandSignaturePayload(prepareCommand))), SignedAt: clock}
	prepareBody := jsonPublishBody(t, prepareSig, release, f.spk, f.metadata)
	var preparePublish publishRequest
	if err := json.Unmarshal(prepareBody.Bytes(), &preparePublish); err != nil {
		t.Fatal(err)
	}
	prepareRuntimeContract, err := base64.StdEncoding.DecodeString(preparePublish.RuntimeContractB64)
	if err != nil {
		t.Fatal(err)
	}
	preparePublish.ScanReport = signedClamAVReportFixture(t, prepareRoute, f.spk, f.metadata, release, prepareRuntimeContract, clock)
	prepareBytes, err := json.Marshal(preparePublish)
	if err != nil {
		t.Fatal(err)
	}
	prepareRequest, err := http.NewRequest(http.MethodPost, listener.URL+prepareRoute, bytes.NewReader(prepareBytes))
	if err != nil {
		t.Fatal(err)
	}
	prepareRequest.Header.Set("Content-Type", "application/json")
	prepareRequest.Header.Set(controlCommandHeader, controlHeader(t, prepareCommand))
	prepareRequest.Header.Set(controlPearlSignatureHeader, controlHeader(t, prepareSignature))
	prepared, err := client.Do(prepareRequest)
	if err != nil {
		t.Fatalf("control-private-mtls-prepare-positive: %v", err)
	}
	preparedBody, err := io.ReadAll(prepared.Body)
	prepared.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if prepared.StatusCode != http.StatusOK {
		t.Fatalf("control-private-mtls-prepare-positive: %d %s", prepared.StatusCode, preparedBody)
	}
	m.rawAccounts[grantPDA.Base58()] = controlGrantBlob(policyPDA, appID, releaseMeta.publisherSquadsVault, publisherKey, storePublisherActionPublishRelease, 3, clock)

	body := jsonPublishBody(t, preflight.sig, preflight.releaseBytes, preflight.spk, preflight.metadata)
	missing := httptest.NewRequest(http.MethodPost, command.Route, bytes.NewReader(body.Bytes()))
	missing.Header.Set("Content-Type", "application/json")
	missing.Header.Set(controlCommandHeader, controlHeader(t, command))
	missing.Header.Set(controlPearlSignatureHeader, controlHeader(t, pearlSignature))
	missing.Header.Set(controlOfflineApprovalHeader, controlHeader(t, offlineApproval))
	missingResponse := httptest.NewRecorder()
	svc.handleControlRelease(missingResponse, missing)
	if missingResponse.Code == http.StatusOK || !strings.Contains(missingResponse.Body.String(), "scan-report-missing") {
		t.Fatalf("scan-report-missing: %d %s", missingResponse.Code, missingResponse.Body.String())
	}
	var publishBody publishRequest
	if err := json.Unmarshal(body.Bytes(), &publishBody); err != nil {
		t.Fatal(err)
	}
	runtimeContract, err := base64.StdEncoding.DecodeString(publishBody.RuntimeContractB64)
	if err != nil {
		t.Fatal(err)
	}
	publishBody.ScanReport = signedClamAVReportFixture(t, command.Route, preflight.spk, preflight.metadata, preflight.releaseBytes, runtimeContract, clock)
	for _, negative := range []struct {
		name   string
		change func(*appscan.Report)
	}{
		{"scan-report-wrong-artifact", func(r *appscan.Report) { r.SPKSHA256 = appscan.Hash([]byte("other artifact")) }},
		{"scan-report-wrong-signer", func(r *appscan.Report) { r.Signature = "AA" }},
		{"scan-report-expired", func(r *appscan.Report) { r.ScannedAtUnix = clock.Add(-appscan.MaxAge - time.Second).Unix() }},
		{"scan-report-wrong-purpose", func(r *appscan.Report) { r.Target = "/publish" }},
	} {
		candidate := publishBody
		negative.change(&candidate.ScanReport)
		negativeBody, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, command.Route, bytes.NewReader(negativeBody))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(controlCommandHeader, controlHeader(t, command))
		request.Header.Set(controlPearlSignatureHeader, controlHeader(t, pearlSignature))
		request.Header.Set(controlOfflineApprovalHeader, controlHeader(t, offlineApproval))
		response := httptest.NewRecorder()
		svc.handleControlRelease(response, request)
		if response.Code == http.StatusOK || !strings.Contains(response.Body.String(), negative.name) {
			t.Fatalf("%s: status=%d body=%s", negative.name, response.Code, response.Body.String())
		}
	}
	boundBody, err := json.Marshal(publishBody)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, listener.URL+command.Route, bytes.NewReader(boundBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(controlCommandHeader, controlHeader(t, command))
	req.Header.Set(controlPearlSignatureHeader, controlHeader(t, pearlSignature))
	req.Header.Set(controlOfflineApprovalHeader, controlHeader(t, offlineApproval))
	response, err := client.Do(req)
	if err != nil {
		t.Fatalf("control-private-mtls-publish-positive: %v", err)
	}
	responseBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("control-private-mtls-publish-positive: %d %s", response.StatusCode, responseBody)
	}
	var receipt Receipt
	if err := json.Unmarshal(responseBody, &receipt); err != nil {
		t.Fatalf("control-publish-public-readback: decode receipt: %v", err)
	}
	publicRuntime := catalogRuntime{appNonces: svc.appNonces, catalogGenerations: svc.catalogGenerations,
		expectedUID: svc.catalogExpectedUID, expectedGID: svc.catalogExpectedGID}
	publicRouter := newPublicRouterWithService(svc.cfg, op, m, nil, publicRuntime, svc, false)
	served := exactGET(publicRouter, "/packages/"+metadataPackageID(f.metadata))
	if served.Code != http.StatusOK || !bytes.Equal(served.Body.Bytes(), f.spk) {
		t.Fatalf("control-publish-public-readback: package = %d %q", served.Code, served.Body.Bytes())
	}
	indexBytes := exactGETOK(t, publicRouter, "/apps/index.json")
	pointerBytes := exactGETOK(t, publicRouter, "/apps/pointers/"+metadataAppID(f.metadata)+".json")
	exactAssertCatalogSelection(t, op, f, indexBytes, pointerBytes, receipt)
	// The response could be lost after the sidecar has switched the catalog.
	// An exact command retry must return its durable receipt before it attempts
	// to parse a body or claim the publisher envelope nonce again.
	retry := httptest.NewRequest(http.MethodPost, command.Route, nil)
	retry.Header.Set(controlCommandHeader, controlHeader(t, command))
	retry.Header.Set(controlPearlSignatureHeader, controlHeader(t, pearlSignature))
	retry.Header.Set(controlOfflineApprovalHeader, controlHeader(t, offlineApproval))
	w := httptest.NewRecorder()
	svc.handleControlRelease(w, retry)
	if w.Code != http.StatusOK {
		t.Fatalf("completed control publish retry got %d: %s", w.Code, w.Body.String())
	}
}

func signedClamAVReportFixture(t *testing.T, target string, spk, metadata, release, runtimeContract []byte, now time.Time) appscan.Report {
	t.Helper()
	dir := t.TempDir()
	db := filepath.Join(dir, "db")
	if err := os.Mkdir(db, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := []byte("known scan marker fixture\n")
	markerHash := md5.Sum(marker)
	if err := os.WriteFile(filepath.Join(db, "fixture.hdb"), []byte(fmt.Sprintf("%x:%d:Known.Marker.Fixture\n", markerHash, len(marker))), 0o600); err != nil {
		t.Fatal(err)
	}
	content := [4][]byte{spk, metadata, release, runtimeContract}
	version, database, err := appscan.ScanFiles(content, db, dir)
	if err != nil {
		t.Fatalf("control-publish-scan-producer: %v", err)
	}
	if _, _, err := appscan.ScanFiles([4][]byte{marker, metadata, release, runtimeContract}, db, dir); err == nil {
		t.Fatal("control-publish-scanner-detection-required")
	}
	seed := sha256.Sum256([]byte("store-security-rehearsal-scanner"))
	report := appscan.Report{Schema: appscan.Schema, Method: "POST", Target: target, SPKSHA256: appscan.Hash(spk), MetadataSHA256: appscan.Hash(metadata), ReleaseSHA256: appscan.Hash(release), RuntimeContractSHA256: appscan.Hash(runtimeContract), ScannedAtUnix: now.Unix(), ScannerVersion: version, DatabaseVersion: database, Clean: true}
	if err := report.Sign(ed25519.NewKeyFromSeed(seed[:])); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestControlPrepareStagesOnlyWithPearlCommandAndPrepareGrant(t *testing.T) {
	clock := time.Now().UTC().Add(time.Second).Truncate(time.Millisecond)
	cfg, _ := testConfig(t)
	cfg.CatalogRepoRoot = t.TempDir()
	cfg.ProgramID = programID.Base58()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
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
	command, pearlSignature, _, pearlKey, humanKey, _ := newControlCommand(t, clock, "dossier-prepare", preflight, policyPDA.Base58(), grantPDA.Base58(), controlCommandActionPrepare)
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
