package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// exactCurrentReadOnlyChain makes the capability boundary in this proof
// explicit: the production router receives only chainReader fetch methods. The
// write counter represents mutation APIs on the ceremony side of the boundary;
// it must remain zero throughout stage, promotion, serving and restart.
type exactCurrentReadOnlyChain struct {
	*mockChainReader
	readCalls  int
	writeCalls int
}

func (c *exactCurrentReadOnlyChain) FetchReleaseEntry(ctx context.Context, addr string) ([32]byte, verify.AttestationStatus, error) {
	c.readCalls++
	return c.mockChainReader.FetchReleaseEntry(ctx, addr)
}

func (c *exactCurrentReadOnlyChain) FetchReleaseEntryMeta(ctx context.Context, addr string) (releaseEntryMeta, error) {
	c.readCalls++
	return c.mockChainReader.FetchReleaseEntryMeta(ctx, addr)
}

func (c *exactCurrentReadOnlyChain) FetchActiveReleaseEntriesByAppID(ctx context.Context, appID [32]byte) ([]releaseEntryMeta, error) {
	c.readCalls++
	return c.mockChainReader.FetchActiveReleaseEntriesByAppID(ctx, appID)
}

func (c *exactCurrentReadOnlyChain) FetchReleaseEntryAppID(ctx context.Context, addr string) ([32]byte, error) {
	c.readCalls++
	return c.mockChainReader.FetchReleaseEntryAppID(ctx, addr)
}

func (c *exactCurrentReadOnlyChain) FetchStoreOperatorAuthz(ctx context.Context, addr string) (verify.AuthorizationStatus, verify.Pubkey, uint8, bool, [32]byte, error) {
	c.readCalls++
	return c.mockChainReader.FetchStoreOperatorAuthz(ctx, addr)
}

func (c *exactCurrentReadOnlyChain) FetchBlacklistEntry(ctx context.Context, addr string) (bool, verify.BlacklistType, error) {
	c.readCalls++
	return c.mockChainReader.FetchBlacklistEntry(ctx, addr)
}

func (c *exactCurrentReadOnlyChain) FetchFoundationAppEntry(ctx context.Context, addr string) ([32]byte, uint8, verify.ApprovalStatus, error) {
	c.readCalls++
	return c.mockChainReader.FetchFoundationAppEntry(ctx, addr)
}

func TestG2ExactCurrentBootstrapStagePromoteIsReadOnlyIdempotentAndReplayDurable(t *testing.T) {
	cfg, opts, _ := newCatalogBootstrapFixture(t, "authorized")
	cfg.LicenseNFTMint = randPubkeyB58(t)
	cfg.Domain = "exact-current.store.example.org"
	cfg.StoreID = "exact-current-store"
	cfg.CatalogRepoRoot = t.TempDir()
	cfg.ServeVerifyTTLSeconds = -1

	operator := newTestIdentity(t, "exact-current-operator", cfg.LicenseNFTMint, cfg.Domain)
	publisher := newTestIdentity(t, "exact-current-publisher", randPubkeyB58(t), "publisher.example.org")
	cfg.Policy.AcceptPublishers = []string{publisher.Public().SignPubkeyB58}
	fixture := buildValidFixture(t, cfg, randPubkeyB58(t))
	release := mustJSON(t, fixture.rel)
	seedSlot(t, cfg.CatalogRepoRoot, "hrbrlife", "exact-current", "app", fixture.metadata)
	if err := NewCatalogAssembler(cfg.CatalogRepoRoot, cfg.DistDir).AssemblePublishedApp(fixture.spk, release, fixture.metadata); err != nil {
		t.Fatalf("seed legacy exact release: %v", err)
	}

	baseChain := newMockChainReader()
	fixture.pinAccept(baseChain, operatorSignPub32(t, operator))
	chain := &exactCurrentReadOnlyChain{mockChainReader: baseChain}
	activeBefore := exactActiveSetBytes(t, baseChain, fixture.appID)
	if len(baseChain.releaseEntry) != 1 {
		t.Fatalf("chain fixture has %d ReleaseEntries, want exactly one", len(baseChain.releaseEntry))
	}

	opts.nonce.Now = time.Now
	operatorPublicKey, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	opts.operatorPublicKey = ed25519.PublicKey(operatorPublicKey)
	runtime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err != nil {
		t.Fatalf("authorized legacy bootstrap: %v", err)
	}
	router := newRouterWithCatalogRuntime(cfg, operator, chain, nil, runtime)

	now := time.Now().UTC()
	stageEnvelope := signPublishForRoute(t, publisher, operator.Public(), fixture.spk, release, "/publish/stage", now, 5*time.Minute, "g2-exact-current-stage")
	promoteEnvelope := signPublishForRoute(t, publisher, operator.Public(), fixture.spk, release, "/publish", now, 5*time.Minute, "g2-exact-current-promote")
	stageBody := exactPublishBody(t, stageEnvelope, release, fixture.spk, fixture.metadata)
	promoteBody := exactPublishBody(t, promoteEnvelope, release, fixture.spk, fixture.metadata)

	stage := exactRequest(router, http.MethodPost, "/publish/stage", stageBody)
	if stage.Code != http.StatusOK {
		t.Fatalf("purpose-bound stage = %d: %s", stage.Code, stage.Body.String())
	}
	promote := exactRequest(router, http.MethodPost, "/publish", promoteBody)
	if promote.Code != http.StatusOK {
		t.Fatalf("purpose-bound promote = %d: %s", promote.Code, promote.Body.String())
	}
	var receipt Receipt
	if err := json.Unmarshal(promote.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("decode promotion receipt: %v", err)
	}

	served := exactGET(router, "/packages/"+metadataPackageID(fixture.metadata))
	if served.Code != http.StatusOK || !bytes.Equal(served.Body.Bytes(), fixture.spk) {
		t.Fatalf("served package = %d %q", served.Code, served.Body.Bytes())
	}
	indexBytes := exactGETOK(t, router, "/apps/index.json")
	pointerBytes := exactGETOK(t, router, "/apps/pointers/"+metadataAppID(fixture.metadata)+".json")
	exactAssertCatalogSelection(t, operator, fixture, indexBytes, pointerBytes, receipt)

	rolloutPath, err := rolloutStatePath(cfg, metadataAppID(fixture.metadata))
	if err != nil {
		t.Fatal(err)
	}
	rolloutBefore, err := os.ReadFile(rolloutPath)
	if err != nil {
		t.Fatal(err)
	}

	// A fresh purpose-bound envelope may safely retry the already-selected exact
	// release. It must not alter served bytes, index selection, rollout state or
	// the chain Active set (a pointer re-sign in a later wall-clock second is not
	// a release-selection change).
	retryEnvelope := signPublishForRoute(t, publisher, operator.Public(), fixture.spk, release, "/publish", time.Now().UTC(), 5*time.Minute, "g2-exact-current-promote-retry")
	retry := exactRequest(router, http.MethodPost, "/publish", exactPublishBody(t, retryEnvelope, release, fixture.spk, fixture.metadata))
	if retry.Code != http.StatusOK {
		t.Fatalf("fresh-envelope idempotent promote = %d: %s", retry.Code, retry.Body.String())
	}
	if got := exactGETOK(t, router, "/apps/index.json"); !bytes.Equal(got, indexBytes) {
		t.Fatal("idempotent promotion changed apps/index.json")
	}
	if got := exactGETOK(t, router, "/packages/"+metadataPackageID(fixture.metadata)); !bytes.Equal(got, fixture.spk) {
		t.Fatal("idempotent promotion changed served package bytes")
	}
	rolloutAfter, err := os.ReadFile(rolloutPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rolloutBefore, rolloutAfter) {
		t.Fatal("idempotent promotion changed rollout selection state")
	}

	// Reconstruct both bootstrap state and the production router from the same
	// durable roots. Previously accepted envelopes must still refuse as replay.
	restartedRuntime, err := bootstrapCatalogRuntimeWithOptions(cfg, true, opts)
	if err != nil {
		t.Fatalf("restart committed bootstrap: %v", err)
	}
	restarted := newRouterWithCatalogRuntime(cfg, operator, chain, nil, restartedRuntime)
	for _, replay := range []struct {
		path string
		body []byte
	}{
		{path: "/publish/stage", body: stageBody},
		{path: "/publish", body: promoteBody},
	} {
		got := exactRequest(restarted, http.MethodPost, replay.path, replay.body)
		if got.Code != http.StatusUnauthorized || !bytes.Contains(got.Body.Bytes(), []byte("nonce already consumed")) {
			t.Fatalf("restart replay %s = %d: %s", replay.path, got.Code, got.Body.String())
		}
	}

	activeAfter := exactActiveSetBytes(t, baseChain, fixture.appID)
	if !bytes.Equal(activeBefore, activeAfter) {
		t.Fatalf("chain Active set changed:\nbefore=%s\nafter=%s", activeBefore, activeAfter)
	}
	if chain.readCalls == 0 {
		t.Fatal("proof did not exercise chain reads")
	}
	if chain.writeCalls != 0 {
		t.Fatalf("store invoked %d chain write APIs, want zero", chain.writeCalls)
	}
}

func exactPublishBody(t *testing.T, sig envelope.Signed, release, spk, metadata []byte) []byte {
	t.Helper()
	body := jsonPublishBody(t, sig, release, spk, metadata)
	return append([]byte(nil), body.Bytes()...)
}

func exactRequest(handler http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func exactGET(handler http.Handler, path string) *httptest.ResponseRecorder {
	return exactRequest(handler, http.MethodGet, path, nil)
}

func exactGETOK(t *testing.T, handler http.Handler, path string) []byte {
	t.Helper()
	w := exactGET(handler, path)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", path, w.Code, w.Body.String())
	}
	return append([]byte(nil), w.Body.Bytes()...)
}

func exactActiveSetBytes(t *testing.T, chain *mockChainReader, appID [32]byte) []byte {
	t.Helper()
	active, err := chain.FetchActiveReleaseEntriesByAppID(context.Background(), appID)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 1 || active[0].Status != verify.AttestationStatusActive {
		t.Fatalf("Active set = %+v, want one exact Active ReleaseEntry", active)
	}
	raw, err := json.Marshal(active)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func exactAssertCatalogSelection(t *testing.T, operator *identity.Private, fixture publishFixture, indexBytes, pointerBytes []byte, receipt Receipt) {
	t.Helper()
	var index struct {
		Apps []struct {
			AppID     string      `json:"appId"`
			PackageID string      `json:"packageId"`
			Version   string      `json:"version"`
			UpdatedAt int64       `json:"updatedAt"`
			Attest    ReleaseJSON `json:"attest"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		t.Fatalf("decode current index: %v", err)
	}
	if len(index.Apps) != 1 {
		t.Fatalf("current index has %d apps, want one exact app", len(index.Apps))
	}
	row := index.Apps[0]
	if row.AppID != metadataAppID(fixture.metadata) || row.PackageID != metadataPackageID(fixture.metadata) {
		t.Fatalf("current index selection = app %q package %q", row.AppID, row.PackageID)
	}
	if row.Version != fixture.rel.Version || row.Attest.Version != fixture.rel.Version ||
		row.Attest.AppHash != fixture.rel.AppHash || row.Attest.SignedAtUnix != fixture.rel.SignedAtUnix ||
		row.UpdatedAt != fixture.rel.SignedAtUnix*1000 {
		t.Fatalf("current index changed exact appHash/version/timestamp: %+v", row)
	}

	var pointer AppCatalogPointer
	if err := json.Unmarshal(pointerBytes, &pointer); err != nil {
		t.Fatalf("decode current pointer: %v", err)
	}
	indexHash := sha256.Sum256(indexBytes)
	if pointer.AppID != row.AppID || pointer.PackageID != row.PackageID ||
		pointer.AppHash != fixture.rel.AppHash || pointer.Version != fixture.rel.Version ||
		pointer.CatalogSHA256 != hex.EncodeToString(indexHash[:]) {
		t.Fatalf("signed pointer does not select exact current release: %+v", pointer)
	}
	publicKey, err := operator.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyAppCatalogPointer(ed25519.PublicKey(publicKey), pointer); err != nil {
		t.Fatalf("verify current pointer signature: %v", err)
	}
	if receipt.Catalog == nil || *receipt.Catalog != pointer {
		t.Fatalf("promotion receipt pointer differs from served pointer: receipt=%+v served=%+v", receipt.Catalog, pointer)
	}
}
