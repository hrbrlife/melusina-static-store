package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// countingChainReader counts the four reads the catalog projection makes per app
// row, so a test can assert how many chain reads a request actually cost.
type countingChainReader struct {
	*mockChainReader
	reads atomic.Int32
}

func (c *countingChainReader) FetchReleaseEntryMeta(ctx context.Context, addr string) (releaseEntryMeta, error) {
	c.reads.Add(1)
	return c.mockChainReader.FetchReleaseEntryMeta(ctx, addr)
}

func (c *countingChainReader) FetchStoreReleaseListingMeta(ctx context.Context, addr string) (storeReleaseListingMeta, error) {
	c.reads.Add(1)
	return c.mockChainReader.FetchStoreReleaseListingMeta(ctx, addr)
}

func (c *countingChainReader) FetchStoreOperatorAuthz(ctx context.Context, addr string) (verify.AuthorizationStatus, verify.Pubkey, uint8, bool, [32]byte, error) {
	c.reads.Add(1)
	return c.mockChainReader.FetchStoreOperatorAuthz(ctx, addr)
}

func (c *countingChainReader) FetchBlacklistEntry(ctx context.Context, addr string) (bool, verify.BlacklistType, error) {
	c.reads.Add(1)
	return c.mockChainReader.FetchBlacklistEntry(ctx, addr)
}

// An appId that is not a row in this snapshot can never be served, yet the
// pointer route used to run the FULL catalog projection before discovering that
// -- about 96 getAccountInfo calls per 404, on an unauthenticated route anyone
// could pull on. That amplification is a direct contributor to the RPC key
// exhaustion that took the catalog down (F-235).
//
// The 404 itself is not new; only its position is. The positive control in the
// same test proves the counter works and that a REAL pointer still does chain
// work, so a zero on the unknown path cannot be a broken fixture.
func TestCatalogPointerUnknownAppIDCostsNoChainReads(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	operator := newTestIdentity(t, "pointer-amplifier", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = operator.Public().SignPubkeyB58
	prod := variantFixture(t, cfg, randPubkeyB58(t), "production")
	prodPackage := writeServeFixture(t, cfg.DistDir, prod)
	prodAppID := "app-" + prodPackage[:8]
	sourceCatalog, err := os.ReadFile(filepath.Join(cfg.DistDir, "apps", "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeProjectionPointer(t, cfg.DistDir, cfg, operator, prodAppID, prodPackage, prod, sourceCatalog)

	mock := newMockChainReader()
	pinReleaseActive(mock, prod)
	counting := &countingChainReader{mockChainReader: mock}
	gate := newServeGate(cfg, counting, http.FileServer(http.Dir(cfg.DistDir)), operator)
	gate.verifyTTL = 0

	// POSITIVE CONTROL: a real pointer must still do chain work.
	counting.reads.Store(0)
	if got := serveGet(t, gate, http.MethodGet, "/apps/pointers/"+prodAppID+".json"); got.Code != http.StatusOK {
		t.Fatalf("known pointer = %d: %s", got.Code, got.Body.String())
	}
	if counting.reads.Load() == 0 {
		t.Fatal("known pointer did no chain reads — the counter or fixture is broken, so a zero elsewhere proves nothing")
	}

	// THE AMPLIFIER: an appId with no pointer must 404 with ZERO chain reads.
	counting.reads.Store(0)
	got := serveGet(t, gate, http.MethodGet, "/apps/pointers/app-doesnotexist.json")
	if got.Code != http.StatusNotFound {
		t.Fatalf("unknown pointer = %d, want 404: %s", got.Code, got.Body.String())
	}
	if reads := counting.reads.Load(); reads != 0 {
		t.Fatalf("unknown appId cost %d chain reads, want 0 — the projection is still running before the existence check", reads)
	}
}
