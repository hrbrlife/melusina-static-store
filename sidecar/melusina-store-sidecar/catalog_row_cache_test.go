package main

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type catalogRowCountingReader struct {
	chainReader
	listingReads atomic.Int32
}

func (r *catalogRowCountingReader) FetchStoreReleaseListingMeta(ctx context.Context, addr string) (storeReleaseListingMeta, error) {
	r.listingReads.Add(1)
	return r.chainReader.FetchStoreReleaseListingMeta(ctx, addr)
}

func TestServeCatalogIndex_VerifiedRowCacheSkipsRPCUntilExpiry(t *testing.T) {
	cfg, chain, fixture, _, _ := serveSetup(t)
	pinReleaseActive(chain, fixture)
	cfg.CatalogVerifiedRowTTLSeconds = 10
	reader := &catalogRowCountingReader{chainReader: chain}
	gate := newServeGate(cfg, reader, http.FileServer(http.Dir(cfg.DistDir)))
	gate.verifyTTL = 0
	now := time.Unix(100, 0)
	gate.now = func() time.Time { return now }
	for request := 1; request <= 2; request++ {
		response := serveGet(t, gate, http.MethodGet, "/apps/index.json")
		if response.Code != http.StatusOK {
			t.Fatalf("catalog request %d = %d: %s", request, response.Code, response.Body.String())
		}
	}
	if got := reader.listingReads.Load(); got != 1 {
		t.Fatalf("warm exact signed row caused %d listing RPC reads, want one", got)
	}
	now = now.Add(10 * time.Second)
	response := serveGet(t, gate, http.MethodGet, "/apps/index.json")
	if response.Code != http.StatusOK {
		t.Fatalf("expired catalog request = %d: %s", response.Code, response.Body.String())
	}
	if got := reader.listingReads.Load(); got != 2 {
		t.Fatalf("expired row caused %d listing RPC reads, want two", got)
	}
}

func TestCatalogRowCacheReusesOnlyExactPositiveVerdictWithinTTL(t *testing.T) {
	now := time.Unix(100, 0)
	g := &serveGate{catalogRowTTL: 10 * time.Second, now: func() time.Time { return now },
		catalogRowVerdict: make(map[string]time.Time), catalogRowFlights: make(map[string]*catalogRowFlight)}
	calls := 0
	verify := func() error { calls++; return nil }
	for _, key := range []string{"hash:app:row-a", "hash:app:row-a"} {
		if err := g.verifyCatalogRow(context.Background(), key, verify); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("same verified row caused %d chain checks, want one", calls)
	}
	now = now.Add(9 * time.Second)
	if err := g.verifyCatalogRow(context.Background(), "hash:app:row-a", verify); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("unexpired verified row caused %d chain checks", calls)
	}
	if err := g.verifyCatalogRow(context.Background(), "hash:app:row-b", verify); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("changed signed row reused old verdict: %d checks", calls)
	}
	now = now.Add(time.Second)
	if err := g.verifyCatalogRow(context.Background(), "hash:app:row-a", verify); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("expired row reused stale verdict: %d checks", calls)
	}
	refusal := errors.New("chain listing delisted")
	refusedCalls := 0
	for range 2 {
		if err := g.verifyCatalogRow(context.Background(), "hash:app:delisted", func() error { refusedCalls++; return refusal }); !errors.Is(err, refusal) {
			t.Fatalf("refusal changed: %v", err)
		}
	}
	if refusedCalls != 2 {
		t.Fatalf("delisted row was cached after %d checks", refusedCalls)
	}
}
