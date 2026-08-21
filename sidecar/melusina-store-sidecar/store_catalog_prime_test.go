package main

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// batchStub is a batch-capable source. The embedded chainReader is nil so any
// unexpected forwarding panics rather than silently passing.
type batchStub struct {
	chainReader
	calls    atomic.Int32
	addrSeen []string
	answer   func(addr string) accountValue
	failWith error
	shortBy  int
}

func (b *batchStub) fetchMultipleAccounts(_ context.Context, addrs []string) ([]accountValue, error) {
	b.calls.Add(1)
	b.addrSeen = append(b.addrSeen, addrs...)
	if b.failWith != nil {
		return nil, b.failWith
	}
	out := make([]accountValue, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, b.answer(a))
	}
	return out[:len(out)-b.shortBy], nil
}

// liveCountingReader counts per-row reads that reach the LIVE path.
type liveCountingReader struct {
	chainReader
	release atomic.Int32
	listing atomic.Int32
}

func (l *liveCountingReader) FetchReleaseEntryMeta(_ context.Context, _ string) (releaseEntryMeta, error) {
	l.release.Add(1)
	return releaseEntryMeta{}, nil
}

func (l *liveCountingReader) FetchStoreReleaseListingMeta(_ context.Context, _ string) (storeReleaseListingMeta, error) {
	l.listing.Add(1)
	return storeReleaseListingMeta{}, nil
}

func primeTestFixture(t *testing.T, rows int) (Config, []catalogGateCandidate, []string) {
	t.Helper()
	cfg, _ := testConfig(t)
	// Supply real key material rather than skipping when the shared fixture has
	// none. A skipped test is indistinguishable from a passing one in CI, and the
	// whole point here is to prove the prime ENGAGES.
	cfg.StoreAuthority = randPubkeyB58(t)
	cfg.ReleaseMasterNftMint = randPubkeyB58(t)
	storeAuthority, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.StoreAuthority))
	if err != nil {
		t.Fatalf("store authority fixture unusable: %v", err)
	}
	master := cfg.ReleaseMasterNftMint
	masterMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(master))
	if err != nil {
		t.Fatalf("master mint fixture unusable: %v", err)
	}
	candidates := make([]catalogGateCandidate, 0, rows)
	var want []string
	for i := 0; i < rows; i++ {
		var raw [32]byte
		raw[0] = byte(i + 1)
		appHashHex := hex.EncodeToString(raw[:])
		candidates = append(candidates, catalogGateCandidate{
			appID: appHashHex[:8],
			app:   servedApp{rel: ReleaseJSON{AppHash: appHashHex, MasterNftMint: master}},
		})
		relPDA, _, err := pda.Release(masterMint, raw, programID)
		if err != nil {
			t.Fatal(err)
		}
		listingPDA, _, err := pda.StoreReleaseListing(storeAuthority, raw, programID)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, relPDA.Base58(), listingPDA.Base58())
	}
	return cfg, candidates, want
}

// THE TRAP. memoChainReader embeds a chainReader INTERFACE, which does not
// declare fetchMultipleAccounts, so asserting batch support on the fall-through
// reader can never succeed however capable the concrete reader beneath it is.
// A version that did so would compile, pass every test that does not count
// reads, deploy, and prime nothing at all. This pins the separation.
func TestPrimeCatalogAccountsEngagesThroughAMemoWrapper(t *testing.T) {
	cfg, candidates, want := primeTestFixture(t, 32)
	stub := &batchStub{answer: func(addr string) accountValue {
		return accountValue{data: []byte("account:" + addr), present: true}
	}}
	live := &liveCountingReader{}
	inner := chainReader(newMemoChainReader(live))

	primed := primeCatalogAccounts(context.Background(), cfg, inner, stub, candidates)
	if primed == inner {
		t.Fatal("prime did not engage — it fell through, so the batch never happens (the silent no-op)")
	}
	if got := stub.calls.Load(); got != 1 {
		t.Fatalf("batch calls = %d, want exactly 1 for %d rows", got, len(candidates))
	}
	if len(stub.addrSeen) != len(want) {
		t.Fatalf("batched %d addresses, want %d (2 per row)", len(stub.addrSeen), len(want))
	}
	// Every read must now be answered from the snapshot, not the live reader.
	for _, addr := range want {
		if _, err := primed.FetchReleaseEntryMeta(context.Background(), addr); err != nil {
			// decode failure is fine here; reaching the LIVE reader is not
			_ = err
		}
	}
	if live.release.Load() != 0 {
		t.Fatalf("%d release reads reached the live reader despite being primed", live.release.Load())
	}
}

// Without batch support the prime must return the reader UNCHANGED, so the
// request still works exactly as before.
func TestPrimeCatalogAccountsFallsThroughWithoutBatchSupport(t *testing.T) {
	cfg, candidates, _ := primeTestFixture(t, 4)
	live := &liveCountingReader{}
	inner := chainReader(live)
	if got := primeCatalogAccounts(context.Background(), cfg, inner, struct{}{}, candidates); got != inner {
		t.Fatal("prime replaced the reader despite the source having no batch support")
	}
}

// A failed batch must NOT fail the request: it degrades to live reads.
func TestPrimeCatalogAccountsDegradesOnBatchFailure(t *testing.T) {
	cfg, candidates, _ := primeTestFixture(t, 4)
	live := &liveCountingReader{}
	inner := chainReader(live)
	stub := &batchStub{failWith: errors.New("rpc down"), answer: func(string) accountValue { return accountValue{} }}
	if got := primeCatalogAccounts(context.Background(), cfg, inner, stub, candidates); got != inner {
		t.Fatal("a failed batch must degrade to the unmodified reader, not a partial snapshot")
	}
	short := &batchStub{shortBy: 1, answer: func(addr string) accountValue { return accountValue{data: []byte("x"), present: true} }}
	if got := primeCatalogAccounts(context.Background(), cfg, inner, short, candidates); got != inner {
		t.Fatal("a short batch answer must degrade rather than mis-associate slots")
	}
}

// An account the batch reported ABSENT must surface as ErrPDANotFound — the same
// fail-closed answer the live path gives — never as an empty success.
func TestPrimedReaderSurfacesAbsentAccountsAsNotFound(t *testing.T) {
	live := &liveCountingReader{}
	primed := &primedChainReader{
		chainReader: live,
		snap:        map[string]accountValue{"absent-pda": {present: false}},
	}
	if _, err := primed.FetchReleaseEntryMeta(context.Background(), "absent-pda"); !errors.Is(err, verify.ErrPDANotFound) {
		t.Fatalf("absent release entry = %v, want ErrPDANotFound", err)
	}
	if _, err := primed.FetchStoreReleaseListingMeta(context.Background(), "absent-pda"); !errors.Is(err, verify.ErrPDANotFound) {
		t.Fatalf("absent listing = %v, want ErrPDANotFound", err)
	}
	if live.release.Load() != 0 || live.listing.Load() != 0 {
		t.Fatal("an absent primed account must not fall through to a live read")
	}
}
