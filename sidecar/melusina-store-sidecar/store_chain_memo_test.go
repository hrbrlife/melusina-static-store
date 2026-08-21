package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// The embedded chainReader is deliberately nil: if the memo ever forwards a
// method it has no business intercepting, the test panics instead of silently
// passing. Only FetchStoreOperatorAuthz is implemented here.
type countingAuthzReader struct {
	chainReader
	calls atomic.Int32
	err   error
}

func (c *countingAuthzReader) FetchStoreOperatorAuthz(_ context.Context, _ string) (verify.AuthorizationStatus, verify.Pubkey, uint8, bool, [32]byte, error) {
	c.calls.Add(1)
	var authority verify.Pubkey
	authority[0] = 0xAB
	var domain [32]byte
	domain[0] = 0xCD
	return verify.AuthorizationStatus(0), authority, 0x01, true, domain, c.err
}

// The live shape: one request, 32 app rows, all reading the SAME
// request-invariant StoreOperatorAuthorization address. That cost 32 chain reads
// and is a large share of why one catalog page exhausted the RPC key (F-235).
func TestMemoChainReaderCollapsesTheRequestInvariantAuthzRead(t *testing.T) {
	inner := &countingAuthzReader{}
	memo := newMemoChainReader(inner)
	const rows = 32
	const addr = "CvQ1KRa9LiKDW4ZjY414UbpChYt4HV4SAX3hwhNMnnK5"

	var wg sync.WaitGroup
	results := make([]verify.Pubkey, rows)
	for i := 0; i < rows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, authority, _, _, _, err := memo.FetchStoreOperatorAuthz(context.Background(), addr)
			if err != nil {
				t.Errorf("row %d: %v", i, err)
			}
			results[i] = authority
		}(i)
	}
	wg.Wait()

	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("chain reads = %d for %d rows, want exactly 1", got, rows)
	}
	for i, authority := range results {
		if authority[0] != 0xAB {
			t.Fatalf("row %d got a different answer than its siblings: %x", i, authority[0])
		}
	}
	// A DIFFERENT address must still reach the chain — the memo keys on address,
	// it does not blanket-answer every authz read.
	if _, _, _, _, _, err := memo.FetchStoreOperatorAuthz(context.Background(), "AnotherAddressEntirely111111111111111111111"); err != nil {
		t.Fatal(err)
	}
	if got := inner.calls.Load(); got != 2 {
		t.Fatalf("chain reads = %d after a second distinct address, want 2", got)
	}
}

// A failure must be memoized too: retrying it 31 more times is the amplification
// being removed, and two rows must never disagree about the same account.
func TestMemoChainReaderMemoizesFailureWithinTheRequest(t *testing.T) {
	inner := &countingAuthzReader{err: errors.New("chain says no")}
	memo := newMemoChainReader(inner)
	for i := 0; i < 5; i++ {
		if _, _, _, _, _, err := memo.FetchStoreOperatorAuthz(context.Background(), "addr"); err == nil {
			t.Fatal("memoized failure surfaced as success")
		}
	}
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("chain reads = %d, want 1 — a failure must not be retried per row", got)
	}
}

// A cancellation belongs to the CALLER, not the account. Memoizing it would let
// one row's timeout poison every sibling row in the same request.
func TestMemoChainReaderDoesNotMemoizeACancelledRead(t *testing.T) {
	inner := &countingAuthzReader{}
	memo := newMemoChainReader(inner)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, _, _, _ = memo.FetchStoreOperatorAuthz(ctx, "addr")
	if _, _, _, _, _, err := memo.FetchStoreOperatorAuthz(context.Background(), "addr"); err != nil {
		t.Fatal(err)
	}
	if got := inner.calls.Load(); got != 2 {
		t.Fatalf("chain reads = %d, want 2 — a cancelled read must not be memoized", got)
	}
}
