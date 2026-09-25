package main

import (
	"context"
	"sync"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// memoChainReader removes a read the catalog gate performs REDUNDANTLY, and only
// that. It is not a cache in the usual sense: its lifetime is one catalog
// request, it is discarded when that request returns, and it never survives to
// answer a later one.
//
// One read is request-invariant yet performed once per app row: the
// StoreOperatorAuthorization account, whose PDA comes from (licenseNftMint,
// storeDomainHash), so every row asks for the same address. At 32 rows that is
// 32 identical reads of one address in a single request, and it is a large
// share of why one /apps/index.json cost ~128 getAccountInfo calls and
// exhausted the store's RPC key (F-235). The Store's own LicenseEntry and the
// ResellerEntry it names (store_own_licence.go) are request-invariant in the
// same way: every row's serve gate holds the Store's licence to
// verify_license's rule, so each is read once per request. Clearance reads
// (BlacklistStatusEntry) are memoized by address too: each app's App clearance
// is its own address, so the memo only collapses a clearance two rows share,
// and the catalog prime (store_catalog_prime.go) is what batches the per-app
// ones.
//
// Nothing about verification changes. The same address is read, decoded by the
// same function, and judged by the same predicates in verify.go, which is not
// touched. The first read still goes to the chain; every later read of the SAME
// address within the SAME request reuses that exact answer. An error is memoized
// too, deliberately: a failure must not be retried 31 more times, and a row must
// never see a different verdict than its siblings for the same account.
// It is SINGLE-FLIGHT, not merely a lookaside map. The catalog gate starts its
// workers together, so a plain check-then-fetch lets every worker miss before the
// first answer lands and issue the very read being eliminated. That is a
// thundering herd: mostly harmless in a quiet test, and worst exactly when the
// request is busiest. Concurrent callers for one address wait on the first
// caller's result instead.
type memoChainReader struct {
	chainReader
	mu        sync.Mutex
	authz     map[string]*memoRead[authzResult]
	clearance map[string]*memoRead[*verify.Account]
	licence   map[string]*memoRead[licenseEntryHead]
	reseller  map[string]*memoRead[verify.ResellerEntry]
}

// authzResult is one StoreOperatorAuthorization read, held as one value.
type authzResult struct {
	status          verify.AuthorizationStatus
	storeAuthority  verify.Pubkey
	allowedTierMask uint8
	isRoot          bool
	storeDomainHash [32]byte
}

func newMemoChainReader(inner chainReader) *memoChainReader {
	return &memoChainReader{
		chainReader: inner,
		authz:       make(map[string]*memoRead[authzResult], 1),
		clearance:   make(map[string]*memoRead[*verify.Account], 1),
		licence:     make(map[string]*memoRead[licenseEntryHead], 1),
		reseller:    make(map[string]*memoRead[verify.ResellerEntry], 1),
	}
}

// memoRead is one in-flight-or-settled read of one address. done is closed
// when value and err are final.
type memoRead[T any] struct {
	done  chan struct{}
	value T
	err   error
}

// readOnce answers addr from table, reading it through read at most once per
// request; every memoized read goes through it.
//
// Someone else owning an address means waiting for their answer rather than
// issuing the duplicate read this type exists to remove. A caller whose own
// context dies while waiting returns its own error and leaves the in-flight
// read alone for the others. A context cancellation is a property of the
// CALLER, not of the account, so keeping it would poison every sibling row
// with one row's timeout: an answer produced under a cancelled context is
// dropped from the table first, then the waiters are released onto that same
// non-authoritative answer, and the next fresh caller re-reads the chain.
func readOnce[T any](ctx context.Context, mu *sync.Mutex, table map[string]*memoRead[T], addr string, read func(context.Context, string) (T, error)) (T, error) {
	mu.Lock()
	entry, found := table[addr]
	if !found {
		entry = &memoRead[T]{done: make(chan struct{})}
		table[addr] = entry
	}
	mu.Unlock()

	if found {
		select {
		case <-entry.done:
			return entry.value, entry.err
		case <-ctx.Done():
			var zero T
			return zero, ctx.Err()
		}
	}

	entry.value, entry.err = read(ctx, addr)
	if ctx.Err() != nil {
		mu.Lock()
		if table[addr] == entry {
			delete(table, addr)
		}
		mu.Unlock()
	}
	close(entry.done)
	return entry.value, entry.err
}

// FetchBlacklistStatusAccount is keyed by the clearance's address: rows that
// share a clearance share one read, and rows that do not simply each read their
// own. Every row hands the same account to verify.RequireBlacklistClear, which
// never modifies it.
func (m *memoChainReader) FetchBlacklistStatusAccount(ctx context.Context, addrB58 string) (*verify.Account, error) {
	return readOnce(ctx, &m.mu, m.clearance, addrB58, m.chainReader.FetchBlacklistStatusAccount)
}

func (m *memoChainReader) FetchStoreOperatorAuthz(ctx context.Context, addrB58 string) (verify.AuthorizationStatus, verify.Pubkey, uint8, bool, [32]byte, error) {
	r, err := readOnce(ctx, &m.mu, m.authz, addrB58, func(ctx context.Context, addr string) (authzResult, error) {
		status, authority, mask, isRoot, domainHash, err := m.chainReader.FetchStoreOperatorAuthz(ctx, addr)
		return authzResult{status, authority, mask, isRoot, domainHash}, err
	})
	return r.status, r.storeAuthority, r.allowedTierMask, r.isRoot, r.storeDomainHash, err
}

func (m *memoChainReader) FetchLicenseEntry(ctx context.Context, addrB58 string) (licenseEntryHead, error) {
	return readOnce(ctx, &m.mu, m.licence, addrB58, m.chainReader.FetchLicenseEntry)
}

func (m *memoChainReader) FetchResellerEntry(ctx context.Context, addrB58 string) (verify.ResellerEntry, error) {
	return readOnce(ctx, &m.mu, m.reseller, addrB58, m.chainReader.FetchResellerEntry)
}
