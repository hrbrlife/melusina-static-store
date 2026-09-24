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
// exhausted the store's RPC key (F-235). Clearance reads (BlacklistStatusEntry)
// are memoized by address too: each app's App clearance is its own address, so
// the memo only collapses a clearance two rows share, and the catalog prime
// (store_catalog_prime.go) is what batches the per-app ones.
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
	authz     map[string]*authzEntry
	clearance map[string]*clearanceEntry
	// licence and reseller are the Store's own LicenseEntry and the
	// ResellerEntry it names (store_own_licence.go). Like the operator row they
	// are request-invariant, and every row's serve gate reads both.
	licence  map[string]*memoRead[storeLicenceEntry]
	reseller map[string]*memoRead[storeResellerEntry]
}

// authzEntry is one in-flight-or-settled read. done is closed when res is final.
type authzEntry struct {
	done chan struct{}
	res  authzResult
}

type authzResult struct {
	status          verify.AuthorizationStatus
	storeAuthority  verify.Pubkey
	allowedTierMask uint8
	isRoot          bool
	storeDomainHash [32]byte
	err             error
}

func newMemoChainReader(inner chainReader) *memoChainReader {
	return &memoChainReader{
		chainReader: inner,
		authz:       make(map[string]*authzEntry, 1),
		clearance:   make(map[string]*clearanceEntry, 1),
		licence:     make(map[string]*memoRead[storeLicenceEntry], 1),
		reseller:    make(map[string]*memoRead[storeResellerEntry], 1),
	}
}

// memoRead is one in-flight-or-settled read of one address, with the same
// single-flight and cancellation rules as authzEntry.
type memoRead[T any] struct {
	done  chan struct{}
	value T
	err   error
}

// readOnce answers addr from table, reading it through read at most once per
// request. A caller whose context dies while waiting returns its own error;
// an answer produced under a cancelled context is dropped from the table
// before the waiters see it, so the next fresh caller re-reads the chain.
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

func (m *memoChainReader) FetchLicenseEntry(ctx context.Context, addrB58 string) (storeLicenceEntry, error) {
	return readOnce(ctx, &m.mu, m.licence, addrB58, m.chainReader.FetchLicenseEntry)
}

func (m *memoChainReader) FetchResellerEntry(ctx context.Context, addrB58 string) (storeResellerEntry, error) {
	return readOnce(ctx, &m.mu, m.reseller, addrB58, m.chainReader.FetchResellerEntry)
}

// clearanceEntry mirrors authzEntry for a BlacklistStatusEntry read, keyed by
// its address: rows that share a clearance share one read, and rows that do
// not simply each read their own.
type clearanceEntry struct {
	done  chan struct{}
	entry blacklistStatusEntry
	err   error
}

func (m *memoChainReader) FetchBlacklistStatus(ctx context.Context, addrB58 string) (blacklistStatusEntry, error) {
	m.mu.Lock()
	entry, found := m.clearance[addrB58]
	if !found {
		entry = &clearanceEntry{done: make(chan struct{})}
		m.clearance[addrB58] = entry
	}
	m.mu.Unlock()

	if found {
		select {
		case <-entry.done:
			return entry.entry, entry.err
		case <-ctx.Done():
			return blacklistStatusEntry{}, ctx.Err()
		}
	}

	status, err := m.chainReader.FetchBlacklistStatus(ctx, addrB58)
	entry.entry, entry.err = status, err
	if ctx.Err() != nil {
		m.mu.Lock()
		if m.clearance[addrB58] == entry {
			delete(m.clearance, addrB58)
		}
		m.mu.Unlock()
	}
	close(entry.done)
	return status, err
}

func (m *memoChainReader) FetchStoreOperatorAuthz(ctx context.Context, addrB58 string) (verify.AuthorizationStatus, verify.Pubkey, uint8, bool, [32]byte, error) {
	m.mu.Lock()
	entry, found := m.authz[addrB58]
	if !found {
		entry = &authzEntry{done: make(chan struct{})}
		m.authz[addrB58] = entry
	}
	m.mu.Unlock()

	if found {
		// Someone else owns this address: wait for their answer rather than
		// issuing the duplicate read this type exists to remove. A caller whose
		// own context dies while waiting returns its own error and leaves the
		// in-flight read alone for the others.
		select {
		case <-entry.done:
			r := entry.res
			return r.status, r.storeAuthority, r.allowedTierMask, r.isRoot, r.storeDomainHash, r.err
		case <-ctx.Done():
			var authority verify.Pubkey
			var domainHash [32]byte
			return 0, authority, 0, false, domainHash, ctx.Err()
		}
	}

	status, authority, mask, isRoot, domainHash, err := m.chainReader.FetchStoreOperatorAuthz(ctx, addrB58)
	entry.res = authzResult{status, authority, mask, isRoot, domainHash, err}
	// A context cancellation is a property of the CALLER, not of the account, so
	// keeping it would poison every sibling row with one row's timeout. Drop the
	// entry first, then release the waiters onto that same non-authoritative
	// answer; the next fresh caller re-reads the chain.
	if ctx.Err() != nil {
		m.mu.Lock()
		if m.authz[addrB58] == entry {
			delete(m.authz, addrB58)
		}
		m.mu.Unlock()
	}
	close(entry.done)
	return status, authority, mask, isRoot, domainHash, err
}
