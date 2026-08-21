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
// TWO reads are request-invariant yet performed once per app row: the
// StoreOperatorAuthorization account, whose PDA comes from (licenseNftMint,
// storeDomainHash), and the blacklist account, whose PDA comes from the app's
// masterNftMint — one mint estate-wide, so every row asks for the same address. At 32 rows that is 32 identical reads of one address in a
// single request, and it is a large share of why one /apps/index.json cost ~128
// getAccountInfo calls and exhausted the store's RPC key (F-235).
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
	blacklist map[string]*blacklistEntry
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
		blacklist:   make(map[string]*blacklistEntry, 1),
	}
}

// blacklistEntry mirrors authzEntry for the second request-invariant read.
// verifyNotBlacklisted derives its PDA from the app's masterNftMint, and the
// estate publishes every app under ONE master mint, so all 32 rows ask for the
// same address. Keying on the address means this collapses when they match and
// simply does nothing when they do not — it never assumes they are equal.
type blacklistEntry struct {
	done    chan struct{}
	present bool
	kind    verify.BlacklistType
	err     error
}

func (m *memoChainReader) FetchBlacklistEntry(ctx context.Context, addrB58 string) (bool, verify.BlacklistType, error) {
	m.mu.Lock()
	entry, found := m.blacklist[addrB58]
	if !found {
		entry = &blacklistEntry{done: make(chan struct{})}
		m.blacklist[addrB58] = entry
	}
	m.mu.Unlock()

	if found {
		select {
		case <-entry.done:
			return entry.present, entry.kind, entry.err
		case <-ctx.Done():
			return false, 0, ctx.Err()
		}
	}

	present, kind, err := m.chainReader.FetchBlacklistEntry(ctx, addrB58)
	entry.present, entry.kind, entry.err = present, kind, err
	if ctx.Err() != nil {
		m.mu.Lock()
		if m.blacklist[addrB58] == entry {
			delete(m.blacklist, addrB58)
		}
		m.mu.Unlock()
	}
	close(entry.done)
	return present, kind, err
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
