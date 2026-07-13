package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testPublishNonceLedgerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestPublishNonceLedgerClaimReplayAndRestart(t *testing.T) {
	now := time.UnixMilli(1_720_000_000_000)
	root, opts := newTestPublishNonceLedger(t, now, 4)
	ledger := openTestPublishNonceLedger(t, root, opts)
	payloadHash := strings.Repeat("a", 64)

	if err := ledger.Claim("source|destination", "nonce-one", payloadHash, now.Add(time.Minute).UnixMilli(), now); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := ledger.Claim("source|destination", "nonce-one", payloadHash, now.Add(time.Minute).UnixMilli(), now); !errors.Is(err, errPublishNonceReplay) {
		t.Fatalf("same-process replay = %v, want replay", err)
	}

	restarted := openTestPublishNonceLedger(t, root, opts)
	if err := restarted.Claim("source|destination", "nonce-one", payloadHash, now.Add(time.Minute).UnixMilli(), now); !errors.Is(err, errPublishNonceReplay) {
		t.Fatalf("restart replay = %v, want replay", err)
	}
}

func TestPublishNonceLedgerScopeIsLengthDelimited(t *testing.T) {
	left := publishNonceKey("ab", "c")
	right := publishNonceKey("a", "bc")
	if left == right {
		t.Fatal("length-delimited tuples collided")
	}
}

func TestPublishNonceLedgerRejectsExpiredClaimBeforeMutation(t *testing.T) {
	now := time.UnixMilli(1_720_000_000_000)
	root, opts := newTestPublishNonceLedger(t, now, 2)
	ledger := openTestPublishNonceLedger(t, root, opts)
	err := ledger.Claim("scope", "nonce", strings.Repeat("b", 64), now.Add(-time.Millisecond).UnixMilli(), now)
	if !errors.Is(err, errPublishNonceExpired) {
		t.Fatalf("expired claim = %v", err)
	}
	if got := claimEntryCount(t, root); got != 0 {
		t.Fatalf("expired claim created %d markers", got)
	}
}

func TestPublishNonceLedgerGCIsStrictlyPastExpiry(t *testing.T) {
	now := time.UnixMilli(1_720_000_000_000)
	expires := now.Add(time.Second)
	root, opts := newTestPublishNonceLedger(t, now, 2)
	ledger := openTestPublishNonceLedger(t, root, opts)
	if err := ledger.Claim("scope", "nonce", strings.Repeat("c", 64), expires.UnixMilli(), now); err != nil {
		t.Fatal(err)
	}

	opts.Now = func() time.Time { return expires }
	_ = openTestPublishNonceLedger(t, root, opts)
	if got := claimEntryCount(t, root); got != 1 {
		t.Fatalf("marker count at exact expiry = %d, want 1", got)
	}

	opts.Now = func() time.Time { return expires.Add(time.Millisecond) }
	_ = openTestPublishNonceLedger(t, root, opts)
	if got := claimEntryCount(t, root); got != 0 {
		t.Fatalf("marker count strictly past expiry = %d, want 0", got)
	}
}

func TestPublishNonceLedgerClockRollbackFailsClosed(t *testing.T) {
	now := time.UnixMilli(1_720_000_000_000)
	root, opts := newTestPublishNonceLedger(t, now, 2)
	ledger := openTestPublishNonceLedger(t, root, opts)
	if err := ledger.Claim("scope", "nonce", strings.Repeat("d", 64), now.Add(time.Hour).UnixMilli(), now); err != nil {
		t.Fatal(err)
	}

	rolledBack := opts
	rolledBack.Now = func() time.Time { return now.Add(-time.Millisecond) }
	if _, err := openPublishNonceLedger(root, testPublishNonceLedgerID, rolledBack); !errors.Is(err, errPublishNonceClockRollback) {
		t.Fatalf("rollback open = %v", err)
	}
	if err := ledger.Claim("scope", "other", strings.Repeat("e", 64), now.Add(time.Hour).UnixMilli(), now.Add(-time.Millisecond)); !errors.Is(err, errPublishNonceClockRollback) {
		t.Fatalf("rollback claim = %v", err)
	}
	if err := ledger.CheckClock(now.Add(-time.Millisecond)); !errors.Is(err, errPublishNonceClockRollback) {
		t.Fatalf("pre-verification rollback check = %v", err)
	}
}

func TestPublishNonceLedgerManifestDetectsMissingAndReplaced(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, path string)
	}{
		{"missing", func(t *testing.T, path string) { mustRemove(t, path) }},
		{"replaced", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("replacement\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.UnixMilli(1_720_000_000_000)
			root, opts := newTestPublishNonceLedger(t, now, 2)
			ledger := openTestPublishNonceLedger(t, root, opts)
			if err := ledger.Claim("scope", "nonce", strings.Repeat("f", 64), now.Add(time.Hour).UnixMilli(), now); err != nil {
				t.Fatal(err)
			}
			marker := onlyClaimPath(t, root)
			tc.mutate(t, marker)
			if _, err := openPublishNonceLedger(root, testPublishNonceLedgerID, opts); err == nil {
				t.Fatal("open accepted a missing/replaced listed marker")
			}
		})
	}
}

func TestPublishNonceLedgerExtraMarkerIsConservativelyBurned(t *testing.T) {
	now := time.UnixMilli(1_720_000_000_000)
	root, opts := newTestPublishNonceLedger(t, now, 2)
	ledger := openTestPublishNonceLedger(t, root, opts)
	realSync := ledger.syncFile
	var calls atomic.Int32
	ledger.syncFile = func(f *os.File) error {
		if calls.Add(1) == 3 { // pre-claim state, marker, then marker-manifest state
			return errors.New("injected state fsync failure")
		}
		return realSync(f)
	}
	err := ledger.Claim("scope", "nonce", strings.Repeat("1", 64), now.Add(time.Hour).UnixMilli(), now)
	if err == nil || !strings.Contains(err.Error(), "injected state fsync failure") {
		t.Fatalf("claim fault = %v", err)
	}
	if got := claimEntryCount(t, root); got != 1 {
		t.Fatalf("uncertain claim marker count = %d", got)
	}

	restarted := openTestPublishNonceLedger(t, root, opts)
	if err := restarted.Claim("scope", "nonce", strings.Repeat("1", 64), now.Add(time.Hour).UnixMilli(), now); !errors.Is(err, errPublishNonceReplay) {
		t.Fatalf("uncertain claim replay = %v", err)
	}
}

func TestPublishNonceLedgerMalformedValidNameCountsAndNeverGCs(t *testing.T) {
	now := time.UnixMilli(1_720_000_000_000)
	root, opts := newTestPublishNonceLedger(t, now, 1)
	name := strings.Repeat("2", 64)
	if err := os.WriteFile(filepath.Join(root, publishNonceClaimsDirName, name), []byte("truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishNonceSyncDir(filepath.Join(root, publishNonceClaimsDirName)); err != nil {
		t.Fatal(err)
	}
	ledger := openTestPublishNonceLedger(t, root, opts)
	if err := ledger.Claim("scope", "new", strings.Repeat("3", 64), now.Add(24*time.Hour).UnixMilli(), now); !errors.Is(err, errPublishNonceCapacity) {
		t.Fatalf("claim with malformed marker at cap = %v", err)
	}
	later := opts
	later.Now = func() time.Time { return now.Add(365 * 24 * time.Hour) }
	if _, err := openPublishNonceLedger(root, testPublishNonceLedgerID, later); err != nil {
		t.Fatalf("malformed marker should remain conservatively manifestable: %v", err)
	}
	if got := claimEntryCount(t, root); got != 1 {
		t.Fatalf("malformed marker was collected, count=%d", got)
	}
}

func TestPublishNonceLedgerConcurrentSameNonceOneWinner(t *testing.T) {
	now := time.UnixMilli(1_720_000_000_000)
	root, opts := newTestPublishNonceLedger(t, now, 4)
	first := openTestPublishNonceLedger(t, root, opts)
	second := openTestPublishNonceLedger(t, root, opts)
	errs := concurrentClaims(
		func() error {
			return first.Claim("scope", "same", strings.Repeat("4", 64), now.Add(time.Hour).UnixMilli(), now)
		},
		func() error {
			return second.Claim("scope", "same", strings.Repeat("4", 64), now.Add(time.Hour).UnixMilli(), now)
		},
	)
	assertOneSuccessOneError(t, errs, errPublishNonceReplay)
	if got := claimEntryCount(t, root); got != 1 {
		t.Fatalf("same-nonce race markers = %d", got)
	}
}

func TestPublishNonceLedgerConcurrentCapacityAtMostOneAddition(t *testing.T) {
	now := time.UnixMilli(1_720_000_000_000)
	root, opts := newTestPublishNonceLedger(t, now, 2)
	seed := openTestPublishNonceLedger(t, root, opts)
	if err := seed.Claim("scope", "seed", strings.Repeat("5", 64), now.Add(time.Hour).UnixMilli(), now); err != nil {
		t.Fatal(err)
	}
	first := openTestPublishNonceLedger(t, root, opts)
	second := openTestPublishNonceLedger(t, root, opts)
	errs := concurrentClaims(
		func() error {
			return first.Claim("scope", "left", strings.Repeat("6", 64), now.Add(time.Hour).UnixMilli(), now)
		},
		func() error {
			return second.Claim("scope", "right", strings.Repeat("7", 64), now.Add(time.Hour).UnixMilli(), now)
		},
	)
	assertOneSuccessOneError(t, errs, errPublishNonceCapacity)
	if got := claimEntryCount(t, root); got != 2 {
		t.Fatalf("capacity race markers = %d, want 2", got)
	}
}

func TestOpenPublishNonceLedgerNeverCreatesMissingState(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, publishNonceLedgerDirName)
	opts := defaultPublishNonceLedgerOptions()
	opts.Capacity = 2
	if _, err := openPublishNonceLedger(root, testPublishNonceLedgerID, opts); err == nil {
		t.Fatal("open created or accepted missing ledger")
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime open mutated missing root: %v", err)
	}

	now := time.UnixMilli(1_720_000_000_000)
	root, opts = newTestPublishNonceLedger(t, now, 2)
	mustRemove(t, filepath.Join(root, publishNonceStateFileName))
	if _, err := openPublishNonceLedger(root, testPublishNonceLedgerID, opts); err == nil {
		t.Fatal("open accepted missing state")
	}
	if _, err := os.Lstat(filepath.Join(root, publishNonceStateFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime open recreated state: %v", err)
	}
}

func TestOpenPublishNonceLedgerRejectsUnsafeMarker(t *testing.T) {
	now := time.UnixMilli(1_720_000_000_000)
	root, opts := newTestPublishNonceLedger(t, now, 2)
	name := strings.Repeat("8", 64)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, publishNonceClaimsDirName, name)); err != nil {
		t.Fatal(err)
	}
	if _, err := openPublishNonceLedger(root, testPublishNonceLedgerID, opts); err == nil {
		t.Fatal("open accepted symlink marker")
	}
}

func newTestPublishNonceLedger(t *testing.T, now time.Time, capacity int) (string, publishNonceLedgerOptions) {
	t.Helper()
	root := filepath.Join(t.TempDir(), publishNonceLedgerDirName)
	opts := defaultPublishNonceLedgerOptions()
	opts.Capacity = capacity
	opts.Now = func() time.Time { return now }
	if err := initializePublishNonceLedger(root, testPublishNonceLedgerID, opts); err != nil {
		t.Fatalf("initialize nonce ledger: %v", err)
	}
	return root, opts
}

func openTestPublishNonceLedger(t *testing.T, root string, opts publishNonceLedgerOptions) *publishNonceLedger {
	t.Helper()
	ledger, err := openPublishNonceLedger(root, testPublishNonceLedgerID, opts)
	if err != nil {
		t.Fatalf("open nonce ledger: %v", err)
	}
	return ledger
}

func claimEntryCount(t *testing.T, root string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, publishNonceClaimsDirName))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func onlyClaimPath(t *testing.T, root string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, publishNonceClaimsDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("claim entries = %d, want 1", len(entries))
	}
	return filepath.Join(root, publishNonceClaimsDirName, entries[0].Name())
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func concurrentClaims(fns ...func() error) []error {
	start := make(chan struct{})
	errs := make([]error, len(fns))
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Add(1)
		go func(i int, fn func() error) {
			defer wg.Done()
			<-start
			errs[i] = fn()
		}(i, fn)
	}
	close(start)
	wg.Wait()
	return errs
}

func assertOneSuccessOneError(t *testing.T, errs []error, want error) {
	t.Helper()
	var successes, matches int
	for _, err := range errs {
		if err == nil {
			successes++
		} else if errors.Is(err, want) {
			matches++
		} else {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if successes != 1 || matches != 1 {
		t.Fatalf("concurrent results = %v; successes=%d %s=%d", errs, successes, fmt.Sprint(want), matches)
	}
}
