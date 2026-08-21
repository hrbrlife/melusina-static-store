package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

func writeRPCAccountResponse(t *testing.T, w http.ResponseWriter, data []byte) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"value": map[string]any{
				"data":  []string{base64.StdEncoding.EncodeToString(data), "base64"},
				"owner": defaultLicenseProgramID,
			},
		},
	}); err != nil {
		t.Fatalf("encode RPC response: %v", err)
	}
}

func TestConfiguredRPCReader_RetriesRawCascadeReadThenUsesFallback(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		http.Error(w, "temporary upstream failure", http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	want := []byte("raw-cascade-account")
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		writeRPCAccountResponse(t, w, want)
	}))
	defer fallback.Close()

	reader := newConfiguredStoreRPCReader(Config{
		RPCURL:          primary.URL,
		RPCFallbackURLs: []string{fallback.URL},
		RPCAttempts:     2,
	}).(*rpcFailoverChainReader)
	reader.delay = 0
	data, owner, err := reader.fetchRawAccount(context.Background(), "cascade-account")
	if err != nil {
		t.Fatalf("fetchRawAccount: %v", err)
	}
	if !bytes.Equal(data, want) || owner != defaultLicenseProgramID {
		t.Fatalf("raw fallback = (%q, %q), want (%q, %q)", data, owner, want, defaultLicenseProgramID)
	}
	if calls := primaryCalls.Load(); calls != 2 {
		t.Fatalf("primary raw calls = %d, want bounded 2", calls)
	}
	if calls := fallbackCalls.Load(); calls != 1 {
		t.Fatalf("fallback raw calls = %d, want 1", calls)
	}
}

func TestConfiguredRPCReader_RetriesTransportFailureThenUsesFallback(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		http.Error(w, "temporary upstream failure", http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	var wantHash, wantAppID [32]byte
	for i := range wantHash {
		wantHash[i] = byte(i + 1)
		wantAppID[i] = byte(0xA0 + i)
	}
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		writeRPCAccountResponse(t, w, buildReleaseEntryBlobForTest(wantHash, wantAppID, [32]byte{}, "2.0.32", 1, verify.AttestationStatusActive))
	}))
	defer fallback.Close()

	reader := newConfiguredStoreRPCReader(Config{
		RPCURL:          primary.URL,
		RPCFallbackURLs: []string{fallback.URL},
		RPCAttempts:     2,
	}).(*rpcFailoverChainReader)
	reader.delay = 0
	got, err := reader.FetchReleaseEntryMeta(context.Background(), "release-entry")
	if err != nil {
		t.Fatalf("FetchReleaseEntryMeta: %v", err)
	}
	if got.AppHash != wantHash || got.AppID != wantAppID || got.Status != verify.AttestationStatusActive {
		t.Fatalf("unexpected fallback metadata: %+v", got)
	}
	if calls := primaryCalls.Load(); calls != 2 {
		t.Fatalf("primary calls = %d, want bounded 2", calls)
	}
	if calls := fallbackCalls.Load(); calls != 1 {
		t.Fatalf("fallback calls = %d, want 1", calls)
	}
}

func TestConfiguredRPCReader_DoesNotMaskDefinitiveChainDenial(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"value":null}}`))
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		http.Error(w, "fallback must not be contacted", http.StatusInternalServerError)
	}))
	defer fallback.Close()

	reader := newConfiguredStoreRPCReader(Config{
		RPCURL:          primary.URL,
		RPCFallbackURLs: []string{fallback.URL},
		RPCAttempts:     2,
	}).(*rpcFailoverChainReader)
	reader.delay = 0
	_, err := reader.FetchReleaseEntryMeta(context.Background(), "missing-release-entry")
	if !errors.Is(err, verify.ErrPDANotFound) {
		t.Fatalf("error = %v, want ErrPDANotFound", err)
	}
	if calls := primaryCalls.Load(); calls != 1 {
		t.Fatalf("primary calls = %d, want 1 definitive response", calls)
	}
	if calls := fallbackCalls.Load(); calls != 0 {
		t.Fatalf("fallback calls = %d, want 0 after definitive denial", calls)
	}
}

func TestConfiguredRPCReader_FailsClosedAfterBoundedTransportAttempts(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "unavailable", http.StatusBadGateway)
	}))
	defer server.Close()

	reader := newConfiguredStoreRPCReader(Config{RPCURL: server.URL, RPCAttempts: 2}).(*rpcFailoverChainReader)
	reader.delay = 0
	_, err := reader.FetchReleaseEntryMeta(context.Background(), "release-entry")
	if !errors.Is(err, verify.ErrRPCUnreachable) {
		t.Fatalf("error = %v, want ErrRPCUnreachable", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("calls = %d, want exactly 2 bounded attempts", got)
	}
}

// heliusQuotaExhaustedBody is the exact payload the live devnet provider returned on
// 2026-08-21 when the store's only trusted RPC key ran out of credits. It is reproduced
// verbatim because the two tests below turn on how it is DELIVERED, not what it says.
const heliusQuotaExhaustedBody = `{"jsonrpc":"2.0","error":{"code":-32429,"message":"max usage reached"}}`

// A quota-exhausted endpoint is an availability failure, not a chain verdict, so the reader
// must treat it as retryable and advance to the next trusted endpoint. This is the exact
// regression that took the default Bazaar catalog to HTTP 503 (F-235): the provider returned
// this body with HTTP 429, the store had one endpoint configured, and the catalog gate
// fail-closed. The suite previously covered only 503 and 502, so nothing pinned 429.
func TestConfiguredRPCReader_QuotaExhaustedHTTP429AdvancesToFallback(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(heliusQuotaExhaustedBody))
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	var wantHash, wantAppID [32]byte
	for i := range wantHash {
		wantHash[i] = byte(i + 1)
		wantAppID[i] = byte(0xA0 + i)
	}
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		writeRPCAccountResponse(t, w, buildReleaseEntryBlobForTest(wantHash, wantAppID, [32]byte{}, "2.0.33", 1, verify.AttestationStatusActive))
	}))
	defer fallback.Close()

	reader := newConfiguredStoreRPCReader(Config{
		RPCURL:          primary.URL,
		RPCFallbackURLs: []string{fallback.URL},
		RPCAttempts:     2,
	}).(*rpcFailoverChainReader)
	reader.delay = 0
	got, err := reader.FetchReleaseEntryMeta(context.Background(), "release-entry")
	if err != nil {
		t.Fatalf("FetchReleaseEntryMeta: %v", err)
	}
	if got.AppHash != wantHash || got.AppID != wantAppID || got.Status != verify.AttestationStatusActive {
		t.Fatalf("unexpected fallback metadata: %+v", got)
	}
	if calls := primaryCalls.Load(); calls != 2 {
		t.Fatalf("primary calls = %d, want bounded 2 before failover", calls)
	}
	if calls := fallbackCalls.Load(); calls != 1 {
		t.Fatalf("fallback calls = %d, want 1", calls)
	}
}

// The same quota error delivered with HTTP 200 does NOT reach the fallback, because
// classification is status-code-driven: verify.GetAccountInfo maps any status >= 400 to
// ErrRPCUnreachable BEFORE it parses the body, and a 200 carrying a JSON-RPC error instead
// yields a bare error that the failover loop treats as a definitive chain denial.
//
// This test pins CURRENT behaviour rather than desired behaviour, and it is deliberately a
// documented fragility: a provider that signals quota exhaustion as 200 + error body would
// silently defeat failover entirely and reproduce F-235 with every endpoint configured
// correctly. Closing it means typing the RPC error in the shared melusina-identity-gate
// module so quota/rate-limit codes are retryable while genuine denials stay definitive —
// that is a cross-repo change to a module the whole estate shares, tracked as its own work
// item. If this test ever starts failing because the fallback WAS contacted, that is the
// upstream fix landing, and the assertions below should be inverted deliberately.
func TestConfiguredRPCReader_QuotaExhaustedHTTP200DoesNotReachFallback(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(heliusQuotaExhaustedBody))
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		http.Error(w, "fallback must not be contacted", http.StatusInternalServerError)
	}))
	defer fallback.Close()

	reader := newConfiguredStoreRPCReader(Config{
		RPCURL:          primary.URL,
		RPCFallbackURLs: []string{fallback.URL},
		RPCAttempts:     2,
	}).(*rpcFailoverChainReader)
	reader.delay = 0
	_, err := reader.FetchReleaseEntryMeta(context.Background(), "release-entry")
	if err == nil {
		t.Fatal("FetchReleaseEntryMeta succeeded, want an error")
	}
	if errors.Is(err, verify.ErrRPCUnreachable) {
		t.Fatalf("error = %v, want a non-retryable error for a 200-delivered quota failure", err)
	}
	if calls := primaryCalls.Load(); calls != 1 {
		t.Fatalf("primary calls = %d, want 1 (treated as definitive, no retry)", calls)
	}
	if calls := fallbackCalls.Load(); calls != 0 {
		t.Fatalf("fallback calls = %d, want 0 — a 200-delivered quota error never fails over", calls)
	}
}
