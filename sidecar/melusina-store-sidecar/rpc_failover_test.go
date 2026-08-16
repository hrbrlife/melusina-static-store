package main

import (
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
				"data": []string{base64.StdEncoding.EncodeToString(data), "base64"},
			},
		},
	}); err != nil {
		t.Fatalf("encode RPC response: %v", err)
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
		writeRPCAccountResponse(t, w, buildReleaseEntryBlobForTest(wantHash, wantAppID, "2.0.32", 1, verify.AttestationStatusActive))
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
