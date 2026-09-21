package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func writeGenesisHashResponse(t *testing.T, w http.ResponseWriter, result string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  result,
	}); err != nil {
		t.Fatalf("encode getGenesisHash response: %v", err)
	}
}

func TestStoreRPCReaderFetchGenesisHashUsesTheExactRPCMethod(t *testing.T) {
	want := randPubkeyB58(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request = %s content-type=%q", r.Method, r.Header.Get("Content-Type"))
		}
		var request storeRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.JSONRPC != "2.0" || request.ID != 1 || request.Method != "getGenesisHash" || len(request.Params) != 0 {
			t.Fatalf("request = %+v", request)
		}
		writeGenesisHashResponse(t, w, want)
	}))
	defer server.Close()

	got, err := newStoreRPCReader(server.URL).FetchGenesisHash(context.Background())
	if err != nil {
		t.Fatalf("FetchGenesisHash: %v", err)
	}
	if got != want {
		t.Fatalf("genesis = %q, want %q", got, want)
	}
}

func TestConfiguredStoreGenesisReaderRetriesTransportThenUsesFallback(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		http.Error(w, "temporary upstream failure", http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	want := randPubkeyB58(t)
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		writeGenesisHashResponse(t, w, want)
	}))
	defer fallback.Close()

	reader := newConfiguredStoreRPCReader(Config{
		RPCURL:          primary.URL,
		RPCFallbackURLs: []string{fallback.URL},
		RPCAttempts:     2,
	}).(*rpcFailoverChainReader)
	reader.delay = 0
	got, err := reader.FetchGenesisHash(context.Background())
	if err != nil {
		t.Fatalf("FetchGenesisHash: %v", err)
	}
	if got != want {
		t.Fatalf("genesis = %q, want %q", got, want)
	}
	if calls := primaryCalls.Load(); calls != 2 {
		t.Fatalf("primary calls = %d, want 2", calls)
	}
	if calls := fallbackCalls.Load(); calls != 1 {
		t.Fatalf("fallback calls = %d, want 1", calls)
	}
}

func TestStoreRPCReaderFetchGenesisHashRefusesMalformedResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeGenesisHashResponse(t, w, "not-a-base58-pubkey")
	}))
	defer server.Close()

	_, err := newStoreRPCReader(server.URL).FetchGenesisHash(context.Background())
	if err == nil {
		t.Fatal("malformed getGenesisHash result accepted")
	}
}

func TestConfiguredStoreGenesisReaderDoesNotMaskMalformedResult(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		writeGenesisHashResponse(t, w, "not-a-base58-pubkey")
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		writeGenesisHashResponse(t, w, randPubkeyB58(t))
	}))
	defer fallback.Close()

	reader := newConfiguredStoreRPCReader(Config{
		RPCURL:          primary.URL,
		RPCFallbackURLs: []string{fallback.URL},
		RPCAttempts:     2,
	}).(*rpcFailoverChainReader)
	reader.delay = 0
	if _, err := reader.FetchGenesisHash(context.Background()); err == nil {
		t.Fatal("malformed primary getGenesisHash result accepted")
	}
	if calls := primaryCalls.Load(); calls != 1 {
		t.Fatalf("primary calls = %d, want one definitive response", calls)
	}
	if calls := fallbackCalls.Load(); calls != 0 {
		t.Fatalf("fallback calls = %d, want zero after malformed primary response", calls)
	}
}
