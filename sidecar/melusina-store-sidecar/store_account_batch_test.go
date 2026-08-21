package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

func batchServer(t *testing.T, calls *atomic.Int32, sizes *[]int, handler func(addrs []string) any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Params []json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Errorf("bad request: %v", err)
		}
		var addrs []string
		if err := json.Unmarshal(req.Params[0], &addrs); err != nil {
			t.Errorf("bad addrs: %v", err)
		}
		if sizes != nil {
			*sizes = append(*sizes, len(addrs))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(handler(addrs))
	}))
}

func accountSlot(payload string) map[string]any {
	return map[string]any{"data": []string{base64.StdEncoding.EncodeToString([]byte(payload)), "base64"}}
}

// Slot i must BE address i, and a null slot must mean "the chain answered: this
// account does not exist" — a definitive answer, never confused with a transport
// failure. Mis-association here would let one app's account authorize another.
func TestFetchMultipleAccountsMapsSlotsPositionally(t *testing.T) {
	var calls atomic.Int32
	srv := batchServer(t, &calls, nil, func(addrs []string) any {
		value := make([]any, len(addrs))
		for i, a := range addrs {
			if a == "absent" {
				value[i] = nil
				continue
			}
			value[i] = accountSlot("data-for-" + a)
		}
		return map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"value": value}}
	})
	defer srv.Close()

	got, err := newStoreRPCReader(srv.URL).fetchMultipleAccounts(context.Background(), []string{"a", "absent", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("slots = %d, want 3", len(got))
	}
	if !got[0].present || string(got[0].data) != "data-for-a" {
		t.Fatalf("slot 0 = %+v", got[0])
	}
	if got[1].present {
		t.Fatal("slot 1 must be absent, not present — a missing PDA must stay fail-closed")
	}
	if !got[2].present || string(got[2].data) != "data-for-c" {
		t.Fatalf("slot 2 = %+v", got[2])
	}
}

// A length disagreement means the answer cannot be attributed to the requested
// addresses. Refusing is the only safe option; silently zipping would be the
// mis-association bug.
func TestFetchMultipleAccountsRefusesLengthMismatch(t *testing.T) {
	var calls atomic.Int32
	srv := batchServer(t, &calls, nil, func(addrs []string) any {
		return map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"value": []any{accountSlot("only-one")}}}
	})
	defer srv.Close()
	_, err := newStoreRPCReader(srv.URL).fetchMultipleAccounts(context.Background(), []string{"a", "b", "c"})
	if err == nil || !strings.Contains(err.Error(), "slots for") {
		t.Fatalf("length mismatch accepted: %v", err)
	}
}

// The RPC caps addresses per call, so a 32-app catalog must not become one
// oversized request that a provider rejects.
func TestFetchMultipleAccountsChunksAndPreservesOrder(t *testing.T) {
	var calls atomic.Int32
	var sizes []int
	srv := batchServer(t, &calls, &sizes, func(addrs []string) any {
		value := make([]any, len(addrs))
		for i, a := range addrs {
			value[i] = accountSlot(a)
		}
		return map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"value": value}}
	})
	defer srv.Close()

	addrs := make([]string, 250)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("addr-%03d", i)
	}
	got, err := newStoreRPCReader(srv.URL).fetchMultipleAccounts(context.Background(), addrs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 250 {
		t.Fatalf("slots = %d, want 250", len(got))
	}
	if calls.Load() != 3 {
		t.Fatalf("requests = %d, want 3 chunks of <=%d", calls.Load(), getMultipleAccountsLimit)
	}
	for _, size := range sizes {
		if size > getMultipleAccountsLimit {
			t.Fatalf("chunk of %d exceeds the %d limit", size, getMultipleAccountsLimit)
		}
	}
	for i, v := range got {
		if !v.present || string(v.data) != addrs[i] {
			t.Fatalf("slot %d out of order: %q", i, string(v.data))
		}
	}
}

// The batch path must fail over on exactly what every other read fails over on —
// the F-235 shape: HTTP 429 carrying a quota body.
func TestFetchMultipleAccountsFailsOverOnQuota429(t *testing.T) {
	var primaryCalls, fallbackCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(heliusQuotaExhaustedBody))
	}))
	defer primary.Close()
	fallback := batchServer(t, &fallbackCalls, nil, func(addrs []string) any {
		value := make([]any, len(addrs))
		for i, a := range addrs {
			value[i] = accountSlot(a)
		}
		return map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"value": value}}
	})
	defer fallback.Close()

	reader := newConfiguredStoreRPCReader(Config{
		RPCURL: primary.URL, RPCFallbackURLs: []string{fallback.URL}, RPCAttempts: 2,
	}).(*rpcFailoverChainReader)
	reader.delay = 0
	got, err := reader.fetchMultipleAccounts(context.Background(), []string{"x"})
	if err != nil {
		t.Fatalf("batch read did not fail over: %v", err)
	}
	if len(got) != 1 || string(got[0].data) != "x" {
		t.Fatalf("fallback answer = %+v", got)
	}
	if primaryCalls.Load() != 2 || fallbackCalls.Load() != 1 {
		t.Fatalf("primary=%d fallback=%d, want 2 and 1", primaryCalls.Load(), fallbackCalls.Load())
	}
}

// ...and must NOT fail over on a definitive answer, exactly like the single-read
// path. A 200 carrying a JSON-RPC error is not retried and never reaches the
// fallback — the same documented fragility, kept consistent rather than silently
// different on the batch path.
func TestFetchMultipleAccountsDoesNotFailOverOnDefinitiveError(t *testing.T) {
	var primaryCalls, fallbackCalls atomic.Int32
	primary := batchServer(t, &primaryCalls, nil, func(addrs []string) any {
		return map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32602, "message": "invalid params"}}
	})
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		http.Error(w, "fallback must not be contacted", http.StatusInternalServerError)
	}))
	defer fallback.Close()

	reader := newConfiguredStoreRPCReader(Config{
		RPCURL: primary.URL, RPCFallbackURLs: []string{fallback.URL}, RPCAttempts: 2,
	}).(*rpcFailoverChainReader)
	reader.delay = 0
	_, err := reader.fetchMultipleAccounts(context.Background(), []string{"x"})
	if err == nil || errors.Is(err, verify.ErrRPCUnreachable) {
		t.Fatalf("definitive rpc error was treated as retryable: %v", err)
	}
	if primaryCalls.Load() != 1 || fallbackCalls.Load() != 0 {
		t.Fatalf("primary=%d fallback=%d, want 1 and 0", primaryCalls.Load(), fallbackCalls.Load())
	}
}
