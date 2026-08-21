package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

const quotaBody = `{"jsonrpc":"2.0","error":{"code":-32429,"message":"max usage reached"}}`

func absentAccount(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"context":{},"value":null}}`))
}

// The exact shape that took the catalog down: a quota-exhausted endpoint
// answering HTTP 429. The controller must advance to the next trusted endpoint
// rather than fail the tick — its boot ceremony turns a chain error into
// log.Fatalf under Restart=on-failure, so not failing over means a crash loop.
func TestFailoverRPCAdvancesOnQuota429(t *testing.T) {
	var primaryCalls, fallbackCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(quotaBody))
	}))
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		absentAccount(w)
	}))
	defer fallback.Close()

	f := newFailoverRPC(primary.URL, []string{fallback.URL}, 2)
	f.delay = 0
	// An absent account is a DEFINITIVE answer; reaching it proves the fallback
	// was consulted and its verdict returned unaltered.
	_, _, err := f.FetchReleaseEntry(context.Background(), "SomeReleasePDA")
	if !errors.Is(err, verify.ErrPDANotFound) {
		t.Fatalf("error = %v, want the fallback's definitive ErrPDANotFound", err)
	}
	if primaryCalls.Load() != 2 || fallbackCalls.Load() != 1 {
		t.Fatalf("primary=%d fallback=%d, want 2 and 1", primaryCalls.Load(), fallbackCalls.Load())
	}
}

// A definitive chain verdict must NOT be retried elsewhere. Shopping other
// endpoints after a real denial is equivocation-seeking, not resilience.
func TestFailoverRPCDoesNotShopADefinitiveDenial(t *testing.T) {
	var primaryCalls, fallbackCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		absentAccount(w)
	}))
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		http.Error(w, "fallback must not be contacted", http.StatusInternalServerError)
	}))
	defer fallback.Close()

	f := newFailoverRPC(primary.URL, []string{fallback.URL}, 2)
	f.delay = 0
	if _, _, err := f.FetchReleaseEntry(context.Background(), "SomeReleasePDA"); !errors.Is(err, verify.ErrPDANotFound) {
		t.Fatalf("error = %v, want ErrPDANotFound", err)
	}
	if primaryCalls.Load() != 1 || fallbackCalls.Load() != 0 {
		t.Fatalf("primary=%d fallback=%d, want 1 and 0 — a denial was shopped to another endpoint", primaryCalls.Load(), fallbackCalls.Load())
	}
}

// With every endpoint unreachable the controller fails CLOSED with a bounded
// attempt count, never an unbounded retry storm.
func TestFailoverRPCFailsClosedWithBoundedAttempts(t *testing.T) {
	var calls atomic.Int32
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "unavailable", http.StatusBadGateway)
	}))
	defer dead.Close()
	f := newFailoverRPC(dead.URL, nil, 2)
	f.delay = 0
	_, err := f.FetchSidecarIdentity(context.Background(), "SomeIdentityPDA")
	if !errors.Is(err, verify.ErrRPCUnreachable) {
		t.Fatalf("error = %v, want ErrRPCUnreachable", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want exactly 2 bounded attempts", calls.Load())
	}
}

func TestNormalizeControllerRPCEndpoints(t *testing.T) {
	if _, _, _, err := normalizeControllerRPCEndpoints("", []string{"https://a"}, 0); err == nil ||
		!strings.Contains(err.Error(), "requires solanaRpcUrl") {
		t.Fatalf("orphaned fallback list accepted: %v", err)
	}
	// A duplicate is not harmless: it burns an attempt budget on an endpoint
	// already known to be failing.
	if _, _, _, err := normalizeControllerRPCEndpoints("https://a", []string{"https://a"}, 0); err == nil ||
		!strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate endpoint accepted: %v", err)
	}
	if _, _, _, err := normalizeControllerRPCEndpoints("https://a", []string{"  "}, 0); err == nil {
		t.Fatal("empty fallback endpoint accepted")
	}
	if _, _, _, err := normalizeControllerRPCEndpoints("https://a", nil, 9); err == nil {
		t.Fatal("out-of-range attempts accepted")
	}
	primary, fb, attempts, err := normalizeControllerRPCEndpoints(" https://a ", []string{" https://b "}, 0)
	if err != nil || primary != "https://a" || len(fb) != 1 || fb[0] != "https://b" || attempts != controllerDefaultRPCAttempts {
		t.Fatalf("valid set mangled: %q %v %d %v", primary, fb, attempts, err)
	}
	// Errors must never echo an endpoint: these URLs carry API keys.
	_, _, _, err = normalizeControllerRPCEndpoints("https://x?api-key=SECRET", []string{"https://x?api-key=SECRET"}, 0)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("validation error leaked an endpoint value: %v", err)
	}
}
