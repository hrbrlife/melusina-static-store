package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

func TestConfiguredRPCReader_BoundedSignedBackoffAndFiveAttempts(t *testing.T) {
	for _, check := range []struct {
		failures int
		want     time.Duration
	}{
		{1, 250 * time.Millisecond}, {2, 500 * time.Millisecond}, {3, time.Second},
		{4, 2 * time.Second}, {5, 2 * time.Second},
	} {
		if got := boundedRPCBackoff(250*time.Millisecond, check.failures); got != check.want {
			t.Fatalf("backoff after %d failures = %s, want %s", check.failures, got, check.want)
		}
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer server.Close()
	reader := newConfiguredStoreRPCReader(Config{RPCURL: server.URL, RPCAttempts: 5, RPCBackoffMillis: 250}).(*rpcFailoverChainReader)
	if reader.delay != 250*time.Millisecond {
		t.Fatalf("signed backoff = %s", reader.delay)
	}
	reader.delay = 0 // isolate the attempt bound from wall-clock waiting
	_, _, err := reader.fetchRawAccount(context.Background(), "account")
	if !errors.Is(err, verify.ErrRPCUnreachable) || calls.Load() != 5 {
		t.Fatalf("bounded five-attempt retry = (%v, %d calls)", err, calls.Load())
	}
}

func TestConfiguredRPCReader_RefusesWrongOriginTLSPin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeRPCAccountResponse(t, w, []byte("pinned-account"))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	good := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	for _, check := range []struct {
		name, pin string
		allowed   bool
	}{
		{"correct pin", hex.EncodeToString(good[:]), true},
		{"wrong pin", strings.Repeat("0", 64), false},
	} {
		t.Run(check.name, func(t *testing.T) {
			reader := newStoreRPCReader(server.URL, check.pin)
			reader.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
			data, _, err := reader.fetchRawAccount(context.Background(), "account")
			if check.allowed && (err != nil || !bytes.Equal(data, []byte("pinned-account"))) {
				t.Fatalf("correct pinned origin refused: data=%q err=%v", data, err)
			}
			if !check.allowed && (!errors.Is(err, verify.ErrRPCUnreachable) || !strings.Contains(err.Error(), "rpc-tls-spki-pin-mismatch")) {
				t.Fatalf("wrong pinned origin accepted: data=%q err=%v", data, err)
			}
		})
	}
}

func TestConfiguredRPCReader_OrderedFallbackUsesItsOwnTLSPin(t *testing.T) {
	var primaryCalls, fallbackCalls atomic.Int32
	primary := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer primary.Close()
	fallback := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		writeRPCAccountResponse(t, w, []byte("fallback-account"))
	}))
	defer fallback.Close()
	pool := x509.NewCertPool()
	pool.AddCert(primary.Certificate())
	pool.AddCert(fallback.Certificate())
	primaryPin := sha256.Sum256(primary.Certificate().RawSubjectPublicKeyInfo)
	fallbackPin := sha256.Sum256(fallback.Certificate().RawSubjectPublicKeyInfo)
	makeReader := func(pins []string) *rpcFailoverChainReader {
		reader := newConfiguredStoreRPCReader(Config{
			RPCURL: primary.URL, RPCFallbackURLs: []string{fallback.URL},
			RPCTLSSPKISHA256: pins, RPCAttempts: 1,
		}).(*rpcFailoverChainReader)
		reader.delay = 0
		for _, raw := range reader.rawReaders {
			raw.(*storeRPCReader).HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
		}
		return reader
	}
	reader := makeReader([]string{hex.EncodeToString(primaryPin[:]), hex.EncodeToString(fallbackPin[:])})
	data, _, err := reader.fetchRawAccount(context.Background(), "account")
	if err != nil || !bytes.Equal(data, []byte("fallback-account")) || primaryCalls.Load() != 1 || fallbackCalls.Load() != 1 {
		t.Fatalf("ordered pinned fallback = (data=%q, err=%v, primary=%d, fallback=%d)", data, err, primaryCalls.Load(), fallbackCalls.Load())
	}
	reader = makeReader([]string{hex.EncodeToString(primaryPin[:]), strings.Repeat("0", 64)})
	data, _, err = reader.fetchRawAccount(context.Background(), "account")
	if !errors.Is(err, verify.ErrRPCUnreachable) || !strings.Contains(err.Error(), "rpc-tls-spki-pin-mismatch") || len(data) != 0 {
		t.Fatalf("wrong fallback origin pin accepted: data=%q err=%v", data, err)
	}
	if primaryCalls.Load() != 2 || fallbackCalls.Load() != 1 {
		t.Fatalf("wrong fallback pin reached HTTP handler: primary=%d fallback=%d", primaryCalls.Load(), fallbackCalls.Load())
	}
}

func writeRPCAccountResponse(t *testing.T, w http.ResponseWriter, data []byte) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"value": map[string]any{
				"data":  []string{base64.StdEncoding.EncodeToString(data), "base64"},
				"owner": testLicenseProgramID,
			},
		},
	}); err != nil {
		t.Fatalf("encode RPC response: %v", err)
	}
}

func TestConfiguredRPCReader_ExhaustionPreservesLastProviderStatus(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer server.Close()

	reader := newConfiguredStoreRPCReader(Config{RPCURL: server.URL, RPCAttempts: 2}).(*rpcFailoverChainReader)
	reader.delay = 0
	checks := []struct {
		name string
		read func() error
	}{
		{"operator authorization", func() error {
			_, _, _, _, _, err := reader.FetchStoreOperatorAuthz(context.Background(), "operator-authz")
			return err
		}},
		{"raw account", func() error {
			_, _, err := reader.fetchRawAccount(context.Background(), "cascade-account")
			return err
		}},
		{"batched accounts", func() error {
			_, err := reader.fetchMultipleAccounts(context.Background(), []string{"first-account"})
			return err
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			before := calls.Load()
			err := check.read()
			if !errors.Is(err, verify.ErrRPCUnreachable) ||
				!strings.Contains(err.Error(), "2 transport failure(s)") ||
				!strings.Contains(err.Error(), "HTTP 429") ||
				!strings.Contains(err.Error(), "rate limited") {
				t.Fatalf("exhausted RPC error = %v, want sentinel, bounded attempts and last HTTP 429 cause", err)
			}
			if got := calls.Load() - before; got != 2 {
				t.Fatalf("RPC attempts = %d, want 2", got)
			}
		})
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
	if !bytes.Equal(data, want) || owner != testLicenseProgramID {
		t.Fatalf("raw fallback = (%q, %q), want (%q, %q)", data, owner, want, testLicenseProgramID)
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
