package releasefinalizer

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func finalizerHTTPFixture(t *testing.T, now time.Time) (*HTTPHandler, Request, *testObserver, *testSigner, *x509.Certificate) {
	t.Helper()
	engine, request, _, observer, signer, public := finalizerFixture(t, now)
	records, err := OpenRepository(filepath.Join(t.TempDir(), "records"), "finalizer-a", public)
	if err != nil {
		t.Fatal(err)
	}
	records.now = func() time.Time { return now }
	runner, err := NewRunner(engine, records, &memoryBodyVault{})
	if err != nil {
		t.Fatal(err)
	}
	runner.now = func() time.Time { return now }
	leaf := &x509.Certificate{Raw: []byte("verified-store-link-leaf")}
	sum := sha256.Sum256(leaf.Raw)
	handler, err := NewHTTPHandler(runner, hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	return handler, request, observer, signer, leaf
}

func finalizerMTLSRequest(method, path string, body []byte, leaf *x509.Certificate) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}

func TestHTTPHandlerPinsStoreLinkAndReturnsExactFinalizationResult(t *testing.T) {
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	handler, request, observer, signer, leaf := finalizerHTTPFixture(t, now)
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, finalizerMTLSRequest(http.MethodPost, jobCollectionPath, raw, leaf))
	if start.Code != http.StatusAccepted {
		t.Fatalf("start = %d: %s", start.Code, start.Body.String())
	}
	var job Job
	if err := json.Unmarshal(start.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	collect := httptest.NewRecorder()
	handler.ServeHTTP(collect, finalizerMTLSRequest(http.MethodGet, jobCollectionPath+"/"+job.ID, nil, leaf))
	if collect.Code != http.StatusOK {
		t.Fatalf("collect = %d: %s", collect.Code, collect.Body.String())
	}
	var response completion
	if err := json.Unmarshal(collect.Body.Bytes(), &response); err != nil || response.Result.Job != job || response.Result.FinalCandidateSHA256 == "" || response.FinalCandidateB64 == "" || observer.calls != 1 || signer.calls != 1 {
		t.Fatalf("completion=%#v observer/signer=%d/%d err=%v", response, observer.calls, signer.calls, err)
	}
}

func TestHTTPHandlerRefusesUnpinnedAndPendingClients(t *testing.T) {
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	handler, request, observer, signer, leaf := finalizerHTTPFixture(t, now)
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	noTLS := httptest.NewRecorder()
	noTLSRequest := httptest.NewRequest(http.MethodPost, jobCollectionPath, bytes.NewReader(raw))
	noTLSRequest.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(noTLS, noTLSRequest)
	if noTLS.Code != http.StatusForbidden || observer.calls != 0 || signer.calls != 0 {
		t.Fatalf("unverified request = %d observer/signer=%d/%d", noTLS.Code, observer.calls, signer.calls)
	}
	other := &x509.Certificate{Raw: []byte("other-store-link-leaf")}
	wrongTLS := httptest.NewRecorder()
	handler.ServeHTTP(wrongTLS, finalizerMTLSRequest(http.MethodPost, jobCollectionPath, raw, other))
	if wrongTLS.Code != http.StatusForbidden || observer.calls != 0 || signer.calls != 0 {
		t.Fatalf("wrong certificate request = %d observer/signer=%d/%d", wrongTLS.Code, observer.calls, signer.calls)
	}
	observer.observation.State = ProposalPending
	pending := httptest.NewRecorder()
	handler.ServeHTTP(pending, finalizerMTLSRequest(http.MethodPost, jobCollectionPath, raw, leaf))
	if pending.Code != http.StatusAccepted || observer.calls != 1 || signer.calls != 0 {
		t.Fatalf("pending request = %d observer/signer=%d/%d", pending.Code, observer.calls, signer.calls)
	}
	var job Job
	if err := json.Unmarshal(pending.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	poll := httptest.NewRecorder()
	handler.ServeHTTP(poll, finalizerMTLSRequest(http.MethodGet, jobCollectionPath+"/"+job.ID, nil, leaf))
	if poll.Code != http.StatusAccepted || observer.calls != 2 || signer.calls != 0 {
		t.Fatalf("pending poll = %d observer/signer=%d/%d", poll.Code, observer.calls, signer.calls)
	}
}
