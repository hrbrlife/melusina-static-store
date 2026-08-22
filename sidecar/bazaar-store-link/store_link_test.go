package storelink

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testStoreID   = "melusina-os-root-store"
	testDossierID = "0123456789abcdef01234567"
)

type capturedForwarder struct {
	requests []ForwardRequest
	response ForwardResponse
	err      error
}

func (f *capturedForwarder) Forward(_ context.Context, request ForwardRequest) (ForwardResponse, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return ForwardResponse{}, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	f.requests = append(f.requests, request)
	if f.err != nil {
		return ForwardResponse{}, f.err
	}
	return f.response, nil
}

func testConfig() Config {
	return Config{
		ListenAddr:     "127.0.0.1:9400",
		StoreID:        testStoreID,
		SidecarURL:     "https://127.0.0.1:9443",
		ClientCertPath: "/etc/bazaar-store-link/client.pem",
		ClientKeyPath:  "/etc/bazaar-store-link/client.key",
		SidecarCAPath:  "/etc/bazaar-store-link/sidecar-ca.pem",
	}
}

func encodedHeader(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func releaseRequest(t *testing.T, action string) *http.Request {
	t.Helper()
	path := "/v1/release-commands/" + testDossierID + "/" + action
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"candidate":"bounded"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(controlCommandHeader, encodedHeader(t, wireCommand{
		DossierID: testDossierID, Action: actionToCommandAction(action), Route: sidecarReleasePath(testDossierID, action), Method: http.MethodPost,
	}))
	request.Header.Set(controlPearlSignatureHeader, encodedHeader(t, map[string]string{"signature": "placeholder"}))
	if action == "publish" {
		request.Header.Set(controlOfflineApprovalHeader, encodedHeader(t, map[string]string{"signature": "human"}))
	}
	return request
}

func newTestHandler(t *testing.T, forwarder *capturedForwarder) *Handler {
	t.Helper()
	handler, err := NewHandler(testConfig(), forwarder)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestReleaseForwardingIsExactlyBounded(t *testing.T) {
	forwarder := &capturedForwarder{response: ForwardResponse{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}}, Body: []byte(`{"state":"staged"}`)}}
	handler := newTestHandler(t, forwarder)
	request := releaseRequest(t, "prepare")
	request.Header.Set("X-Untrusted-Forward", "must-not-reach-sidecar")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Body.String() != `{"state":"staged"}` || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("release response = %d %q %#v", recorder.Code, recorder.Body.String(), recorder.Header())
	}
	if len(forwarder.requests) != 1 {
		t.Fatalf("forwards = %d, want 1", len(forwarder.requests))
	}
	got := forwarder.requests[0]
	if got.Method != http.MethodPost || got.Path != "/control/v1/releases/"+testDossierID+"/prepare" {
		t.Fatalf("forward target = %s %s", got.Method, got.Path)
	}
	if got.Headers.Get("X-Untrusted-Forward") != "" || got.Headers.Get(controlOfflineApprovalHeader) != "" || got.Headers.Get(controlCommandHeader) == "" || got.Headers.Get(controlPearlSignatureHeader) == "" {
		t.Fatalf("forward headers = %#v", got.Headers)
	}
}

func TestReleaseBoundaryRefusesAnythingButExactOperation(t *testing.T) {
	cases := []struct {
		name string
		edit func(*http.Request)
		want int
	}{
		{"wrong method", func(r *http.Request) { r.Method = http.MethodGet }, http.StatusMethodNotAllowed},
		{"query", func(r *http.Request) { r.URL.RawQuery = "target=other" }, http.StatusNotFound},
		{"missing approval", func(r *http.Request) { r.Header.Del(controlOfflineApprovalHeader) }, http.StatusBadRequest},
		{"approval on prepare", func(r *http.Request) {
			r.Header.Set(controlOfflineApprovalHeader, encodedHeader(t, map[string]string{"signature": "wrong"}))
		}, http.StatusBadRequest},
		{"mismatched command action", func(r *http.Request) {
			r.Header.Set(controlCommandHeader, encodedHeader(t, wireCommand{DossierID: testDossierID, Action: "prepare_release", Route: sidecarReleasePath(testDossierID, "prepare"), Method: http.MethodPost}))
		}, http.StatusForbidden},
		{"wrong content type", func(r *http.Request) { r.Header.Set("Content-Type", "application/octet-stream") }, http.StatusUnsupportedMediaType},
		{"too large", func(r *http.Request) { r.ContentLength = maxCandidateBytes + 1 }, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forwarder := &capturedForwarder{response: ForwardResponse{StatusCode: http.StatusOK}}
			handler := newTestHandler(t, forwarder)
			action := "publish"
			if tc.name == "approval on prepare" {
				action = "prepare"
			}
			request := releaseRequest(t, action)
			tc.edit(request)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != tc.want || len(forwarder.requests) != 0 {
				t.Fatalf("status/forwards = %d/%d, want %d/0", recorder.Code, len(forwarder.requests), tc.want)
			}
		})
	}
}

func TestAuthorityIsStorePinnedAndHasNoForwardedCallerHeaders(t *testing.T) {
	forwarder := &capturedForwarder{response: ForwardResponse{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: []byte(`{"schema":"bazaar-control-authority-snapshot-v1"}`)}}
	handler := newTestHandler(t, forwarder)
	request := httptest.NewRequest(http.MethodGet, "/v1/authority/"+testStoreID+"/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/11111111111111111111111111111111", nil)
	request.Header.Set(controlCommandHeader, "must-not-forward")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || len(forwarder.requests) != 1 {
		t.Fatalf("authority status/forwards = %d/%d", recorder.Code, len(forwarder.requests))
	}
	got := forwarder.requests[0]
	if got.Path != "/control/v1/authority/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/11111111111111111111111111111111" || len(got.Headers) != 0 {
		t.Fatalf("authority forwarding = %q %#v", got.Path, got.Headers)
	}

	wrongStore := httptest.NewRequest(http.MethodGet, "/v1/authority/another-store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/11111111111111111111111111111111", nil)
	wrongRecorder := httptest.NewRecorder()
	handler.ServeHTTP(wrongRecorder, wrongStore)
	if wrongRecorder.Code != http.StatusNotFound || len(forwarder.requests) != 1 {
		t.Fatalf("wrong store status/forwards = %d/%d", wrongRecorder.Code, len(forwarder.requests))
	}
}

func TestConnectorNeverBuildsAnArbitrarySidecarRequest(t *testing.T) {
	for _, tc := range []struct {
		method string
		path   string
		want   bool
	}{
		{http.MethodPost, "/control/v1/releases/" + testDossierID + "/prepare", true},
		{http.MethodPost, "/control/v1/releases/" + testDossierID + "/publish", true},
		{http.MethodGet, "/control/v1/authority/app/publisher", true},
		{http.MethodPost, "/publish", false},
		{http.MethodDelete, "/control/v1/releases/" + testDossierID + "/publish", false},
		{http.MethodGet, "/control/v1/authority/app/publisher/extra", false},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if got := canonicalSidecarPath(tc.method, tc.path); got != tc.want {
				t.Fatalf("canonicalSidecarPath() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConfigKeepsTheConnectorOnPrivateOrigins(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Config)
		want bool
	}{
		{"baseline", func(*Config) {}, true},
		{"public listener", func(c *Config) { c.ListenAddr = "0.0.0.0:9460" }, false},
		{"public sidecar", func(c *Config) { c.SidecarURL = "https://bazaar.example.org:9443" }, false},
		{"query-bearing sidecar", func(c *Config) { c.SidecarURL = "https://127.0.0.1:9443/?other=store" }, false},
		{"missing mTLS client key path", func(c *Config) { c.ClientKeyPath = "" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfig()
			tc.edit(&config)
			err := config.Validate()
			if (err == nil) != tc.want {
				t.Fatalf("Validate() = %v, want success=%v", err, tc.want)
			}
		})
	}
}

func TestForwardFailureNeverLeaksAsSuccess(t *testing.T) {
	forwarder := &capturedForwarder{err: errors.New("dial refused")}
	handler := newTestHandler(t, forwarder)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, releaseRequest(t, "prepare"))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("forward failure status = %d, want %d", recorder.Code, http.StatusBadGateway)
	}
}
