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
	"os"
	"path/filepath"
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

type capturedWorkerForwarder struct {
	buildRequests        []WorkerRequest
	preparationRequests  []WorkerRequest
	finalizationRequests []WorkerRequest
	proofRequests        []WorkerRequest
	buildResponse        WorkerResponse
	preparationResponse  WorkerResponse
	finalizationResponse WorkerResponse
	proofResponse        WorkerResponse
	err                  error
}

func (f *capturedWorkerForwarder) ForwardBuild(_ context.Context, request WorkerRequest) (WorkerResponse, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return WorkerResponse{}, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	f.buildRequests = append(f.buildRequests, request)
	if f.err != nil {
		return WorkerResponse{}, f.err
	}
	return f.buildResponse, nil
}

func (f *capturedWorkerForwarder) ForwardReleasePreparation(_ context.Context, request WorkerRequest) (WorkerResponse, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return WorkerResponse{}, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	f.preparationRequests = append(f.preparationRequests, request)
	if f.err != nil {
		return WorkerResponse{}, f.err
	}
	return f.preparationResponse, nil
}

func (f *capturedWorkerForwarder) ForwardReleaseFinalization(_ context.Context, request WorkerRequest) (WorkerResponse, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return WorkerResponse{}, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	f.finalizationRequests = append(f.finalizationRequests, request)
	if f.err != nil {
		return WorkerResponse{}, f.err
	}
	return f.finalizationResponse, nil
}

func (f *capturedWorkerForwarder) ForwardTenantProof(_ context.Context, request WorkerRequest) (WorkerResponse, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return WorkerResponse{}, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	f.proofRequests = append(f.proofRequests, request)
	if f.err != nil {
		return WorkerResponse{}, f.err
	}
	return f.proofResponse, nil
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
		Schema: "bazaar-control-command-v1", DossierID: testDossierID, Action: actionToCommandAction(action), Route: sidecarReleasePath(testDossierID, action), Method: http.MethodPost,
	}))
	request.Header.Set(controlPearlSignatureHeader, encodedHeader(t, map[string]string{"signature": "placeholder"}))
	if action == "publish" {
		request.Header.Set(controlOfflineApprovalHeader, encodedHeader(t, map[string]string{"signature": "human"}))
	}
	return request
}

func releaseRequestV2(t *testing.T) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/release-commands/"+testDossierID+"/publish", strings.NewReader(`{"candidate":"bounded"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(controlCommandHeader, encodedHeader(t, wireCommand{
		Schema: "bazaar-control-command-v2", DossierID: testDossierID, Action: "publish_release", Route: sidecarReleasePath(testDossierID, "publish"), Method: http.MethodPost,
	}))
	request.Header.Set(controlPearlSignatureHeader, encodedHeader(t, map[string]string{"signature": "placeholder"}))
	request.Header.Set(controlReleaseAuthorizationHeader, encodedHeader(t, map[string]string{"signature": "stable-human"}))
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

func newJobTestHandler(t *testing.T, forwarder *capturedForwarder, workers WorkerForwarder) *Handler {
	t.Helper()
	handler, err := NewHandlerWithWorkers(testConfig(), forwarder, workers)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func buildJobRequest(t *testing.T) *http.Request {
	t.Helper()
	body := `{"schema":"bazaar-control-trusted-build-job-v1","dossierId":"` + testDossierID + `","storeId":"` + testStoreID + `","appId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sourceRef":"refs/heads/dev-publish","sourceCommit":"0123456789abcdef0123456789abcdef01234567","version":"1.2.3","requestDigest":"` + strings.Repeat("a", 64) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/build-jobs", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func proofJobRequest(t *testing.T) *http.Request {
	t.Helper()
	body := `{"schema":"bazaar-control-tenant-proof-request-v1","dossierId":"` + testDossierID + `","storeId":"` + testStoreID + `","appId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":"1.2.3","packageId":"pkg-1","appHash":"` + strings.Repeat("b", 64) + `","releaseHash":"` + strings.Repeat("c", 64) + `","releaseDigest":"` + strings.Repeat("d", 64) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/tenant-proof-jobs", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func proofResumeHTTPRequest(t *testing.T, jobID, dossierID, releaseDigest string) *http.Request {
	t.Helper()
	body := `{"schema":"bazaar-control-tenant-proof-resume-request-v1","dossierId":"` + dossierID + `","releaseDigest":"` + releaseDigest + `"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/tenant-proof-jobs/"+jobID+"/resume", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func preparationJobRequest(t *testing.T) *http.Request {
	t.Helper()
	body := `{"schema":"bazaar-control-release-preparation-request-v1","dossierId":"` + testDossierID + `","storeId":"` + testStoreID + `","appId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sourceRef":"refs/heads/dev-publish","sourceCommit":"0123456789abcdef0123456789abcdef01234567","version":"1.2.3","buildAttestationDigest":"` + strings.Repeat("a", 64) + `","candidateSha256":"` + strings.Repeat("b", 64) + `","candidateBytes":1,"artifactSha256":"` + strings.Repeat("c", 64) + `","metadataSha256":"` + strings.Repeat("d", 64) + `","packageId":"pkg-1","appHash":"` + strings.Repeat("e", 64) + `","action":"prepare_release","requestDigest":"` + strings.Repeat("f", 64) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/release-preparation-jobs", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func finalizationJobRequest(t *testing.T) *http.Request {
	t.Helper()
	body := `{"schema":"bazaar-control-release-finalization-request-v1","dossierId":"` + testDossierID + `","storeId":"` + testStoreID + `","appId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","candidateSha256":"` + strings.Repeat("9", 64) + `","candidateBytes":42,"finalizationInputSha256":"` + strings.Repeat("8", 64) + `","finalizationInputBytes":42,"releaseAuthorizationDigest":"` + strings.Repeat("a", 64) + `","proposalReference":"squads:proposal-1","proposalDigest":"` + strings.Repeat("b", 64) + `","expectedPriorAppHash":"` + strings.Repeat("c", 64) + `","releaseHash":"` + strings.Repeat("d", 64) + `","stageId":"` + strings.Repeat("e", 64) + `","storePolicy":"policy-1","policyEpoch":7,"publisherGrant":"grant-1","grantEpoch":3,"action":"finalize_release","requestDigest":"` + strings.Repeat("f", 64) + `"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/release-finalization-jobs", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
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

func TestV2ReleaseForwardingRelaysOnlyStableAuthorization(t *testing.T) {
	forwarder := &capturedForwarder{response: ForwardResponse{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: []byte(`{"state":"live"}`)}}
	handler := newTestHandler(t, forwarder)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, releaseRequestV2(t))
	if recorder.Code != http.StatusOK || len(forwarder.requests) != 1 {
		t.Fatalf("v2 status/forwards = %d/%d", recorder.Code, len(forwarder.requests))
	}
	headers := forwarder.requests[0].Headers
	if headers.Get(controlReleaseAuthorizationHeader) == "" || headers.Get(controlOfflineApprovalHeader) != "" || headers.Get(controlCommandHeader) == "" || headers.Get(controlPearlSignatureHeader) == "" {
		t.Fatalf("v2 forward headers = %#v", headers)
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
		{"v2 with legacy approval", func(r *http.Request) {
			r.Header.Set(controlCommandHeader, encodedHeader(t, wireCommand{Schema: "bazaar-control-command-v2", DossierID: testDossierID, Action: "publish_release", Route: sidecarReleasePath(testDossierID, "publish"), Method: http.MethodPost}))
			r.Header.Set(controlReleaseAuthorizationHeader, encodedHeader(t, map[string]string{"signature": "stable-human"}))
		}, http.StatusBadRequest},
		{"approval on prepare", func(r *http.Request) {
			r.Header.Set(controlOfflineApprovalHeader, encodedHeader(t, map[string]string{"signature": "wrong"}))
		}, http.StatusBadRequest},
		{"mismatched command action", func(r *http.Request) {
			r.Header.Set(controlCommandHeader, encodedHeader(t, wireCommand{Schema: "bazaar-control-command-v1", DossierID: testDossierID, Action: "prepare_release", Route: sidecarReleasePath(testDossierID, "prepare"), Method: http.MethodPost}))
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

func TestStoreStatusIsFixedReadOnlyAndStorePinned(t *testing.T) {
	checkedAt := "2026-08-22T15:04:05Z"
	forwarder := &capturedForwarder{response: ForwardResponse{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: []byte(`{"schema":"bazaar-control-store-status-v1","storeId":"` + testStoreID + `","status":"ready","checkedAt":"` + checkedAt + `"}`)}}
	handler := newTestHandler(t, forwarder)
	request := httptest.NewRequest(http.MethodGet, "/v1/store-status", nil)
	request.Header.Set(controlCommandHeader, "must-not-forward")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || len(forwarder.requests) != 1 || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("store status/result = %d/%d headers=%#v body=%s", recorder.Code, len(forwarder.requests), recorder.Header(), recorder.Body.String())
	}
	got := forwarder.requests[0]
	if got.Method != http.MethodGet || got.Path != "/control/v1/status" || len(got.Headers) != 0 {
		t.Fatalf("store status forwarding = %#v", got)
	}

	wrongMethod := httptest.NewRecorder()
	handler.ServeHTTP(wrongMethod, httptest.NewRequest(http.MethodPost, "/v1/store-status", nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed || len(forwarder.requests) != 1 {
		t.Fatalf("store status mutation = %d forwards=%d", wrongMethod.Code, len(forwarder.requests))
	}
	wrongStore := &capturedForwarder{response: ForwardResponse{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: []byte(`{"schema":"bazaar-control-store-status-v1","storeId":"other-store","status":"ready","checkedAt":"` + checkedAt + `"}`)}}
	wrongHandler := newTestHandler(t, wrongStore)
	wrongResponse := httptest.NewRecorder()
	wrongHandler.ServeHTTP(wrongResponse, httptest.NewRequest(http.MethodGet, "/v1/store-status", nil))
	if wrongResponse.Code != http.StatusBadGateway {
		t.Fatalf("wrong Store status accepted: %d %s", wrongResponse.Code, wrongResponse.Body.String())
	}
}

func TestStorePolicyIsFixedReadOnlyAndStorePinned(t *testing.T) {
	forwarder := &capturedForwarder{response: ForwardResponse{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: []byte(`{"schema":"bazaar-control-store-policy-snapshot-v1","storeId":"` + testStoreID + `","storePolicy":"policy_123","policyEpoch":7}`)}}
	handler := newTestHandler(t, forwarder)
	request := httptest.NewRequest(http.MethodGet, "/v1/store-policy", nil)
	request.Header.Set(controlCommandHeader, "must-not-forward")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || len(forwarder.requests) != 1 || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("store policy/result = %d/%d headers=%#v body=%s", recorder.Code, len(forwarder.requests), recorder.Header(), recorder.Body.String())
	}
	got := forwarder.requests[0]
	if got.Method != http.MethodGet || got.Path != "/control/v1/policy" || len(got.Headers) != 0 {
		t.Fatalf("store policy forwarding = %#v", got)
	}

	wrongMethod := httptest.NewRecorder()
	handler.ServeHTTP(wrongMethod, httptest.NewRequest(http.MethodPost, "/v1/store-policy", nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed || len(forwarder.requests) != 1 {
		t.Fatalf("store policy mutation = %d forwards=%d", wrongMethod.Code, len(forwarder.requests))
	}
	wrongStore := &capturedForwarder{response: ForwardResponse{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: []byte(`{"schema":"bazaar-control-store-policy-snapshot-v1","storeId":"other-store","storePolicy":"policy_123","policyEpoch":7}`)}}
	wrongHandler := newTestHandler(t, wrongStore)
	wrongResponse := httptest.NewRecorder()
	wrongHandler.ServeHTTP(wrongResponse, httptest.NewRequest(http.MethodGet, "/v1/store-policy", nil))
	if wrongResponse.Code != http.StatusBadGateway {
		t.Fatalf("wrong Store policy accepted: %d %s", wrongResponse.Code, wrongResponse.Body.String())
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
		{http.MethodGet, "/control/v1/status", true},
		{http.MethodGet, "/control/v1/policy", true},
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

func TestDurableWorkerJobsHaveOnlyFixedRoutesAndBodies(t *testing.T) {
	workers := &capturedWorkerForwarder{
		buildResponse:        WorkerResponse{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"schema":"bazaar-control-trusted-build-job-v1"}`))},
		preparationResponse:  WorkerResponse{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"schema":"bazaar-control-release-preparation-job-v1"}`))},
		finalizationResponse: WorkerResponse{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"schema":"bazaar-control-release-finalization-job-v1"}`))},
		proofResponse:        WorkerResponse{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"schema":"bazaar-control-tenant-proof-job-v1"}`))},
	}
	handler := newJobTestHandler(t, &capturedForwarder{}, workers)

	buildRecorder := httptest.NewRecorder()
	handler.ServeHTTP(buildRecorder, buildJobRequest(t))
	if buildRecorder.Code != http.StatusAccepted || len(workers.buildRequests) != 1 {
		t.Fatalf("build status/requests = %d/%d", buildRecorder.Code, len(workers.buildRequests))
	}
	build := workers.buildRequests[0]
	if build.Method != http.MethodPost || build.Path != "/v1/build-jobs" {
		t.Fatalf("build worker request = %s %s", build.Method, build.Path)
	}

	preparationRecorder := httptest.NewRecorder()
	handler.ServeHTTP(preparationRecorder, preparationJobRequest(t))
	if preparationRecorder.Code != http.StatusAccepted || len(workers.preparationRequests) != 1 {
		t.Fatalf("preparation status/requests = %d/%d", preparationRecorder.Code, len(workers.preparationRequests))
	}
	preparation := workers.preparationRequests[0]
	if preparation.Method != http.MethodPost || preparation.Path != "/v1/release-preparation-jobs" {
		t.Fatalf("preparation worker request = %s %s", preparation.Method, preparation.Path)
	}

	finalizationRecorder := httptest.NewRecorder()
	handler.ServeHTTP(finalizationRecorder, finalizationJobRequest(t))
	if finalizationRecorder.Code != http.StatusAccepted || len(workers.finalizationRequests) != 1 {
		t.Fatalf("finalization status/requests = %d/%d", finalizationRecorder.Code, len(workers.finalizationRequests))
	}
	finalization := workers.finalizationRequests[0]
	if finalization.Method != http.MethodPost || finalization.Path != "/v1/release-finalization-jobs" {
		t.Fatalf("finalization worker request = %s %s", finalization.Method, finalization.Path)
	}

	proofRecorder := httptest.NewRecorder()
	handler.ServeHTTP(proofRecorder, proofJobRequest(t))
	if proofRecorder.Code != http.StatusAccepted || len(workers.proofRequests) != 1 {
		t.Fatalf("proof status/requests = %d/%d", proofRecorder.Code, len(workers.proofRequests))
	}
	proof := workers.proofRequests[0]
	if proof.Method != http.MethodPost || proof.Path != "/v1/tenant-proof-jobs" {
		t.Fatalf("proof worker request = %s %s", proof.Method, proof.Path)
	}

	workers.proofResponse = WorkerResponse{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"schema":"bazaar-control-tenant-proof-job-v1"}`))}
	pollRecorder := httptest.NewRecorder()
	handler.ServeHTTP(pollRecorder, httptest.NewRequest(http.MethodGet, "/v1/tenant-proof-jobs/0123456789abcdef01234567", nil))
	if pollRecorder.Code != http.StatusAccepted || len(workers.proofRequests) != 2 {
		t.Fatalf("proof poll status/requests = %d/%d", pollRecorder.Code, len(workers.proofRequests))
	}
	if workers.proofRequests[1].Path != "/v1/tenant-proof-jobs/0123456789abcdef01234567" {
		t.Fatalf("proof poll path = %q", workers.proofRequests[1].Path)
	}

	workers.proofResponse = WorkerResponse{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"schema":"bazaar-control-tenant-proof-job-v1"}`))}
	resumeRecorder := httptest.NewRecorder()
	handler.ServeHTTP(resumeRecorder, proofResumeHTTPRequest(t, testDossierID, testDossierID, strings.Repeat("d", 64)))
	if resumeRecorder.Code != http.StatusAccepted || len(workers.proofRequests) != 3 {
		t.Fatalf("proof resume status/requests = %d/%d", resumeRecorder.Code, len(workers.proofRequests))
	}
	resume := workers.proofRequests[2]
	if resume.Method != http.MethodPost || resume.Path != "/v1/tenant-proof-jobs/0123456789abcdef01234567/resume" {
		t.Fatalf("proof resume worker request = %s %s", resume.Method, resume.Path)
	}
	resumeBody, err := io.ReadAll(resume.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(resumeBody) != `{"schema":"bazaar-control-tenant-proof-resume-request-v1","dossierId":"0123456789abcdef01234567","releaseDigest":"`+strings.Repeat("d", 64)+`"}` {
		t.Fatalf("proof resume body = %q", resumeBody)
	}

	workers.preparationResponse = WorkerResponse{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"schema":"bazaar-control-release-preparation-job-v1"}`))}
	pollRecorder = httptest.NewRecorder()
	handler.ServeHTTP(pollRecorder, httptest.NewRequest(http.MethodGet, "/v1/release-preparation-jobs/0123456789abcdef01234567", nil))
	if pollRecorder.Code != http.StatusAccepted || len(workers.preparationRequests) != 2 || workers.preparationRequests[1].Path != "/v1/release-preparation-jobs/0123456789abcdef01234567" {
		t.Fatalf("preparation poll status/requests/path = %d/%d/%q", pollRecorder.Code, len(workers.preparationRequests), workers.preparationRequests[1].Path)
	}

	workers.finalizationResponse = WorkerResponse{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"schema":"bazaar-control-release-finalization-job-v1"}`))}
	pollRecorder = httptest.NewRecorder()
	handler.ServeHTTP(pollRecorder, httptest.NewRequest(http.MethodGet, "/v1/release-finalization-jobs/0123456789abcdef01234567", nil))
	if pollRecorder.Code != http.StatusAccepted || len(workers.finalizationRequests) != 2 || workers.finalizationRequests[1].Path != "/v1/release-finalization-jobs/0123456789abcdef01234567" {
		t.Fatalf("finalization poll status/requests/path = %d/%d/%q", pollRecorder.Code, len(workers.finalizationRequests), workers.finalizationRequests[1].Path)
	}
}

func TestWorkerPollRelaysSafeNeedsAttentionState(t *testing.T) {
	workers := &capturedWorkerForwarder{
		finalizationResponse: WorkerResponse{
			StatusCode: http.StatusConflict,
			Header:     http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}},
			Body:       io.NopCloser(strings.NewReader("Release finalization needs attention. The catalog is unchanged.\n")),
		},
	}
	handler := newJobTestHandler(t, &capturedForwarder{}, workers)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/release-finalization-jobs/0123456789abcdef01234567", nil))
	if recorder.Code != http.StatusConflict || recorder.Body.String() != "Release finalization needs attention. The catalog is unchanged.\n" || len(workers.finalizationRequests) != 1 {
		t.Fatalf("attention poll = %d %q requests=%d", recorder.Code, recorder.Body.String(), len(workers.finalizationRequests))
	}
}

func TestWorkerJobRelayFailsClosed(t *testing.T) {
	forwarder := &capturedForwarder{}
	noWorkers := newTestHandler(t, forwarder)
	recorder := httptest.NewRecorder()
	noWorkers.ServeHTTP(recorder, buildJobRequest(t))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured job status = %d", recorder.Code)
	}

	workers := &capturedWorkerForwarder{}
	handler := newJobTestHandler(t, forwarder, workers)
	badJSON := httptest.NewRequest(http.MethodPost, "/v1/build-jobs", strings.NewReader(`{"schema":"wrong"}`))
	badJSON.Header.Set("Content-Type", "application/json")
	badRecorder := httptest.NewRecorder()
	handler.ServeHTTP(badRecorder, badJSON)
	if badRecorder.Code != http.StatusBadRequest || len(workers.buildRequests) != 0 {
		t.Fatalf("bad job status/requests = %d/%d", badRecorder.Code, len(workers.buildRequests))
	}

	badPreparation := preparationJobRequest(t)
	badPreparation.Body = io.NopCloser(strings.NewReader(`{"schema":"bazaar-control-release-preparation-request-v1","action":"publish_release"}`))
	badPreparation.ContentLength = int64(len(`{"schema":"bazaar-control-release-preparation-request-v1","action":"publish_release"}`))
	badPreparationRecorder := httptest.NewRecorder()
	handler.ServeHTTP(badPreparationRecorder, badPreparation)
	if badPreparationRecorder.Code != http.StatusBadRequest || len(workers.preparationRequests) != 0 {
		t.Fatalf("bad preparation status/requests = %d/%d", badPreparationRecorder.Code, len(workers.preparationRequests))
	}

	badFinalization := finalizationJobRequest(t)
	badFinalization.Body = io.NopCloser(strings.NewReader(`{"schema":"bazaar-control-release-finalization-request-v1","action":"publish_release"}`))
	badFinalization.ContentLength = int64(len(`{"schema":"bazaar-control-release-finalization-request-v1","action":"publish_release"}`))
	badFinalizationRecorder := httptest.NewRecorder()
	handler.ServeHTTP(badFinalizationRecorder, badFinalization)
	if badFinalizationRecorder.Code != http.StatusBadRequest || len(workers.finalizationRequests) != 0 {
		t.Fatalf("bad finalization status/requests = %d/%d", badFinalizationRecorder.Code, len(workers.finalizationRequests))
	}

	missingCandidate := finalizationJobRequest(t)
	missingBody, err := io.ReadAll(missingCandidate.Body)
	if err != nil {
		t.Fatal(err)
	}
	missingBody = []byte(strings.Replace(string(missingBody), `,"candidateSha256":"`+strings.Repeat("9", 64)+`","candidateBytes":42,"finalizationInputSha256":"`+strings.Repeat("8", 64)+`","finalizationInputBytes":42`, "", 1))
	missingCandidate.Body = io.NopCloser(strings.NewReader(string(missingBody)))
	missingCandidate.ContentLength = int64(len(missingBody))
	missingCandidateRecorder := httptest.NewRecorder()
	handler.ServeHTTP(missingCandidateRecorder, missingCandidate)
	if missingCandidateRecorder.Code != http.StatusBadRequest || len(workers.finalizationRequests) != 0 {
		t.Fatalf("missing finalization candidate status/requests = %d/%d", missingCandidateRecorder.Code, len(workers.finalizationRequests))
	}

	missingFinalizationInput := finalizationJobRequest(t)
	missingBody, err = io.ReadAll(missingFinalizationInput.Body)
	if err != nil {
		t.Fatal(err)
	}
	missingBody = []byte(strings.Replace(string(missingBody), `,"finalizationInputSha256":"`+strings.Repeat("8", 64)+`","finalizationInputBytes":42`, "", 1))
	missingFinalizationInput.Body = io.NopCloser(strings.NewReader(string(missingBody)))
	missingFinalizationInput.ContentLength = int64(len(missingBody))
	missingFinalizationInputRecorder := httptest.NewRecorder()
	handler.ServeHTTP(missingFinalizationInputRecorder, missingFinalizationInput)
	if missingFinalizationInputRecorder.Code != http.StatusBadRequest || len(workers.finalizationRequests) != 0 {
		t.Fatalf("missing finalization input status/requests = %d/%d", missingFinalizationInputRecorder.Code, len(workers.finalizationRequests))
	}

	wrongRoute := httptest.NewRequest(http.MethodPost, "/v1/build-jobs/0123456789abcdef01234567", nil)
	wrongRecorder := httptest.NewRecorder()
	handler.ServeHTTP(wrongRecorder, wrongRoute)
	if wrongRecorder.Code != http.StatusMethodNotAllowed || len(workers.buildRequests) != 0 {
		t.Fatalf("wrong job route status/requests = %d/%d", wrongRecorder.Code, len(workers.buildRequests))
	}

	badResume := proofResumeHTTPRequest(t, testDossierID, "not-a-dossier", strings.Repeat("d", 64))
	badResumeRecorder := httptest.NewRecorder()
	handler.ServeHTTP(badResumeRecorder, badResume)
	if badResumeRecorder.Code != http.StatusBadRequest || len(workers.proofRequests) != 0 {
		t.Fatalf("bad proof resume status/requests = %d/%d", badResumeRecorder.Code, len(workers.proofRequests))
	}

	inventedAction := httptest.NewRequest(http.MethodPost, "/v1/tenant-proof-jobs/0123456789abcdef01234567/delete", strings.NewReader(`{"schema":"bazaar-control-tenant-proof-resume-request-v1","dossierId":"`+testDossierID+`","releaseDigest":"`+strings.Repeat("d", 64)+`"}`))
	inventedAction.Header.Set("Content-Type", "application/json")
	inventedRecorder := httptest.NewRecorder()
	handler.ServeHTTP(inventedRecorder, inventedAction)
	if inventedRecorder.Code != http.StatusNotFound || len(workers.proofRequests) != 0 {
		t.Fatalf("invented proof action status/requests = %d/%d", inventedRecorder.Code, len(workers.proofRequests))
	}
}

func TestWorkerProvisioningRequiresEveryFixedOrigin(t *testing.T) {
	if _, err := NewWorkerForwarder(testConfig()); err == nil || !strings.Contains(err.Error(), "workerCaPath") {
		t.Fatalf("unprovisioned workers error = %v", err)
	}

	config := testConfig()
	config.WorkerCAPath = "/etc/bazaar-store-link/worker-ca.pem"
	config.BuildWorkerURL = "https://127.0.0.1:9461"
	config.TenantProofWorkerURL = "https://127.0.0.1:9462"
	if _, err := NewWorkerForwarder(config); err == nil || !strings.Contains(err.Error(), "releasePreparationWorkerUrl") {
		t.Fatalf("missing preparation origin error = %v", err)
	}
	config.ReleasePreparationWorkerURL = "https://127.0.0.1:9463"
	if _, err := NewWorkerForwarder(config); err == nil || !strings.Contains(err.Error(), "releaseFinalizationWorkerUrl") {
		t.Fatalf("missing finalization origin error = %v", err)
	}
}

func TestLoadConfigRejectsGroupOrWorldWritableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store-link.json")
	raw, err := json.Marshal(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig() for 0600 config = %v", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig() accepted a group-writable connector config")
	}
	if err := os.Chmod(path, 0o602); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig() accepted a world-writable connector config")
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
