package storelink

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type failedWorkerBody struct{}

func (failedWorkerBody) Read(p []byte) (int, error) {
	copy(p, "{}")
	return 2, errors.New("interrupted worker stream")
}
func (failedWorkerBody) Close() error { return nil }

func TestWorkerResultPreservesCompleteMSBReviewAndRefusesOversizeBeforeSuccess(t *testing.T) {
	full := `{"attestation":{"sourceReview":"` + strings.Repeat(`\u003c`, 1<<20) + `"}}`
	for _, test := range []struct {
		name         string
		body         io.ReadCloser
		length       int64
		start        bool
		status, want int
		expected     string
	}{
		{"full escaped review", io.NopCloser(strings.NewReader(full)), int64(len(full)), false, http.StatusOK, http.StatusOK, full},
		{"declared oversized build", io.NopCloser(strings.NewReader("{}")), maxBuildJobResultBytes + 1, false, http.StatusOK, http.StatusBadGateway, ""},
		{"unknown length oversized acknowledgement", io.NopCloser(strings.NewReader(strings.Repeat("x", int(maxProofJobResultBytes)+1))), -1, true, http.StatusAccepted, http.StatusBadGateway, ""},
		{"interrupted success body", failedWorkerBody{}, -1, false, http.StatusOK, http.StatusBadGateway, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			workers := &capturedWorkerForwarder{buildResponse: WorkerResponse{StatusCode: test.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: test.body, ContentLength: test.length}}
			h := newJobTestHandler(t, &capturedForwarder{}, workers)
			request := httptest.NewRequest(http.MethodGet, "/v1/build-jobs/"+testDossierID, nil)
			response := httptest.NewRecorder()
			h.forwardJobResponse(response, request, buildJobCollection, WorkerRequest{Method: http.MethodGet, Path: request.URL.Path, Body: io.NopCloser(strings.NewReader(""))}, test.start, false)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
			if test.expected != "" && response.Body.String() != test.expected {
				t.Fatal("complete escaped review was changed or truncated")
			}
		})
	}
}
