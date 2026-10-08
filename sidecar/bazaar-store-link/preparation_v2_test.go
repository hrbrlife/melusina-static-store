package storelink

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPreparationV2RetainsReviewedSelectionAndRefusesSchemaDrift(t *testing.T) {
	request := preparationJobRequest(t)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	full := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"reviewedPriorAppHash":"`+strings.Repeat("a", 64)+`"}`)...)
	for _, test := range []struct {
		name  string
		body  []byte
		valid bool
	}{
		{"current exact reviewed baseline", full, true},
		{"retired v1", bytes.ReplaceAll(full, []byte("request-v2"), []byte("request-v1")), false},
		{"malformed prior", bytes.ReplaceAll(full, []byte(`"reviewedPriorAppHash":"`+strings.Repeat("a", 64)+`"`), []byte(`"reviewedPriorAppHash":"unverified-source"`)), false},
		{"unknown source authority", append(append([]byte(nil), full[:len(full)-1]...), []byte(`,"sourceBaselineAuthenticated":true}`)...), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			workers := &capturedWorkerForwarder{preparationResponse: WorkerResponse{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"schema":"bazaar-control-release-preparation-job-v1"}`))}}
			h := newJobTestHandler(t, &capturedForwarder{}, workers)
			r := httptest.NewRequest(http.MethodPost, "/v1/release-preparation-jobs", bytes.NewReader(test.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if test.valid {
				if w.Code != http.StatusAccepted || len(workers.preparationRequests) != 1 {
					t.Fatalf("valid current request rejected: %d", w.Code)
				}
				forwarded, _ := io.ReadAll(workers.preparationRequests[0].Body)
				if !bytes.Equal(forwarded, test.body) {
					t.Fatal("reviewed baseline changed in relay")
				}
			} else if w.Code == http.StatusAccepted || len(workers.preparationRequests) != 0 {
				t.Fatal("schema drift reached preparation worker")
			}
		})
	}
}
