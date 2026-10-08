package storelink

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPreparationReturnRelaysOnlyExactReceiptToExistingStoreJob(t *testing.T) {
	path := "/v1/release-preparation-jobs/" + testDossierID + "/stage-receipt"
	body := []byte(`{"schema":"bazaar-control-private-stage-return-v1","storeId":"` + testStoreID + `","requestDigest":"` + testDossierID + strings.Repeat("a", 40) + `","offerDigest":"` + strings.Repeat("b", 64) + `","receipt":{"schema":"melusina-app-stage-receipt-v1","stageId":"` + strings.Repeat("c", 64) + `","appId":"paint","appHash":"` + strings.Repeat("d", 64) + `","releaseHash":"` + strings.Repeat("e", 64) + `","servingDomainHash":"` + strings.Repeat("f", 64) + `","storedAt":1788940000,"operatorSignature":"signed-original-store-receipt"}}`)
	for _, test := range []struct {
		name  string
		body  []byte
		path  string
		valid bool
	}{
		{"exact receipt", body, path, true},
		{"other Store", bytes.Replace(body, []byte(testStoreID), []byte("other-store"), 1), path, false},
		{"other job", body, strings.Replace(path, testDossierID, strings.Repeat("9", 24), 1), false},
		{"proposal input", append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"proposal":"caller-selected"}`)...), path, false},
		{"execution route", body, strings.Replace(path, "stage-receipt", "execute", 1), false},
		{"receipt query", body, path + "?execute=true", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			workers := &capturedWorkerForwarder{preparationResponse: WorkerResponse{StatusCode: 202, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"job":"accepted"}`))}}
			h := newJobTestHandler(t, &capturedForwarder{}, workers)
			r := httptest.NewRequest(http.MethodPost, test.path, bytes.NewReader(test.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if test.valid {
				if w.Code != 202 || len(workers.preparationRequests) != 1 || !canonicalJobPath(http.MethodPost, path, releasePreparationJobCollection) {
					t.Fatalf("valid receipt: %d", w.Code)
				}
				forwarded, _ := io.ReadAll(workers.preparationRequests[0].Body)
				if !bytes.Equal(forwarded, body) {
					t.Fatal("receipt bytes changed")
				}
			} else if w.Code == 202 || len(workers.preparationRequests) != 0 {
				t.Fatal("caller authority reached worker")
			}
		})
	}
}
