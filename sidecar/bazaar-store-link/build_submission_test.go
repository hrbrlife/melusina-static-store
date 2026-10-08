package storelink

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildSubmissionCarriesOnlyServerFetchedEvidence(t *testing.T) {
	selected, appID := selectedSnapshotFixture(t)
	forwarder := &capturedForwarder{response: ForwardResponse{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: selected}}
	workers := &capturedWorkerForwarder{buildResponse: WorkerResponse{StatusCode: http.StatusAccepted, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"job":"pending"}`))}}
	h := newJobTestHandler(t, forwarder, workers)
	r := buildJobRequest(t)
	original, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(original))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted || len(workers.buildRequests) != 1 || len(forwarder.requests) != 1 {
		t.Fatalf("private submission: %d %s", w.Code, w.Body.String())
	}
	if forwarder.requests[0].Path != privateSelectedReleasePrefix+appID || workers.buildRequests[0].Path != buildSubmissionPath {
		t.Fatal("submission selected a noncanonical route")
	}
	raw, _ := io.ReadAll(workers.buildRequests[0].Body)
	var submission buildSubmission
	if err := json.Unmarshal(raw, &submission); err != nil {
		t.Fatal(err)
	}
	if submission.Schema != buildSubmissionSchema || !bytes.Equal(submission.SourceIntent, original) {
		t.Fatal("original source intent changed")
	}
	var before, after selectedReleaseSnapshot
	if json.Unmarshal(selected, &before) != nil || json.Unmarshal(submission.SelectedRelease, &after) != nil {
		t.Fatal("selected object malformed")
	}
	for i, pair := range [][2][]byte{{before.Index, after.Index}, {before.Pointer, after.Pointer}, {before.Metadata, after.Metadata}, {before.Release, after.Release}, {before.RuntimeContract, after.RuntimeContract}, {before.SPK, after.SPK}} {
		if !bytes.Equal(pair[0], pair[1]) {
			t.Fatalf("public artifact %d changed in private submission", i)
		}
	}
	if canonicalJobPath(http.MethodPost, "/v1/build-jobs", buildJobCollection) || !canonicalJobPath(http.MethodPost, buildSubmissionPath, buildJobCollection) || canonicalJobPath(http.MethodPost, buildSubmissionPath, releasePreparationJobCollection) {
		t.Fatal("private submission route scope widened")
	}
}

func TestBrowserCannotSupplyBuildEvidenceOrAnotherStore(t *testing.T) {
	for name, edit := range map[string]func([]byte) []byte{
		"selected release": func(b []byte) []byte { return bytes.Replace(b, []byte("{"), []byte(`{"selectedRelease":{},`), 1) },
		"baseline": func(b []byte) []byte {
			return bytes.Replace(b, []byte("{"), []byte(`{"sourceReviewBaseline":{"selectedAppHash":"untrusted"},`), 1)
		},
		"other Store": func(b []byte) []byte { return bytes.Replace(b, []byte(testStoreID), []byte("other-store"), 1) },
	} {
		t.Run(name, func(t *testing.T) {
			forward := &capturedForwarder{}
			workers := &capturedWorkerForwarder{}
			h := newJobTestHandler(t, forward, workers)
			r := buildJobRequest(t)
			raw, _ := io.ReadAll(r.Body)
			body := edit(raw)
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || len(forward.requests) != 0 || len(workers.buildRequests) != 0 {
				t.Fatal("browser-selected evidence or foreign Store reached private services")
			}
		})
	}
	h := newJobTestHandler(t, &capturedForwarder{}, &capturedWorkerForwarder{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, buildSubmissionPath, strings.NewReader(`{}`)))
	if w.Code != http.StatusNotFound {
		t.Fatal("internal submission route exposed to browser")
	}
}

func TestUnavailableSelectedReleaseNeverStartsBuild(t *testing.T) {
	forward := &capturedForwarder{response: ForwardResponse{StatusCode: http.StatusServiceUnavailable}}
	workers := &capturedWorkerForwarder{}
	h := newJobTestHandler(t, forward, workers)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, buildJobRequest(t))
	if w.Code != http.StatusServiceUnavailable || len(workers.buildRequests) != 0 {
		t.Fatal("unverified selected release reached build worker")
	}
}
