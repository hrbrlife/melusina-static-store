package storelink

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func selectedSnapshotFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	appID := strings.Repeat("a", 52)
	value := selectedReleaseSnapshot{Schema: selectedReleaseSchema, StoreID: testStoreID, AppID: appID, GenerationID: "generation-0123456789abcdef", ObservedAt: time.Now().UTC(), Index: []byte("{\n\"apps\":[]\n}"), Pointer: []byte("{}\n"), Metadata: []byte("{} "), Release: []byte("{}"), RuntimeContract: []byte("{}"), SPK: bytes.Repeat([]byte("x"), 2<<20)}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return raw, appID
}

func TestStoreLinkSelectedReleasePreservesReadoutAndFixedRoute(t *testing.T) {
	raw, appID := selectedSnapshotFixture(t)
	forward := &capturedForwarder{response: ForwardResponse{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: raw}}
	h, err := NewHandler(testConfig(), forward)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, selectedReleasePrefix+appID, nil)
	r.Header.Set("Authorization", "caller-supplied-secret")
	r.Header.Set("X-Bazaar-Control-Command", "not-a-command")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), raw) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("selected response changed: %d", w.Code)
	}
	if len(forward.requests) != 1 || forward.requests[0].Path != privateSelectedReleasePrefix+appID || len(forward.requests[0].Headers) != 0 {
		t.Fatal("selected read inherited caller authority or chose a route")
	}
	for _, path := range []string{selectedReleasePrefix + appID + "?url=https://attacker.invalid", selectedReleasePrefix + appID + "/metadata", selectedReleasePrefix + "short", selectedReleasePrefix + strings.ToUpper(appID)} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code == http.StatusOK {
			t.Fatal("unscoped route accepted")
		}
	}
	if len(forward.requests) != 1 {
		t.Fatal("invalid routes reached the private Store")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, selectedReleasePrefix+appID, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal("selected read allowed mutation")
	}
}

func TestStoreLinkSelectedReleaseRefusesWrapperDrift(t *testing.T) {
	raw, appID := selectedSnapshotFixture(t)
	for name, mutate := range map[string]func([]byte) []byte{
		"wrong Store": func(b []byte) []byte { return bytes.Replace(b, []byte(testStoreID), []byte("other-store"), 1) },
		"wrong app":   func(b []byte) []byte { return bytes.Replace(b, []byte(appID), []byte(strings.Repeat("b", 52)), 1) },
		"alias":       func(b []byte) []byte { return bytes.Replace(b, []byte(`"appId"`), []byte(`"APPID"`), 1) },
		"duplicate": func(b []byte) []byte {
			return bytes.Replace(b, []byte("{"), []byte(`{"schema":"`+selectedReleaseSchema+`",`), 1)
		},
		"source assertion": func(b []byte) []byte {
			return bytes.Replace(b, []byte("{"), []byte(`{"sourceBaselineAuthenticated":true,`), 1)
		},
		"truncated":    func(b []byte) []byte { return b[:len(b)-1] },
		"extra object": func(b []byte) []byte { return append(b, []byte("{}")...) },
	} {
		t.Run(name, func(t *testing.T) {
			if validateSelectedReleaseSnapshot(mutate(bytes.Clone(raw)), testStoreID, appID, time.Now()) == nil {
				t.Fatal("invalid selected evidence accepted")
			}
		})
	}
	var value selectedReleaseSnapshot
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	value.ObservedAt = time.Now().Add(-11 * time.Minute)
	stale, _ := json.Marshal(value)
	if validateSelectedReleaseSnapshot(stale, testStoreID, appID, time.Now()) == nil {
		t.Fatal("stale readout accepted")
	}
	value.ObservedAt = time.Now()
	value.Index = append([]byte(`{"padding":"`), bytes.Repeat([]byte("a"), int(maxSelectedReleaseJSONBytes))...)
	value.Index = append(value.Index, []byte(`"}`)...)
	large, _ := json.Marshal(value)
	if validateSelectedReleaseSnapshot(large, testStoreID, appID, time.Now()) == nil {
		t.Fatal("oversized public JSON accepted")
	}
}

func TestSidecarForwarderLargerReadBoundIsSelectedRouteOnly(t *testing.T) {
	raw, appID := selectedSnapshotFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	f := &SidecarForwarder{origin: origin, http: server.Client()}
	for path, wantOK := range map[string]bool{privateSelectedReleasePrefix + appID: true, "/control/v1/status": false, "/control/v1/policy": false} {
		response, err := f.Forward(context.Background(), ForwardRequest{Method: http.MethodGet, Path: path, Body: io.NopCloser(strings.NewReader(""))})
		if (err == nil) != wantOK {
			t.Fatalf("path %s: %v", path, err)
		}
		if wantOK && !bytes.Equal(response.Body, raw) {
			t.Fatal("selected response changed")
		}
	}
	if canonicalSidecarPath(http.MethodPost, privateSelectedReleasePrefix+appID) || canonicalSidecarPath(http.MethodGet, privateSelectedReleasePrefix+appID+"/any") {
		t.Fatal("private selected route widened")
	}
}
