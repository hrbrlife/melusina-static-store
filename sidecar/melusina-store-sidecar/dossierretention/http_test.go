package dossierretention

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDossierCustodyTransportPositiveAndMutations(t *testing.T) {
	s, source, scope, encrypted := fixture(t)
	call := func(req storeRequest) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		httpReq := httptest.NewRequest(http.MethodPost, "/v1/dossier", bytes.NewReader(body))
		out := httptest.NewRecorder()
		s.Handler().ServeHTTP(out, httpReq)
		return out
	}
	positive := call(storeRequest{source, scope, encrypted})
	if positive.Code != http.StatusOK {
		t.Fatalf("signed custody positive: %d %s", positive.Code, positive.Body.String())
	}
	var member Member
	if json.Unmarshal(positive.Body.Bytes(), &member) != nil || member.KeyID != "storage-export" {
		t.Fatal("signed member missing from transport")
	}
	if _, err := s.load("case-A", "tester-A", "corr-A"); err != nil {
		t.Fatal("durable custody missing:", err)
	}
	mutated := scope
	mutated.TesterRef = "tester-B"
	bad := call(storeRequest{source, mutated, encrypted})
	if bad.Code != http.StatusConflict || !strings.Contains(bad.Body.String(), "pack-cross-tester") {
		t.Fatalf("cross-tester transport survived: %d %s", bad.Code, bad.Body.String())
	}
	bad = call(storeRequest{source, scope, []byte("different")})
	if bad.Code != http.StatusConflict || !strings.Contains(bad.Body.String(), "dossier-object-digest-mismatch") {
		t.Fatalf("object substitution survived: %d %s", bad.Code, bad.Body.String())
	}
}
