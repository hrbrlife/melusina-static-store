package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRequirePearlControlRetiresLegacyAppRoutesBeforeAnyMutation(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PrivateStageDir = t.TempDir()
	cfg.Policy.RequirePearlControlForAppPublish = true
	handler := newRouter(cfg, nil, nil, nil)

	for _, path := range []string{"/publish", "/publish/stage"} {
		request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{"looks":"like a publish request"}`)))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusGone || !strings.Contains(response.Body.String(), "Bazaar Control") {
			t.Fatalf("retired route %s = %d: %s", path, response.Code, response.Body.String())
		}
	}
	entries, err := os.ReadDir(cfg.PrivateStageDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("retired legacy routes touched stage state: entries=%v err=%v", entries, err)
	}

	// Pearl commands have a separate exact prefix and must not be swallowed by
	// the retirement handler. It can fail for missing control headers, but not
	// as a retired legacy endpoint.
	request := httptest.NewRequest(http.MethodPost, "/control/v1/releases/dossier/prepare", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code == http.StatusGone {
		t.Fatalf("Pearl control route was retired with the legacy routes: %s", response.Body.String())
	}
}
