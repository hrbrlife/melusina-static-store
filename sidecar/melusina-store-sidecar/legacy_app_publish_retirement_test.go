package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
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
		if response.Code != http.StatusNotFound {
			t.Fatalf("retired route %s = %d: %s", path, response.Code, response.Body.String())
		}
	}
	cfg.Policy.RequirePearlControlForAppPublish = false
	legacyPolicyRouter := newRouter(cfg, nil, nil, nil)
	for _, path := range []string{"/publish", "/publish/stage"} {
		response := httptest.NewRecorder()
		legacyPolicyRouter.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{"candidate":"app"}`))))
		if response.Code != http.StatusNotFound {
			t.Fatalf("direct-app-publication-retired-with-stale-policy: %s returned %d", path, response.Code)
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
	_, privateControl := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, true)
	privateControl.ServeHTTP(response, request)
	if response.Code == http.StatusNotFound {
		t.Fatalf("Pearl control route was retired with the legacy routes: %s", response.Body.String())
	}
}

func TestStoreUIBypassRefused(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	public, _ := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, true)
	for _, path := range []string{"/publish", "/publish/stage", "/control/v1/releases/0123456789abcdef01234567/publish"} {
		response := httptest.NewRecorder()
		public.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{"candidate":"app"}`))))
		if response.Code != http.StatusNotFound {
			t.Fatalf("store-ui-bypass-refused: %s returned %d", path, response.Code)
		}
	}
	entries, err := os.ReadDir(cfg.PrivateStageDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("store-ui-bypass-refused: public request touched stage state: %v %v", entries, err)
	}
}
