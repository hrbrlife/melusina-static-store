package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The serving policy names exactly one app publication authority. Each
// inactive route answers by name before it reads a body, claims a nonce or
// touches stage state; the active one reaches its ordinary gate.
func TestServingPolicySelectsExactlyOneAppPublicationAuthority(t *testing.T) {
	for _, pearl := range []bool{false, true} {
		cfg, _ := testConfig(t)
		cfg.PrivateStageDir = t.TempDir()
		cfg.Policy.RequirePearlControlForAppPublish = pearl
		public, private := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, true)
		for _, path := range []string{"/publish", "/publish/stage"} {
			response := httptest.NewRecorder()
			public.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{"looks":"like a publish request"}`))))
			retired := response.Code == http.StatusGone && strings.Contains(response.Body.String(), "check=app_publication_authority")
			if pearl != retired {
				t.Fatalf("pearl=%t direct %s = %d: %s", pearl, path, response.Code, response.Body.String())
			}
			if !pearl && response.Code != http.StatusServiceUnavailable {
				t.Fatalf("active direct route %s without chain/operator = %d: %s", path, response.Code, response.Body.String())
			}
		}
		for _, path := range []string{"/control/v1/releases/dossier/prepare", "/control/v1/releases/dossier/publish"} {
			response := httptest.NewRecorder()
			private.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
			refused := response.Code == http.StatusConflict && strings.Contains(response.Body.String(), "check=app_publication_authority")
			if pearl == refused || response.Code == http.StatusNotFound {
				t.Fatalf("pearl=%t control %s = %d: %s", pearl, path, response.Code, response.Body.String())
			}
		}
		entries, err := os.ReadDir(cfg.PrivateStageDir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("pearl=%t inactive authority touched stage state: entries=%v err=%v", pearl, entries, err)
		}
	}
}

func TestControlRouteRemainsPrivateWhileDirectRoutesUseTheirGate(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	public, _ := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, true)
	for _, path := range []string{"/control/v1/releases/0123456789abcdef01234567/publish"} {
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
