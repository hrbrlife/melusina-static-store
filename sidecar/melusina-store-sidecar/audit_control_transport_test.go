package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The production main passes configured() to the governed router. A signed
// profile without a private listener must not silently select the development
// combined surface on the public catalog listener.
func TestAuditControlTransportWhenPrivateListenerAbsent(t *testing.T) {
	_, profilePath, inputPath, outputPath, input := newStoreConfigRenderFixture(t)
	writeStoreConfigRenderInput(t, inputPath, input)
	if _, err := renderEstateStoreConfig(estateStoreConfigRenderOptions{
		profilePath: profilePath, inputPath: inputPath, outputPath: outputPath,
	}); err != nil {
		t.Fatalf("signed profile config render: %v", err)
	}
	cfg, err := LoadConfig(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StoreLinkControlMTLS.configured() {
		t.Fatal("rendered config unexpectedly has a private Store Link listener")
	}
	cfg.DistDir = t.TempDir()
	cfg.PrivateStageDir = t.TempDir()
	public, _ := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, cfg.StoreLinkControlMTLS.configured())
	request := httptest.NewRequest(http.MethodPost, "/control/v1/releases/dossier/prepare", nil)
	response := httptest.NewRecorder()
	public.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("public typed control route should reach command parsing under rendered config, got %d: %s", response.Code, response.Body.String())
	}
	// The production route still requires a signed command. The finding is
	// public transport of that route, not acceptance of an unsigned mutation.
	isolated, _ := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, true)
	response = httptest.NewRecorder()
	isolated.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("isolated public route = %d, want 404", response.Code)
	}
}
