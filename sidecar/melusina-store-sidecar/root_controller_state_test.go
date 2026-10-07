package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestH09_3_6PrivateRootControllerStateReadback(t *testing.T) {
	fixture := newHostApplyPlanFixture(t)
	public := newPublicRouterWithService(fixture.svc.cfg, fixture.svc.operator, fixture.chain, nil, catalogRuntime{}, fixture.svc, true)
	publicResponse := httptest.NewRecorder()
	public.ServeHTTP(publicResponse, httptest.NewRequest(http.MethodGet, rootControllerStatePath, nil))
	if publicResponse.Code != http.StatusNotFound {
		t.Fatalf("3.6::title-claim: public readback route = %d, want 404", publicResponse.Code)
	}

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, rootControllerStoreMarker), 0o700); err != nil {
		t.Fatal(err)
	}
	handler := newRootControllerStateHandler(root)
	request := httptest.NewRequest(http.MethodGet, rootControllerStatePath, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("3.6::title-claim: root Store readback: %d %s", response.Code, response.Body.String())
	}
	var value map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil || value["noControllerConfig"] != true || value["rootStoreHost"] != true {
		t.Fatalf("3.6::title-claim: invalid root Store readback: %v %v", value, err)
	}
	configDir := filepath.Join(root, rootControllerConfigDir)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, rootControllerConfigName), []byte("unexpected\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "3.6::title-claim") {
		t.Fatalf("3.6::title-claim: planted config was not refused by name: %d %s", response.Code, response.Body.String())
	}
}
