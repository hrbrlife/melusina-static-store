package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPrivateControlStatusReportsOnlyReadyBoundedControlService(t *testing.T) {
	clock := time.Date(2026, 8, 22, 15, 4, 5, 0, time.UTC)
	cfg, _ := testConfig(t)
	svc := newTestService(t, cfg, newMockChainReader(), newTestIdentity(t, "control-status", cfg.LicenseNFTMint, cfg.Domain))
	svc.now = func() time.Time { return clock }

	response := httptest.NewRecorder()
	newControlReleaseRouter(svc).ServeHTTP(response, httptest.NewRequest(http.MethodGet, controlStatusPath, nil))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("control status = %d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var snapshot controlStatusSnapshot
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Schema != controlStatusSnapshotSchema || snapshot.StoreID != cfg.StoreID || snapshot.Status != "ready" || !snapshot.CheckedAt.Equal(clock) {
		t.Fatalf("control status snapshot = %#v", snapshot)
	}
}

func TestControlStatusFailsClosedAndNeverExistsOnPublicListener(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PrivateStageDir = t.TempDir()
	public, control := newRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, true)

	publicResponse := httptest.NewRecorder()
	public.ServeHTTP(publicResponse, httptest.NewRequest(http.MethodGet, controlStatusPath, nil))
	if publicResponse.Code != http.StatusNotFound {
		t.Fatalf("public listener exposed control status: %d %s", publicResponse.Code, publicResponse.Body.String())
	}

	privateResponse := httptest.NewRecorder()
	control.ServeHTTP(privateResponse, httptest.NewRequest(http.MethodGet, controlStatusPath, nil))
	if privateResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("unready control status = %d %s", privateResponse.Code, privateResponse.Body.String())
	}

	wrongMethod := httptest.NewRecorder()
	control.ServeHTTP(wrongMethod, httptest.NewRequest(http.MethodPost, controlStatusPath, nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed {
		t.Fatalf("control status accepted mutation method: %d", wrongMethod.Code)
	}
	query := httptest.NewRecorder()
	control.ServeHTTP(query, httptest.NewRequest(http.MethodGet, controlStatusPath+"?catalog=1", nil))
	if query.Code != http.StatusNotFound {
		t.Fatalf("control status accepted query: %d", query.Code)
	}
}
