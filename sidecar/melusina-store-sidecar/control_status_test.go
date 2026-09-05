package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestPrivateControlStatusReportsOnlyReadyBoundedControlService(t *testing.T) {
	clock := time.Date(2026, 8, 22, 15, 4, 5, 0, time.UTC)
	cfg, _ := testConfig(t)
	cfg.ProgramID = programID.Base58()
	op := newTestIdentity(t, "control-status", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = op.Public().SignPubkeyB58
	chain := newMockChainReader()
	license, err := primitives.PubkeyFromBase58(cfg.LicenseNFTMint)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := primitives.PubkeyFromBase58(cfg.StoreAuthority)
	if err != nil {
		t.Fatal(err)
	}
	authz, _, err := pda.StoreOperatorAuthorization(license, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	policyPDA, err := deriveStoreControlPolicy(license, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	chain.rawAccounts[policyPDA.Base58()] = controlPolicyBlob(license, primitives.StoreDomainHash(cfg.Domain), authority, authz, [32]byte{1}, [32]byte{2}, 7)
	svc := newTestService(t, cfg, chain, op)
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

func TestPrivateControlStatusRequiresAnActiveStorePolicy(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.ProgramID = programID.Base58()
	op := newTestIdentity(t, "control-status-policy", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = op.Public().SignPubkeyB58
	svc := newTestService(t, cfg, newMockChainReader(), op)

	response := httptest.NewRecorder()
	newControlReleaseRouter(svc).ServeHTTP(response, httptest.NewRequest(http.MethodGet, controlStatusPath, nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("control status without active policy = %d %s", response.Code, response.Body.String())
	}
}

func TestControlStatusFailsClosedAndNeverExistsOnPublicListener(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PrivateStageDir = t.TempDir()
	public, control := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, true)

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
