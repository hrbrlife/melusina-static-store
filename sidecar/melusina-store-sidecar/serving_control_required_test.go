package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

func TestControlPublicRouteAbsentWithoutMTLS(t *testing.T) {
	for _, configured := range []bool{false, true} {
		cfg := Config{StoreID: "local-store"}
		if configured {
			cfg.StoreLinkControlMTLS.ListenAddr = "127.0.0.1:9443"
		}
		public, _ := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, configured)
		request := httptest.NewRequest(http.MethodPost, "/control/v1/releases/dossier/prepare", strings.NewReader("{}"))
		response := httptest.NewRecorder()
		public.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("control-public-route-absent-without-mtls: configured=%t status=%d", configured, response.Code)
		}
	}
}

func TestServingStoreRequiresControlMTLS(t *testing.T) {
	if err := requireServingControlMTLS(Config{}); err == nil || !strings.Contains(err.Error(), "store_link_control_mtls") {
		t.Fatalf("serving-store-control-mtls-required: got %v", err)
	}
	profile := storeEstateProfileFixture(t)
	digest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	security := signedStoreSecurityFixture(t, profile, digest)
	cfg := Config{EstateProfile: &profile, StoreSecurityProfile: &security, StoreID: security.StoreID,
		StoreLinkControlMTLS: StoreLinkControlMTLSConfig{ListenAddr: security.ControlListenAddr, StoreLinkClientCertSHA256: security.StoreLinkClientCertSHA256},
		Policy:               Policy{RequirePearlControlForAppPublish: true, RequireScanReport: true, ScannerEd25519PublicKey: security.ScannerEd25519PublicKey}}
	if err := requireServingControlMTLS(cfg); err != nil {
		t.Fatalf("serving-store-control-mtls-positive: %v", err)
	}
	cfg.Policy.RequirePearlControlForAppPublish = false
	if err := requireServingControlMTLS(cfg); err == nil || !strings.Contains(err.Error(), "require_pearl_control_for_app_publish") {
		t.Fatalf("serving-store-single-app-rail-required: %v", err)
	}
	cfg.Policy.RequirePearlControlForAppPublish = true
	cfg.StoreLinkControlMTLS.StoreLinkClientCertSHA256 = strings.Repeat("0", 64)
	if err := requireServingControlMTLS(cfg); err == nil || !strings.Contains(err.Error(), "signed Store security fields") {
		t.Fatalf("serving-store-link-client-pin-bound: %v", err)
	}
}
