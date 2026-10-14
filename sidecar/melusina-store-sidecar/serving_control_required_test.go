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
	// False declares the direct enrolled-publisher route as the one app
	// authority. It needs at least one profile-named publisher; an empty
	// list would declare an authority nobody can exercise.
	cfg.Policy.RequirePearlControlForAppPublish = false
	if err := requireServingControlMTLS(cfg); err == nil || !strings.Contains(err.Error(), "accept_publishers must name the enrolled publishers") {
		t.Fatalf("serving-store-direct-authority-needs-publishers: %v", err)
	}
	cfg.Policy.AcceptPublishers = []string{storeConfigRenderTestPublisher(t, profile)}
	if err := requireServingControlMTLS(cfg); err != nil {
		t.Fatalf("serving-store-direct-authority-positive: %v", err)
	}
	cfg.Policy.RequirePearlControlForAppPublish = true
	cfg.StoreLinkControlMTLS.StoreLinkClientCertSHA256 = strings.Repeat("0", 64)
	if err := requireServingControlMTLS(cfg); err == nil || !strings.Contains(err.Error(), "signed Store security fields") {
		t.Fatalf("serving-store-link-client-pin-bound: %v", err)
	}
}

func storeConfigRenderTestPublisher(t *testing.T, profile estateprofile.EstateProfileV1) string {
	t.Helper()
	keys, err := storeConfigRenderPublisherKeys(profile.ReleaseTrust.PublisherKeys)
	if err != nil || len(keys) == 0 {
		t.Fatalf("fixture profile names no publisher key: %v", err)
	}
	return keys[0]
}
