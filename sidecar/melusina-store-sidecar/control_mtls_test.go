package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/controltlsissue"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

func newControlTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Bazaar Control test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return certificate, key, pool
}

func newControlTestLeaf(t *testing.T, serial int64, name string, usage x509.ExtKeyUsage, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writeControlCertificate(t *testing.T, dir, name string, certificate tls.Certificate) (string, string) {
	t.Helper()
	key, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("control test key type = %T", certificate.PrivateKey)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestStoreLinkControlMTLSRequiresTLS13VerifiedAndPinnedStoreLinkLeaf(t *testing.T) {
	ca, caKey, roots := newControlTestCA(t)
	serverLeaf := newControlTestLeaf(t, 2, "sidecar.test", x509.ExtKeyUsageServerAuth, ca, caKey)
	storeLinkLeaf := newControlTestLeaf(t, 3, "store-link.test", x509.ExtKeyUsageClientAuth, ca, caKey)
	otherLeaf := newControlTestLeaf(t, 4, "other.test", x509.ExtKeyUsageClientAuth, ca, caKey)
	dir := t.TempDir()
	serverCertPath, serverKeyPath := writeControlCertificate(t, dir, "server", serverLeaf)
	caPath := filepath.Join(dir, "client-ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	pinned := sha256.Sum256(storeLinkLeaf.Certificate[0])
	tlsConfig, err := newStoreLinkControlTLSConfig(StoreLinkControlMTLSConfig{
		ListenAddr: "127.0.0.1:9443", CertPath: serverCertPath, KeyPath: serverKeyPath, ClientCAPath: caPath,
		StoreLinkClientCertSHA256: hex.EncodeToString(pinned[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.ClientCAs == nil {
		t.Fatalf("control TLS did not require TLS-1.3 verified mTLS: %#v", tlsConfig)
	}
	cfg := Config{StoreID: "local-control-test"}
	_, control := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, true)
	productionServer, err := newStoreLinkControlServer(StoreLinkControlMTLSConfig{
		ListenAddr: "127.0.0.1:9443", CertPath: serverCertPath, KeyPath: serverKeyPath, ClientCAPath: caPath,
		StoreLinkClientCertSHA256: hex.EncodeToString(pinned[:]),
	}, control)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(productionServer.Handler)
	server.TLS = productionServer.TLSConfig
	server.StartTLS()
	defer server.Close()
	newClient := func(certificate tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "sidecar.test", Certificates: []tls.Certificate{certificate},
		}}}
	}
	response, err := newClient(storeLinkLeaf).Get(server.URL + "/control/v1/releases/dossier/prepare")
	if err != nil {
		t.Fatalf("pinned Store Link request: %v", err)
	}
	response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		t.Fatalf("pinned Store Link did not reach governed private control route: %d", response.StatusCode)
	}
	if _, err := newClient(otherLeaf).Get(server.URL + "/control/v1/releases/dossier/prepare"); err == nil {
		t.Fatal("a different certificate from the trusted CA reached the Store Link control listener")
	}
}

func TestIssuedControlIdentityReachesOnlyPrivateProductionRouter(t *testing.T) {
	bundle, pin, err := controltlsissue.Issue("127.0.0.1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	caPath := filepath.Join(dir, "ca.crt")
	for path, content := range map[string]string{serverCertPath: bundle.ServerCertPEM, serverKeyPath: bundle.ServerKeyPEM, caPath: bundle.ClientCAPEM} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	profile := storeEstateProfileFixture(t)
	profileDigest, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	security := signedStoreSecurityFixture(t, profile, profileDigest, pin)
	cfg, _ := testConfig(t)
	cfg.StoreID = profile.Store.StoreID
	cfg.EstateProfile = &profile
	cfg.StoreSecurityProfile = &security
	cfg.Policy.RequirePearlControlForAppPublish = true
	cfg.Policy.RequireScanReport = true
	cfg.Policy.ScannerEd25519PublicKey = security.ScannerEd25519PublicKey
	cfg.StoreLinkControlMTLS = StoreLinkControlMTLSConfig{ListenAddr: security.ControlListenAddr, CertPath: serverCertPath,
		KeyPath: serverKeyPath, ClientCAPath: caPath, StoreLinkClientCertSHA256: pin}
	if err := requireServingControlMTLS(cfg); err != nil {
		t.Fatalf("issued-control-mtls-positive: %v", err)
	}
	public, private := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, true)
	production, err := newStoreLinkControlServer(cfg.StoreLinkControlMTLS, private)
	if err != nil {
		t.Fatalf("issued-control-mtls-positive: %v", err)
	}
	server := httptest.NewUnstartedServer(production.Handler)
	server.TLS = production.TLSConfig
	server.StartTLS()
	defer server.Close()
	clientCert, err := tls.X509KeyPair([]byte(bundle.ClientCertPEM), []byte(bundle.ClientKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(bundle.ClientCAPEM)) {
		t.Fatal("issued-control-ca-absent")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13,
		RootCAs: roots, Certificates: []tls.Certificate{clientCert}}}}
	response, err := client.Get(server.URL + "/control/v1/releases/dossier/prepare")
	if err != nil {
		t.Fatalf("issued-control-mtls-positive: %v", err)
	}
	response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		t.Fatal("issued-control-mtls-positive: private route absent")
	}
	probe := httptest.NewRecorder()
	public.ServeHTTP(probe, httptest.NewRequest(http.MethodGet, "/control/v1/releases/dossier/prepare", nil))
	if probe.Code != http.StatusNotFound {
		t.Fatalf("control-public-route-absent-without-mtls: %d", probe.Code)
	}
}

func TestIsolatedControlSurfaceDoesNotExistOnPublicCatalogListener(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PrivateStageDir = t.TempDir()
	public, control := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, true)
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/control/v1/releases/dossier/prepare", nil),
		httptest.NewRequest(http.MethodGet, "/control/v1/authority/"+strings.Repeat("a", 52)+"/11111111111111111111111111111111", nil),
	} {
		response := httptest.NewRecorder()
		public.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("public listener exposed Pearl control route %s: %d %s", request.URL.Path, response.Code, response.Body.String())
		}
		response = httptest.NewRecorder()
		control.ServeHTTP(response, request)
		if response.Code == http.StatusNotFound {
			t.Fatalf("private Pearl control surface did not own %s", request.URL.Path)
		}
	}
}

func TestPublicStoreReleaseRouteAbsentWithAndWithoutPrivateListener(t *testing.T) {
	for _, privateListener := range []bool{false, true} {
		t.Run(map[bool]string{false: "without-private-mtls", true: "with-private-mtls"}[privateListener], func(t *testing.T) {
			cfg, _ := testConfig(t)
			cfg.PrivateStageDir = t.TempDir()
			public, control := newGovernedRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, privateListener)
			for _, withClientCertificate := range []bool{false, true} {
				request := httptest.NewRequest(http.MethodPost, "/control/v1/releases/dossier/prepare", nil)
				if withClientCertificate {
					request.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{{}}}
				}
				response := httptest.NewRecorder()
				public.ServeHTTP(response, request)
				if response.Code != http.StatusNotFound {
					t.Fatalf("PUBLIC_STORE_RELEASE_CONTROL_ROUTE_MUST_BE_404: private=%t clientCert=%t status=%d", privateListener, withClientCertificate, response.Code)
				}
			}
			privateResponse := httptest.NewRecorder()
			control.ServeHTTP(privateResponse, httptest.NewRequest(http.MethodPost, "/control/v1/releases/dossier/prepare", nil))
			if privateResponse.Code == http.StatusNotFound {
				t.Fatal("PRIVATE_STORE_RELEASE_CONTROL_ROUTE_MUST_EXIST")
			}
		})
	}
}
