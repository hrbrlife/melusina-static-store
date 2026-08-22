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

func TestPearlControlMTLSRequiresTLS13VerifiedAndPinnedPearlLeaf(t *testing.T) {
	ca, caKey, roots := newControlTestCA(t)
	serverLeaf := newControlTestLeaf(t, 2, "sidecar.test", x509.ExtKeyUsageServerAuth, ca, caKey)
	pearlLeaf := newControlTestLeaf(t, 3, "pearl.test", x509.ExtKeyUsageClientAuth, ca, caKey)
	otherLeaf := newControlTestLeaf(t, 4, "other.test", x509.ExtKeyUsageClientAuth, ca, caKey)
	dir := t.TempDir()
	serverCertPath, serverKeyPath := writeControlCertificate(t, dir, "server", serverLeaf)
	caPath := filepath.Join(dir, "client-ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	pinned := sha256.Sum256(pearlLeaf.Certificate[0])
	tlsConfig, err := newPearlControlTLSConfig(PearlControlMTLSConfig{
		ListenAddr: "127.0.0.1:9443", CertPath: serverCertPath, KeyPath: serverKeyPath, ClientCAPath: caPath,
		PearlClientCertSHA256: hex.EncodeToString(pinned[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 || tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert || tlsConfig.ClientCAs == nil {
		t.Fatalf("control TLS did not require TLS-1.3 verified mTLS: %#v", tlsConfig)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.PeerCertificates) != 1 {
			http.Error(w, "missing verified Pearl mTLS", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()
	newClient := func(certificate tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "sidecar.test", Certificates: []tls.Certificate{certificate},
		}}}
	}
	response, err := newClient(pearlLeaf).Get(server.URL)
	if err != nil {
		t.Fatalf("pinned Pearl request: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("pinned Pearl status = %d", response.StatusCode)
	}
	if _, err := newClient(otherLeaf).Get(server.URL); err == nil {
		t.Fatal("a different certificate from the trusted CA reached the Pearl-control listener")
	}
}

func TestIsolatedControlSurfaceDoesNotExistOnPublicCatalogListener(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.PrivateStageDir = t.TempDir()
	public, control := newRouterSurfaces(cfg, nil, nil, nil, catalogRuntime{}, true)
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
