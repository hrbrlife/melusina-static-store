package releasefinalizer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newFinalizerTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Bazaar finalizer test CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return certificate, key, roots
}

func newFinalizerTestLeaf(t *testing.T, serial int64, name string, usage x509.ExtKeyUsage, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writeFinalizerCertificate(t *testing.T, dir, name string, certificate tls.Certificate) (string, string) {
	t.Helper()
	key, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("finalizer test key type = %T", certificate.PrivateKey)
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

func TestMTLSServerRequiresPinnedStoreLinkAtHandshake(t *testing.T) {
	ca, caKey, roots := newFinalizerTestCA(t)
	serverLeaf := newFinalizerTestLeaf(t, 2, "finalizer.test", x509.ExtKeyUsageServerAuth, ca, caKey)
	storeLinkLeaf := newFinalizerTestLeaf(t, 3, "store-link.test", x509.ExtKeyUsageClientAuth, ca, caKey)
	otherLeaf := newFinalizerTestLeaf(t, 4, "other-store-link.test", x509.ExtKeyUsageClientAuth, ca, caKey)
	dir := t.TempDir()
	serverCertPath, serverKeyPath := writeFinalizerCertificate(t, dir, "server", serverLeaf)
	caPath := filepath.Join(dir, "client-ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	clientLeaf, err := x509.ParseCertificate(storeLinkLeaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pinned := sha256.Sum256(clientLeaf.Raw)
	handler, _, _, _, _ := finalizerHTTPFixture(t, time.Now().UTC())
	handler.storeLinkCertSHA = hex.EncodeToString(pinned[:])

	server, err := NewMTLSServer(MTLSConfig{
		ListenAddr: "127.0.0.1:0", CertPath: serverCertPath, KeyPath: serverKeyPath, ClientCAPath: caPath,
		StoreLinkClientCertSHA256: hex.EncodeToString(pinned[:]),
	}, handler)
	if err != nil {
		t.Fatal(err)
	}
	if server.TLSConfig.MinVersion != tls.VersionTLS13 || server.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || server.TLSConfig.ClientCAs == nil {
		t.Fatalf("finalizer mTLS configuration is weak: %#v", server.TLSConfig)
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Errorf("finalizer server shutdown: %v", err)
		}
		if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("finalizer server exit: %v", err)
		}
	})

	newClient := func(certificate tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "finalizer.test", Certificates: []tls.Certificate{certificate},
		}}}
	}
	url := "https://" + listener.Addr().String() + jobCollectionPath + "/" + "0123456789abcdef01234567"
	response, err := newClient(storeLinkLeaf).Get(url)
	if err != nil {
		t.Fatalf("pinned Store Link request: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("pinned Store Link request = %d, want handler 404", response.StatusCode)
	}
	if _, err := newClient(otherLeaf).Get(url); err == nil {
		t.Fatal("a same-CA but unpinned client reached the finalizer")
	}
}

func TestMTLSServerRefusesWeakOrMismatchedConfiguration(t *testing.T) {
	handler, _, _, _, _ := finalizerHTTPFixture(t, time.Now().UTC())
	if _, err := NewMTLSServer(MTLSConfig{}, handler); err == nil {
		t.Fatal("empty finalizer mTLS configuration was accepted")
	}
	dir := t.TempDir()
	for _, name := range []string{"server.crt", "server.key", "ca.crt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not a certificate"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := NewMTLSServer(MTLSConfig{
		ListenAddr: "127.0.0.1:9444", CertPath: filepath.Join(dir, "server.crt"), KeyPath: filepath.Join(dir, "server.key"), ClientCAPath: filepath.Join(dir, "ca.crt"),
		StoreLinkClientCertSHA256: strings.Repeat("a", 64),
	}, handler); err == nil || err.Error() != "finalizer mTLS server and handler pin different Store Link identities" {
		t.Fatalf("mismatched handler pin error = %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "server.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	handler.storeLinkCertSHA = strings.Repeat("a", 64)
	if _, err := NewMTLSServer(MTLSConfig{
		ListenAddr: "127.0.0.1:9444", CertPath: filepath.Join(dir, "server.crt"), KeyPath: filepath.Join(dir, "server.key"), ClientCAPath: filepath.Join(dir, "ca.crt"),
		StoreLinkClientCertSHA256: strings.Repeat("a", 64),
	}, handler); err == nil || err.Error() != "finalizer serving key must be a mode-0600 regular file" {
		t.Fatalf("weak key mode error = %v", err)
	}
}
