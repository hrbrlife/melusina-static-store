package publishclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The pin is the exact observed leaf, not every certificate the pinned
// certificate could issue. A self-signed pinned certificate that is also a CA
// must not admit a different server leaf it signed for the same name.
func TestPublisherLeafIssuedByPinnedCertificateRefused(t *testing.T) {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pinned-store"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	childKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	childTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "other-store-leaf"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	childDER, err := x509.CreateCertificate(rand.Reader, childTemplate, caCert, &childKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{childDER, caDER}, PrivateKey: childKey}}}
	server.StartTLS()
	defer server.Close()
	pin := filepath.Join(t.TempDir(), "leaf.pem")
	if err := os.WriteFile(pin, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := New(server.URL, "", pin, time.Minute)
	if err != nil {
		t.Fatalf("PUBLISHER_PIN_FIXTURE_REFUSED: %v", err)
	}
	response, err := client.Get(server.URL)
	if err == nil {
		response.Body.Close()
		t.Fatal("PUBLISHER_LEAF_ISSUED_BY_PIN_ACCEPTED")
	}
	if !strings.Contains(err.Error(), "publisher_tls_leaf_changed") {
		t.Fatalf("PUBLISHER_LEAF_ISSUED_BY_PIN_WRONG_REFUSAL: %v", err)
	}
}
