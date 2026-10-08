package storelink

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
	"io"
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

func newWorkerTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Bazaar Store Link worker test CA"},
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
	return certificate, key
}

func newWorkerTestLeaf(t *testing.T, serial int64, name string, usage x509.ExtKeyUsage, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	if usage == x509.ExtKeyUsageServerAuth {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writeWorkerTestCertificate(t *testing.T, dir, name string, certificate tls.Certificate) (string, string) {
	t.Helper()
	key, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("worker test key type = %T", certificate.PrivateKey)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func workerLeafDigest(certificate tls.Certificate) string {
	digest := sha256.Sum256(certificate.Certificate[0])
	return hex.EncodeToString(digest[:])
}

func TestWorkerForwarderUsesMutualTLSAndPinsEachWorkerLeaf(t *testing.T) {
	ca, caKey := newWorkerTestCA(t)
	workerLeaf := newWorkerTestLeaf(t, 2, "worker", x509.ExtKeyUsageServerAuth, ca, caKey)
	storeLinkLeaf := newWorkerTestLeaf(t, 3, "store-link", x509.ExtKeyUsageClientAuth, ca, caKey)
	otherStoreLinkLeaf := newWorkerTestLeaf(t, 4, "other-store-link", x509.ExtKeyUsageClientAuth, ca, caKey)
	trustedClientDigest := sha256.Sum256(storeLinkLeaf.Certificate[0])
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca)

	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/build-jobs" {
			t.Fatalf("worker route = %q", request.URL.Path)
		}
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"jobId":"0123456789abcdef01234567"}`))
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{workerLeaf},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
				return io.ErrUnexpectedEOF
			}
			actual := sha256.Sum256(state.VerifiedChains[0][0].Raw)
			if actual != trustedClientDigest {
				return io.ErrClosedPipe
			}
			return nil
		},
	}
	server.StartTLS()
	defer server.Close()

	dir := t.TempDir()
	clientCertPath, clientKeyPath := writeWorkerTestCertificate(t, dir, "store-link", storeLinkLeaf)
	otherClientCertPath, otherClientKeyPath := writeWorkerTestCertificate(t, dir, "other-store-link", otherStoreLinkLeaf)
	caPath := filepath.Join(dir, "worker-ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	config := testConfig()
	config.ClientCertPath = clientCertPath
	config.ClientKeyPath = clientKeyPath
	config.WorkerCAPath = caPath
	config.BuildWorkerURL = server.URL
	config.ReleasePreparationWorkerURL = server.URL
	config.ReleaseFinalizationWorkerURL = server.URL
	config.TenantProofWorkerURL = server.URL
	config.BuildWorkerCertSHA256 = workerLeafDigest(workerLeaf)
	config.ReleasePreparationWorkerCertSHA256 = strings.Repeat("b", sha256.Size*2)
	config.ReleaseFinalizationWorkerCertSHA256 = strings.Repeat("c", sha256.Size*2)
	config.TenantProofWorkerCertSHA256 = strings.Repeat("d", sha256.Size*2)

	forwarder, err := NewWorkerForwarder(config)
	if err != nil {
		t.Fatal(err)
	}
	response, err := forwarder.ForwardBuild(context.Background(), WorkerRequest{
		Method: http.MethodPost,
		Path:   "/v1/build-jobs",
		Body:   io.NopCloser(strings.NewReader(`{"schema":"bazaar-control-trusted-build-job-v1"}`)),
	})
	if err != nil {
		t.Fatalf("pinned mTLS worker call: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted || requests != 1 {
		t.Fatalf("pinned mTLS worker response/requests = %d/%d", response.StatusCode, requests)
	}

	wrongPin := config
	wrongPin.BuildWorkerCertSHA256 = strings.Repeat("a", sha256.Size*2)
	forwarder, err = NewWorkerForwarder(wrongPin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forwarder.ForwardBuild(context.Background(), WorkerRequest{Method: http.MethodPost, Path: "/v1/build-jobs", Body: io.NopCloser(strings.NewReader("{}"))}); err == nil {
		t.Fatal("Store Link accepted a trusted-CA worker with the wrong leaf pin")
	}
	if requests != 1 {
		t.Fatalf("wrong-pinned worker reached HTTP handler %d times", requests)
	}

	wrongClient := config
	wrongClient.ClientCertPath, wrongClient.ClientKeyPath = otherClientCertPath, otherClientKeyPath
	forwarder, err = NewWorkerForwarder(wrongClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forwarder.ForwardBuild(context.Background(), WorkerRequest{Method: http.MethodPost, Path: "/v1/build-jobs", Body: io.NopCloser(strings.NewReader("{}"))}); err == nil {
		t.Fatal("worker accepted a different Store Link leaf from the same CA")
	}
	if requests != 1 {
		t.Fatalf("wrong Store Link client reached HTTP handler %d times", requests)
	}
}

func TestSidecarForwarderUsesMutualTLSAndPinsSidecarLeaf(t *testing.T) {
	ca, caKey := newWorkerTestCA(t)
	sidecarLeaf := newWorkerTestLeaf(t, 2, "sidecar", x509.ExtKeyUsageServerAuth, ca, caKey)
	storeLinkLeaf := newWorkerTestLeaf(t, 3, "store-link", x509.ExtKeyUsageClientAuth, ca, caKey)
	otherStoreLinkLeaf := newWorkerTestLeaf(t, 4, "other-store-link", x509.ExtKeyUsageClientAuth, ca, caKey)
	trustedClientDigest := sha256.Sum256(storeLinkLeaf.Certificate[0])
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca)

	requests := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/control/v1/status" {
			t.Fatalf("sidecar route = %q", request.URL.Path)
		}
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"schema":"bazaar-control-store-status-v1"}`))
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{sidecarLeaf},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientRoots,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
				return io.ErrUnexpectedEOF
			}
			actual := sha256.Sum256(state.VerifiedChains[0][0].Raw)
			if actual != trustedClientDigest {
				return io.ErrClosedPipe
			}
			return nil
		},
	}
	server.StartTLS()
	defer server.Close()

	dir := t.TempDir()
	clientCertPath, clientKeyPath := writeWorkerTestCertificate(t, dir, "store-link", storeLinkLeaf)
	otherClientCertPath, otherClientKeyPath := writeWorkerTestCertificate(t, dir, "other-store-link", otherStoreLinkLeaf)
	caPath := filepath.Join(dir, "sidecar-ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	config := testConfig()
	config.SidecarURL = server.URL
	config.ClientCertPath = clientCertPath
	config.ClientKeyPath = clientKeyPath
	config.SidecarCAPath = caPath
	config.SidecarCertSHA256 = workerLeafDigest(sidecarLeaf)

	forwarder, err := NewSidecarForwarder(config)
	if err != nil {
		t.Fatal(err)
	}
	response, err := forwarder.Forward(context.Background(), ForwardRequest{Method: http.MethodGet, Path: "/control/v1/status", Headers: make(http.Header), Body: io.NopCloser(strings.NewReader(""))})
	if err != nil {
		t.Fatalf("pinned mTLS sidecar call: %v", err)
	}
	if response.StatusCode != http.StatusOK || requests != 1 {
		t.Fatalf("pinned mTLS sidecar response/requests = %d/%d", response.StatusCode, requests)
	}

	wrongPin := config
	wrongPin.SidecarCertSHA256 = strings.Repeat("a", sha256.Size*2)
	forwarder, err = NewSidecarForwarder(wrongPin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forwarder.Forward(context.Background(), ForwardRequest{Method: http.MethodGet, Path: "/control/v1/status", Headers: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}); err == nil {
		t.Fatal("Store Link accepted a trusted-CA sidecar with the wrong leaf pin")
	}
	if requests != 1 {
		t.Fatalf("wrong-pinned sidecar reached HTTP handler %d times", requests)
	}

	wrongClient := config
	wrongClient.ClientCertPath, wrongClient.ClientKeyPath = otherClientCertPath, otherClientKeyPath
	forwarder, err = NewSidecarForwarder(wrongClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := forwarder.Forward(context.Background(), ForwardRequest{Method: http.MethodGet, Path: "/control/v1/status", Headers: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}); err == nil {
		t.Fatal("sidecar accepted a different Store Link leaf from the same CA")
	}
	if requests != 1 {
		t.Fatalf("wrong Store Link client reached sidecar handler %d times", requests)
	}

	missingPin := config
	missingPin.SidecarCertSHA256 = ""
	if _, err := NewSidecarForwarder(missingPin); err == nil || !strings.Contains(err.Error(), "sidecarCertSha256") {
		t.Fatalf("missing sidecar leaf pin error = %v", err)
	}
}

func TestStoreLinkTLSInputsRequireProtectedRealFiles(t *testing.T) {
	ca, caKey := newWorkerTestCA(t)
	clientLeaf := newWorkerTestLeaf(t, 2, "store-link", x509.ExtKeyUsageClientAuth, ca, caKey)
	dir := t.TempDir()
	certPath, keyPath := writeWorkerTestCertificate(t, dir, "store-link", clientLeaf)
	if _, err := loadStoreLinkClientIdentity(certPath, keyPath); err != nil {
		t.Fatalf("protected Store Link client identity: %v", err)
	}
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStoreLinkClientIdentity(certPath, keyPath); err == nil {
		t.Fatal("Store Link accepted a group-readable client key")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	keyLink := filepath.Join(dir, "store-link-link.key")
	if err := os.Symlink(keyPath, keyLink); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStoreLinkClientIdentity(certPath, keyLink); err == nil {
		t.Fatal("Store Link accepted a symlinked client key")
	}

	caPath := filepath.Join(dir, "worker-ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedStoreLinkFile(caPath, "worker CA", false); err != nil {
		t.Fatalf("protected worker CA: %v", err)
	}
	if err := os.Chmod(caPath, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedStoreLinkFile(caPath, "worker CA", false); err == nil {
		t.Fatal("Store Link accepted a group-writable worker CA")
	}
	if err := os.Chmod(caPath, 0o600); err != nil {
		t.Fatal(err)
	}
	caLink := filepath.Join(dir, "worker-ca-link.crt")
	if err := os.Symlink(caPath, caLink); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedStoreLinkFile(caLink, "worker CA", false); err == nil {
		t.Fatal("Store Link accepted a symlinked worker CA")
	}
}
