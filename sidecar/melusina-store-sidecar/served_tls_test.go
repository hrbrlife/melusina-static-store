package main

import (
	"bytes"
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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// servedTLSReloadIntervalChildEnv shortens servedTLSReloadInterval in a
// startup child (TestStoreStartupChild), so a rotation test does not wait for
// the production interval.
const servedTLSReloadIntervalChildEnv = "MELUSINA_STORE_TEST_SERVED_TLS_RELOAD_INTERVAL"

const servedTLSTestHost = "localhost"

type servedTLSTestIssuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// servedTLSTestPair is a certificate chain (leaf first) and the leaf's key.
type servedTLSTestPair struct {
	chain [][]byte
	key   *ecdsa.PrivateKey
}

func servedTLSTestSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

func servedTLSTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func newServedTLSTestRoot(t *testing.T, name string) *servedTLSTestIssuer {
	t.Helper()
	key := servedTLSTestKey(t)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: servedTLSTestSerial(t), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &servedTLSTestIssuer{cert: cert, key: key}
}

func (issuer *servedTLSTestIssuer) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(issuer.cert)
	return pool
}

func (issuer *servedTLSTestIssuer) intermediate(t *testing.T, name string, notBefore, notAfter time.Time) *servedTLSTestIssuer {
	t.Helper()
	key := servedTLSTestKey(t)
	template := &x509.Certificate{
		SerialNumber: servedTLSTestSerial(t), Subject: pkix.Name{CommonName: name},
		NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &servedTLSTestIssuer{cert: cert, key: key}
}

// leaf issues a server leaf for localhost and 127.0.0.1. The chain is the
// leaf alone; withIntermediates appends the issuers a client needs.
func (issuer *servedTLSTestIssuer) leaf(t *testing.T, notBefore, notAfter time.Time) servedTLSTestPair {
	t.Helper()
	key := servedTLSTestKey(t)
	template := &x509.Certificate{
		SerialNumber: servedTLSTestSerial(t), Subject: pkix.Name{CommonName: servedTLSTestHost},
		DNSNames: []string{servedTLSTestHost}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	return servedTLSTestPair{chain: [][]byte{der}, key: key}
}

func (issuer *servedTLSTestIssuer) validLeaf(t *testing.T) servedTLSTestPair {
	t.Helper()
	now := time.Now()
	return issuer.leaf(t, now.Add(-time.Hour), now.Add(time.Hour))
}

func (pair servedTLSTestPair) withIntermediates(intermediates ...*servedTLSTestIssuer) servedTLSTestPair {
	chain := append([][]byte(nil), pair.chain...)
	for _, intermediate := range intermediates {
		chain = append(chain, intermediate.cert.Raw)
	}
	return servedTLSTestPair{chain: chain, key: pair.key}
}

func (pair servedTLSTestPair) fingerprint() [32]byte {
	return sha256.Sum256(pair.chain[0])
}

func (pair servedTLSTestPair) certPEM() []byte {
	var out bytes.Buffer
	for _, der := range pair.chain {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return out.Bytes()
}

func (pair servedTLSTestPair) keyPEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(pair.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// writeServedTLSTestFile replaces path atomically, as a renewal tool does.
func writeServedTLSTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func writeServedTLSTestPair(t *testing.T, certPath, keyPath string, pair servedTLSTestPair) {
	t.Helper()
	writeServedTLSTestFile(t, keyPath, pair.keyPEM(t))
	writeServedTLSTestFile(t, certPath, pair.certPEM())
}

type servedTLSTestLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *servedTLSTestLog) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *servedTLSTestLog) count(substring string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if strings.Contains(line, substring) {
			n++
		}
	}
	return n
}

func (l *servedTLSTestLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// startServedTLSTestServer serves an HTTP handler through the Store's own
// served TLS configuration.
func startServedTLSTestServer(t *testing.T, served *servedTLSCertificate) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "served-tls-ok") }),
		TLSConfig:         served.tlsConfig(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	return listener.Addr().String()
}

// servedLeafOverTLS makes a fresh, fully verifying TLS connection (the
// client trusts only roots) and a request over it, and returns the leaf the
// server presented.
func servedLeafOverTLS(t *testing.T, addr string, roots *x509.CertPool) ([32]byte, error) {
	t.Helper()
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, ServerName: servedTLSTestHost},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		return [32]byte{}, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusOK {
		return [32]byte{}, fmt.Errorf("status %d", response.StatusCode)
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return [32]byte{}, fmt.Errorf("no peer certificate")
	}
	return sha256.Sum256(response.TLS.PeerCertificates[0].Raw), nil
}

func requireServedLeaf(t *testing.T, addr string, roots *x509.CertPool, want servedTLSTestPair, label string) {
	t.Helper()
	got, err := servedLeafOverTLS(t, addr, roots)
	if err != nil {
		t.Fatalf("%s: TLS request failed: %v", label, err)
	}
	if got != want.fingerprint() {
		wantFP := want.fingerprint()
		t.Fatalf("%s: served leaf sha256=%s, want %s", label, hex.EncodeToString(got[:]), hex.EncodeToString(wantFP[:]))
	}
}

func servedTLSTestConfig(dir string) Config {
	return Config{TLS: TLSConfig{CertPath: filepath.Join(dir, "cert.pem"), KeyPath: filepath.Join(dir, "key.pem")}}
}

func newServedTLSTestCertificate(t *testing.T, cfg Config, bound *verifiedBootIdentity, now func() time.Time) (*servedTLSCertificate, *servedTLSTestLog) {
	t.Helper()
	logs := &servedTLSTestLog{}
	served, err := newServedTLSCertificate(cfg, bound, now, logs.logf)
	if err != nil {
		t.Fatalf("newServedTLSCertificate: %v", err)
	}
	return served, logs
}

// A renewed pair reaches new handshakes without a restart, and an unchanged
// pair is not reloaded.
func TestServedTLSCertificateRotatesForNewHandshakesWithoutRestart(t *testing.T) {
	root := newServedTLSTestRoot(t, "served TLS test root")
	cfg := servedTLSTestConfig(t.TempDir())
	first := root.validLeaf(t)
	writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, first)
	served, logs := newServedTLSTestCertificate(t, cfg, nil, time.Now)
	addr := startServedTLSTestServer(t, served)
	requireServedLeaf(t, addr, root.pool(), first, "start-up")

	if served.reload() {
		t.Fatalf("served-tls-unchanged-pair-reloaded:\n%s", logs)
	}
	second := root.validLeaf(t)
	writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, second)
	if !served.reload() {
		t.Fatalf("served-tls-rotation-not-loaded: a valid renewed pair was not loaded:\n%s", logs)
	}
	requireServedLeaf(t, addr, root.pool(), second, "served-tls-rotation-not-served")
	if logs.count("served TLS certificate reloaded from "+cfg.TLS.CertPath) != 1 {
		t.Fatalf("rotation was not logged once:\n%s", logs)
	}

	// Positive control for chain handling: a leaf under an intermediate the
	// client does not hold verifies only if the intermediate is served too.
	now := time.Now()
	intermediate := root.intermediate(t, "served TLS test intermediate", now.Add(-time.Hour), now.Add(time.Hour))
	chained := intermediate.validLeaf(t).withIntermediates(intermediate)
	writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, chained)
	if !served.reload() {
		t.Fatalf("served-tls-rotation-not-loaded: a valid leaf+intermediate chain was not loaded:\n%s", logs)
	}
	requireServedLeaf(t, addr, root.pool(), chained, "served-tls-chain-not-served")
}

// Each bad pair is refused by name, is never served, is logged once however
// often it is re-read, and does not stop a later good pair.
func TestServedTLSCertificateRefusesABadPairAndKeepsServing(t *testing.T) {
	root := newServedTLSTestRoot(t, "served TLS test root")
	now := time.Now()
	garbage := []byte("not a certificate")
	intermediate := root.intermediate(t, "served TLS test intermediate", now.Add(-time.Hour), now.Add(time.Hour))
	otherIntermediate := root.intermediate(t, "unrelated intermediate", now.Add(-time.Hour), now.Add(time.Hour))
	expiredIntermediate := root.intermediate(t, "expired intermediate", now.Add(-48*time.Hour), now.Add(-time.Hour))

	cases := []struct {
		name    string
		refusal string
		cause   string
		write   func(t *testing.T, cfg Config)
	}{
		{
			name: "key-mismatch", refusal: servedTLSKeyPairRefused, cause: "private key does not match public key",
			write: func(t *testing.T, cfg Config) {
				leaf := root.validLeaf(t)
				leaf.key = root.validLeaf(t).key
				writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, leaf)
			},
		},
		{
			name: "expired-leaf", refusal: servedTLSExpired + ":0",
			write: func(t *testing.T, cfg Config) {
				writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, root.leaf(t, now.Add(-2*time.Hour), now.Add(-time.Hour)))
			},
		},
		{
			name: "not-yet-valid-leaf", refusal: servedTLSNotYetValid + ":0",
			write: func(t *testing.T, cfg Config) {
				writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, root.leaf(t, now.Add(time.Hour), now.Add(2*time.Hour)))
			},
		},
		{
			name: "expired-intermediate", refusal: servedTLSExpired + ":1",
			write: func(t *testing.T, cfg Config) {
				writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, expiredIntermediate.validLeaf(t).withIntermediates(expiredIntermediate))
			},
		},
		{
			name: "unparsable-leaf", refusal: servedTLSChainUnparsable + ":0",
			write: func(t *testing.T, cfg Config) {
				pair := root.validLeaf(t)
				pair.chain = [][]byte{garbage}
				writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, pair)
			},
		},
		{
			name: "unparsable-intermediate", refusal: servedTLSChainUnparsable + ":1",
			write: func(t *testing.T, cfg Config) {
				pair := intermediate.validLeaf(t)
				pair.chain = append(pair.chain, garbage)
				writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, pair)
			},
		},
		{
			name: "wrong-intermediate", refusal: servedTLSChainOrder + ":0",
			write: func(t *testing.T, cfg Config) {
				writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, intermediate.validLeaf(t).withIntermediates(otherIntermediate))
			},
		},
		{
			name: "reversed-chain", refusal: servedTLSChainOrder + ":0",
			write: func(t *testing.T, cfg Config) {
				pair := intermediate.validLeaf(t)
				pair.chain = [][]byte{pair.chain[0], root.cert.Raw, intermediate.cert.Raw}
				writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, pair)
			},
		},
		{
			name: "no-certificate", refusal: servedTLSChainEmpty,
			write: func(t *testing.T, cfg Config) {
				pair := root.validLeaf(t)
				writeServedTLSTestFile(t, cfg.TLS.KeyPath, pair.keyPEM(t))
				writeServedTLSTestFile(t, cfg.TLS.CertPath, pair.keyPEM(t))
			},
		},
		{
			name: "key-file-missing", refusal: servedTLSReadFailed,
			write: func(t *testing.T, cfg Config) {
				if err := os.Remove(cfg.TLS.KeyPath); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := servedTLSTestConfig(t.TempDir())
			good := root.validLeaf(t)
			writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, good)
			served, logs := newServedTLSTestCertificate(t, cfg, nil, time.Now)
			addr := startServedTLSTestServer(t, served)
			requireServedLeaf(t, addr, root.pool(), good, "start-up")

			tc.write(t, cfg)
			if served.reload() {
				t.Fatalf("served-tls-bad-pair-loaded:%s: the bad pair replaced the served certificate:\n%s", tc.name, logs)
			}
			requireServedLeaf(t, addr, root.pool(), good, "served-tls-bad-pair-served:"+tc.name)
			refused := "served TLS certificate reload refused: " + tc.refusal
			if logs.count(refused) != 1 || (tc.cause != "" && logs.count(tc.cause) != 1) {
				t.Fatalf("served-tls-refusal-not-named:%s: want one %q (cause %q):\n%s", tc.name, refused, tc.cause, logs)
			}
			goodFP := good.fingerprint()
			if logs.count("still serving leaf sha256="+hex.EncodeToString(goodFP[:])) != 1 {
				t.Fatalf("refusal does not name the leaf still served:\n%s", logs)
			}
			for i := 0; i < 3; i++ {
				served.reload()
			}
			if logs.count("reload refused") != 1 {
				t.Fatalf("served-tls-refusal-repeated:%s: an unchanged bad pair was logged again:\n%s", tc.name, logs)
			}

			recovered := root.validLeaf(t)
			writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, recovered)
			if !served.reload() {
				t.Fatalf("served-tls-no-recovery:%s: a good pair after a refused one was not loaded:\n%s", tc.name, logs)
			}
			requireServedLeaf(t, addr, root.pool(), recovered, "served-tls-no-recovery:"+tc.name)
		})
	}
}

// A refusal is not remembered by content: a pair refused as not yet valid is
// loaded, unchanged, once its window opens.
func TestServedTLSCertificateRetriesARefusedPairWhenItBecomesValid(t *testing.T) {
	root := newServedTLSTestRoot(t, "served TLS test root")
	cfg := servedTLSTestConfig(t.TempDir())
	realNow := time.Now()
	good := root.leaf(t, realNow.Add(-3*time.Hour), realNow.Add(time.Hour))
	writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, good)
	clock := realNow.Add(-2 * time.Hour)
	served, logs := newServedTLSTestCertificate(t, cfg, nil, func() time.Time { return clock })

	later := root.leaf(t, realNow.Add(-time.Hour), realNow.Add(time.Hour))
	writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, later)
	if served.reload() || logs.count("reload refused: "+servedTLSNotYetValid+":0") != 1 {
		t.Fatalf("served-tls-not-yet-valid-accepted: a pair not yet valid at the Store's clock was not refused by name:\n%s", logs)
	}
	clock = realNow
	if !served.reload() {
		t.Fatalf("served-tls-refusal-cached: the same pair was not loaded after its window opened:\n%s", logs)
	}
	addr := startServedTLSTestServer(t, served)
	requireServedLeaf(t, addr, root.pool(), later, "served-tls-refusal-cached")
}

// Start-up applies the same checks; with nothing to fall back to, a bad pair
// is an error by name.
func TestServedTLSCertificateStartupRefusesABadPair(t *testing.T) {
	root := newServedTLSTestRoot(t, "served TLS test root")
	now := time.Now()
	for _, tc := range []struct {
		name    string
		refusal string
		pair    func() servedTLSTestPair
	}{
		{"expired", servedTLSExpired + ":0", func() servedTLSTestPair { return root.leaf(t, now.Add(-2*time.Hour), now.Add(-time.Hour)) }},
		{"key-mismatch", servedTLSKeyPairRefused, func() servedTLSTestPair {
			pair := root.validLeaf(t)
			pair.key = servedTLSTestKey(t)
			return pair
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := servedTLSTestConfig(t.TempDir())
			writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, tc.pair())
			if _, err := newServedTLSCertificate(cfg, nil, time.Now, t.Logf); err == nil || !strings.HasPrefix(err.Error(), tc.refusal) {
				t.Fatalf("served-tls-startup-accepted-bad-pair:%s: err = %v, want %s", tc.name, err, tc.refusal)
			}
		})
	}
}

func servedTLSBoundIdentity(pair servedTLSTestPair) *verifiedBootIdentity {
	return &verifiedBootIdentity{facts: bootIdentityFacts{tlsFingerprint: pair.fingerprint()}}
}

// When the served file is the file boot identity bound, a renewed leaf is
// refused by name and the bound leaf stays served, however the two paths are
// spelled. When they are different files, the served one rotates and what
// boot identity binds does not move.
func TestServedTLSCertificateBoundToBootIdentityRefusesANewLeaf(t *testing.T) {
	root := newServedTLSTestRoot(t, "served TLS test root")
	for _, tc := range []struct {
		name  string
		bound func(t *testing.T, cfg Config) string
	}{
		{"default-path", func(*testing.T, Config) string { return "" }},
		{"same-path", func(_ *testing.T, cfg Config) string { return cfg.TLS.CertPath }},
		{"same-path-spelled-differently", func(_ *testing.T, cfg Config) string {
			separator := string(filepath.Separator)
			return filepath.Dir(cfg.TLS.CertPath) + separator + "." + separator + filepath.Base(cfg.TLS.CertPath)
		}},
		{"symlink", func(t *testing.T, cfg Config) string {
			link := filepath.Join(t.TempDir(), "bound.pem")
			if err := os.Symlink(cfg.TLS.CertPath, link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := servedTLSTestConfig(t.TempDir())
			bound := root.validLeaf(t)
			writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, bound)
			cfg.BootIdentity.TLSCertPath = tc.bound(t, cfg)
			served, logs := newServedTLSTestCertificate(t, cfg, servedTLSBoundIdentity(bound), time.Now)
			if served.pin == nil {
				t.Fatalf("served-tls-identity-not-pinned:%s: the served file is the boot-identity file", tc.name)
			}
			addr := startServedTLSTestServer(t, served)
			requireServedLeaf(t, addr, root.pool(), bound, "start-up")

			writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, root.validLeaf(t))
			if served.reload() {
				t.Fatalf("served-tls-identity-pin-bypassed:%s: a new leaf replaced the bound one:\n%s", tc.name, logs)
			}
			requireServedLeaf(t, addr, root.pool(), bound, "served-tls-identity-pin-bypassed:"+tc.name)
			if logs.count("reload refused: "+servedTLSIdentityPinned) != 1 {
				t.Fatalf("served-tls-refusal-not-named:%s:\n%s", tc.name, logs)
			}
		})
	}

	t.Run("startup-leaf-differs-from-bound", func(t *testing.T) {
		cfg := servedTLSTestConfig(t.TempDir())
		writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, root.validLeaf(t))
		if _, err := newServedTLSCertificate(cfg, servedTLSBoundIdentity(root.validLeaf(t)), time.Now, t.Logf); err == nil || !strings.HasPrefix(err.Error(), servedTLSIdentityPinned) {
			t.Fatalf("served-tls-startup-accepted-unbound-leaf: err = %v", err)
		}
	})

	t.Run("separate-identity-file", func(t *testing.T) {
		dir := t.TempDir()
		cfg := servedTLSTestConfig(dir)
		identityLeaf := root.validLeaf(t)
		cfg.BootIdentity.TLSCertPath = filepath.Join(dir, "identity.pem")
		writeServedTLSTestFile(t, cfg.BootIdentity.TLSCertPath, identityLeaf.certPEM())
		first := root.validLeaf(t)
		writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, first)
		served, logs := newServedTLSTestCertificate(t, cfg, servedTLSBoundIdentity(identityLeaf), time.Now)
		if served.pin != nil {
			t.Fatalf("a served file separate from the boot-identity file was pinned")
		}
		addr := startServedTLSTestServer(t, served)
		requireServedLeaf(t, addr, root.pool(), first, "start-up")
		second := root.validLeaf(t)
		writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, second)
		if !served.reload() {
			t.Fatalf("served-tls-rotation-not-loaded: separate served file:\n%s", logs)
		}
		requireServedLeaf(t, addr, root.pool(), second, "served-tls-rotation-not-served")
		// What boot identity binds is untouched: it still reads the identity file.
		bindingFP, err := tlsCertFingerprint(bootIdentityTLSCertPath(cfg))
		if err != nil {
			t.Fatal(err)
		}
		if bindingFP != identityLeaf.fingerprint() {
			t.Fatalf("boot identity would now bind %x, want the identity leaf", bindingFP)
		}
	})
}

// The watcher reloads on its own interval and stops with its context.
func TestServedTLSCertificateWatchReloadsOnItsInterval(t *testing.T) {
	root := newServedTLSTestRoot(t, "served TLS test root")
	cfg := servedTLSTestConfig(t.TempDir())
	first := root.validLeaf(t)
	writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, first)
	served, logs := newServedTLSTestCertificate(t, cfg, nil, time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		served.watch(ctx, 20*time.Millisecond)
		close(done)
	}()
	second := root.validLeaf(t)
	writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, second)
	deadline := time.Now().Add(20 * time.Second)
	for sha256.Sum256(served.current.Load().Leaf.Raw) != second.fingerprint() {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("served-tls-watch-not-reloading:\n%s", logs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("served TLS watcher did not stop with its context")
	}
}

// servedTLSCallee names a call's function or method.
func servedTLSCallee(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// main() hands the served certificate the boot identity it verified and
// serves the public listener only through it. The identity pin is only as
// good as that argument: nil there would let a renewed bound leaf be served,
// and naming the files to ListenAndServeTLS would bypass the reload checks.
// Both builds compile this main.go; the standard build also runs it (see
// served_tls_startup_standard_test.go).
func TestStoreMainServesThroughTheBoundServedCertificate(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "main" && fn.Recv == nil {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("main.go has no main()")
	}
	var verified string
	var servedArgs []string
	var configured, watched bool
	var listenFiles []string
	ast.Inspect(body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.AssignStmt:
			if len(n.Rhs) != 1 {
				return true
			}
			if call, ok := n.Rhs[0].(*ast.CallExpr); ok {
				if ident, isIdent := n.Lhs[0].(*ast.Ident); isIdent && servedTLSCallee(call) == "deriveEnrolledBootIdentity" {
					verified = ident.Name
				}
				if lhs, isSelector := n.Lhs[0].(*ast.SelectorExpr); isSelector && lhs.Sel.Name == "TLSConfig" && servedTLSCallee(call) == "tlsConfig" {
					configured = true
				}
			}
		case *ast.GoStmt:
			if servedTLSCallee(n.Call) == "watch" {
				watched = true
			}
		case *ast.CallExpr:
			switch servedTLSCallee(n) {
			case "newServedTLSCertificate":
				if len(n.Args) != 4 {
					servedArgs = append(servedArgs, "<arity>")
					return true
				}
				ident, _ := n.Args[1].(*ast.Ident)
				if ident == nil {
					servedArgs = append(servedArgs, "<not an identifier>")
					return true
				}
				servedArgs = append(servedArgs, ident.Name)
			case "ListenAndServeTLS":
				for _, arg := range n.Args {
					if literal, ok := arg.(*ast.BasicLit); !ok || literal.Value != `""` {
						listenFiles = append(listenFiles, fmt.Sprintf("%T", arg))
					}
				}
			}
		}
		return true
	})
	if verified == "" {
		t.Fatal("main() no longer assigns deriveEnrolledBootIdentity's verified identity; update this check with it")
	}
	if len(servedArgs) != 1 || servedArgs[0] != verified {
		t.Fatalf("served-tls-identity-not-passed: main() calls newServedTLSCertificate with %v, want exactly one call passing %q", servedArgs, verified)
	}
	if !configured {
		t.Fatal("served-tls-listener-not-configured: main() does not set the listener's TLSConfig from the served certificate")
	}
	if !watched {
		t.Fatal("served-tls-not-watched: main() does not start the served certificate's reload loop")
	}
	if len(listenFiles) != 0 {
		t.Fatalf("served-tls-listener-loads-files: main() names certificate files to ListenAndServeTLS (%v), bypassing the reload checks", listenFiles)
	}
}
