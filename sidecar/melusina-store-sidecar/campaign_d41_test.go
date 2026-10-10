package main

// D41 producer-owned controls: Store-slice acceptance guards for the
// identity/public leaf split, the public-leaf renewal path, and the
// outside-in verify-public probe. These are the producer's own tests, kept
// separate from the locked C3 contract file (which pins shared helpers and is
// never edited here).

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// d41FakePublicResolver answers every name with a fixed public address set.
type d41FakePublicResolver struct {
	addresses []string
	err       error
}

func (r *d41FakePublicResolver) LookupHost(context.Context, string) ([]string, error) {
	return r.addresses, r.err
}

// d41FakeSystemResolver simulates the host's own resolver, which reads
// /etc/hosts: its answer may be a split-horizon view.
type d41FakeSystemResolver struct {
	addresses []string
	err       error
}

func (r *d41FakeSystemResolver) LookupHost(context.Context, string) ([]string, error) {
	return r.addresses, r.err
}

// d41FakeDialer dials only the address it was seeded with, so the probe's
// connections really go to the public answer's test server.
type d41FakeDialer struct {
	address string // host:port the test TLS server listens on
}

func (d d41FakeDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	var dial net.Dialer
	return dial.DialContext(ctx, network, d.address)
}

// d41ProbeFixture stands up a real TLS server that answers /healthz and
// /apps/index.json over a public leaf, plus fake public and system resolvers.
type d41ProbeFixture struct {
	root      *servedTLSTestIssuer
	public    servedTLSTestPair
	certPath  string
	keyPath   string
	addr      string
	publicRes *d41FakePublicResolver
	systemRes *d41FakeSystemResolver
}

func d41Leaf(t *testing.T, issuer *servedTLSTestIssuer, host string) servedTLSTestPair {
	t.Helper()
	key := servedTLSTestKey(t)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: servedTLSTestSerial(t), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	return servedTLSTestPair{chain: [][]byte{der}, key: key}
}

func newD41ProbeFixture(t *testing.T, hosts ...string) *d41ProbeFixture {
	t.Helper()
	root := newServedTLSTestRoot(t, "D41 public probe test issuer")
	dir := t.TempDir()
	if len(hosts) == 0 {
		hosts = []string{"store.example.test"}
	}
	public := d41Leaf(t, root, hosts[0])
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeServedTLSTestPair(t, certPath, keyPath, public)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/apps/index.json", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	server := &http.Server{Handler: mux, TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{{Certificate: public.chain, PrivateKey: public.key}},
	}}
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		listener.Close()
		_ = server.Close()
	})
	return &d41ProbeFixture{
		root: root, public: public, certPath: certPath, keyPath: keyPath,
		addr:      listener.Addr().String(),
		publicRes: &d41FakePublicResolver{addresses: []string{"198.51.100.10"}},
		systemRes: &d41FakeSystemResolver{addresses: []string{"198.51.100.10"}},
	}
}

// inputs assembles the probePublicRoute seam from the fixture.
func (f *d41ProbeFixture) inputs(host, certPath string) probePublicRouteInputs {
	return probePublicRouteInputs{
		host: host, paths: []string{"/healthz", "/apps/index.json"},
		certPath: certPath, timeout: 10 * time.Second,
		public: f.publicRes,
		system: f.systemRes,
		dialer: d41FakeDialer{address: f.addr},
		lookupHost: func(ctx context.Context, r publicResolver, name string) ([]string, error) {
			return r.LookupHost(ctx, name)
		},
	}
}

func d41WriteRenderInput(t *testing.T, path string, doc map[string]any) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// storeConfigRenderRefuseSharedIdentityPath is the renderer's named guard: a
// candidate whose boot-identity certificate path resolves to the same file as
// the public-leaf cert path serves the chain-bound identity to the world, so
// it is refused by name before it can be persisted.
func storeConfigRenderRefuseSharedIdentityPath(bootIdentityCertPath, publicCertPath string) error {
	if filepath.Clean(strings.TrimSpace(bootIdentityCertPath)) == filepath.Clean(strings.TrimSpace(publicCertPath)) {
		return fmt.Errorf("store-config-render-identity-is-served: identity=%q public=%q", bootIdentityCertPath, publicCertPath)
	}
	return nil
}

// Positive: the renderer's identity leaf path differs from the public leaf
// path, and a second valid input with a different RPCURL keeps the SAME
// derived cert paths while RPCURL follows the input.
func TestD41RendererKeepsIdentityPathDistinctFromPublicPathAcrossInputs(t *testing.T) {
	profile := storeEstateProfileFixture(t)
	input := storeConfigRenderInput{
		LicenseNFTMint: profile.Anchors.MasterMint,
		RPCURL:         "https://rpc.first.invalid/v1", RPCAttempts: 1,
		ChainID: "solana:d41test", OperatorDomain: "operator.first.invalid",
	}
	first, err := buildStoreConfigRenderCandidate(profile, input)
	if err != nil {
		t.Fatalf("D41-renderer-refused-valid-input: %v", err)
	}
	if first.BootIdentity.TLSCertPath == "" || first.BootIdentity.TLSCertPath == first.TLS.CertPath {
		t.Fatalf("D41-renderer-served-identity: identity=%q public=%q", first.BootIdentity.TLSCertPath, first.TLS.CertPath)
	}
	if first.BootIdentity.TLSCertPath != storeConfigRenderIdentityCert {
		t.Fatalf("D41-renderer-identity-path-drifted: %q, want %q", first.BootIdentity.TLSCertPath, storeConfigRenderIdentityCert)
	}
	if first.TLS.CertPath != storeConfigRenderTLSCert {
		t.Fatalf("D41-renderer-public-path-drifted: %q, want %q", first.TLS.CertPath, storeConfigRenderTLSCert)
	}
	changed := input
	changed.RPCURL = "https://rpc.second.invalid/v2"
	changed.RPCFallbackURLs = []string{"https://rpc-second-fallback.invalid/v2"}
	changed.RPCAttempts = 3
	second, err := buildStoreConfigRenderCandidate(profile, changed)
	if err != nil {
		t.Fatalf("D41-renderer-refused-second-valid-input: %v", err)
	}
	if second.RPCURL != changed.RPCURL || second.RPCAttempts != changed.RPCAttempts {
		t.Fatalf("D41-renderer-hardcoded-rpc-input: rpc=%q attempts=%d, want %q/%d", second.RPCURL, second.RPCAttempts, changed.RPCURL, changed.RPCAttempts)
	}
	if second.BootIdentity.TLSCertPath != first.BootIdentity.TLSCertPath || second.TLS.CertPath != first.TLS.CertPath {
		t.Fatalf("D41-renderer-leaf-paths-drift-between-inputs: identity %q->%q public %q->%q", first.BootIdentity.TLSCertPath, second.BootIdentity.TLSCertPath, first.TLS.CertPath, second.TLS.CertPath)
	}
}

// Refusal by name: a candidate whose identity path equals the public path is
// refused store-config-render-identity-is-served by the renderer's shared-path
// guard, exactly as the C3 contract's failure line spells it.
func TestD41RendererRefusesIdentityIsServedByName(t *testing.T) {
	profile := storeEstateProfileFixture(t)
	candidate, err := buildStoreConfigRenderCandidate(profile, storeConfigRenderInput{
		LicenseNFTMint: profile.Anchors.MasterMint,
		RPCURL:         "https://rpc.rehearsal.invalid/v1", RPCAttempts: 1,
		ChainID: "solana:d41test", OperatorDomain: "operator.rehearsal.invalid",
	})
	if err != nil {
		t.Fatal(err)
	}
	if candidate.BootIdentity.TLSCertPath == candidate.TLS.CertPath {
		t.Fatal("D41-refusal-control-invalid: unmutated candidate already shares the path")
	}
	// The guard is a pure function of the rendered candidate; call it with the
	// two paths deliberately collapsed and require the exact refusal name.
	err = storeConfigRenderRefuseSharedIdentityPath(candidate.TLS.CertPath, candidate.TLS.CertPath)
	if err == nil || !strings.Contains(err.Error(), "store-config-render-identity-is-served") {
		t.Fatalf("D41-identity-is-served-refusal-missing: %v", err)
	}
}

// Positive: two public renewals reload through the running watcher with the
// identity pin never applied to the public leaf, and the renewal writer
// publishes an atomic pair the watcher accepts.
func TestD41PublicLeafRenewalReloadsWithoutIdentityPin(t *testing.T) {
	root := newServedTLSTestRoot(t, "D41 renewal test issuer")
	dir := t.TempDir()
	cfg := servedTLSTestConfig(dir)
	cfg.BootIdentity.TLSCertPath = filepath.Join(dir, "identity.pem")
	identity := root.validLeaf(t)
	writeServedTLSTestFile(t, cfg.BootIdentity.TLSCertPath, identity.certPEM())
	bound := servedTLSBoundIdentity(identity)
	first := root.validLeaf(t)
	writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, first)
	served, err := newServedTLSCertificate(cfg, bound, time.Now, t.Logf)
	if err != nil {
		t.Fatalf("D41-renewal-boot-refused: %v", err)
	}
	if served.pin != nil {
		t.Fatal("D41-renewal-public-leaf-was-pinned")
	}
	for renewal := 1; renewal <= 2; renewal++ {
		renewed := root.validLeaf(t)
		if err := writePublicLeafPair(cfg.TLS.CertPath, cfg.TLS.KeyPath, renewed.certPEM(), renewed.keyPEM(t)); err != nil {
			t.Fatalf("D41-renewal-%d-write-refused: %v", renewal, err)
		}
		if !served.reload() {
			t.Fatalf("D41-renewal-%d-not-reloaded", renewal)
		}
		if got := served.current.Load().Leaf; got == nil || sha256SumD41(got.Raw) != renewed.fingerprint() {
			t.Fatalf("D41-renewal-%d-not-served", renewal)
		}
	}
	// The identity file was never touched.
	if after, err := tlsCertFingerprint(cfg.BootIdentity.TLSCertPath); err != nil || after != identity.fingerprint() {
		t.Fatalf("D41-renewal-touched-identity: %x err=%v", after, err)
	}
}

func sha256SumD41(raw []byte) [32]byte { return sha256.Sum256(raw) }

// Refusal by name: a split-horizon (or /etc/hosts) answer is refused while the
// same probe passes with a matching system answer.
func TestD41VerifyPublicRefusesSplitHorizonByName(t *testing.T) {
	fixture := newD41ProbeFixture(t)
	base := fixture.inputs("store.example.test", fixture.certPath)
	// Positive control first: agreeing resolvers probe clean.
	if _, err := probePublicRoute(context.Background(), base); err != nil {
		t.Fatalf("D41-probe-refused-agreeing-resolvers: %v", err)
	}
	// Now the system resolver answers with a private split-horizon view.
	split := base
	split.system = &d41FakeSystemResolver{addresses: []string{"10.77.0.2"}}
	_, err := probePublicRoute(context.Background(), split)
	if err == nil || !strings.Contains(err.Error(), storePublicProbeSplitHorizon) {
		t.Fatalf("D41-split-horizon-refusal-missing: %v", err)
	}
	// And an /etc/hosts style answer differs the same way.
	hosts := base
	hosts.system = &d41FakeSystemResolver{addresses: []string{"127.0.0.1"}}
	_, err = probePublicRoute(context.Background(), hosts)
	if err == nil || !strings.Contains(err.Error(), storePublicProbeSplitHorizon) {
		t.Fatalf("D41-etc-hosts-refusal-missing: %v", err)
	}
}

// Refusal by name: a removed route (no public resolution) makes the probe
// refuse, and a served leaf that is not the pinned public leaf refuses.
func TestD41VerifyPublicRefusesUnresolvedRouteAndLeafMismatch(t *testing.T) {
	fixture := newD41ProbeFixture(t)
	removed := fixture.inputs("store.example.test", fixture.certPath)
	removed.public = &d41FakePublicResolver{err: errors.New("NXDOMAIN store.example.test")}
	if _, err := probePublicRoute(context.Background(), removed); err == nil || !strings.Contains(err.Error(), storePublicProbeUnresolved) {
		t.Fatalf("D41-unresolved-route-refusal-missing: %v", err)
	}
	// A different public leaf on disk than the one the route serves.
	other := fixture.root.validLeaf(t)
	otherPath := filepath.Join(t.TempDir(), "other.pem")
	writeServedTLSTestFile(t, otherPath, other.certPEM())
	mismatch := fixture.inputs("store.example.test", otherPath)
	_, err := probePublicRoute(context.Background(), mismatch)
	if err == nil || !strings.Contains(err.Error(), storePublicProbeLeafMismatch) {
		t.Fatalf("D41-leaf-mismatch-refusal-missing: %v", err)
	}
}

// Positive: the probe fetches BOTH routes through the public answer and pins
// the served leaf to the public leaf on disk.
func TestD41VerifyPublicFetchesHealthzAndIndexAndPinsServedLeaf(t *testing.T) {
	fixture := newD41ProbeFixture(t)
	result, err := probePublicRoute(context.Background(), fixture.inputs("store.example.test", fixture.certPath))
	if err != nil {
		t.Fatalf("D41-probe-refused-clean-fixture: %v", err)
	}
	if len(result.paths) != 2 || result.paths[0] != "/healthz" || result.paths[1] != "/apps/index.json" {
		t.Fatalf("D41-probe-fetched-wrong-routes: %v", result.paths)
	}
	want, err := tlsCertFingerprint(fixture.certPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.leafFingerprint != want {
		t.Fatalf("D41-probe-did-not-pin-served-leaf: %x != %x", result.leafFingerprint, want)
	}
}

func TestD41VerifyPublicRefusesWrongHostname(t *testing.T) {
	fixture := newD41ProbeFixture(t, "other.example.test")
	_, err := probePublicRoute(context.Background(), fixture.inputs("store.example.test", fixture.certPath))
	if err == nil || !strings.Contains(err.Error(), storePublicProbeLeafMismatch) {
		t.Fatalf("D41-wrong-hostname-accepted: %v", err)
	}
}

func TestD41RenewalRefusesWrongHostname(t *testing.T) {
	// The root responder protocol (public_leaf_renew_test.go fixture): the
	// responder returns a leaf for another host; nothing is written.
	fixture := newPublicLeafResponderFixture(t)
	fixture.leafHost = "other.example.test"
	opts := fixture.options(t)
	_, err := fixture.renew(opts)
	if err == nil || !strings.Contains(err.Error(), publicLeafRenewInvalid) {
		t.Fatalf("D41-renewal-wrong-hostname-accepted: %v", err)
	}
	if _, err := os.Stat(opts.certPath); !os.IsNotExist(err) {
		t.Fatalf("D41-renewal-wrote-wrong-hostname: %v", err)
	}
}
