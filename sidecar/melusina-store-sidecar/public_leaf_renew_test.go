package main

// V-STEP4-STORE: the Store's public-leaf-renew caller against the estate's
// root ACME responder protocol (deploy-ui internal/acmeresponder leaf.go):
// a Store-generated key, a CSR for exactly the Store's domain, signed with the
// Store's Ed25519 delegation key, an SPKI-pinned responder, and a chain-only
// response.

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testPublicLeafDomain       = "store.example.test"
	testPublicLeafDelegationID = "acme-store-store-example-test-0123456789ab"
)

// publicLeafResponderFixture is a stand-in for the root responder: it checks
// the Store's signature over the exact canonical bytes, the CSR's name and
// self-signature, then issues from a test CA (root -> intermediate -> leaf).
type publicLeafResponderFixture struct {
	server     *httptest.Server
	root       *servedTLSTestIssuer
	inter      *servedTLSTestIssuer
	delegation ed25519.PrivateKey
	seedPath   string
	// leafHost and leafKey override the issued leaf to model a hostile CA.
	leafHost       string
	leafKey        crypto.PublicKey
	status         int
	responseSuffix string
	requests       int
	headers        http.Header
}

func newPublicLeafResponderFixture(t *testing.T) *publicLeafResponderFixture {
	t.Helper()
	fixture := &publicLeafResponderFixture{root: newServedTLSTestRoot(t, "public leaf test root")}
	now := time.Now()
	fixture.inter = fixture.root.intermediate(t, "public leaf test intermediate", now.Add(-time.Hour), now.Add(time.Hour))
	_, fixture.delegation, _ = ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	fixture.seedPath = filepath.Join(dir, "delegation.seed")
	if err := os.WriteFile(fixture.seedPath, fixture.delegation.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.requests++
		fixture.headers = r.Header.Clone()
		if fixture.status != 0 {
			w.WriteHeader(fixture.status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "acme_leaf_rate_exceeded"})
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != publicLeafRoute || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "route", http.StatusNotFound)
			return
		}
		var signed publicLeafSignedRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&signed) != nil {
			http.Error(w, "decode", http.StatusBadRequest)
			return
		}
		message, _ := publicLeafCanonicalBytes(signed.Request)
		signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
		if signed.Request.Schema != publicLeafRequestSchema || signed.Request.DelegationID != testPublicLeafDelegationID ||
			!ed25519.Verify(fixture.delegation.Public().(ed25519.PublicKey), message, signature) {
			http.Error(w, `{"error":"acme_leaf_signature_not_delegation_key"}`, http.StatusForbidden)
			return
		}
		der, err := base64.RawURLEncoding.DecodeString(signed.Request.CSR)
		csr, csrErr := x509.ParseCertificateRequest(der)
		if err != nil || csrErr != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 1 || csr.DNSNames[0] != signed.Request.Domain {
			http.Error(w, `{"error":"acme_leaf_csr_invalid"}`, http.StatusBadRequest)
			return
		}
		host, key := signed.Request.Domain, csr.PublicKey
		if fixture.leafHost != "" {
			host = fixture.leafHost
		}
		if fixture.leafKey != nil {
			key = fixture.leafKey
		}
		template := &x509.Certificate{SerialNumber: servedTLSTestSerial(t), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		leaf, err := x509.CreateCertificate(rand.Reader, template, fixture.inter.cert, key, fixture.inter.key)
		if err != nil {
			http.Error(w, "issue", http.StatusInternalServerError)
			return
		}
		var chain bytes.Buffer
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: leaf})
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: fixture.inter.cert.Raw})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(publicLeafResponse{Schema: publicLeafResponseSchema, Domain: signed.Request.Domain, ChainPEM: chain.String()})
		if fixture.responseSuffix != "" {
			_, _ = w.Write([]byte(fixture.responseSuffix))
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *publicLeafResponderFixture) responderPin() string {
	sum := sha256.Sum256(f.server.Certificate().RawSubjectPublicKeyInfo)
	return "spki-sha256:" + hex.EncodeToString(sum[:])
}

func (f *publicLeafResponderFixture) options(t *testing.T) publicLeafRenewalOptions {
	t.Helper()
	dir := t.TempDir()
	return publicLeafRenewalOptions{responderURL: f.server.URL, responderSPKI: f.responderPin(), delegationKey: f.seedPath,
		delegationID: testPublicLeafDelegationID, domain: testPublicLeafDomain,
		certPath: filepath.Join(dir, "current", "cert.pem"), keyPath: filepath.Join(dir, "current", "key.pem"), roots: f.root.pool()}
}

func (f *publicLeafResponderFixture) renew(opts publicLeafRenewalOptions) (time.Time, error) {
	return renewPublicLeaf(opts, publicLeafResponderClient(opts.responderURL, opts.responderSPKI))
}

func TestPublicLeafRenewalSendsASignedCSRAndKeepsItsOwnKey(t *testing.T) {
	fixture := newPublicLeafResponderFixture(t)
	opts := fixture.options(t)
	notAfter, err := fixture.renew(opts)
	if err != nil {
		t.Fatalf("POSITIVE_CONTROL_REFUSED: the Store did not renew through the root responder: %v", err)
	}
	pair, err := tls.LoadX509KeyPair(opts.certPath, opts.keyPath)
	if err != nil {
		t.Fatalf("the published pair does not load: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.DNSNames[0] != testPublicLeafDomain || !leaf.NotAfter.Equal(notAfter) || len(pair.Certificate) != 2 {
		t.Fatalf("published chain is not the Store's leaf plus intermediate: %v", err)
	}
	info, err := os.Stat(opts.keyPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the Store's public leaf key is not private: %v", err)
	}
	if fixture.headers.Get("Authorization") != "" {
		t.Fatal("PUBLIC_LEAF_BEARER_TOKEN_SENT: the signed request must be the only authority")
	}
}

func TestPublicLeafRenewalRefusesByName(t *testing.T) {
	for name, item := range map[string]struct {
		setup  func(*publicLeafResponderFixture, *publicLeafRenewalOptions)
		prefix string
	}{
		"unpaired output paths": {func(_ *publicLeafResponderFixture, o *publicLeafRenewalOptions) {
			root := filepath.Dir(filepath.Dir(o.certPath))
			o.certPath, o.keyPath = filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
		}, publicLeafPairLayoutRefused},
		"unpinned responder": {func(_ *publicLeafResponderFixture, o *publicLeafRenewalOptions) {
			o.responderSPKI = "spki-sha256:" + strings.Repeat("0", 64)
		}, publicLeafRenewRefused},
		"absent responder pin": {func(_ *publicLeafResponderFixture, o *publicLeafRenewalOptions) {
			o.responderSPKI = ""
		}, publicLeafRenewResponderUnpinned},
		"plain http responder": {func(_ *publicLeafResponderFixture, o *publicLeafRenewalOptions) {
			o.responderURL = strings.Replace(o.responderURL, "https://", "http://", 1)
		}, publicLeafRenewResponderUnpinned},
		"wrong leaf name": {func(f *publicLeafResponderFixture, _ *publicLeafRenewalOptions) { f.leafHost = "other.example.test" }, publicLeafRenewInvalid},
		"leaf for another key": {func(f *publicLeafResponderFixture, _ *publicLeafRenewalOptions) {
			f.leafKey = &servedTLSTestKey(t).PublicKey
		}, publicLeafRenewWrongKey},
		"untrusted chain": {func(_ *publicLeafResponderFixture, o *publicLeafRenewalOptions) {
			o.roots = newServedTLSTestRoot(t, "another root").pool()
		}, publicLeafRenewUntrusted},
		"responder refusal": {func(f *publicLeafResponderFixture, _ *publicLeafRenewalOptions) {
			f.status = http.StatusTooManyRequests
		}, publicLeafRenewRefused},
		"second response object": {func(f *publicLeafResponderFixture, _ *publicLeafRenewalOptions) { f.responseSuffix = "{}\n" }, publicLeafRenewInvalid},
		"foreign delegation key": {func(f *publicLeafResponderFixture, _ *publicLeafRenewalOptions) {
			_, foreign, _ := ed25519.GenerateKey(rand.Reader)
			if err := os.WriteFile(f.seedPath, foreign.Seed(), 0o600); err != nil {
				t.Fatal(err)
			}
		}, publicLeafRenewRefused},
		"readable delegation key": {func(f *publicLeafResponderFixture, _ *publicLeafRenewalOptions) {
			if err := os.Chmod(f.seedPath, 0o644); err != nil {
				t.Fatal(err)
			}
		}, publicLeafRenewDelegationUnsafe},
		"malformed delegation ID": {func(_ *publicLeafResponderFixture, o *publicLeafRenewalOptions) { o.delegationID = "store" }, publicLeafRenewDelegationUnsafe},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newPublicLeafResponderFixture(t)
			opts := fixture.options(t)
			item.setup(fixture, &opts)
			if _, err := fixture.renew(opts); err == nil || !strings.HasPrefix(err.Error(), item.prefix) {
				t.Fatalf("%s: got %v, want %s", name, err, item.prefix)
			} else if name == "unpinned responder" && !strings.Contains(err.Error(), publicLeafRenewResponderPinFailed) {
				t.Fatalf("%s: got %v, want %s by name", name, err, publicLeafRenewResponderPinFailed)
			}
			if name == "unpaired output paths" && fixture.requests != 0 {
				t.Fatal("PUBLIC_LEAF_PAIR_BAD_PATH_SPENT_CA_BUDGET: the responder was called before the path refusal")
			}
			if _, err := os.Stat(opts.certPath); !os.IsNotExist(err) {
				t.Fatalf("%s: a refused renewal wrote the public leaf: %v", name, err)
			}
			if _, err := os.Stat(opts.keyPath); !os.IsNotExist(err) {
				t.Fatalf("%s: a refused renewal wrote the public key: %v", name, err)
			}
		})
	}
}

func TestPublicLeafRenewalIsDueOnlyInTheLastThird(t *testing.T) {
	fixture := newPublicLeafResponderFixture(t)
	opts := fixture.options(t)
	if !publicLeafRenewalDue(opts.certPath, opts.keyPath, testPublicLeafDomain, time.Now()) {
		t.Fatal("an absent public leaf was not due")
	}
	if _, err := fixture.renew(opts); err != nil {
		t.Fatal(err)
	}
	leaf, err := parsePublicLeafCertFile(opts.certPath)
	if err != nil {
		t.Fatal(err)
	}
	if publicLeafRenewalDue(opts.certPath, opts.keyPath, testPublicLeafDomain, leaf.NotBefore.Add(time.Minute)) {
		t.Fatal("PUBLIC_LEAF_RENEWED_EARLY: a fresh leaf was due, spending the CA budget every interval")
	}
	if !publicLeafRenewalDue(opts.certPath, opts.keyPath, testPublicLeafDomain, leaf.NotAfter.Add(-time.Minute)) {
		t.Fatal("a leaf in its last third was not due")
	}
	if !publicLeafRenewalDue(opts.certPath, opts.keyPath, "other.example.test", leaf.NotBefore.Add(time.Minute)) {
		t.Fatal("a leaf for another host was not due")
	}
	if err := os.WriteFile(opts.keyPath, []byte("invalid key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !publicLeafRenewalDue(opts.certPath, opts.keyPath, testPublicLeafDomain, leaf.NotBefore.Add(time.Minute)) {
		t.Fatal("PUBLIC_LEAF_INVALID_KEY_NOT_RENEWED: a valid certificate with a broken key was treated as current")
	}
}

// TestPublicLeafRequestBytesAreTheResponderContract pins the exact signed
// bytes. deploy-ui internal/acmeresponder TestLeafCanonicalBytesAreTheStoreContract
// asserts the same literal, so either side drifting fails by this name.
func TestPublicLeafRequestBytesAreTheResponderContract(t *testing.T) {
	raw, err := publicLeafCanonicalBytes(publicLeafRequest{Schema: publicLeafRequestSchema, DelegationID: "acme-store-store-example-test-0123456789ab",
		Domain: "store.example.test", CSR: "MIIB", IssuedAt: "2026-10-10T00:00:00Z", Nonce: strings.Repeat("A", 43)})
	if err != nil {
		t.Fatal(err)
	}
	want := "MELUSINA_ACME_LEAF_REQUEST_V1\n" +
		`{"schema":"melusina-acme-leaf-request-v1","delegationId":"acme-store-store-example-test-0123456789ab","domain":"store.example.test","csr":"MIIB","issuedAt":"2026-10-10T00:00:00Z","nonce":"` + strings.Repeat("A", 43) + `"}`
	if string(raw) != want {
		t.Fatalf("STORE_LEAF_REQUEST_WIRE_DRIFTED:\n got %q\nwant %q", raw, want)
	}
}
