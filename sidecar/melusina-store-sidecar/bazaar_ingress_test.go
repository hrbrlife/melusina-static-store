package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

func bazaarTestFixture(t *testing.T) (Config, bazaarIngressMarker) {
	t.Helper()
	profile := c3D41SignedProfile(t)
	cfg := Config{EstateProfile: &profile, Domain: profile.Store.RootDomain, StoreID: profile.Store.StoreID}
	profileSHA, err := estateprofile.VerifyProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	marker := bazaarIngressMarker{Schema: bazaarIngressSchema, EstateID: profile.EstateID, EstateProfileSHA256: profileSHA, StoreID: profile.Store.StoreID,
		CanonicalHostname: profile.Store.RootDomain, BazaarHostname: "bazaar." + strings.TrimPrefix(profile.Store.RootDomain, "store."), EdgeProfileSHA256: strings.Repeat("a", 64)}
	return cfg, marker
}
func markerJSON(t *testing.T, m bazaarIngressMarker) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBazaarMarkerRequiresExactVerifiedStoreAndSafeFile(t *testing.T) {
	cfg, marker := bazaarTestFixture(t)
	raw := markerJSON(t, marker)
	if _, err := verifyBazaarMarker(raw, cfg); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*bazaarIngressMarker){
		"estate":      func(m *bazaarIngressMarker) { m.EstateID = strings.Repeat("1", 64) },
		"profile":     func(m *bazaarIngressMarker) { m.EstateProfileSHA256 = strings.Repeat("1", 64) },
		"store":       func(m *bazaarIngressMarker) { m.StoreID = "foreign" },
		"canonical":   func(m *bazaarIngressMarker) { m.CanonicalHostname = "store.foreign.test" },
		"alias":       func(m *bazaarIngressMarker) { m.BazaarHostname = "other.example.test" },
		"edge digest": func(m *bazaarIngressMarker) { m.EdgeProfileSHA256 = strings.Repeat("A", 64) },
		"schema":      func(m *bazaarIngressMarker) { m.Schema = "foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := marker
			mutate(&changed)
			if _, err := verifyBazaarMarker(markerJSON(t, changed), cfg); err == nil {
				t.Fatal("accepted wrong marker")
			}
		})
	}
	if _, err := verifyBazaarMarker(append(raw[:len(raw)-1], []byte(",\"schema\":\"duplicate\"}")...), cfg); err == nil {
		t.Fatal("accepted duplicate key")
	}
	badCfg := cfg
	badCfg.Domain = "store.foreign.test"
	if _, err := verifyBazaarMarker(raw, badCfg); err == nil {
		t.Fatal("accepted foreign serving config")
	}
	badProfile := *cfg.EstateProfile
	badProfile.Signatures = nil
	badCfg = cfg
	badCfg.EstateProfile = &badProfile
	if _, err := verifyBazaarMarker(raw, badCfg); err == nil {
		t.Fatal("accepted unsigned estate")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "marker.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	if _, err := openBazaarMarkerOwned(file, uid); err != nil {
		t.Fatal(err)
	}
	if uid != 0 {
		if _, err := openBazaarMarker(file); err == nil {
			t.Fatal("accepted non-root marker")
		}
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := openBazaarMarkerOwned(file, uid); err == nil {
		t.Fatal("accepted broad permissions")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openBazaarMarkerOwned(link, uid); err == nil {
		t.Fatal("accepted symlink")
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(file, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := openBazaarMarkerOwned(file, uid); err == nil {
		t.Fatal("accepted hardlink")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := openBazaarMarkerOwned(fifo, uid); err == nil {
		t.Fatal("accepted FIFO")
	}
}

func TestBazaarIngressTLSAndBoundedPublicRoutes(t *testing.T) {
	cfg, marker := bazaarTestFixture(t)
	now := time.Now()
	dir := t.TempDir()
	cfg.TLS.CertPath = filepath.Join(dir, "private-cert.pem")
	cfg.TLS.KeyPath = filepath.Join(dir, "private-key.pem")
	root := newServedTLSTestRoot(t, "fixture public root")
	intermediate := root.intermediate(t, "fixture intermediate", now.Add(-time.Hour), now.Add(time.Hour))
	private := d41Leaf(t, intermediate, cfg.Domain).withIntermediates(intermediate)
	writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, private)
	before, err := os.ReadFile(cfg.TLS.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "bazaar", "current", "cert.pem"), filepath.Join(dir, "bazaar", "current", "key.pem")
	first := d41Leaf(t, intermediate, marker.BazaarHostname).withIntermediates(intermediate)
	if err := publishPublicLeafPair(certPath, keyPath, first.certPEM(), first.keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := readBazaarCertificate(certPath, keyPath, marker.BazaarHostname, cfg, root.pool(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := readBazaarCertificate(certPath, keyPath, "wrong.example.test", cfg, root.pool(), now); err == nil {
		t.Fatal("accepted wrong DNS name")
	}
	if _, err := readBazaarCertificate(certPath, keyPath, marker.BazaarHostname, cfg, newServedTLSTestRoot(t, "foreign CA").pool(), now); err == nil {
		t.Fatal("accepted private or foreign CA")
	}
	if _, err := readBazaarCertificate(cfg.TLS.CertPath, cfg.TLS.KeyPath, marker.BazaarHostname, cfg, root.pool(), now); err == nil {
		t.Fatal("accepted private listener files")
	}
	if _, err := bazaarIngressRoots(); err != nil {
		t.Fatal(err)
	}

	markerPath := filepath.Join(dir, "marker.json")
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	var calls atomic.Int64
	b := &bazaarIngressWorker{cfg: cfg, handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) }),
		markerPath: markerPath, certPath: certPath, keyPath: keyPath, addr: addr, roots: root.pool(), now: time.Now, logf: func(string, ...any) {},
		readMarker: func(p string) ([]byte, error) { return openBazaarMarkerOwned(p, uint32(os.Geteuid())) }}
	defer b.stop()
	b.tick()
	if b.server != nil {
		t.Fatal("listener started without marker")
	}
	if err := os.WriteFile(markerPath, markerJSON(t, marker), 0600); err != nil {
		t.Fatal(err)
	}
	b.tick()
	if b.server == nil {
		t.Fatal("valid marker and certificate did not start listener")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: root.pool(), ServerName: marker.BazaarHostname, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	do := func(method, path string) int {
		t.Helper()
		req, err := http.NewRequest(method, "https://"+marker.BazaarHostname+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			res, e := client.Do(req)
			if e == nil {
				_, _ = io.Copy(io.Discard, res.Body)
				_ = res.Body.Close()
				return res.StatusCode
			}
			if time.Now().After(deadline) {
				t.Fatalf("listener unavailable: %v", e)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if got := do("GET", "/apps/index.json"); got != 200 {
		t.Fatalf("catalog: %d", got)
	}
	// The listener itself refuses a foreign SNI before any HTTP handler runs.
	foreign, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, ServerName: "store.example.test", MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		foreign.Close()
		t.Fatal("foreign SNI reached the Bazaar listener")
	}
	if got := do("POST", "/apps/index.json"); got != 404 {
		t.Fatalf("POST: %d", got)
	}
	if got := do("GET", "/publish"); got != 404 {
		t.Fatalf("publish: %d", got)
	}
	if got := do("GET", "/control/v1/private"); got != 404 {
		t.Fatalf("control: %d", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("restricted route reached backend %d times", calls.Load())
	}
	old := sha256.Sum256(b.current.Load().Certificate[0])
	next := d41Leaf(t, intermediate, marker.BazaarHostname).withIntermediates(intermediate)
	if err := publishPublicLeafPair(certPath, keyPath, next.certPEM(), next.keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	b.tick()
	if sha256.Sum256(b.current.Load().Certificate[0]) == old {
		t.Fatal("valid renewal did not reload")
	}
	rotated := sha256.Sum256(b.current.Load().Certificate[0])
	wrong := d41Leaf(t, intermediate, "wrong.example.test").withIntermediates(intermediate)
	if err := publishPublicLeafPair(certPath, keyPath, wrong.certPEM(), wrong.keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	b.tick()
	if sha256.Sum256(b.current.Load().Certificate[0]) != rotated {
		t.Fatal("bad renewal replaced valid leaf")
	}
	after, err := os.ReadFile(cfg.TLS.CertPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("private certificate changed")
	}
	if err := os.Remove(markerPath); err != nil {
		t.Fatal(err)
	}
	b.tick()
	if b.server != nil || b.current.Load() != nil {
		t.Fatal("removed marker left ingress active")
	}
}

func TestBazaarPublicHandlerRequiresAliasHostAndSNI(t *testing.T) {
	h := bazaarReadOnlyHandler("bazaar.example.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	for _, tc := range []struct {
		host, sni, path, method string
		want                    int
	}{
		{"bazaar.example.test", "bazaar.example.test", "/", "GET", 200},
		{"bazaar.example.test:443", "bazaar.example.test", "/assets/app.js", "HEAD", 200},
		{"store.example.test", "bazaar.example.test", "/", "GET", 404},
		{"bazaar.example.test", "store.example.test", "/", "GET", 404},
		{"bazaar.example.test", "bazaar.example.test", "/publish", "GET", 404},
		{"bazaar.example.test", "bazaar.example.test", "/", "POST", 404},
		{"bazaar.example.test", "bazaar.example.test", "/apps/index.json?target=foreign", "GET", 404},
	} {
		r, err := http.NewRequest(tc.method, "https://"+tc.host+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = tc.host
		r.TLS = &tls.ConnectionState{ServerName: tc.sni}
		w := &bazaarTestWriter{header: make(http.Header)}
		h.ServeHTTP(w, r)
		if w.code != tc.want {
			t.Fatalf("%+v got %d", tc, w.code)
		}
	}
}

type bazaarTestWriter struct {
	header http.Header
	code   int
}

func (w *bazaarTestWriter) Header() http.Header  { return w.header }
func (w *bazaarTestWriter) WriteHeader(code int) { w.code = code }
func (w *bazaarTestWriter) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = 200
	}
	return len(p), nil
}

func TestBazaarIngressDualNamesIndependentTLSReadinessAndRotation(t *testing.T) {
	cfg, marker := bazaarTestFixture(t)
	dir := t.TempDir()
	cfg.TLS.CertPath, cfg.TLS.KeyPath = filepath.Join(dir, "private-cert"), filepath.Join(dir, "private-key")
	now := time.Now()
	root := newServedTLSTestRoot(t, "public root")
	intermediate := root.intermediate(t, "intermediate", now.Add(-time.Hour), now.Add(time.Hour))
	private := d41Leaf(t, intermediate, cfg.Domain).withIntermediates(intermediate)
	writeServedTLSTestPair(t, cfg.TLS.CertPath, cfg.TLS.KeyPath, private)
	privateBefore, err := os.ReadFile(cfg.TLS.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	canonicalCert, canonicalKey := filepath.Join(dir, "canonical", "current", "cert.pem"), filepath.Join(dir, "canonical", "current", "key.pem")
	bazaarCert, bazaarKey := filepath.Join(dir, "bazaar", "current", "cert.pem"), filepath.Join(dir, "bazaar", "current", "key.pem")
	canonicalPair := d41Leaf(t, intermediate, marker.CanonicalHostname).withIntermediates(intermediate)
	if err := publishPublicLeafPair(canonicalCert, canonicalKey, canonicalPair.certPEM(), canonicalPair.keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(dir, "marker")
	if err := os.WriteFile(markerPath, markerJSON(t, marker), 0600); err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	b := &bazaarIngressWorker{cfg: cfg, handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		markerPath: markerPath, certPath: bazaarCert, keyPath: bazaarKey, canonicalCertPath: canonicalCert, canonicalKeyPath: canonicalKey,
		addr: addr, roots: root.pool(), now: time.Now, logf: func(string, ...any) {},
		readMarker: func(p string) ([]byte, error) { return openBazaarMarkerOwned(p, uint32(os.Geteuid())) }}
	defer b.stop()
	b.tick()
	if b.server == nil || b.canonicalCurrent.Load() == nil || b.current.Load() != nil {
		t.Fatal("canonical leaf did not start independently")
	}
	request := func(sni, host string) (int, [32]byte, error) {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: root.pool(), ServerName: sni, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}}
		defer tr.CloseIdleConnections()
		req, e := http.NewRequest("GET", "https://"+host+"/apps/index.json", nil)
		if e != nil {
			return 0, [32]byte{}, e
		}
		client := &http.Client{Transport: tr, Timeout: time.Second}
		res, e := client.Do(req)
		if e != nil {
			return 0, [32]byte{}, e
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode, sha256.Sum256(res.TLS.PeerCertificates[0].Raw), nil
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, _, err = request(marker.CanonicalHostname, marker.CanonicalHostname)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("canonical TLS unavailable: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, _, err = request(marker.BazaarHostname, marker.BazaarHostname); err == nil {
		t.Fatal("missing Bazaar pair served a certificate")
	}
	wrong := d41Leaf(t, intermediate, "wrong.example.test").withIntermediates(intermediate)
	if err := publishPublicLeafPair(bazaarCert, bazaarKey, wrong.certPEM(), wrong.keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	b.tick()
	if b.current.Load() != nil {
		t.Fatal("wrong Bazaar name became ready")
	}
	if status, _, err := request(marker.CanonicalHostname, marker.CanonicalHostname); err != nil || status != 200 {
		t.Fatalf("bad Bazaar disrupted canonical: status %d error %v", status, err)
	}
	bazaarPair := d41Leaf(t, intermediate, marker.BazaarHostname).withIntermediates(intermediate)
	if err := publishPublicLeafPair(bazaarCert, bazaarKey, bazaarPair.certPEM(), bazaarPair.keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	b.tick()
	status, canonicalBefore, err := request(marker.CanonicalHostname, marker.CanonicalHostname)
	if err != nil || status != 200 {
		t.Fatalf("canonical: %d %v", status, err)
	}
	status, bazaarBefore, err := request(marker.BazaarHostname, marker.BazaarHostname)
	if err != nil || status != 200 {
		t.Fatalf("Bazaar: %d %v", status, err)
	}
	if canonicalBefore == bazaarBefore {
		t.Fatal("names shared a public leaf")
	}
	if status, _, err := request(marker.CanonicalHostname, marker.BazaarHostname); err != nil || status != 404 {
		t.Fatalf("cross-name Host accepted: %d %v", status, err)
	}
	if status, _, err := request(marker.BazaarHostname, marker.CanonicalHostname); err != nil || status != 404 {
		t.Fatalf("cross-name Host accepted: %d %v", status, err)
	}
	if err := publishPublicLeafPair(canonicalCert, canonicalKey, wrong.certPEM(), wrong.keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	bazaarNext := d41Leaf(t, intermediate, marker.BazaarHostname).withIntermediates(intermediate)
	if err := publishPublicLeafPair(bazaarCert, bazaarKey, bazaarNext.certPEM(), bazaarNext.keyPEM(t)); err != nil {
		t.Fatal(err)
	}
	b.tick()
	status, canonicalAfter, err := request(marker.CanonicalHostname, marker.CanonicalHostname)
	if err != nil || status != 200 || canonicalAfter != canonicalBefore {
		t.Fatal("invalid canonical rotation displaced valid leaf")
	}
	status, bazaarAfter, err := request(marker.BazaarHostname, marker.BazaarHostname)
	if err != nil || status != 200 || bazaarAfter == bazaarBefore {
		t.Fatal("Bazaar rotation did not proceed independently")
	}
	privateAfter, err := os.ReadFile(cfg.TLS.CertPath)
	if err != nil || !bytes.Equal(privateBefore, privateAfter) {
		t.Fatal("private pinned certificate changed")
	}
	if err := os.Remove(markerPath); err != nil {
		t.Fatal(err)
	}
	b.tick()
	if b.current.Load() != nil || b.canonicalCurrent.Load() != nil || b.server != nil {
		t.Fatal("marker removal left public names enabled")
	}
}
