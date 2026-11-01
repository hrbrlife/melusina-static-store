package main

// Optional, separately authorized public Store and Bazaar TLS listener. The fixed marker is
// installed by the owner-authorized Store-edge delivery, not by an HTTP caller.
// The existing Store listener, origin, boot identity and private leaf do not
// change. Missing or bad alias inputs close only this optional listener.

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

const (
	bazaarIngressMarkerPath = "/etc/melusina/store/bazaar-ingress.json"
	bazaarIngressCertPath   = "/etc/melusina/store/bazaar-tls/current/cert.pem"
	bazaarIngressKeyPath    = "/etc/melusina/store/bazaar-tls/current/key.pem"
	canonicalPublicCertPath = "/etc/melusina/store/canonical-public-tls/current/cert.pem"
	canonicalPublicKeyPath  = "/etc/melusina/store/canonical-public-tls/current/key.pem"
	bazaarIngressAddr       = ":8447"
	bazaarIngressSchema     = "melusina.store-bazaar-ingress.v1"
	bazaarIngressPoll       = 5 * time.Second
)

// The corresponding edge issuer is fixed to the Let's Encrypt production
// directory. Embed its public ISRG trust anchors instead of accepting a local
// private CA that might also be installed in the Store's system trust bundle.
//
//go:embed bazaar_isrg_roots.pem
var bazaarISRGRootsPEM []byte

type bazaarIngressMarker struct {
	Schema              string `json:"schema"`
	EstateID            string `json:"estateId"`
	EstateProfileSHA256 string `json:"estateProfileSha256"`
	StoreID             string `json:"storeId"`
	CanonicalHostname   string `json:"canonicalHostname"`
	BazaarHostname      string `json:"bazaarHostname"`
	EdgeProfileSHA256   string `json:"edgeProfileSha256"`
}

func bazaarIngressRoots() (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bazaarISRGRootsPEM) {
		return nil, errors.New("bazaar ingress public roots unavailable")
	}
	return roots, nil
}

// openBazaarMarker refuses a symlink, FIFO, hardlink, non-root owner or mode
// other than 0600 before decoding. O_NONBLOCK prevents a malicious FIFO from
// holding the Store's optional listener worker indefinitely.
func openBazaarMarker(name string) ([]byte, error) {
	return openBazaarMarkerOwned(name, 0)
}

func openBazaarMarkerOwned(name string, owner uint32) ([]byte, error) {
	f, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode() != 0600 || st.Uid != owner || st.Nlink != 1 || info.Size() <= 0 || info.Size() > 4096 {
		return nil, errors.New("bazaar ingress marker is not an exclusive root-owned 0600 regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return nil, errors.New("bazaar ingress marker cannot be read")
	}
	return raw, nil
}

func verifyBazaarMarker(raw []byte, cfg Config) (bazaarIngressMarker, error) {
	var m bazaarIngressMarker
	if cfg.EstateProfile == nil {
		return m, errors.New("bazaar ingress estate unavailable")
	}
	// Verify again here so the marker cannot become authoritative when this
	// helper is reused outside the serving startup gate.
	profileSHA, err := estateprofile.VerifyProfile(*cfg.EstateProfile)
	if err != nil {
		return m, errors.New("bazaar ingress estate unverified")
	}
	if err := estateprofile.DecodeStrictDocument(raw, 4096, &m); err != nil {
		return m, errors.New("bazaar ingress marker malformed")
	}
	estate := cfg.EstateProfile
	canonical := estate.Store.RootDomain
	root, ok := strings.CutPrefix(canonical, "store.")
	if !ok || root == "" || !estate.Store.IsRoot || cfg.Domain != canonical || cfg.StoreID != estate.Store.StoreID ||
		m.Schema != bazaarIngressSchema || m.EstateID != estate.EstateID || m.EstateProfileSHA256 != profileSHA || m.StoreID != estate.Store.StoreID ||
		m.CanonicalHostname != canonical || m.BazaarHostname != "bazaar."+root || !validLowerHexDigest(m.EdgeProfileSHA256) {
		return bazaarIngressMarker{}, errors.New("bazaar ingress marker scope refused")
	}
	return m, nil
}

// The same copy of a certificate/key may not serve the private Store or its
// chain-bound boot identity. Check filesystem identity, not only path names.
func refuseBazaarPrivateAliases(certPath, keyPath string, cfg Config) error {
	aliasCert, err := os.Stat(certPath)
	if err != nil {
		return err
	}
	aliasKey, err := os.Stat(keyPath)
	if err != nil {
		return err
	}
	for _, pair := range []struct {
		info  os.FileInfo
		other string
	}{
		{aliasCert, cfg.TLS.CertPath}, {aliasKey, cfg.TLS.KeyPath}, {aliasCert, bootIdentityTLSCertPath(cfg)},
	} {
		if pair.other == "" {
			continue
		}
		other, err := os.Stat(pair.other)
		if err != nil {
			return fmt.Errorf("bazaar ingress private TLS unobservable: %w", err)
		}
		if os.SameFile(pair.info, other) {
			return errors.New("bazaar ingress aliases private TLS material")
		}
	}
	return nil
}

func readBazaarCertificate(certPath, keyPath, hostname string, cfg Config, roots *x509.CertPool, now time.Time) (*tls.Certificate, error) {
	if roots == nil {
		return nil, errors.New("bazaar ingress public roots unavailable")
	}
	if err := refuseBazaarPrivateAliases(certPath, keyPath, cfg); err != nil {
		return nil, err
	}
	certPEM, keyPEM, err := readServedTLSFiles(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, errors.New("bazaar ingress certificate pair invalid")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("bazaar ingress certificate key invalid")
	}
	if _, err := verifyPublicLeafChain(certPEM, hostname, key, roots, now); err != nil {
		return nil, err
	}
	pair.Leaf = leaf
	return &pair, nil
}

// bazaarPublicPath is intentionally the same narrow public browser, catalog,
// package and update allowlist used by the Store alias ingress producer.
func bazaarPublicPath(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	name := r.URL.Path
	if name == "" || !strings.HasPrefix(name, "/") || len(name) > 512 || r.URL.RawPath != "" || r.URL.EscapedPath() != name || path.Clean(name) != name || strings.Contains(name, "//") || (r.URL.RawQuery != "" && name != "/" && name != "/index.html") || len(r.URL.RawQuery) > 2048 {
		return false
	}
	for _, c := range name {
		if !(c == '/' || c == '-' || c == '_' || c == '.' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	switch name {
	case "/", "/index.html", "/manifest.json", "/sw.js", "/installation-policy.json", "/update/install.sh", "/apps/index.json", "/healthz", "/.well-known/melusina/trust-bundle.json", "/update/generation.json", "/update/sidecar-classes-v1.json", "/update/manifest.json":
		return true
	}
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	for _, part := range parts {
		if part == "" || part[0] == '.' {
			return false
		}
	}
	if len(parts) == 2 && parts[0] == "packages" {
		decoded, err := hex.DecodeString(parts[1])
		return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == parts[1]
	}
	if len(parts) == 3 && parts[0] == "apps" && parts[1] == "pointers" {
		return strings.HasSuffix(parts[2], ".json") && len(strings.TrimSuffix(parts[2], ".json")) >= 32
	}
	if len(parts) == 3 && parts[0] == "releases" {
		switch parts[1] {
		case "shell", "sidecar", "app", "data":
			return true
		}
		return false
	}
	if len(parts) < 2 || len(parts) > 5 {
		return false
	}
	ext := strings.ToLower(path.Ext(parts[len(parts)-1]))
	switch parts[0] {
	case "assets":
		return ext == ".js" || ext == ".css" || ext == ".woff" || ext == ".woff2"
	case "icons", "images", "screenshots":
		return ext == ".svg" || ext == ".png" || ext == ".ico" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || ext == ".webp"
	}
	return false
}

func bazaarReadOnlyHandler(hostname string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if strings.Contains(host, ":") {
			parsed, port, err := net.SplitHostPort(host)
			if err != nil || (port != "443" && port != "8447") {
				http.NotFound(w, r)
				return
			}
			host = parsed
		}
		if (r.Method != http.MethodGet && r.Method != http.MethodHead) || r.TLS == nil || strings.ToLower(r.TLS.ServerName) != hostname || host != hostname || !bazaarPublicPath(r) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Both names share the listener but each request must use the same admitted
// name in its TLS SNI and HTTP Host. The handler stays the same read-only
// Store surface for either name.
func twoNamesPublicReadOnlyHandler(canonical, bazaar string, next http.Handler) http.Handler {
	canonicalHandler := bazaarReadOnlyHandler(canonical, next)
	bazaarHandler := bazaarReadOnlyHandler(bazaar, next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.NotFound(w, r)
			return
		}
		switch strings.ToLower(r.TLS.ServerName) {
		case canonical:
			canonicalHandler.ServeHTTP(w, r)
		case bazaar:
			bazaarHandler.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// bazaarIngressWorker is independent of the private Store server. It observes
// the fixed marker and separate pairs after startup, so verified edge delivery
// can add either public hostname without restarting the Store. Removing or
// invalidating the marker closes the listener; a bad renewed pair never
// replaces the last valid pair for that name.
type bazaarIngressWorker struct {
	cfg                                 Config
	handler                             http.Handler
	markerPath, certPath, keyPath, addr string
	canonicalCertPath, canonicalKeyPath string
	roots                               *x509.CertPool
	now                                 func() time.Time
	readMarker                          func(string) ([]byte, error)
	logf                                func(string, ...any)
	current                             atomic.Pointer[tls.Certificate]
	canonicalCurrent                    atomic.Pointer[tls.Certificate]
	server                              *http.Server
	done                                <-chan error
	lastError                           string
}

func (b *bazaarIngressWorker) stop() {
	if b.server != nil {
		_ = b.server.Close()
		b.server = nil
		b.done = nil
	}
	b.current.Store(nil)
	b.canonicalCurrent.Store(nil)
}
func (b *bazaarIngressWorker) report(err error) {
	message := ""
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		message = err.Error()
	}
	if message != "" && message != b.lastError {
		b.logf("bazaar ingress: %s", message)
	}
	b.lastError = message
}
func (b *bazaarIngressWorker) tick() {
	readMarker := b.readMarker
	if readMarker == nil {
		readMarker = openBazaarMarker
	}
	raw, err := readMarker(b.markerPath)
	if err != nil {
		b.stop()
		b.report(err)
		return
	}
	marker, err := verifyBazaarMarker(raw, b.cfg)
	if err != nil {
		b.stop()
		b.report(err)
		return
	}
	certificate, bazaarErr := readBazaarCertificate(b.certPath, b.keyPath, marker.BazaarHostname, b.cfg, b.roots, b.now())
	if bazaarErr == nil {
		b.current.Store(certificate)
	}
	canonical, canonicalErr := readBazaarCertificate(b.canonicalCertPath, b.canonicalKeyPath, marker.CanonicalHostname, b.cfg, b.roots, b.now())
	if canonicalErr == nil {
		b.canonicalCurrent.Store(canonical)
	}
	if b.current.Load() == nil && b.canonicalCurrent.Load() == nil {
		b.report(errors.Join(bazaarErr, canonicalErr))
		return
	}
	b.report(nil)
	if b.server != nil {
		return
	}
	srv := newPublicServer(b.addr, twoNamesPublicReadOnlyHandler(marker.CanonicalHostname, marker.BazaarHostname, b.handler))
	srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		var current *tls.Certificate
		switch strings.ToLower(hello.ServerName) {
		case marker.CanonicalHostname:
			current = b.canonicalCurrent.Load()
		case marker.BazaarHostname:
			current = b.current.Load()
		}
		if current == nil || current.Leaf == nil || b.now().Before(current.Leaf.NotBefore) || !b.now().Before(current.Leaf.NotAfter) {
			return nil, errors.New("public Store certificate unavailable")
		}
		return current, nil
	}}
	done := make(chan error, 1)
	b.server, b.done = srv, done
	go func() { done <- srv.ListenAndServeTLS("", "") }()
}
func (b *bazaarIngressWorker) run(ctx context.Context) {
	ticker := time.NewTicker(bazaarIngressPoll)
	defer ticker.Stop()
	defer b.stop()
	for {
		b.tick()
		select {
		case <-ctx.Done():
			return
		case err := <-b.done:
			b.server, b.done = nil, nil
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				b.report(err)
			}
			// A failed bind must not turn an optional listener into a busy loop.
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		case <-ticker.C:
		}
	}
}

func startBazaarIngress(ctx context.Context, cfg Config, handler http.Handler, logf func(string, ...any)) {
	roots, err := bazaarIngressRoots()
	if err != nil {
		logf("bazaar ingress: %v", err)
		return
	}
	worker := &bazaarIngressWorker{cfg: cfg, handler: handler, markerPath: bazaarIngressMarkerPath, certPath: bazaarIngressCertPath,
		keyPath: bazaarIngressKeyPath, canonicalCertPath: canonicalPublicCertPath, canonicalKeyPath: canonicalPublicKeyPath,
		addr: bazaarIngressAddr, roots: roots, now: time.Now, logf: logf}
	go worker.run(ctx)
}
