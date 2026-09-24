package main

// Served TLS certificate reload (first-install spec §7, Store commit 6).
//
// The public listener used to load tls.cert_path and tls.key_path once, when
// the process started, so a renewed certificate reached clients only after a
// restart. The listener now takes its certificate from servedTLSCertificate.
// It re-reads both files every servedTLSReloadInterval and replaces the
// certificate it gives new handshakes only when the new pair passes the same
// validation as the start-up load. Each refusal has a name:
//
//   - tls.cert_path holds at least one CERTIFICATE block, and every block
//     parses (served-tls-chain-empty, served-tls-chain-unparsable:<i>);
//   - when the served file is the boot-identity certificate, the leaf is still
//     the one the SidecarIdentityEntry and the estate enrollment bind
//     (served-tls-identity-pinned);
//   - every certificate is inside its validity window now
//     (served-tls-not-yet-valid:<i>, served-tls-expired:<i>);
//   - each certificate is signed by the one after it
//     (served-tls-chain-order:<i>);
//   - the private key in tls.key_path belongs to the leaf
//     (served-tls-key-pair-refused).
//
// A pair that fails any check is never served. The listener keeps the
// certificate it already has and logs the refusal by name, once for each
// distinct pair of file contents and refusal. At start-up there is nothing to
// fall back to, so the same refusal stops the Store.
//
// This changes only what the public listener serves. It does not change what
// boot identity binds: at start, boot identity compares the leaf at
// bootIdentityTLSCertPath with the chain and the enrollment, and nothing here
// reads, moves or re-checks that binding. So when tls.cert_path is that same
// file, a renewed leaf is refused here, because the next start would refuse
// it too. The Store keeps serving the bound leaf until the owners have moved
// the binding (a new SidecarIdentityEntry key version and an enrollment
// successor) and the Store restarts. A served certificate that is a
// different file from the bound one may rotate freely. The Store Link control
// listener has its own certificate and is unchanged.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// servedTLSReloadInterval is how often the Store re-reads its served
// certificate and key. It is a variable only so the startup tests can shorten
// it in their child process.
var servedTLSReloadInterval = 30 * time.Second

const (
	servedTLSReadFailed        = "served-tls-read-failed"
	servedTLSChainEmpty        = "served-tls-chain-empty"
	servedTLSChainUnparsable   = "served-tls-chain-unparsable"
	servedTLSIdentityPinned    = "served-tls-identity-pinned"
	servedTLSNotYetValid       = "served-tls-not-yet-valid"
	servedTLSExpired           = "served-tls-expired"
	servedTLSChainOrder        = "served-tls-chain-order"
	servedTLSKeyPairRefused    = "served-tls-key-pair-refused"
	servedTLSIdentityUnresolve = "served-tls-identity-path-unresolved"
)

// servedTLSIdentityPin is set when the served certificate file is the file
// boot identity bound at start. The served leaf may then never change.
type servedTLSIdentityPin struct {
	path        string
	fingerprint [32]byte
}

// servedTLSCertificate is the public listener's certificate source.
type servedTLSCertificate struct {
	certPath string
	keyPath  string
	pin      *servedTLSIdentityPin
	now      func() time.Time
	logf     func(format string, args ...any)

	current atomic.Pointer[tls.Certificate]

	mu          sync.Mutex
	servedFiles [32]byte
	lastRefusal string
}

// newServedTLSCertificate loads and validates the configured served pair.
// bound is the verified boot identity, or nil for a read-only Store. A
// non-nil error is fatal at the call site.
func newServedTLSCertificate(cfg Config, bound *verifiedBootIdentity, now func() time.Time, logf func(string, ...any)) (*servedTLSCertificate, error) {
	if cfg.TLS.CertPath == "" || cfg.TLS.KeyPath == "" {
		return nil, errors.New("served TLS certificate needs both tls.cert_path and tls.key_path")
	}
	pin, err := servedTLSIdentityPinFor(cfg, bound)
	if err != nil {
		return nil, err
	}
	served := &servedTLSCertificate{
		certPath: cfg.TLS.CertPath,
		keyPath:  cfg.TLS.KeyPath,
		pin:      pin,
		now:      now,
		logf:     logf,
	}
	certPEM, keyPEM, err := readServedTLSFiles(served.certPath, served.keyPath)
	if err != nil {
		return nil, err
	}
	certificate, err := validateServedTLSPair(certPEM, keyPEM, now(), pin)
	if err != nil {
		return nil, err
	}
	served.current.Store(certificate)
	served.servedFiles = servedTLSFilesDigest(certPEM, keyPEM)
	return served, nil
}

// servedTLSIdentityPinFor decides whether the served file is the file boot
// identity bound. The same cleaned path, or the same file reached another
// way, pins the served leaf to the bound fingerprint. Anything that cannot
// be resolved refuses start-up rather than guess.
func servedTLSIdentityPinFor(cfg Config, bound *verifiedBootIdentity) (*servedTLSIdentityPin, error) {
	if bound == nil {
		return nil, nil
	}
	boundPath := bootIdentityTLSCertPath(cfg)
	servedPath := strings.TrimSpace(cfg.TLS.CertPath)
	pin := &servedTLSIdentityPin{path: boundPath, fingerprint: bound.facts.tlsFingerprint}
	if filepath.Clean(boundPath) == filepath.Clean(servedPath) {
		return pin, nil
	}
	boundInfo, err := os.Stat(boundPath)
	if err != nil {
		return nil, fmt.Errorf("%s: boot-identity certificate %s: %w", servedTLSIdentityUnresolve, boundPath, err)
	}
	servedInfo, err := os.Stat(servedPath)
	if err != nil {
		return nil, fmt.Errorf("%s: served certificate %s: %w", servedTLSIdentityUnresolve, servedPath, err)
	}
	if os.SameFile(boundInfo, servedInfo) {
		return pin, nil
	}
	return nil, nil
}

func readServedTLSFiles(certPath, keyPath string) ([]byte, []byte, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", servedTLSReadFailed, err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", servedTLSReadFailed, err)
	}
	return certPEM, keyPEM, nil
}

// servedTLSFilesDigest identifies one pair of file contents.
func servedTLSFilesDigest(certPEM, keyPEM []byte) [32]byte {
	h := sha256.New()
	var length [8]byte
	for _, part := range [][]byte{certPEM, keyPEM} {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		h.Write(length[:])
		h.Write(part)
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

// validateServedTLSPair returns the certificate the listener may serve, or
// the first named refusal. Error text never contains the current time, so a
// repeated refusal of the same files logs once.
func validateServedTLSPair(certPEM, keyPEM []byte, now time.Time, pin *servedTLSIdentityPin) (*tls.Certificate, error) {
	var chain []*x509.Certificate
	for rest := certPEM; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", servedTLSChainUnparsable, len(chain), err)
		}
		chain = append(chain, certificate)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("%s: no CERTIFICATE block", servedTLSChainEmpty)
	}
	leafFingerprint := sha256.Sum256(chain[0].Raw)
	if pin != nil && leafFingerprint != pin.fingerprint {
		return nil, fmt.Errorf("%s: the served certificate is the boot-identity certificate %s, bound as tls_cert_fingerprint %s; leaf %s is served only after the binding moves and the Store restarts", servedTLSIdentityPinned, pin.path, hex.EncodeToString(pin.fingerprint[:]), hex.EncodeToString(leafFingerprint[:]))
	}
	for i, certificate := range chain {
		if now.Before(certificate.NotBefore) {
			return nil, fmt.Errorf("%s:%d: %q not before %s", servedTLSNotYetValid, i, certificate.Subject.String(), certificate.NotBefore.UTC().Format(time.RFC3339))
		}
		if now.After(certificate.NotAfter) {
			return nil, fmt.Errorf("%s:%d: %q not after %s", servedTLSExpired, i, certificate.Subject.String(), certificate.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return nil, fmt.Errorf("%s:%d: %q is not signed by the next certificate %q: %w", servedTLSChainOrder, i, chain[i].Subject.String(), chain[i+1].Subject.String(), err)
		}
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", servedTLSKeyPairRefused, err)
	}
	pair.Leaf = chain[0]
	return &pair, nil
}

// tlsConfig is the public listener's TLS configuration.
func (s *servedTLSCertificate) tlsConfig() *tls.Config {
	return &tls.Config{GetCertificate: s.GetCertificate}
}

// GetCertificate hands every handshake the certificate currently served.
func (s *servedTLSCertificate) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.current.Load(), nil
}

// reload re-reads both files. It replaces the served certificate only when
// the contents changed and pass validation, and reports whether it did.
func (s *servedTLSCertificate) reload() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	certPEM, keyPEM, err := readServedTLSFiles(s.certPath, s.keyPath)
	if err != nil {
		s.refuse(err.Error(), err)
		return false
	}
	digest := servedTLSFilesDigest(certPEM, keyPEM)
	if digest == s.servedFiles {
		s.lastRefusal = ""
		return false
	}
	certificate, err := validateServedTLSPair(certPEM, keyPEM, s.now(), s.pin)
	if err != nil {
		s.refuse(hex.EncodeToString(digest[:])+" "+err.Error(), err)
		return false
	}
	previous := s.current.Load()
	s.current.Store(certificate)
	s.servedFiles = digest
	s.lastRefusal = ""
	previousFingerprint := sha256.Sum256(previous.Leaf.Raw)
	fingerprint := sha256.Sum256(certificate.Leaf.Raw)
	s.logf("served TLS certificate reloaded from %s: leaf sha256=%s not after %s (was sha256=%s)", s.certPath, hex.EncodeToString(fingerprint[:]), certificate.Leaf.NotAfter.UTC().Format(time.RFC3339), hex.EncodeToString(previousFingerprint[:]))
	return true
}

func (s *servedTLSCertificate) refuse(key string, err error) {
	if key == s.lastRefusal {
		return
	}
	s.lastRefusal = key
	current := s.current.Load()
	fingerprint := sha256.Sum256(current.Leaf.Raw)
	s.logf("served TLS certificate reload refused: %v; still serving leaf sha256=%s not after %s", err, hex.EncodeToString(fingerprint[:]), current.Leaf.NotAfter.UTC().Format(time.RFC3339))
}

// watch reloads every interval until ctx ends.
func (s *servedTLSCertificate) watch(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reload()
		}
	}
}
