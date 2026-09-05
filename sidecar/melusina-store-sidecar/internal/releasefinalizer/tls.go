package releasefinalizer

// Fixed mTLS server configuration for the finalization worker.
//
// This package deliberately accepts neither a generic http.Handler nor a
// caller-selected client identity. The one listener may serve the fixed
// HTTPHandler only, and both the TLS handshake and the handler pin the one
// configured Store Link leaf certificate. The configuration is not a way to
// expose the worker to terminals, browsers, or the public Store sidecar.

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// MTLSConfig is the deployer-owned configuration for one finalizer worker.
// Certificate and CA files are public material, but the server key remains an
// owner-only regular file. The Store Link leaf digest is an explicit identity
// pin in addition to normal PKIX client-certificate verification.
type MTLSConfig struct {
	ListenAddr                string
	CertPath                  string
	KeyPath                   string
	ClientCAPath              string
	StoreLinkClientCertSHA256 string
}

// NewMTLSServer returns, but does not start, the one fixed finalizer listener.
// A deployment service unit owns its lifecycle. This function cannot select a
// route family, accept a generic HTTP handler, weaken TLS client validation, or
// replace the Store Link leaf pin at runtime.
func NewMTLSServer(config MTLSConfig, handler *HTTPHandler) (*http.Server, error) {
	if handler == nil {
		return nil, errors.New("finalizer mTLS server requires a fixed handler")
	}
	normalized, pinnedLeaf, err := normalizeMTLSConfig(config)
	if err != nil {
		return nil, err
	}
	if normalized.StoreLinkClientCertSHA256 != handler.storeLinkCertSHA {
		return nil, errors.New("finalizer mTLS server and handler pin different Store Link identities")
	}

	certificate, err := tls.LoadX509KeyPair(normalized.CertPath, normalized.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("load finalizer serving certificate: %w", err)
	}
	clientPEM, err := os.ReadFile(normalized.ClientCAPath)
	if err != nil {
		return nil, fmt.Errorf("read finalizer client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientPEM) {
		return nil, errors.New("finalizer client CA contains no certificates")
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || state.PeerCertificates[0] == nil || !certificateInVerifiedChains(state.PeerCertificates[0], state.VerifiedChains) {
				return errors.New("finalizer requires a verified Store Link client certificate")
			}
			actual := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(actual[:], pinnedLeaf) != 1 {
				return errors.New("finalizer client certificate is not the pinned Store Link identity")
			}
			return nil
		},
	}
	return &http.Server{
		Addr:              normalized.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         tlsConfig,
	}, nil
}

func normalizeMTLSConfig(config MTLSConfig) (MTLSConfig, []byte, error) {
	config.ListenAddr = strings.TrimSpace(config.ListenAddr)
	if _, port, err := net.SplitHostPort(config.ListenAddr); err != nil || port == "" {
		return MTLSConfig{}, nil, errors.New("finalizer mTLS listen address must be host:port")
	}
	for label, raw := range map[string]string{
		"cert path": config.CertPath, "key path": config.KeyPath, "client CA path": config.ClientCAPath,
	} {
		path, err := absoluteRegularPath(raw, label)
		if err != nil {
			return MTLSConfig{}, nil, err
		}
		switch label {
		case "cert path":
			config.CertPath = path
		case "key path":
			config.KeyPath = path
		case "client CA path":
			config.ClientCAPath = path
		}
	}
	if err := ownerOnlyKeyFile(config.KeyPath); err != nil {
		return MTLSConfig{}, nil, err
	}
	config.StoreLinkClientCertSHA256 = strings.ToLower(strings.TrimSpace(config.StoreLinkClientCertSHA256))
	if !lowerHex(config.StoreLinkClientCertSHA256, sha256.Size*2) {
		return MTLSConfig{}, nil, errors.New("finalizer Store Link certificate digest is invalid")
	}
	pinnedLeaf, err := hex.DecodeString(config.StoreLinkClientCertSHA256)
	if err != nil || len(pinnedLeaf) != sha256.Size {
		return MTLSConfig{}, nil, errors.New("finalizer Store Link certificate digest is invalid")
	}
	return config, pinnedLeaf, nil
}

func absoluteRegularPath(raw, label string) (string, error) {
	path := filepath.Clean(strings.TrimSpace(raw))
	if !filepath.IsAbs(path) || path == "/" {
		return "", fmt.Errorf("finalizer %s must be an absolute file path", label)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("finalizer %s must be a real regular file", label)
	}
	return path, nil
}

func ownerOnlyKeyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return errors.New("finalizer serving key must be a mode-0600 regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return errors.New("finalizer serving key must be a mode-0600 regular file")
	}
	return nil
}
