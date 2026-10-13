package publishclient

// NewClient returns the publisher's TLS client for a temporary private Store
// ingress. The HTTPS URL retains the signed Store audience and SNI; only the
// TCP destination changes. The exact observed Store leaf is the trust anchor.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"
)

func NewClient(storeURL, connectAddress, leafPath string, timeout time.Duration) (*http.Client, error) {
	origin, err := url.Parse(storeURL)
	if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil ||
		origin.Path != "" && origin.Path != "/" || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("publisher_store_origin_invalid")
	}
	if timeout <= 0 {
		return nil, errors.New("publisher_timeout_invalid")
	}
	if connectAddress != "" {
		host, port, err := net.SplitHostPort(connectAddress)
		ip, ipErr := netip.ParseAddr(host)
		if err != nil || ipErr != nil || !ip.Is4() || !ip.IsPrivate() || port != "18443" {
			return nil, errors.New("publisher_private_connect_refused")
		}
		if leafPath == "" {
			return nil, errors.New("publisher_tls_pin_required")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ForceAttemptHTTP2 = false
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, ServerName: origin.Hostname()}
	if leafPath != "" {
		info, err := os.Lstat(leafPath)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64<<10 {
			return nil, errors.New("publisher_tls_pin_invalid")
		}
		raw, err := os.ReadFile(leafPath)
		if err != nil {
			return nil, errors.New("publisher_tls_pin_invalid")
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("publisher_tls_pin_invalid")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || cert.VerifyHostname(origin.Hostname()) != nil {
			return nil, errors.New("publisher_tls_pin_invalid")
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		transport.TLSClientConfig.RootCAs = roots
		transport.TLSClientConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, cert.Raw) {
				return errors.New("publisher_tls_leaf_changed")
			}
			return nil
		}
	}
	if connectAddress != "" {
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, connectAddress)
		}
	}
	return &http.Client{Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("publisher_redirect_refused") }}, nil
}
