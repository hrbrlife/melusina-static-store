package main

// Public leaf renewal and the outside-in public probe (D41).
//
// The root Store's certificate split has two halves. The boot-identity leaf
// (config.BootIdentity.TLSCertPath) is chain-bound and self-issued: the
// on-chain SidecarIdentityEntry fingerprints it, so it may only change through
// an owner-signed successor. The public leaf (config.TLS.CertPath) is what the
// public listener actually serves to store.<zone>; it is self-renewing through
// the estate ACME responder and must be able to rotate WITHOUT touching the
// identity binding. This file owns both sides of that split:
//
//   - public-leaf-renew: an explicit subcommand that asks the estate ACME
//     responder for a fresh public leaf and publishes it atomically at the
//     tls paths. The running Store never renews by itself: its
//     servedTLSCertificate watcher (served_tls.go) picks the new pair up on
//     its next tick, which is the hot reload. The watcher's identity pin
//     applies to the boot-identity leaf ONLY — a renewed public pair is
//     deliberately never pinned.
//   - --store-host=verify-public: an outside-in probe that resolves the
//     Store's public route through the CONFIGURED PUBLIC RESOLVER ONLY,
//     refuses an /etc/hosts or split-horizon answer by name
//     (store_public_probe_split_horizon), fetches /healthz and
//     /apps/index.json through that resolution, and pins the served leaf
//     against the public leaf file on disk. A removed route refuses by name.
//
// Neither mode writes the chain, an enrollment, or any identity escrow, and
// neither is part of normal server start-up.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Refusal names for the public probe and the renewal path. Every refusal is
// reported by its exact name so an operator log is greppable.
const (
	storePublicProbeSplitHorizon     = "store_public_probe_split_horizon"
	storePublicProbeUnresolved       = "store_public_probe_unresolved"
	storePublicProbeLeafMismatch     = "store_public_probe_leaf_mismatch"
	storePublicProbeFetchFailed      = "store_public_probe_fetch_failed"
	storePublicProbeStatus           = "store_public_probe_status"
	storePublicProbeResolverRequired = "store_public_probe_resolver_required"
	storePublicProbeResolverInvalid  = "store_public_probe_resolver_invalid"

	publicLeafRenewRefused  = "public-leaf-renew-responder-refused"
	publicLeafRenewInvalid  = "public-leaf-renew-invalid-leaf"
	publicLeafRenewTLSDiver = "public-leaf-renew-tls-pair-refused"
)

const (
	publicLeafRenewalSchema = "melusina.store-public-leaf.v1"
	// The probe fetches exactly these routes through the public route; both
	// must answer for the probe to pass.
	storePublicProbePaths = "/healthz,/apps/index.json"
)

// publicLeafRenewalOptions is deliberately closed: the responder endpoint,
// domain and output paths are operator inputs, never rendered defaults, so a
// config file cannot quietly redirect the identity leaf's neighbor files.
type publicLeafRenewalOptions struct {
	configPath   string
	responderURL string
	token        string
	domain       string
	certPath     string
	keyPath      string
	once         bool
	interval     time.Duration
}

// storeHostVerifyPublicOptions carries the probe inputs. resolver must be the
// estate's PUBLIC resolver address ("host:53"); the probe never consults the
// operating system's resolver for the answer it trusts.
type storeHostVerifyPublicOptions struct {
	configPath string
	host       string
	resolver   string
	timeout    time.Duration
}

// publicResolver is the minimal resolution surface the probe needs, split so
// tests can inject a fake public resolver and a fake "system" (/etc/hosts)
// resolver.
type publicResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

func runPublicLeafRenewSubcommand(args []string) {
	fs := flag.NewFlagSet("public-leaf-renew", flag.ExitOnError)
	opts := publicLeafRenewalOptions{}
	fs.StringVar(&opts.configPath, "config", "store.config.json", "path to operator config (JSON)")
	fs.StringVar(&opts.responderURL, "acme-responder", "", "required base URL of the estate ACME responder")
	fs.StringVar(&opts.token, "acme-token", "", "required bearer token for the estate ACME responder")
	fs.StringVar(&opts.domain, "domain", "", "public leaf domain (default: config domain)")
	fs.StringVar(&opts.certPath, "cert-path", "", "required public leaf cert path (tls.cert_path)")
	fs.StringVar(&opts.keyPath, "key-path", "", "required public leaf key path (tls.key_path)")
	fs.BoolVar(&opts.once, "once", false, "renew exactly once and exit (default: renew on an interval)")
	fs.DurationVar(&opts.interval, "interval", time.Hour, "renewal interval (only with renewals after the first)")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("public-leaf-renew: unexpected positional arguments: %v", fs.Args())
	}
	if strings.TrimSpace(opts.responderURL) == "" || strings.TrimSpace(opts.token) == "" ||
		strings.TrimSpace(opts.certPath) == "" || strings.TrimSpace(opts.keyPath) == "" {
		log.Fatalf("public-leaf-renew: --acme-responder, --acme-token, --cert-path and --key-path are required")
	}
	if opts.domain == "" {
		cfg, err := LoadConfig(opts.configPath)
		if err != nil {
			log.Fatalf("public-leaf-renew: config: %v", err)
		}
		opts.domain = cfg.Domain
	}
	if strings.TrimSpace(opts.domain) == "" {
		log.Fatalf("public-leaf-renew: --domain or config domain is required")
	}
	if err := renewPublicLeafLoop(opts); err != nil {
		log.Fatalf("public-leaf-renew: %v", err)
	}
}

// renewPublicLeafLoop renews once, then (unless --once) keeps renewing on the
// interval. Each renewal publishes the pair atomically; the running Store's
// served TLS watcher reloads it without a restart.
func renewPublicLeafLoop(opts publicLeafRenewalOptions) error {
	client := &http.Client{Timeout: 60 * time.Second}
	for {
		notAfter, err := renewPublicLeaf(opts, client)
		if err != nil {
			return err
		}
		log.Printf("public-leaf-renew: published public leaf for %s, not after %s; the running Store reloads it from %s", opts.domain, notAfter.UTC().Format(time.RFC3339), opts.certPath)
		if opts.once {
			return nil
		}
		time.Sleep(opts.interval)
	}
}

// renewPublicLeaf asks the estate ACME responder for a fresh leaf for the
// public domain and writes the pair to the public paths. The response's leaf
// must be currently valid and its key must pair, or the pair is refused by
// name and the previous pair stays in place.
func renewPublicLeaf(opts publicLeafRenewalOptions, client *http.Client) (time.Time, error) {
	body, err := json.Marshal(map[string]string{"schema": publicLeafRenewalSchema, "domain": opts.domain})
	if err != nil {
		return time.Time{}, err
	}
	request, err := http.NewRequest(http.MethodPost, strings.TrimRight(opts.responderURL, "/")+"/new-leaf", bytes.NewReader(body))
	if err != nil {
		return time.Time{}, err
	}
	request.Header.Set("Authorization", "Bearer "+opts.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", publicLeafRenewRefused, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", publicLeafRenewRefused, err)
	}
	if response.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("%s: responder answered %d: %s", publicLeafRenewRefused, response.StatusCode, strings.TrimSpace(string(raw)))
	}
	var leaf struct {
		Schema  string `json:"schema"`
		Domain  string `json:"domain"`
		CertPEM string `json:"certPem"`
		KeyPEM  string `json:"keyPem"`
	}
	if err := json.Unmarshal(raw, &leaf); err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", publicLeafRenewInvalid, err)
	}
	if leaf.Schema != publicLeafRenewalSchema || leaf.Domain != opts.domain || strings.TrimSpace(leaf.CertPEM) == "" || strings.TrimSpace(leaf.KeyPEM) == "" {
		return time.Time{}, fmt.Errorf("%s: schema %q domain %q", publicLeafRenewInvalid, leaf.Schema, leaf.Domain)
	}
	pair, err := tls.X509KeyPair([]byte(leaf.CertPEM), []byte(leaf.KeyPEM))
	if err != nil || pair.Leaf == nil {
		return time.Time{}, fmt.Errorf("%s: %v", publicLeafRenewTLSDiver, err)
	}
	now := time.Now()
	if now.Before(pair.Leaf.NotBefore) || now.After(pair.Leaf.NotAfter) {
		return time.Time{}, fmt.Errorf("%s: leaf not valid now (not before %s, not after %s)", publicLeafRenewInvalid, pair.Leaf.NotBefore.UTC().Format(time.RFC3339), pair.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if err := pair.Leaf.VerifyHostname(opts.domain); err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", publicLeafRenewInvalid, err)
	}
	if err := writePublicLeafPair(opts.certPath, opts.keyPath, []byte(leaf.CertPEM), []byte(leaf.KeyPEM)); err != nil {
		return time.Time{}, err
	}
	return pair.Leaf.NotAfter, nil
}

// writePublicLeafPair publishes cert and key atomically: each file is written
// to a same-directory temporary, fsynced, and renamed. A partial renewal can
// therefore never reach the running Store's watcher.
func writePublicLeafPair(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := writeAtomicFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("public-leaf-renew-write-key: %w", err)
	}
	if err := writeAtomicFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("public-leaf-renew-write-cert: %w", err)
	}
	return nil
}

func writeAtomicFile(path string, content []byte, mode os.FileMode) error {
	temporary := path + ".renew-tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		os.Remove(temporary)
		return err
	}
	return nil
}

// runStoreHostVerifyPublicSubcommand is the --store-host=verify-public mode:
// resolve the Store's public route through the configured public resolver
// ONLY, refuse a split-horizon//etc/hosts answer by name, fetch /healthz and
// /apps/index.json through that resolution, and pin the served leaf against
// the public leaf on disk.
func runStoreHostVerifyPublicSubcommand(args []string) {
	fs := flag.NewFlagSet("verify-public", flag.ExitOnError)
	opts := storeHostVerifyPublicOptions{timeout: 30 * time.Second}
	fs.StringVar(&opts.configPath, "config", "store.config.json", "path to operator config (JSON)")
	fs.StringVar(&opts.host, "host", "", "public route host (default: config domain)")
	fs.StringVar(&opts.resolver, "resolver", "", "required address of the estate PUBLIC resolver (host:port)")
	fs.DurationVar(&opts.timeout, "timeout", 30*time.Second, "probe timeout")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("verify-public: unexpected positional arguments: %v", fs.Args())
	}
	if strings.TrimSpace(opts.resolver) == "" {
		log.Fatalf("verify-public: %s: --resolver is required", storePublicProbeResolverRequired)
	}
	public, err := newConfiguredPublicResolver(opts.resolver, opts.timeout)
	if err != nil {
		log.Fatalf("verify-public: %s: %v", storePublicProbeResolverInvalid, err)
	}
	cfg, err := LoadConfig(opts.configPath)
	if err != nil {
		log.Fatalf("verify-public: config: %v", err)
	}
	host := opts.host
	if host == "" {
		host = cfg.Domain
	}
	if strings.TrimSpace(host) == "" {
		log.Fatalf("verify-public: --host or config domain is required")
	}
	if cfg.TLS.CertPath == "" {
		log.Fatalf("verify-public: config tls.cert_path is required to pin the served leaf")
	}
	result, err := probePublicRoute(context.Background(), probePublicRouteInputs{
		host:     host,
		paths:    strings.Split(storePublicProbePaths, ","),
		certPath: cfg.TLS.CertPath,
		timeout:  opts.timeout,
		public:   public,
		system:   net.DefaultResolver,
		dialer:   &net.Dialer{Timeout: opts.timeout},
		lookupHost: func(ctx context.Context, r publicResolver, name string) ([]string, error) {
			return r.LookupHost(ctx, name)
		},
	})
	if err != nil {
		log.Fatalf("verify-public: %v", err)
	}
	log.Printf("verify-public: %s answers through public resolution %v; fetched %v; served leaf sha256=%s matches %s", host, result.addresses, result.paths, hex.EncodeToString(result.leafFingerprint[:]), cfg.TLS.CertPath)
}

// probePublicRouteResult is the probe's evidence.
type probePublicRouteResult struct {
	addresses       []string
	paths           []string
	leafFingerprint [32]byte
}

// probePublicRouteInputs carries the resolution and transport seams the tests
// pin. public is the trusted public resolver; system is the host's own
// resolver (which reads /etc/hosts) and is consulted ONLY to detect a
// split-horizon answer.
type probePublicRouteInputs struct {
	host       string
	paths      []string
	certPath   string
	timeout    time.Duration
	public     publicResolver
	system     publicResolver
	dialer     dialContext
	lookupHost func(ctx context.Context, r publicResolver, name string) ([]string, error)
}

type dialContext interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// probePublicRoute resolves host through the public resolver and refuses:
//   - store_public_probe_unresolved when the public resolver has no answer
//     (the D40 static record or SNI route was removed);
//   - store_public_probe_split_horizon when the host's own resolver answers
//     DIFFERENTLY from the public resolver — an /etc/hosts or split-horizon
//     answer must never satisfy this probe.
//
// It then fetches every path over TLS through the resolved addresses, captures
// the served leaf, and refuses store_public_probe_leaf_mismatch when it does
// not hash to the public leaf file on disk.
func probePublicRoute(ctx context.Context, in probePublicRouteInputs) (probePublicRouteResult, error) {
	if in.lookupHost == nil {
		in.lookupHost = func(ctx context.Context, r publicResolver, name string) ([]string, error) {
			return r.LookupHost(ctx, name)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, in.timeout)
	defer cancel()
	if in.public == nil {
		return probePublicRouteResult{}, fmt.Errorf("%s: no public resolver configured", storePublicProbeUnresolved)
	}

	// Split-horizon guard FIRST: the host's own resolver (/etc/hosts and the
	// local resolver's view) must agree with the public answer, or the probe
	// is looking at a private view rather than the public route.
	systemAddresses, systemErr := in.lookupHost(ctx, in.system, in.host)
	publicAddresses, publicErr := in.lookupHost(ctx, in.public, in.host)
	if publicErr != nil || len(publicAddresses) == 0 {
		return probePublicRouteResult{}, fmt.Errorf("%s: public resolution of %s failed: %v", storePublicProbeUnresolved, in.host, publicErr)
	}
	for _, address := range publicAddresses {
		ip, err := netip.ParseAddr(address)
		if err != nil || !ip.Unmap().IsGlobalUnicast() || ip.Unmap().IsPrivate() {
			return probePublicRouteResult{}, fmt.Errorf("%s: the public resolver answered with a local or private address %q for %s", storePublicProbeSplitHorizon, address, in.host)
		}
	}
	if systemErr == nil && len(systemAddresses) > 0 && !sameAddressSet(systemAddresses, publicAddresses) {
		return probePublicRouteResult{}, fmt.Errorf("%s: the local resolver answers %v for %s while the public resolver answers %v; the probe only trusts the public answer", storePublicProbeSplitHorizon, systemAddresses, in.host, publicAddresses)
	}

	publicLeaf, err := parsePublicLeafCertFile(in.certPath)
	if err != nil {
		return probePublicRouteResult{}, fmt.Errorf("%s: %w", storePublicProbeLeafMismatch, err)
	}
	if err := publicLeaf.VerifyHostname(in.host); err != nil {
		return probePublicRouteResult{}, fmt.Errorf("%s: %w", storePublicProbeLeafMismatch, err)
	}
	wantFingerprint := sha256.Sum256(publicLeaf.Raw)

	client := publicProbeHTTPClient(in, publicAddresses)
	var fingerprint [32]byte
	for _, path := range in.paths {
		served, err := fetchThroughPublicRoute(ctx, client, in.host, path)
		if err != nil {
			return probePublicRouteResult{}, fmt.Errorf("%s: %w", storePublicProbeFetchFailed, err)
		}
		if served.status != http.StatusOK {
			return probePublicRouteResult{}, fmt.Errorf("%s:%s answered %d", storePublicProbeStatus, path, served.status)
		}
		if fingerprint == ([32]byte{}) {
			fingerprint = served.leafFingerprint
		} else if fingerprint != served.leafFingerprint {
			return probePublicRouteResult{}, fmt.Errorf("%s: %s served a different leaf than the previous route", storePublicProbeLeafMismatch, path)
		}
	}
	if fingerprint != wantFingerprint {
		return probePublicRouteResult{}, fmt.Errorf("%s: the route serves leaf sha256=%s, but %s holds sha256=%s", storePublicProbeLeafMismatch, hex.EncodeToString(fingerprint[:]), in.certPath, hex.EncodeToString(wantFingerprint[:]))
	}
	return probePublicRouteResult{addresses: publicAddresses, paths: in.paths, leafFingerprint: fingerprint}, nil
}

func sameAddressSet(a, b []string) bool {
	set := map[string]int{}
	for _, address := range a {
		set[address]++
	}
	for _, address := range b {
		set[address]--
	}
	for _, count := range set {
		if count != 0 {
			return false
		}
	}
	return true
}

// publicProbeHTTPClient builds a client whose connections dial the PUBLIC
// addresses only (never a secondary name lookup) and skip chain verification,
// because the pin is by fingerprint against the public leaf on disk.
func publicProbeHTTPClient(in probePublicRouteInputs, addresses []string) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: in.host},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, address := range addresses {
				conn, err := in.dialer.DialContext(ctx, network, net.JoinHostPort(address, port))
				if err != nil {
					lastErr = err
					continue
				}
				return conn, nil
			}
			return nil, lastErr
		},
	}
	return &http.Client{Transport: transport, Timeout: in.timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("verify-public probe never follows redirects")
	}}
}

type publicProbeResponse struct {
	status          int
	leafFingerprint [32]byte
}

// fetchThroughPublicRoute performs one GET over TLS and reports the status and
// the SHA-256 of the served leaf DER.
func fetchThroughPublicRoute(ctx context.Context, client *http.Client, host, path string) (publicProbeResponse, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return publicProbeResponse{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return publicProbeResponse{}, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	var fingerprint [32]byte
	if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
		fingerprint = sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
	} else {
		return publicProbeResponse{}, errors.New("connection did not negotiate TLS")
	}
	return publicProbeResponse{status: response.StatusCode, leafFingerprint: fingerprint}, nil
}

// parsePublicLeafCertFile is a small helper used by the probe's pin check and
// by tests: the SHA-256 of the FIRST certificate in a PEM file.
func parsePublicLeafCertFile(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	for len(raw) > 0 {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
		raw = rest
	}
	return nil, fmt.Errorf("no certificate leaf in %s", path)
}
