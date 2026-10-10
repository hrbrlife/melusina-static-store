package main

// Public leaf renewal and the outside-in public probe (D41).
//
// The root Store's certificate split has two halves. The boot-identity leaf
// (config.BootIdentity.TLSCertPath) is chain-bound and self-issued: the
// on-chain SidecarIdentityEntry fingerprints it, so it may only change through
// an owner-signed successor. The public leaf (config.TLS.CertPath) is what the
// public listener actually serves to store.<zone>; it is self-renewing through
// the estate's root ACME responder and must be able to rotate WITHOUT touching
// the identity binding. This file owns both sides of that split:
//
//   - public-leaf-renew: an explicit subcommand that asks the estate's root
//     ACME responder (deploy-ui internal/acmeresponder, POST /v1/new-leaf)
//     for a fresh public leaf and publishes its pair through one symlink.
//     The Store generates the leaf's private key itself and sends only a CSR
//     for exactly its domain, signed with the Store's own Ed25519 challenge
//     delegation key, which the owner-signed provider edge profile pins as the
//     Store's estate-service delegation. The responder is pinned by its TLS
//     SPKI and returns the chain only; no bearer token and no private key ever
//     cross the wire (V-STEP4-STORE). The running Store never renews by
//     itself: its servedTLSCertificate watcher (served_tls.go) picks the new
//     pair up on its next tick, which is the hot reload. The watcher's
//     identity pin applies to the boot-identity leaf ONLY — a renewed public
//     pair is deliberately never pinned.
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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
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

	publicLeafRenewRefused            = "public-leaf-renew-responder-refused"
	publicLeafRenewInvalid            = "public-leaf-renew-invalid-leaf"
	publicLeafRenewTLSDiver           = "public-leaf-renew-tls-pair-refused"
	publicLeafRenewWrongKey           = "public-leaf-renew-leaf-not-for-store-key"
	publicLeafRenewUntrusted          = "public-leaf-renew-chain-untrusted"
	publicLeafRenewDelegationUnsafe   = "public-leaf-renew-delegation-key-unsafe"
	publicLeafRenewResponderUnpinned  = "public-leaf-renew-responder-unpinned"
	publicLeafRenewResponderPinFailed = "public-leaf-renew-responder-pin-mismatch"
)

const (
	// The wire shared with deploy-ui internal/acmeresponder (leaf.go). The
	// field order of publicLeafRequest is part of the signed bytes.
	publicLeafRequestSchema  = "melusina-acme-leaf-request-v1"
	publicLeafResponseSchema = "melusina-acme-leaf-v1"
	publicLeafRequestTag     = "MELUSINA_ACME_LEAF_REQUEST_V1\n"
	publicLeafRoute          = "/v1/new-leaf"
	// A leaf holds the request open through the responder's staging order,
	// its production order and both authorization waits (15 minutes).
	publicLeafRequestTimeout = 17 * time.Minute
	publicLeafMaxChainBytes  = 64 << 10

	// The probe fetches exactly these routes through the public route; both
	// must answer for the probe to pass.
	storePublicProbePaths = "/healthz,/apps/index.json"
)

var (
	publicLeafDelegationIDPattern = regexp.MustCompile(`^acme-[a-z0-9-]{1,46}-[0-9a-f]{12}$`)
	publicLeafSPKIPattern         = regexp.MustCompile(`^spki-sha256:[0-9a-f]{64}$`)
)

// publicLeafRequest is the exact statement the Store signs.
type publicLeafRequest struct {
	Schema       string `json:"schema"`
	DelegationID string `json:"delegationId"`
	Domain       string `json:"domain"`
	CSR          string `json:"csr"`
	IssuedAt     string `json:"issuedAt"`
	Nonce        string `json:"nonce"`
}

type publicLeafSignedRequest struct {
	Request   publicLeafRequest `json:"request"`
	Signature string            `json:"signature"`
}

type publicLeafResponse struct {
	Schema   string `json:"schema"`
	Domain   string `json:"domain"`
	ChainPEM string `json:"chainPem"`
}

// publicLeafCanonicalBytes is byte for byte acmeresponder.LeafCanonicalBytes.
func publicLeafCanonicalBytes(request publicLeafRequest) ([]byte, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return append([]byte(publicLeafRequestTag), raw...), nil
}

// publicLeafRenewalOptions is deliberately closed: the responder endpoint and
// its SPKI pin, the delegation key file and ID, the domain and the output
// paths are rendered inputs, so a config file cannot quietly redirect the
// identity leaf's neighbor files.
type publicLeafRenewalOptions struct {
	configPath    string
	responderURL  string
	responderSPKI string
	delegationKey string
	delegationID  string
	domain        string
	certPath      string
	keyPath       string
	once          bool
	interval      time.Duration
	// roots verifies the issued chain; nil is the system roots. Only tests
	// set it: no flag reaches it.
	roots *x509.CertPool
	now   func() time.Time
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
	fs.StringVar(&opts.responderURL, "acme-responder", "", "required https origin of the estate's root ACME responder")
	fs.StringVar(&opts.responderSPKI, "acme-responder-spki", "", "required spki-sha256:<hex> pin of the responder's TLS key")
	fs.StringVar(&opts.delegationKey, "delegation-key", "", "required 0600 file holding the Store's Ed25519 leaf delegation seed")
	fs.StringVar(&opts.delegationID, "delegation-id", "", "required estate-service delegation ID the signed edge profile registers for the Store")
	fs.StringVar(&opts.domain, "domain", "", "public leaf domain (default: config domain)")
	fs.StringVar(&opts.certPath, "cert-path", "", "required public leaf cert path (tls.cert_path)")
	fs.StringVar(&opts.keyPath, "key-path", "", "required public leaf key path (tls.key_path)")
	fs.BoolVar(&opts.once, "once", false, "renew exactly once and exit (default: renew on an interval)")
	fs.DurationVar(&opts.interval, "interval", time.Hour, "renewal interval (only with renewals after the first)")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		log.Fatalf("public-leaf-renew: unexpected positional arguments: %v", fs.Args())
	}
	if strings.TrimSpace(opts.certPath) == "" || strings.TrimSpace(opts.keyPath) == "" {
		log.Fatalf("public-leaf-renew: --cert-path and --key-path are required")
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
	if err := validatePublicLeafRenewalOptions(opts); err != nil {
		log.Fatalf("public-leaf-renew: %v", err)
	}
	if err := renewPublicLeafLoop(opts); err != nil {
		log.Fatalf("public-leaf-renew: %v", err)
	}
}

// validatePublicLeafRenewalOptions refuses an unpinned or non-https
// responder, a malformed delegation ID and a non-absolute key path by name.
func validatePublicLeafRenewalOptions(opts publicLeafRenewalOptions) error {
	endpoint, err := url.Parse(opts.responderURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" ||
		endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return fmt.Errorf("%s: --acme-responder must be the responder's https origin", publicLeafRenewResponderUnpinned)
	}
	if !publicLeafSPKIPattern.MatchString(opts.responderSPKI) {
		return fmt.Errorf("%s: --acme-responder-spki must be spki-sha256:<64 hex>", publicLeafRenewResponderUnpinned)
	}
	if !publicLeafDelegationIDPattern.MatchString(opts.delegationID) {
		return fmt.Errorf("%s: --delegation-id is not an estate-service delegation ID", publicLeafRenewDelegationUnsafe)
	}
	if !filepath.IsAbs(opts.delegationKey) || filepath.Clean(opts.delegationKey) != opts.delegationKey {
		return fmt.Errorf("%s: --delegation-key must be an absolute clean path", publicLeafRenewDelegationUnsafe)
	}
	return nil
}

// publicLeafResponderClient trusts exactly the responder's pinned TLS key:
// the responder serves a self-issued certificate for acme.<zone> from its
// journaled responder-tls identity, and the owner-signed profile pins that
// key, so the pin (with the leaf's name and validity) is the trust anchor.
func publicLeafResponderClient(responderURL, pin string) *http.Client {
	endpoint, _ := url.Parse(responderURL)
	hostname := endpoint.Hostname()
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: hostname, InsecureSkipVerify: true,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return fmt.Errorf("%s: the responder presented no certificate", publicLeafRenewResponderPinFailed)
				}
				leaf := state.PeerCertificates[0]
				now := time.Now()
				if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) || leaf.VerifyHostname(hostname) != nil {
					return fmt.Errorf("%s: the responder certificate is not valid for %s", publicLeafRenewResponderPinFailed, hostname)
				}
				sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
				if subtle.ConstantTimeCompare([]byte("spki-sha256:"+hex.EncodeToString(sum[:])), []byte(pin)) != 1 {
					return fmt.Errorf("%s: the responder key differs from the pinned key", publicLeafRenewResponderPinFailed)
				}
				return nil
			}},
	}
	return &http.Client{Timeout: publicLeafRequestTimeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("public-leaf-renew never follows a responder redirect")
	}}
}

// renewPublicLeafLoop renews once (--once), or checks on the interval and
// renews only when the published leaf is absent, for another name, or in the
// last third of its lifetime: every order spends the responder's daily leaf
// budget and the estate's production CA budget. Each renewal publishes the
// pair atomically; the running Store's served TLS watcher reloads it without
// a restart.
func renewPublicLeafLoop(opts publicLeafRenewalOptions) error {
	client := publicLeafResponderClient(opts.responderURL, opts.responderSPKI)
	for {
		if opts.once || publicLeafRenewalDue(opts.certPath, opts.keyPath, opts.domain, time.Now()) {
			notAfter, err := renewPublicLeaf(opts, client)
			if err != nil {
				return err
			}
			log.Printf("public-leaf-renew: published public leaf for %s, not after %s; the running Store reloads it from %s", opts.domain, notAfter.UTC().Format(time.RFC3339), opts.certPath)
		}
		if opts.once {
			return nil
		}
		time.Sleep(opts.interval)
	}
}

// publicLeafRenewalDue is true when the published pair is unreadable or does
// not match, names another host, or has less than a third of its lifetime left.
func publicLeafRenewalDue(certPath, keyPath, domain string, now time.Time) bool {
	certPEM, keyPEM, err := readServedTLSFiles(certPath, keyPath)
	if err != nil {
		return true
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return true
	}
	leaf, err := parsePublicLeafCert(certPEM)
	if err != nil || leaf.VerifyHostname(domain) != nil {
		return true
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	return lifetime <= 0 || leaf.NotAfter.Sub(now) < lifetime/3
}

// renewPublicLeaf generates a fresh P-256 key, asks the root responder for a
// leaf for exactly the public domain with a CSR signed by the Store's
// delegation key, and writes the pair to the public paths. The chain must be
// for the Store's own key, name exactly the domain, be currently valid and
// verify to the trusted roots, or it is refused by name and the previous pair
// stays in place.
func renewPublicLeaf(opts publicLeafRenewalOptions, client *http.Client) (time.Time, error) {
	now := time.Now
	if opts.now != nil {
		now = opts.now
	}
	if err := validatePublicLeafRenewalOptions(opts); err != nil {
		return time.Time{}, err
	}
	delegation, err := loadPublicLeafDelegationKey(opts.delegationKey)
	if err != nil {
		return time.Time{}, err
	}
	defer clear(delegation)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return time.Time{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: opts.domain}, DNSNames: []string{opts.domain}}, key)
	if err != nil {
		return time.Time{}, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return time.Time{}, err
	}
	request := publicLeafRequest{Schema: publicLeafRequestSchema, DelegationID: opts.delegationID, Domain: opts.domain,
		CSR: base64.RawURLEncoding.EncodeToString(csr), IssuedAt: now().UTC().Truncate(time.Second).Format(time.RFC3339),
		Nonce: base64.RawURLEncoding.EncodeToString(nonce)}
	message, err := publicLeafCanonicalBytes(request)
	if err != nil {
		return time.Time{}, err
	}
	body, err := json.Marshal(publicLeafSignedRequest{Request: request, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(delegation, message))})
	if err != nil {
		return time.Time{}, err
	}
	httpRequest, err := http.NewRequest(http.MethodPost, strings.TrimRight(opts.responderURL, "/")+publicLeafRoute, bytes.NewReader(body))
	if err != nil {
		return time.Time{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := client.Do(httpRequest)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", publicLeafRenewRefused, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, publicLeafMaxChainBytes+4096))
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", publicLeafRenewRefused, err)
	}
	if response.StatusCode != http.StatusOK {
		return time.Time{}, fmt.Errorf("%s: responder answered %d: %s", publicLeafRenewRefused, response.StatusCode, strings.TrimSpace(string(raw)))
	}
	var leafResponse publicLeafResponse
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&leafResponse); err != nil || decoder.Decode(new(any)) != io.EOF {
		return time.Time{}, fmt.Errorf("%s: responder did not return one exact leaf response", publicLeafRenewInvalid)
	}
	if leafResponse.Schema != publicLeafResponseSchema || leafResponse.Domain != opts.domain || strings.Contains(leafResponse.ChainPEM, "PRIVATE KEY") {
		return time.Time{}, fmt.Errorf("%s: schema %q domain %q", publicLeafRenewInvalid, leafResponse.Schema, leafResponse.Domain)
	}
	leaf, err := verifyPublicLeafChain([]byte(leafResponse.ChainPEM), opts.domain, &key.PublicKey, opts.roots, now())
	if err != nil {
		return time.Time{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return time.Time{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	defer clear(keyPEM)
	if _, err := tls.X509KeyPair([]byte(leafResponse.ChainPEM), keyPEM); err != nil {
		return time.Time{}, fmt.Errorf("%s: %v", publicLeafRenewTLSDiver, err)
	}
	if err := publishPublicLeafPair(opts.certPath, opts.keyPath, []byte(leafResponse.ChainPEM), keyPEM); err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

// verifyPublicLeafChain requires a PEM chain of certificates only, leaf
// first with at least one intermediate, whose leaf names exactly domain, is
// for the Store's key, is valid now and verifies to roots (system when nil).
func verifyPublicLeafChain(chainPEM []byte, domain string, storeKey *ecdsa.PublicKey, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(chainPEM) == 0 || len(chainPEM) > publicLeafMaxChainBytes {
		return nil, fmt.Errorf("%s: the chain is empty or oversized", publicLeafRenewInvalid)
	}
	var certificates []*x509.Certificate
	for rest := chainPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, fmt.Errorf("%s: the chain has trailing data", publicLeafRenewInvalid)
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s: the chain holds a non-certificate block", publicLeafRenewInvalid)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", publicLeafRenewInvalid, err)
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) < 2 {
		return nil, fmt.Errorf("%s: the chain has no intermediate", publicLeafRenewInvalid)
	}
	leaf := certificates[0]
	leafKey, leafErr := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	ownKey, ownErr := x509.MarshalPKIXPublicKey(storeKey)
	if leafErr != nil || ownErr != nil || !bytes.Equal(leafKey, ownKey) {
		return nil, fmt.Errorf("%s: the leaf is not for the key this Store generated", publicLeafRenewWrongKey)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != domain || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || len(leaf.EmailAddresses) != 0 {
		return nil, fmt.Errorf("%s: the leaf does not name exactly %s", publicLeafRenewInvalid, domain)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("%s: leaf not valid now (not before %s, not after %s)", publicLeafRenewInvalid, leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: domain, Intermediates: intermediates, Roots: roots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, fmt.Errorf("%s: %v", publicLeafRenewUntrusted, err)
	}
	return leaf, nil
}

// loadPublicLeafDelegationKey reads the Store's 32-byte Ed25519 delegation
// seed from a private (0600) regular file, never following a symlink.
func loadPublicLeafDelegationKey(path string) (ed25519.PrivateKey, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", publicLeafRenewDelegationUnsafe, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: the delegation key is not a private %d-byte seed file", publicLeafRenewDelegationUnsafe, ed25519.SeedSize)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(file, seed); err != nil {
		clear(seed)
		return nil, fmt.Errorf("%s: %v", publicLeafRenewDelegationUnsafe, err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	return key, nil
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
	return parsePublicLeafCert(raw)
}

func parsePublicLeafCert(raw []byte) (*x509.Certificate, error) {
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
	return nil, fmt.Errorf("no certificate leaf in public leaf PEM")
}
