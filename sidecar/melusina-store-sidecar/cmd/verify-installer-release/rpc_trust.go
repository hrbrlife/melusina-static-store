package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/storesecurity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The chain read this command makes is trusted only as far as the estate
// owners signed it. The RPC endpoint and the TLS keys it may present come
// from the owner-signed Store-host facts document (the same document the
// deployer verifies and the Store's renderer consumes), verified here under
// the pinned estate profile's owner policy and bound to that profile. Nothing
// else names an endpoint: the controller-shaped config may repeat the signed
// URL but never chooses one, an http:// endpoint is refused, the system CA
// pool is never consulted for this call, the cluster must be the profile's
// genesis, and every account read must be owned by the pinned program.

// Named refusals. Every error below starts with its check name.
var (
	errConfig              = errors.New("check=config")
	errRPCTrustAbsent      = errors.New("check=rpc_trust_absent")
	errRPCTrustInvalid     = errors.New("check=rpc_trust_invalid")
	errRPCTrustUnsigned    = errors.New("check=rpc_trust_unsigned")
	errRPCTrustForeign     = errors.New("check=rpc_trust_foreign_estate")
	errRPCEndpointUnsigned = errors.New("check=rpc_endpoint_unsigned")
	errRPCNotHTTPS         = errors.New("check=rpc_url_not_https")
	errRPCTLSPinAbsent     = errors.New("check=rpc_tls_pin_absent")
	errRPCTLSPin           = errors.New("check=rpc_tls_pin")
	errRPCGenesis          = errors.New("check=rpc_genesis")
	errAccountOwner        = errors.New("check=account_owner")
)

const (
	// storeHostFactsSchema and storeHostFactsDomain are the deployer's
	// melusina.store-host-facts.v1 document and its owner-signed digest
	// domain (deploy-ui/internal/storehost/facts.go StoreHostFactsDigest).
	// testdata/store-host-facts-digest-v1.json pins the digest; the deployer
	// carries a byte-identical copy and asserts the same vectors.
	storeHostFactsSchema = "melusina.store-host-facts.v1"
	storeHostFactsDomain = "MELUSINA_STORE_HOST_FACTS_V1\n"
	maxStoreHostFactsLen = 16 << 10

	// spkiPinPrefix names a pin as the SHA-256 of a certificate's
	// SubjectPublicKeyInfo, the form the deployer's signed rehearsal class and
	// estate-phase source already use.
	spkiPinPrefix = "spki-sha256:"
	maxRPCTLSPins = 4

	rpcRequestTimeout  = 10 * time.Second
	maxRPCResponseSize = 1 << 20
)

// signedStoreHostFacts mirrors the deployer's storehost.StoreHostFacts field
// for field, in the same order with the same JSON tags: its digest is
// sha256(storeHostFactsDomain || json.Marshal(facts without signatures)), so
// a field added, removed or reordered on one side only breaks the shared
// golden vector by name.
type signedStoreHostFacts struct {
	Schema                   string                      `json:"schema"`
	LicenseNFTMint           string                      `json:"licenseNftMint"`
	LicenseRegistryProgramID string                      `json:"licenseRegistryProgramId"`
	ChainID                  string                      `json:"chainId"`
	OperatorDomain           string                      `json:"operatorDomain"`
	RPCURL                   string                      `json:"rpcUrl,omitempty"`
	RPCFallbackURLs          []string                    `json:"rpcFallbackUrls,omitempty"`
	RPCAttempts              int                         `json:"rpcAttempts,omitempty"`
	RPCTLSSPKIPins           []string                    `json:"rpcTlsSpkiPins,omitempty"`
	SecurityProfile          storesecurity.Profile       `json:"securityProfile,omitempty"`
	ControlTLSBundlePath     string                      `json:"controlTlsBundlePath,omitempty"`
	Signatures               []estateprofile.SignatureV1 `json:"signatures,omitempty"`
}

// storeHostFactsPreimage is the exact byte string the owners sign the
// digest of: the facts as compact JSON with the signatures left out.
func storeHostFactsPreimage(facts signedStoreHostFacts) ([]byte, error) {
	facts.Signatures = nil
	return json.Marshal(facts)
}

func storeHostFactsDigest(facts signedStoreHostFacts) (string, error) {
	raw, err := storeHostFactsPreimage(facts)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(storeHostFactsDomain), raw...))
	return hex.EncodeToString(sum[:]), nil
}

// signedRPCTrust is what the owners signed for this command's chain read.
type signedRPCTrust struct {
	endpoint *url.URL
	pins     [][32]byte
}

func decodeStoreHostFacts(raw []byte) (signedStoreHostFacts, error) {
	var facts signedStoreHostFacts
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&facts); err != nil {
		return signedStoreHostFacts{}, fmt.Errorf("%w: %v", errRPCTrustInvalid, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return signedStoreHostFacts{}, fmt.Errorf("%w: trailing JSON after the facts document", errRPCTrustInvalid)
	}
	if facts.Schema != storeHostFactsSchema {
		return signedStoreHostFacts{}, fmt.Errorf("%w: schema %q is not %s", errRPCTrustInvalid, facts.Schema, storeHostFactsSchema)
	}
	return facts, nil
}

// loadSignedRPCTrust reads the owner-signed Store-host facts at path and
// returns the RPC endpoint and TLS pins they sign, after requiring a threshold
// of the pinned profile's current owners over their digest and the facts'
// binding to this estate profile, Store, registry and network.
func loadSignedRPCTrust(path string, profile estateprofile.EstateProfileV1, profileSHA256, programID string) (signedRPCTrust, error) {
	var none signedRPCTrust
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return none, fmt.Errorf("%w: storeHostFactsPath must name the owner-signed Store-host facts by an absolute clean path", errRPCTrustAbsent)
	}
	raw, err := readRegularNoFollow(path, maxStoreHostFactsLen)
	if err != nil {
		return none, fmt.Errorf("%w: %v", errRPCTrustAbsent, err)
	}
	facts, err := decodeStoreHostFacts(raw)
	if err != nil {
		return none, err
	}
	digest, err := storeHostFactsDigest(facts)
	if err != nil {
		return none, fmt.Errorf("%w: %v", errRPCTrustInvalid, err)
	}
	if err := estateprofile.VerifyOwnerThreshold(profile.OwnerPolicy, digest, facts.Signatures); err != nil {
		return none, fmt.Errorf("%w: the Store-host facts are not signed by the pinned profile's owner threshold: %v", errRPCTrustUnsigned, err)
	}
	if facts.SecurityProfile.EstateProfileSHA256 != profileSHA256 || facts.SecurityProfile.StoreID != profile.Store.StoreID ||
		facts.LicenseRegistryProgramID != programID || facts.ChainID != "solana:"+profile.Network.Label {
		return none, fmt.Errorf("%w: the signed facts bind another estate profile, Store, registry or network", errRPCTrustForeign)
	}
	endpoint, err := url.Parse(facts.RPCURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		endpoint.Opaque != "" || endpoint.Fragment != "" || endpoint.RawQuery != "" || endpoint.String() != facts.RPCURL {
		return none, fmt.Errorf("%w: the signed RPC endpoint %q is not a canonical https URL", errRPCNotHTTPS, facts.RPCURL)
	}
	if len(facts.RPCTLSSPKIPins) == 0 || len(facts.RPCTLSSPKIPins) > maxRPCTLSPins {
		return none, fmt.Errorf("%w: the signed facts must name 1..%d RPC TLS SPKI pins", errRPCTLSPinAbsent, maxRPCTLSPins)
	}
	pins := make([][32]byte, 0, len(facts.RPCTLSSPKIPins))
	seen := map[string]bool{}
	for _, pin := range facts.RPCTLSSPKIPins {
		encoded, ok := strings.CutPrefix(pin, spkiPinPrefix)
		decoded, decodeErr := hex.DecodeString(encoded)
		if !ok || decodeErr != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != encoded || seen[pin] {
			return none, fmt.Errorf("%w: RPC TLS pin %q is not a distinct %s<64 lowercase hex>", errRPCTLSPinAbsent, pin, spkiPinPrefix)
		}
		seen[pin] = true
		pins = append(pins, [32]byte(decoded))
	}
	return signedRPCTrust{endpoint: endpoint, pins: pins}, nil
}

// verifyPinnedChain admits a served chain only when it verifies, for host
// and at now, to a certificate whose SubjectPublicKeyInfo the owners pinned:
// the leaf itself or an issuing CA the server presents. The pinned
// certificate is the only root; the system pool is never used.
func verifyPinnedChain(chain []*x509.Certificate, host string, pins [][32]byte, now time.Time) error {
	if len(chain) == 0 {
		return fmt.Errorf("%w: the RPC endpoint presented no certificate", errRPCTLSPin)
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range chain[1:] {
		intermediates.AddCert(certificate)
	}
	for _, candidate := range chain {
		sum := sha256.Sum256(candidate.RawSubjectPublicKeyInfo)
		pinned := false
		for _, pin := range pins {
			if pin == sum {
				pinned = true
			}
		}
		if !pinned {
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(candidate)
		if _, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates,
			CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: the RPC endpoint's certificate chain does not verify for %s to a key the owners pinned", errRPCTLSPin, host)
}

// pinnedRPC is the only HTTP client this command reads the chain with. It
// remembers a TLS pin refusal so the command reports it by name even when
// the HTTP stack flattens the handshake error.
type pinnedRPC struct {
	endpoint string
	client   *http.Client
	mu       sync.Mutex
	refusal  error
}

func newPinnedRPC(trust signedRPCTrust, now func() time.Time) *pinnedRPC {
	rpc := &pinnedRPC{endpoint: trust.endpoint.String()}
	host := trust.endpoint.Hostname()
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: host,
		// The default verifier would trust the system CA pool. It is turned
		// off only so VerifyConnection can admit the owner-pinned chain and
		// nothing else; RootCAs is never set.
		InsecureSkipVerify: true,
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		err := verifyPinnedChain(state.PeerCertificates, host, trust.pins, now())
		if err != nil {
			rpc.mu.Lock()
			rpc.refusal = err
			rpc.mu.Unlock()
		}
		return err
	}
	rpc.client = &http.Client{
		Timeout: rpcRequestTimeout,
		Transport: &http.Transport{
			Proxy:                  nil,
			TLSClientConfig:        config,
			TLSHandshakeTimeout:    rpcRequestTimeout,
			ResponseHeaderTimeout:  rpcRequestTimeout,
			MaxResponseHeaderBytes: 64 << 10,
			DisableCompression:     true,
		},
		// A redirect would name an endpoint the owners did not sign.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return rpc
}

// classify leads with the recorded pin refusal when the handshake was
// refused by name, whatever the HTTP stack wrapped around it.
func (rpc *pinnedRPC) classify(err error) error {
	rpc.mu.Lock()
	defer rpc.mu.Unlock()
	if rpc.refusal != nil {
		return fmt.Errorf("%w (%v)", rpc.refusal, err)
	}
	return err
}

// fetchGenesisHash reads the cluster identity over the pinned client.
func (rpc *pinnedRPC) fetchGenesisHash(ctx context.Context) (string, error) {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "getGenesisHash", "params": []any{}})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, rpc.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := rpc.client.Do(request)
	if err != nil {
		return "", rpc.classify(fmt.Errorf("getGenesisHash: %w", err))
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxRPCResponseSize+1))
	if err != nil || len(raw) > maxRPCResponseSize || response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: getGenesisHash answered HTTP %d", errRPCGenesis, response.StatusCode)
	}
	var parsed struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.Error != nil {
		return "", fmt.Errorf("%w: getGenesisHash returned no result", errRPCGenesis)
	}
	genesis, err := primitives.PubkeyFromBase58(parsed.Result)
	if err != nil || genesis.Base58() != parsed.Result {
		return "", fmt.Errorf("%w: getGenesisHash returned a malformed hash", errRPCGenesis)
	}
	return parsed.Result, nil
}

// requireProfileGenesis compares the cluster the pinned endpoint serves with
// the network the signed profile names, before any account is read.
func requireProfileGenesis(ctx context.Context, rpc *pinnedRPC, profile estateprofile.EstateProfileV1) error {
	observed, err := rpc.fetchGenesisHash(ctx)
	if err != nil {
		return err
	}
	if err := estateprofile.RequireGenesis(profile, observed); err != nil {
		return fmt.Errorf("%w: the RPC endpoint serves genesis %s, the signed profile names %s: %v", errRPCGenesis,
			observed, profile.Network.GenesisHash, err)
	}
	return nil
}

// readRegularNoFollow reads a bounded regular file without following a link.
func readRegularNoFollow(path string, limit int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > limit {
		return nil, fmt.Errorf("empty or larger than %d bytes", limit)
	}
	return raw, nil
}
