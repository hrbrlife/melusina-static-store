package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ── the shared facts digest: the deployer signs it, this command verifies it ──

type factsDigestVector struct {
	Name     string          `json:"name"`
	Facts    json.RawMessage `json:"facts"`
	Preimage string          `json:"preimage"`
	Digest   string          `json:"digest"`
}

type factsDigestVectorFile struct {
	Schema     string              `json:"schema"`
	Notes      []string            `json:"notes"`
	Domain     string              `json:"domain"`
	FieldOrder []string            `json:"fieldOrder"`
	Vectors    []factsDigestVector `json:"vectors"`
}

// TestStoreHostFactsDigestGoldenVectors pins the digest the owners sign to
// the deployer's: testdata/store-host-facts-digest-v1.json is carried byte
// for byte by deploy-ui/internal/storehost/testdata and asserted there by
// TestStoreHostFactsDigestMatchesTheStoreVectors.
func TestStoreHostFactsDigestGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/store-host-facts-digest-v1.json")
	if err != nil {
		t.Fatalf("STORE_HOST_FACTS_DIGEST_VECTORS_ABSENT: %v", err)
	}
	var file factsDigestVectorFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil || file.Schema != "melusina.store-host-facts-digest-vectors.v1" ||
		file.Domain != storeHostFactsDomain || len(file.Vectors) < 2 {
		t.Fatalf("STORE_HOST_FACTS_DIGEST_VECTORS_MALFORMED: %v %q", err, file.Schema)
	}
	var order []string
	kind := reflect.TypeOf(signedStoreHostFacts{})
	for index := 0; index < kind.NumField(); index++ {
		order = append(order, strings.Split(kind.Field(index).Tag.Get("json"), ",")[0])
	}
	if !reflect.DeepEqual(order, file.FieldOrder) {
		t.Fatalf("STORE_HOST_FACTS_STRUCT_ORDER_DRIFT: mirror %v, vectors %v", order, file.FieldOrder)
	}
	pinned := false
	for _, vector := range file.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			sum := sha256.Sum256(append([]byte(file.Domain), vector.Preimage...))
			if hex.EncodeToString(sum[:]) != vector.Digest {
				t.Fatalf("STORE_HOST_FACTS_VECTOR_INCONSISTENT: %x != %s", sum, vector.Digest)
			}
			facts, err := decodeStoreHostFacts(vector.Facts)
			if err != nil {
				t.Fatalf("STORE_HOST_FACTS_VECTOR_REFUSED: %v", err)
			}
			if len(facts.Signatures) == 0 {
				t.Fatal("STORE_HOST_FACTS_VECTOR_UNSIGNED: the vector must prove signatures are excluded")
			}
			preimage, err := storeHostFactsPreimage(facts)
			if err != nil || string(preimage) != vector.Preimage {
				t.Fatalf("STORE_HOST_FACTS_PREIMAGE_DRIFT: %v\n got  %s\n want %s", err, preimage, vector.Preimage)
			}
			digest, err := storeHostFactsDigest(facts)
			if err != nil || digest != vector.Digest {
				t.Fatalf("STORE_HOST_FACTS_DIGEST_DRIFT: %v got %s want %s", err, digest, vector.Digest)
			}
			if len(facts.RPCTLSSPKIPins) > 0 {
				pinned = true
			}
		})
	}
	if !pinned {
		t.Fatal("STORE_HOST_FACTS_VECTORS_LACK_PINS: no vector carries rpcTlsSpkiPins")
	}
	// Control on the control: a changed fact moves the digest.
	facts, _ := decodeStoreHostFacts(file.Vectors[0].Facts)
	facts.RPCURL = "https://10.77.0.9:8899"
	if digest, _ := storeHostFactsDigest(facts); digest == file.Vectors[0].Digest {
		t.Fatal("STORE_HOST_FACTS_FIELD_NOT_BOUND: rpcUrl is not in the signed digest")
	}
	facts, _ = decodeStoreHostFacts(file.Vectors[0].Facts)
	facts.RPCTLSSPKIPins = facts.RPCTLSSPKIPins[:1]
	if digest, _ := storeHostFactsDigest(facts); digest == file.Vectors[0].Digest {
		t.Fatal("STORE_HOST_FACTS_FIELD_NOT_BOUND: rpcTlsSpkiPins is not in the signed digest")
	}
	if _, err := decodeStoreHostFacts(bytes.Replace(file.Vectors[0].Facts, []byte(`"schema":`), []byte(`"rpcCa":"x","schema":`), 1)); !errors.Is(err, errRPCTrustInvalid) {
		t.Fatalf("STORE_HOST_FACTS_UNKNOWN_FIELD_ACCEPTED: %v", err)
	}
}

// ── the pinned chain verifier, against a real CA hierarchy ──

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func testKeyPair(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func issue(t *testing.T, template *x509.Certificate, key *ecdsa.PrivateKey, parent *testCert) testCert {
	t.Helper()
	signerCert, signerKey := template, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCert{cert: cert, key: key}
}

func caTemplate(name string, serial int64, now time.Time) *x509.Certificate {
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
}

func leafTemplate(host string, serial int64, now time.Time) *x509.Certificate {
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	return template
}

func pinOf(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

func TestVerifyPinnedChainAdmitsOnlyAChainToAnOwnerPinnedKey(t *testing.T) {
	now := time.Now()
	host := "rpc.estate.invalid"
	ca := issue(t, caTemplate("estate rpc issuer", 1, now), testKeyPair(t), nil)
	leaf := issue(t, leafTemplate(host, 2, now), testKeyPair(t), &ca)
	rogueCA := issue(t, caTemplate("estate rpc issuer", 3, now), testKeyPair(t), nil)
	rogueLeaf := issue(t, leafTemplate(host, 4, now), testKeyPair(t), &rogueCA)
	chain := []*x509.Certificate{leaf.cert, ca.cert}

	// Positive controls: the issuer key pinned, the leaf key pinned.
	if err := verifyPinnedChain(chain, host, [][32]byte{pinOf(ca.cert)}, now); err != nil {
		t.Fatalf("RPC_PINNED_ISSUER_REFUSED: %v", err)
	}
	if err := verifyPinnedChain(chain[:1], host, [][32]byte{pinOf(leaf.cert)}, now); err != nil {
		t.Fatalf("RPC_PINNED_LEAF_REFUSED: %v", err)
	}
	refused := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, errRPCTLSPin) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	other := sha256.Sum256([]byte("verify-installer-release-test/other-key"))
	refused("RPC_TLS_UNPINNED_CHAIN_ACCEPTED", verifyPinnedChain(chain, host, [][32]byte{other}, now))
	refused("RPC_TLS_EMPTY_PIN_SET_ACCEPTED", verifyPinnedChain(chain, host, nil, now))
	refused("RPC_TLS_NO_CERTIFICATE_ACCEPTED", verifyPinnedChain(nil, host, [][32]byte{pinOf(ca.cert)}, now))
	// The pinned issuer must be presented and must have signed the leaf: a
	// rogue leaf presented beside the genuine (public) issuer certificate
	// does not verify to it.
	refused("RPC_TLS_ROGUE_LEAF_BESIDE_PINNED_ISSUER_ACCEPTED",
		verifyPinnedChain([]*x509.Certificate{rogueLeaf.cert, ca.cert}, host, [][32]byte{pinOf(ca.cert)}, now))
	refused("RPC_TLS_PINNED_ISSUER_NOT_PRESENTED_ACCEPTED",
		verifyPinnedChain(chain[:1], host, [][32]byte{pinOf(ca.cert)}, now))
	refused("RPC_TLS_OTHER_HOST_ACCEPTED",
		verifyPinnedChain(chain, "other.estate.invalid", [][32]byte{pinOf(ca.cert)}, now))
	refused("RPC_TLS_EXPIRED_LEAF_ACCEPTED",
		verifyPinnedChain(chain, host, [][32]byte{pinOf(ca.cert)}, now.Add(13*time.Hour)))
	refused("RPC_TLS_NOT_YET_VALID_LEAF_ACCEPTED",
		verifyPinnedChain(chain, host, [][32]byte{pinOf(ca.cert)}, now.Add(-2*time.Hour)))
	// An IP-addressed rehearsal RPC is checked against its IP SAN.
	ipLeaf := issue(t, leafTemplate("10.77.0.1", 5, now), testKeyPair(t), &ca)
	if err := verifyPinnedChain([]*x509.Certificate{ipLeaf.cert, ca.cert}, "10.77.0.1", [][32]byte{pinOf(ca.cert)}, now); err != nil {
		t.Fatalf("RPC_PINNED_IP_ENDPOINT_REFUSED: %v", err)
	}
	refused("RPC_TLS_OTHER_IP_ACCEPTED",
		verifyPinnedChain([]*x509.Certificate{ipLeaf.cert, ca.cert}, "10.77.0.2", [][32]byte{pinOf(ca.cert)}, now))
}

// The client never trusts the system pool and never follows a redirect.
func TestPinnedRPCClientHasNoSystemTrust(t *testing.T) {
	endpoint, err := url.Parse("https://10.77.0.1:8899")
	if err != nil {
		t.Fatal(err)
	}
	rpc := newPinnedRPC(signedRPCTrust{endpoint: endpoint, pins: [][32]byte{{1}}}, time.Now)
	transport, ok := rpc.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("RPC_CLIENT_TRANSPORT_NOT_PINNED: %T", rpc.client.Transport)
	}
	config := transport.TLSClientConfig
	if config == nil || config.RootCAs != nil || !config.InsecureSkipVerify || config.VerifyConnection == nil ||
		config.ServerName != "10.77.0.1" || transport.Proxy != nil || rpc.client.CheckRedirect == nil {
		t.Fatal("RPC_CLIENT_SYSTEM_TRUST_REACHABLE: the chain-read client must verify only through the owner pins")
	}
}
