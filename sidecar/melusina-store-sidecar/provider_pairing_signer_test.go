package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
)

// providerPairingVectorFile is the shared V2 vector table. The deployer
// carries the same literal bytes and checks them with its own builder
// (installengine.ProviderOperatorInventoryAttestationMessage) and verifier;
// neither repository imports the other.
const providerPairingVectorFile = "testdata/provider-operator-attestation-v2-vectors.json"

// providerPairingFixture holds TEST-ONLY keys derived from public labels. None
// of them is, or may become, an estate key.
type providerPairingFixture struct {
	operator         *identity.Private
	operatorKeyID    string
	receiptKeyID     string // the provider host's dedicated receipt identity
	targetAgentKeyID string // the target agent: the delegated inventory signer
	otherKeyID       string
}

func providerPairingTestSeed(label string) [32]byte {
	return sha256.Sum256([]byte("melusina-store provider-pairing-signer TEST-ONLY seed: " + label))
}

func providerPairingTestKeyID(label string) string {
	seed := providerPairingTestSeed(label)
	return pairingEd25519KeyID(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
}

func newProviderPairingFixture(t *testing.T) providerPairingFixture {
	t.Helper()
	ref := identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     "solana:estate-test",
		ProgramID:   "11111111111111111111111111111111",
		LicenseMint: "11111111111111111111111111111111",
		Domain:      "store.estate.test",
		PDA:         "11111111111111111111111111111111",
		SidecarID:   "store",
		KeyVersion:  1,
	}
	operator, err := identity.NewPrivate(ref, providerPairingTestSeed("store-operator"), providerPairingTestSeed("store-operator-box"))
	if err != nil {
		t.Fatal(err)
	}
	operatorKeyID, err := storeOperatorPairingKeyID(operator)
	if err != nil {
		t.Fatal(err)
	}
	return providerPairingFixture{
		operator:         operator,
		operatorKeyID:    operatorKeyID,
		receiptKeyID:     providerPairingTestKeyID("provider-host-receipt-identity"),
		targetAgentKeyID: providerPairingTestKeyID("target-agent-identity"),
		otherKeyID:       providerPairingTestKeyID("unrelated-key"),
	}
}

func sha256HexForPairingTest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type providerPairingVectorRequest struct {
	name    string
	request string
}

// providerPairingVectorRequests are hand-written requests, deliberately not in
// the canonical key order and with free whitespace, so the vectors prove the
// Store's canonical provider bytes rather than restate them.
func providerPairingVectorRequests(fx providerPairingFixture) []providerPairingVectorRequest {
	return []providerPairingVectorRequest{
		{name: "edge-minimal", request: fmt.Sprintf(`{
  "delegatedInventorySigner": %[2]q,
  "provider": {
    "trustPin": "wg-pubkey:q0hzYv6xHq4xXk5o7i2gE8V4kP1Ubf3mD0tA9cLr2Ws=",
    "inventorySigner": %[2]q,
    "receiptSigner": %[1]q,
    "identity": "edge@edge.estate.test",
    "ownership": "shared-provider",
    "kind": "edge",
    "id": "edge"
  },
  "targetAgentIdentity": %[2]q,
  "targetIdentity": "target:estate-test-host",
  "kind": "provider-operator-inventory-attestation-v2",
  "schema": "melusina-store-provider-pairing-signer-v1"
}`, fx.receiptKeyID, fx.targetAgentKeyID)},
		{name: "edge-with-handoff", request: fmt.Sprintf(`{
  "schema": "melusina-store-provider-pairing-signer-v1",
  "kind": "provider-operator-inventory-attestation-v2",
  "targetIdentity": "target:estate-test-host",
  "targetAgentIdentity": %[2]q,
  "delegatedInventorySigner": %[2]q,
  "provider": {
    "id": "edge",
    "kind": "edge",
    "ownership": "shared-provider",
    "identity": "edge@edge.estate.test",
    "endpoint": "wg://edge.estate.test:51820",
    "trustPin": "wg-pubkey:q0hzYv6xHq4xXk5o7i2gE8V4kP1Ubf3mD0tA9cLr2Ws=",
    "receiptSigner": %[1]q,
    "inventorySigner": %[2]q,
    "control": {
      "ownershipHandoff": {
        "desiredUnitState": "masked",
        "desiredActiveState": "inactive",
        "initialUnitState": "enabled",
        "initialActiveState": "active",
        "managedFiles": [{"sha256": "3333333333333333333333333333333333333333333333333333333333333333", "path": "/etc/nginx/nginx.conf", "mode": 420}],
        "dropIns": [],
        "archivedUnitPath": "/var/lib/melusina/provider/archive/nginx.service",
        "unitFile": {"mode": 420, "path": "/lib/systemd/system/nginx.service", "sha256": "2222222222222222222222222222222222222222222222222222222222222222"},
        "legacyService": "nginx.service",
        "contractGeneration": "1",
        "providerIdentity": "edge@edge.estate.test",
        "providerRef": "provider/edge",
        "schema": "melusina-provider-ownership-handoff-v1"
      }
    }
  }
}`, fx.receiptKeyID, fx.targetAgentKeyID)},
		{name: "dns-with-control", request: fmt.Sprintf(`{
  "schema": "melusina-store-provider-pairing-signer-v1",
  "kind": "provider-operator-inventory-attestation-v2",
  "targetIdentity": "target:estate-test-host",
  "targetAgentIdentity": %[2]q,
  "delegatedInventorySigner": %[2]q,
  "provider": {
    "id": "dns",
    "description": "Shared DNS for estate.test & its tenants <rehearsal>",
    "acmeResponder": {
      "challengeZone": "_acme.estate.test",
      "tlsSpkiSha256": "4444444444444444444444444444444444444444444444444444444444444444",
      "endpoint": "https://acme.estate.test:8453",
      "providerIdentity": "dns@ns1.estate.test",
      "providerRef": "provider/dns",
      "schema": "melusina-provider-acme-responder-v1"
    },
    "control": {
      "rfc2136Policy": {
        "dnssecSigning": true,
        "acmeChallengeZone": "_acme.estate.test",
        "acmeResponderKeyPath": "/etc/bind/keys/acme-responder.key",
        "acmeResponderKeyName": "acme-responder.estate.test.",
        "keyFileMode": 384,
        "legacyAcmeRecordType": "TXT",
        "legacyAcmeKeyName": "",
        "allowedRecordTypes": ["A", "CNAME", "MX", "TXT"],
        "policySha256": "5555555555555555555555555555555555555555555555555555555555555555",
        "namedConfigAfterSha256": "6666666666666666666666666666666666666666666666666666666666666666",
        "namedConfigBefore": {"mode": 420, "sha256": "7777777777777777777777777777777777777777777777777777777777777777", "path": "/etc/bind/named.conf.local"},
        "namedConfigPath": "/etc/bind/named.conf.local",
        "policyPath": "/etc/bind/melusina-update-policy.conf",
        "keyPath": "/etc/bind/keys/tenant-update.key",
        "keyAlgorithm": "hmac-sha256",
        "keyName": "tenant-update.estate.test.",
        "nameservers": ["ns1.estate.test."],
        "zone": "estate.test.",
        "contractGeneration": "1",
        "providerIdentity": "dns@ns1.estate.test",
        "providerRef": "provider/dns",
        "schema": "melusina-provider-rfc2136-policy-v1"
      }
    },
    "inventorySigner": %[2]q,
    "receiptSigner": %[1]q,
    "trustPin": "dns-authority:ns1.estate.test",
    "identity": "dns@ns1.estate.test",
    "ownership": "shared-provider",
    "kind": "dns"
  }
}`, fx.receiptKeyID, fx.targetAgentKeyID)},
		{name: "mail-relay-shared", request: fmt.Sprintf(`{
  "schema": "melusina-store-provider-pairing-signer-v1",
  "kind": "provider-operator-inventory-attestation-v2",
  "targetIdentity": "target:estate-test-host",
  "targetAgentIdentity": %[2]q,
  "delegatedInventorySigner": %[2]q,
  "provider": {
    "mailRelay": {
      "fcrdnsObservedAt": "2026-09-24T00:00:00Z",
      "hourlyMessageLimit": 200,
      "baseContractSha256": "8888888888888888888888888888888888888888888888888888888888888888",
      "tlsSpkiSha256": "9999999999999999999999999999999999999999999999999999999999999999",
      "submissionPort": 587,
      "submissionAddress": "10.77.0.1",
      "egressIpv4": "192.0.2.25",
      "hostname": "relay.estate.test",
      "providerIdentity": "mail@relay.estate.test",
      "providerRef": "provider/mail",
      "schema": "melusina-provider-mail-relay-v1"
    },
    "mxCertificate": {
      "delegationPublicKey": %[3]q,
      "providerIdentity": "mail@relay.estate.test",
      "providerRef": "provider/mail",
      "schema": "melusina-provider-mx-certificate-v1"
    },
    "credentialRef": "secret://provider/mail/relay",
    "inventorySigner": %[2]q,
    "receiptSigner": %[1]q,
    "trustPin": "spki-sha256:9999999999999999999999999999999999999999999999999999999999999999",
    "identity": "mail@relay.estate.test",
    "ownership": "shared-provider",
    "kind": "mail",
    "id": "mail"
  }
}`, fx.receiptKeyID, fx.targetAgentKeyID, fx.otherKeyID)},
	}
}

type providerPairingVectorTable struct {
	Schema                string `json:"schema"`
	Note                  string `json:"note"`
	DeployerSource        string `json:"deployerSource"`
	OperatorKeyID         string `json:"operatorKeyId"`
	OperatorSignPubkeyB58 string `json:"operatorSignPubkeyB58"`
	ReceiptSigner         string `json:"receiptSigner"`
	TargetAgentIdentity   string `json:"targetAgentIdentity"`
	Vectors               []struct {
		Name              string                             `json:"name"`
		Request           json.RawMessage                    `json:"request"`
		CanonicalProvider string                             `json:"canonicalProvider"`
		ProviderDigest    string                             `json:"providerDigest"`
		Message           string                             `json:"message"`
		MessageSHA256     string                             `json:"messageSha256"`
		Attestation       providerOperatorPairingAttestation `json:"attestation"`
	} `json:"vectors"`
}

func loadProviderPairingVectors(t *testing.T) providerPairingVectorTable {
	t.Helper()
	raw, err := os.ReadFile(providerPairingVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var table providerPairingVectorTable
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&table); err != nil {
		t.Fatalf("decode %s: %v", providerPairingVectorFile, err)
	}
	if len(table.Vectors) == 0 {
		t.Fatalf("%s holds no vectors", providerPairingVectorFile)
	}
	return table
}

// The Store's builder reproduces every literal vector byte for byte from the
// hand-written request, and the signer's deterministic Ed25519 signature over
// those bytes is the literal one. The table's requests are the fixture's, so a
// changed request cannot silently regenerate the table.
func TestProviderPairingV2VectorsReproduceByteForByte(t *testing.T) {
	fx := newProviderPairingFixture(t)
	table := loadProviderPairingVectors(t)
	if table.OperatorKeyID != fx.operatorKeyID || table.OperatorSignPubkeyB58 != fx.operator.Public().SignPubkeyB58 ||
		table.ReceiptSigner != fx.receiptKeyID || table.TargetAgentIdentity != fx.targetAgentKeyID {
		t.Fatalf("vector table keys differ from the fixture's test-only keys")
	}
	requests := providerPairingVectorRequests(fx)
	if len(requests) != len(table.Vectors) {
		t.Fatalf("vector table has %d vectors, fixture has %d", len(table.Vectors), len(requests))
	}
	for i, want := range table.Vectors {
		t.Run(want.Name, func(t *testing.T) {
			if requests[i].name != want.Name || !jsonSemanticallyEqual(t, []byte(requests[i].request), want.Request) {
				t.Fatalf("vector %s request differs from the fixture request", want.Name)
			}
			request, err := decodeProviderPairingSignRequest(want.Request)
			if err != nil {
				t.Fatalf("vector request refused: %v", err)
			}
			canonical, err := json.Marshal(request.Provider)
			if err != nil || string(canonical) != want.CanonicalProvider {
				t.Fatalf("canonical provider bytes differ:\n got %s\nwant %s", canonical, want.CanonicalProvider)
			}
			message, digest, err := planProviderPairingAttestation(request, fx.operatorKeyID)
			if err != nil {
				t.Fatalf("vector refused: %v", err)
			}
			if string(message) != want.Message || digest != want.ProviderDigest || sha256HexForPairingTest(message) != want.MessageSHA256 {
				t.Fatalf("V2 message differs from the shared vector:\n got %q (%s)\nwant %q (%s)", message, digest, want.Message, want.ProviderDigest)
			}
			if !strings.HasPrefix(want.Message, "MELUSINA_PROVIDER_OPERATOR_ATTESTATION_V2\n{\"providerDigest\":\""+want.ProviderDigest+"\"") {
				t.Fatalf("vector message does not open with the V2 domain and its provider digest: %q", want.Message)
			}
			signature, err := signProviderPairingMessage(fx.operator, message)
			if err != nil || signature != want.Attestation.Signature {
				t.Fatalf("signature differs from the shared vector: %v", err)
			}
			if want.Attestation.Algorithm != "ed25519" || want.Attestation.KeyID != fx.operatorKeyID || want.Attestation.DelegatedInventorySigner != fx.targetAgentKeyID {
				t.Fatalf("vector attestation fields are not the V2 record: %+v", want.Attestation)
			}
		})
	}
}

func jsonSemanticallyEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var left, right any
	if err := json.Unmarshal(a, &left); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &right); err != nil {
		t.Fatal(err)
	}
	l, _ := json.Marshal(left)
	r, _ := json.Marshal(right)
	return string(l) == string(r)
}

// startProviderPairingSignerForTest serves signer on a fresh socket in a
// mode-0700 directory and returns the socket path.
func startProviderPairingSignerForTest(t *testing.T, signer *providerPairingSigner) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pps")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "signer.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveProviderPairingSignerSocket(ctx, path, signer) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("provider pairing signer did not stop")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := verifyProviderPairingSignerSocket(path); err == nil {
			return path
		}
		select {
		case err := <-done:
			t.Fatalf("provider pairing signer stopped before serving: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("provider pairing signer socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func fixtureProviderPairingSigner(fx providerPairingFixture) *providerPairingSigner {
	return &providerPairingSigner{operator: fx.operator, reverify: func(context.Context) (*identity.Private, error) { return fx.operator, nil }}
}

// sendProviderPairingRaw sends raw bytes to the signer and returns its
// response without any client-side check, so the server's own refusals are
// what the test observes.
func sendProviderPairingRaw(t *testing.T, socket string, raw []byte) providerPairingSignResponse {
	t.Helper()
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(raw); err != nil {
		t.Fatal(err)
	}
	var response providerPairingSignResponse
	decoder := json.NewDecoder(conn)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		t.Fatalf("read signer response: %v", err)
	}
	return response
}

// End to end: the real socket server signs each vector, the real client
// verifies it, and the result is the literal shared attestation.
func TestProviderPairingSignerSocketSignsTheVectorsEndToEnd(t *testing.T) {
	fx := newProviderPairingFixture(t)
	table := loadProviderPairingVectors(t)
	socket := startProviderPairingSignerForTest(t, fixtureProviderPairingSigner(fx))
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("signer socket is not a mode-0600 socket: %v %v", info, err)
	}
	for _, want := range table.Vectors {
		t.Run(want.Name, func(t *testing.T) {
			response, err := requestProviderPairingAttestation(context.Background(), socket, want.Request, fx.operatorKeyID)
			if err != nil {
				t.Fatalf("client refused the signer's answer: %v", err)
			}
			if response.Attestation == nil || *response.Attestation != want.Attestation || response.ProviderDigest != want.ProviderDigest || response.MessageSHA256 != want.MessageSHA256 {
				t.Fatalf("socket attestation differs from the shared vector: %+v", response)
			}
		})
	}
}

// vectorRequestMap returns the first vector's request as a mutable map.
func vectorRequestMap(t *testing.T, fx providerPairingFixture) map[string]any {
	t.Helper()
	var request map[string]any
	if err := json.Unmarshal([]byte(providerPairingVectorRequests(fx)[0].request), &request); err != nil {
		t.Fatal(err)
	}
	return request
}

func encodeRequestMap(t *testing.T, request map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// assertPairingRefusedByName runs raw through the in-process signer (every
// server-side refusal) and requires the named refusal and no attestation.
func assertPairingRefusedByName(t *testing.T, fx providerPairingFixture, raw []byte, named string) {
	t.Helper()
	response := fixtureProviderPairingSigner(fx).sign(context.Background(), raw)
	if response.Attestation != nil || response.Error == "" || !strings.HasPrefix(response.Error, named) {
		t.Fatalf("want refusal %q, got error %q attestation %+v", named, response.Error, response.Attestation)
	}
}

// nonCanonicalKeySpelling returns a second base64url spelling of an ed25519:
// key ID: the last character's two unused bits set. It decodes, leniently,
// to the same 32 bytes.
func nonCanonicalKeySpelling(t *testing.T, keyID string) string {
	t.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := keyID[len(keyID)-1]
	index := strings.IndexByte(alphabet, last)
	if index < 0 || index&0b11 != 0 {
		t.Fatalf("key ID %s does not end in a canonical character", keyID)
	}
	spelled := keyID[:len(keyID)-1] + string(alphabet[index|0b01])
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(spelled, "ed25519:"))
	want, _ := decodeCanonicalPairingKeyID(keyID)
	if err != nil || string(raw) != string(want) || spelled == keyID {
		t.Fatalf("alternative spelling does not decode to the same key: %v", err)
	}
	return spelled
}

func TestPairingSignerRefusesV1Domain(t *testing.T) {
	fx := newProviderPairingFixture(t)
	t.Run("V1 kind", func(t *testing.T) {
		request := vectorRequestMap(t, fx)
		request["kind"] = "provider-operator-attestation-v1"
		assertPairingRefusedByName(t, fx, encodeRequestMap(t, request), refusalPairingSignerV1+":kind")
	})
	t.Run("V1 domain as kind", func(t *testing.T) {
		request := vectorRequestMap(t, fx)
		request["kind"] = providerOperatorAttestationDomainV1
		assertPairingRefusedByName(t, fx, encodeRequestMap(t, request), refusalPairingSignerV1+":MELUSINA_PROVIDER_OPERATOR_ATTESTATION_V1")
	})
	t.Run("V1 domain inside a field", func(t *testing.T) {
		request := vectorRequestMap(t, fx)
		request["targetIdentity"] = "target:" + providerOperatorAttestationDomainV1
		assertPairingRefusedByName(t, fx, encodeRequestMap(t, request), refusalPairingSignerV1+":MELUSINA_PROVIDER_OPERATOR_ATTESTATION_V1")
	})
	t.Run("delegatedReceiptSigner without delegatedInventorySigner", func(t *testing.T) {
		request := vectorRequestMap(t, fx)
		delete(request, "delegatedInventorySigner")
		request["delegatedReceiptSigner"] = fx.targetAgentKeyID
		assertPairingRefusedByName(t, fx, encodeRequestMap(t, request), refusalPairingSignerV1+":delegatedReceiptSigner")
	})
	t.Run("V1 bytes offered to the signing function", func(t *testing.T) {
		v1 := []byte(providerOperatorAttestationDomainV1 + `{"providerDigest":"sha256:00"}`)
		if signature, err := signProviderPairingMessage(fx.operator, v1); err == nil || err.Error() != refusalPairingSignerMessageNotV2 || signature != "" {
			t.Fatalf("V1 bytes were not refused by %s: %q %v", refusalPairingSignerMessageNotV2, signature, err)
		}
		v2 := []byte(providerOperatorInventoryAttestationDomainV2 + `{"providerDigest":"sha256:00"}`)
		if _, err := signProviderPairingMessage(fx.operator, v2); err != nil {
			t.Fatalf("positive control: V2 bytes refused: %v", err)
		}
	})
}

func TestPairingSignerRefusesReceiptSignerEqualToInventorySigner(t *testing.T) {
	fx := newProviderPairingFixture(t)
	request := vectorRequestMap(t, fx)
	request["provider"].(map[string]any)["receiptSigner"] = fx.targetAgentKeyID
	request["targetAgentIdentity"] = fx.otherKeyID
	assertPairingRefusedByName(t, fx, encodeRequestMap(t, request), refusalPairingSignerReceiptIsInventory)
}

func TestPairingSignerRefusesReceiptSignerEqualToTargetAgent(t *testing.T) {
	fx := newProviderPairingFixture(t)
	request := vectorRequestMap(t, fx)
	request["targetAgentIdentity"] = fx.receiptKeyID
	assertPairingRefusedByName(t, fx, encodeRequestMap(t, request), refusalPairingSignerReceiptIsTargetAgent)
	t.Run("second spelling of the same key", func(t *testing.T) {
		request := vectorRequestMap(t, fx)
		request["targetAgentIdentity"] = nonCanonicalKeySpelling(t, fx.receiptKeyID)
		assertPairingRefusedByName(t, fx, encodeRequestMap(t, request), refusalPairingSignerKeyIDInvalid+":targetAgentIdentity")
	})
}

func TestPairingSignerRefusesReceiptSignerEqualToTargetIdentity(t *testing.T) {
	fx := newProviderPairingFixture(t)
	request := vectorRequestMap(t, fx)
	request["targetIdentity"] = fx.receiptKeyID
	assertPairingRefusedByName(t, fx, encodeRequestMap(t, request), refusalPairingSignerReceiptIsTargetIdentity)
	t.Run("second spelling of the same key", func(t *testing.T) {
		request := vectorRequestMap(t, fx)
		request["targetIdentity"] = nonCanonicalKeySpelling(t, fx.receiptKeyID)
		assertPairingRefusedByName(t, fx, encodeRequestMap(t, request), refusalPairingSignerReceiptIsTargetIdentity)
	})
}

func TestPairingSignerRefusesReceiptSignerEqualToStoreOperator(t *testing.T) {
	fx := newProviderPairingFixture(t)
	request := vectorRequestMap(t, fx)
	request["provider"].(map[string]any)["receiptSigner"] = fx.operatorKeyID
	assertPairingRefusedByName(t, fx, encodeRequestMap(t, request), refusalPairingSignerReceiptIsStoreOperator)
	t.Run("second spelling of the Store key", func(t *testing.T) {
		request := vectorRequestMap(t, fx)
		request["provider"].(map[string]any)["receiptSigner"] = nonCanonicalKeySpelling(t, fx.operatorKeyID)
		assertPairingRefusedByName(t, fx, encodeRequestMap(t, request), refusalPairingSignerKeyIDInvalid+":provider.receiptSigner")
	})
}

func TestPairingSignerRefusesProvidersTheTargetAgentWouldRefuse(t *testing.T) {
	fx := newProviderPairingFixture(t)
	cases := []struct {
		name   string
		mutate func(request, provider map[string]any)
		named  string
	}{
		{"dedicated ownership", func(_, p map[string]any) { p["ownership"] = "dedicated-owned" }, refusalPairingSignerProviderInvalid + ":ownership"},
		{"no trust pin", func(_, p map[string]any) { delete(p, "trustPin") }, refusalPairingSignerProviderInvalid + ":trustPin"},
		{"no identity", func(_, p map[string]any) { p["identity"] = "" }, refusalPairingSignerProviderInvalid + ":identity"},
		{"bad provider id", func(_, p map[string]any) { p["id"] = "Edge" }, refusalPairingSignerProviderInvalid + ":id"},
		{"spec inventory signer is not the delegated one", func(_, p map[string]any) { p["inventorySigner"] = fx.otherKeyID }, refusalPairingSignerInventorySignerMismatch},
		{"no target identity", func(r, _ map[string]any) { r["targetIdentity"] = " " }, refusalPairingSignerRequestInvalid + ":targetIdentity"},
		{"unknown provider field", func(_, p map[string]any) { p["notAField"] = "x" }, refusalPairingSignerRequestInvalid + ":json: unknown field"},
		{"unknown nested field", func(_, p map[string]any) {
			p["control"] = map[string]any{"rfc2136Policy": map[string]any{"zone": "estate.test.", "extra": 1}}
		}, refusalPairingSignerRequestInvalid + ":json: unknown field"},
		{"unknown top-level field", func(r, _ map[string]any) { r["note"] = "x" }, refusalPairingSignerRequestInvalid + ":unknown-field:note"},
		{"case-folded top-level field", func(r, _ map[string]any) { r["TargetIdentity"] = "target:other" }, refusalPairingSignerRequestInvalid + ":unknown-field:TargetIdentity"},
		{"wrong schema", func(r, _ map[string]any) { r["schema"] = "melusina-store-listing-signer-v1" }, refusalPairingSignerRequestInvalid + ":schema"},
		{"unknown kind", func(r, _ map[string]any) { r["kind"] = "arbitrary-bytes" }, refusalPairingSignerKindNotSignable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := vectorRequestMap(t, fx)
			tc.mutate(request, request["provider"].(map[string]any))
			assertPairingRefusedByName(t, fx, encodeRequestMap(t, request), tc.named)
		})
	}
	t.Run("positive control", func(t *testing.T) {
		response := fixtureProviderPairingSigner(fx).sign(context.Background(), encodeRequestMap(t, vectorRequestMap(t, fx)))
		if response.Error != "" || response.Attestation == nil {
			t.Fatalf("unmodified vector request refused: %s", response.Error)
		}
	})
}

// The signer has no surface that signs a provider work-order control, a
// target binding, a work order or a receipt: each is refused by name over the
// real socket, and the only signing call in the file is reachable only from
// the V2 path.
func TestPairingSignerHasNoControlSurface(t *testing.T) {
	fx := newProviderPairingFixture(t)
	socket := startProviderPairingSignerForTest(t, fixtureProviderPairingSigner(fx))
	control := map[string]any{
		"apiVersion": "installer.melusina.org/provider-control/v1", "kind": "ProviderWorkOrderControl",
		"contractId": "sha256:" + strings.Repeat("0", 64), "workOrderId": "wo-1", "planId": "plan-1",
		"providerId": "edge", "providerKind": "edge", "receiptSigner": fx.operatorKeyID,
		"issuedAt": "2026-09-24T00:00:00Z", "expiresAt": "2026-09-24T00:30:00Z", "operations": []any{},
		"attestation": map[string]any{"algorithm": "ed25519", "keyId": fx.operatorKeyID},
	}
	cases := []struct {
		name  string
		raw   []byte
		named string
	}{
		{"a ProviderControlContract", encodeRequestMap(t, control), refusalPairingSignerNoControlSurface},
		{"a V2-shaped request of control kind", func() []byte {
			r := vectorRequestMap(t, fx)
			r["kind"] = "ProviderWorkOrderControl"
			return encodeRequestMap(t, r)
		}(), refusalPairingSignerNoControlSurface + ":kind"},
		{"a receipt kind", func() []byte {
			r := vectorRequestMap(t, fx)
			r["kind"] = "OperationReceipt"
			return encodeRequestMap(t, r)
		}(), refusalPairingSignerNoControlSurface + ":kind"},
		{"the control signature domain", func() []byte {
			r := vectorRequestMap(t, fx)
			r["provider"].(map[string]any)["description"] = "MELUSINA_PROVIDER_WORK_ORDER_CONTROL_V1\n" + "sha256:" + strings.Repeat("0", 64)
			return encodeRequestMap(t, r)
		}(), refusalPairingSignerNoControlSurface + ":MELUSINA_PROVIDER_WORK_ORDER_CONTROL_V1"},
		{"the control signature domain as kind", func() []byte {
			r := vectorRequestMap(t, fx)
			r["kind"] = "MELUSINA_PROVIDER_WORK_ORDER_CONTROL_V1\n"
			return encodeRequestMap(t, r)
		}(), refusalPairingSignerNoControlSurface + ":MELUSINA_PROVIDER_WORK_ORDER_CONTROL_V1"},
		{"the target binding domain", func() []byte {
			r := vectorRequestMap(t, fx)
			r["targetIdentity"] = "MELUSINA_PROVIDER_TARGET_BINDING_V1"
			return encodeRequestMap(t, r)
		}(), refusalPairingSignerNoControlSurface + ":MELUSINA_PROVIDER_TARGET_BINDING_V1"},
		{"a receiptSigner field beside the request", func() []byte {
			r := vectorRequestMap(t, fx)
			r["receiptSigner"] = fx.receiptKeyID
			return encodeRequestMap(t, r)
		}(), refusalPairingSignerNoControlSurface + ":field:receiptSigner"},
		{"the provider pairing proof domain", func() []byte {
			r := vectorRequestMap(t, fx)
			r["kind"] = "MELUSINA_PROVIDER_PAIRING_V1"
			return encodeRequestMap(t, r)
		}(), refusalPairingSignerCarriesDomain + ":MELUSINA_PROVIDER_PAIRING_V1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := sendProviderPairingRaw(t, socket, tc.raw)
			if response.Attestation != nil || !strings.HasPrefix(response.Error, tc.named) {
				t.Fatalf("want refusal %q over the socket, got error %q attestation %+v", tc.named, response.Error, response.Attestation)
			}
		})
	}
	t.Run("positive control over the socket", func(t *testing.T) {
		response := sendProviderPairingRaw(t, socket, encodeRequestMap(t, vectorRequestMap(t, fx)))
		if response.Error != "" || response.Attestation == nil {
			t.Fatalf("V2 request refused over the socket: %s", response.Error)
		}
	})
	t.Run("one signing call, reachable only from the V2 path", func(t *testing.T) {
		signers, callers := providerPairingSigningCallSites(t)
		if len(signers) != 1 || signers[0] != "signProviderPairingMessage" {
			t.Fatalf("provider_pairing_signer.go signs outside signProviderPairingMessage: %v", signers)
		}
		if len(callers) != 1 || callers[0] != "sign" {
			t.Fatalf("signProviderPairingMessage is called from %v; only (*providerPairingSigner).sign may call it", callers)
		}
	})
}

// providerPairingSigningCallSites returns the functions in
// provider_pairing_signer.go that call a Sign method or ed25519.Sign, and the
// functions that call signProviderPairingMessage.
func providerPairingSigningCallSites(t *testing.T) (signers, callers []string) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "provider_pairing_signer.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch callee := call.Fun.(type) {
			case *ast.SelectorExpr:
				if callee.Sel.Name == "Sign" {
					signers = append(signers, fn.Name.Name)
				}
			case *ast.Ident:
				if callee.Name == "signProviderPairingMessage" {
					callers = append(callers, fn.Name.Name)
				}
			}
			return true
		})
	}
	return signers, callers
}

// The enrollment gate runs again before every signature: a Store whose
// enrollment no longer verifies, or whose derived operator changed, signs
// nothing, and a legacy unenrolled Store is refused even in the standard build.
func TestPairingSignerRequiresEnrollmentBeforeEverySignature(t *testing.T) {
	fx := newProviderPairingFixture(t)
	raw := encodeRequestMap(t, vectorRequestMap(t, fx))
	gateCalls := 0
	failing := &providerPairingSigner{operator: fx.operator, reverify: func(context.Context) (*identity.Private, error) {
		gateCalls++
		return nil, errors.New("estate enrollment: store-estate-profile-not-enrolled: enrollment state is absent")
	}}
	response := failing.sign(context.Background(), raw)
	if gateCalls != 1 || response.Attestation != nil || !strings.HasPrefix(response.Error, refusalPairingSignerEnrollment+":estate enrollment: store-estate-profile-not-enrolled") {
		t.Fatalf("a failing enrollment gate did not refuse the signature by name (gate calls %d): %q", gateCalls, response.Error)
	}
	other := newTestIdentity(t, "store", "11111111111111111111111111111111", "store.estate.test")
	changed := &providerPairingSigner{operator: fx.operator, reverify: func(context.Context) (*identity.Private, error) { return other, nil }}
	if response := changed.sign(context.Background(), raw); response.Attestation != nil || response.Error != refusalPairingSignerEnrollment+":operator-changed" {
		t.Fatalf("a changed operator was not refused by name: %q", response.Error)
	}
	if err := requireProviderPairingSignerEnrollment(&verifiedBootIdentity{operator: fx.operator}, nil); err == nil || err.Error() != refusalPairingSignerEnrollment+":store-not-owner-enrolled" {
		t.Fatalf("an unenrolled Store was not refused by name: %v", err)
	}
	if err := requireProviderPairingSignerEnrollment(nil, &storeEnrollmentState{}); err == nil || !strings.HasPrefix(err.Error(), refusalPairingSignerEnrollment) {
		t.Fatalf("a Store with no write-capable identity was not refused by name: %v", err)
	}
	if err := requireProviderPairingSignerEnrollment(&verifiedBootIdentity{operator: fx.operator}, &storeEnrollmentState{}); err != nil {
		t.Fatalf("positive control: an enrolled Store was refused: %v", err)
	}
	gateCalls = 0
	passing := &providerPairingSigner{operator: fx.operator, reverify: func(context.Context) (*identity.Private, error) { gateCalls++; return fx.operator, nil }}
	if response := passing.sign(context.Background(), raw); response.Error != "" || gateCalls != 1 {
		t.Fatalf("positive control: a passing gate (calls %d) did not sign: %q", gateCalls, response.Error)
	}
}

func TestProviderPairingSignerSocketRefusesUnsafePaths(t *testing.T) {
	base, err := os.MkdirTemp("", "ppsu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(base, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(private, "regular.sock")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, path, contains string }{
		{"relative", "signer.sock", "absolute"},
		{"missing directory", filepath.Join(base, "absent", "signer.sock"), "socket directory"},
		{"group-readable directory", filepath.Join(open, "signer.sock"), "no group or other access"},
		{"regular file at the path", regular, "refusing to replace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := prepareProviderPairingSignerSocket(tc.path)
			if err == nil || !strings.HasPrefix(err.Error(), refusalPairingSignerSocketUnsafe) || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("want %s containing %q, got %v", refusalPairingSignerSocketUnsafe, tc.contains, err)
			}
		})
	}
	if _, err := os.Stat(regular); err != nil {
		t.Fatalf("the refused regular file was removed: %v", err)
	}
	if err := verifyProviderPairingSignerSocket(regular); err == nil || !strings.HasPrefix(err.Error(), refusalPairingSignerSocketUnsafe) {
		t.Fatalf("the client accepted a regular file as the signer socket: %v", err)
	}
	t.Run("positive control: a stale socket of this user is replaced", func(t *testing.T) {
		stale := filepath.Join(private, "stale.sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		listener.SetUnlinkOnClose(false)
		_ = listener.Close()
		if err := prepareProviderPairingSignerSocket(stale); err != nil {
			t.Fatalf("stale socket refused: %v", err)
		}
		if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale socket not cleared: %v", err)
		}
	})
}

// The client accepts only an attestation by the expected key over the message
// it rebuilds itself.
func TestProviderPairingAttestRefusesAForgedResponse(t *testing.T) {
	fx := newProviderPairingFixture(t)
	table := loadProviderPairingVectors(t)
	want := table.Vectors[0]
	serve := func(t *testing.T, response providerPairingSignResponse) string {
		t.Helper()
		dir, err := os.MkdirTemp("", "ppsf")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		path := filepath.Join(dir, "forged.sock")
		listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		go func() {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			defer conn.Close()
			var ignored json.RawMessage
			_ = json.NewDecoder(conn).Decode(&ignored)
			_ = json.NewEncoder(conn).Encode(response)
		}()
		return path
	}
	good := providerPairingSignResponse{Schema: providerPairingSignerSchema, OperatorKeyID: fx.operatorKeyID, ProviderDigest: want.ProviderDigest, MessageSHA256: want.MessageSHA256, Attestation: &want.Attestation}
	t.Run("positive control", func(t *testing.T) {
		if _, err := requestProviderPairingAttestation(context.Background(), serve(t, good), want.Request, fx.operatorKeyID); err != nil {
			t.Fatalf("the genuine vector response was refused: %v", err)
		}
	})
	forged := good
	forgedAttestation := want.Attestation
	otherSeed := providerPairingTestSeed("forger")
	message := []byte(want.Message)
	forgedAttestation.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(otherSeed[:]), message))
	forged.Attestation = &forgedAttestation
	t.Run("signature by another key under the expected key ID", func(t *testing.T) {
		_, err := requestProviderPairingAttestation(context.Background(), serve(t, forged), want.Request, fx.operatorKeyID)
		if err == nil || err.Error() != refusalPairingSignerResponseInvalid+":signature" {
			t.Fatalf("forged signature not refused by name: %v", err)
		}
	})
	rebound := good
	rebound.ProviderDigest = "sha256:" + strings.Repeat("0", 64)
	t.Run("a different provider digest", func(t *testing.T) {
		_, err := requestProviderPairingAttestation(context.Background(), serve(t, rebound), want.Request, fx.operatorKeyID)
		if err == nil || err.Error() != refusalPairingSignerResponseInvalid+":binding" {
			t.Fatalf("rebound digest not refused by name: %v", err)
		}
	})
	t.Run("another expected key", func(t *testing.T) {
		_, err := requestProviderPairingAttestation(context.Background(), serve(t, good), want.Request, fx.otherKeyID)
		if err == nil || err.Error() != refusalPairingSignerResponseInvalid+":binding" {
			t.Fatalf("an attestation by an unexpected key was not refused by name: %v", err)
		}
	})
}

// The unit starts the signer on a socket in a runtime directory of its own,
// cannot be enabled at boot, and is not yet in the Store bundle: the
// deployer's closed bootstrap member list must admit it first.
func TestProviderPairingSignerUnitIsConstrainedAndNotYetBundled(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	read := func(parts ...string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(append([]string{root}, parts...)...))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	unit := read("deploy", "store-generation", "melusina-store-provider-pairing-signer.service")
	listing := read("deploy", "store-generation", "melusina-store-listing-signer.service")
	for _, required := range []string{
		"ExecStart=/opt/melusina-store/current/bin/melusina-store-sidecar provider-pairing-signer -config /etc/melusina/store/store.config.json -socket /run/melusina-store-provider-pairing/signer.sock\n",
		"RuntimeDirectory=melusina-store-provider-pairing\n",
		"RuntimeDirectoryMode=0700\n",
		"UMask=0077\n",
		"ReadOnlyPaths=/etc/melusina/store\n",
		"ReadWritePaths=/run/melusina-store-provider-pairing\n",
		"NoNewPrivileges=yes\n",
		"ProtectSystem=strict\n",
	} {
		if !strings.Contains(unit, required) {
			t.Fatalf("provider pairing signer unit omits %q", required)
		}
	}
	for _, line := range strings.Split(unit, "\n") {
		if line = strings.TrimSpace(line); line == "[Install]" || strings.HasPrefix(line, "WantedBy=") || strings.HasPrefix(line, "RequiredBy=") {
			t.Fatalf("provider pairing signer unit can be enabled at boot (%q); it is started for a pairing ceremony only", line)
		}
	}
	if strings.Contains(listing, "RuntimeDirectory=melusina-store-provider-pairing") || !strings.Contains(listing, "RuntimeDirectory=melusina\n") {
		t.Fatal("the two signers must keep disjoint runtime directories")
	}
	build := read("scripts", "build-store-generation-release.sh")
	if strings.Contains(build, "melusina-store-provider-pairing-signer.service") {
		t.Fatal("the bundle carries the provider pairing signer unit before the deployer's closed Store bootstrap member list admits it; land the deployer change first and update this test with it")
	}
	contract := read("deploy", "store-generation", "DEPLOYMENT-CONTRACT.md")
	for _, required := range []string{"provider-pairing-signer", "provider-pairing-attest", "melusina-store-provider-pairing-signer.service", "MELUSINA_PROVIDER_OPERATOR_ATTESTATION_V2", "never signs a provider work-order control", "closed member list"} {
		if !strings.Contains(contract, required) {
			t.Fatalf("DEPLOYMENT-CONTRACT.md omits provider pairing signer contract text %q", required)
		}
	}
}
