package main

// Provider pairing signer: the root Store operator's one signing duty toward
// provider hosts.
//
// Shared Edge and DNS providers run no signer of their own. The target agent
// accepts them only with an "operator-attested" pairing: a co-signature by the
// root Store operator over the V2 binding the deployer builds in
// installengine.ProviderOperatorInventoryAttestationMessage
// (deploy-ui/internal/installengine/provider_pairing.go). This file is that
// co-signer, as an enrollment-gated local-socket signer modelled on
// listing-signer. It replaces the deployer's root-store-operator-attestation-
// signer, which read the Store seed from a file, and the practice of pushing a
// signer binary into the Store's container.
//
// It signs exactly one kind of message, the V2 attestation, and builds those
// bytes itself from typed fields. A request never supplies bytes, a digest or
// a domain to sign. It refuses, each by name:
//
//   - the V1 domain and a V1-shaped request (a delegatedReceiptSigner);
//   - anything shaped like a provider work-order control, target binding,
//     work order or receipt, and any request that carries a signing domain.
//     Work-order controls are signed by the provider host's own receipt
//     identity, never by the Store: the deployer binds each control to the
//     receipt signer (provider_work_order_control.go SignProviderControl-
//     Contract and VerifyProviderControlContract), and that key stays off
//     the Store;
//   - a receipt signer equal to the delegated inventory signer, to the target
//     agent's identity, to the target identity, or to the Store's own
//     operator key.
//
// The process passes the enrollment gate at startup and again before every
// signature, and requires an owner enrollment even in the standard build.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
)

const (
	providerPairingSignerSchema = "melusina-store-provider-pairing-signer-v1"
	// providerPairingSignerKindV2 is the one kind this signer signs.
	providerPairingSignerKindV2 = "provider-operator-inventory-attestation-v2"
	// providerOperatorInventoryAttestationDomainV2 is the deployer's
	// providerOperatorInventoryAttestationDomain, byte for byte.
	providerOperatorInventoryAttestationDomainV2 = "MELUSINA_PROVIDER_OPERATOR_ATTESTATION_V2\n"
	// providerOperatorAttestationDomainV1 is recognised only to refuse it.
	providerOperatorAttestationDomainV1 = "MELUSINA_PROVIDER_OPERATOR_ATTESTATION_V1\n"

	providerPairingSignerMaxMessage = 64 << 10
	providerPairingSignerSocketMode = 0o600
	providerPairingSignerTimeout    = 45 * time.Second
	// providerPairingOwnershipShared is installmodel.OwnershipShared. The
	// target agent accepts an operator-attested pairing only for it.
	providerPairingOwnershipShared = "shared-provider"
)

// Refusal names. Each refusal the signer returns starts with one of these.
const (
	refusalPairingSignerRequestInvalid          = "provider-pairing-signer-request-invalid"
	refusalPairingSignerV1                      = "provider-pairing-signer-v1-refused"
	refusalPairingSignerNoControlSurface        = "provider-pairing-signer-no-control-surface"
	refusalPairingSignerCarriesDomain           = "provider-pairing-signer-request-carries-signing-domain"
	refusalPairingSignerKindNotSignable         = "provider-pairing-signer-kind-not-signable"
	refusalPairingSignerProviderInvalid         = "provider-pairing-signer-provider-invalid"
	refusalPairingSignerKeyIDInvalid            = "provider-pairing-signer-key-id-invalid"
	refusalPairingSignerInventorySignerMismatch = "provider-pairing-signer-inventory-signer-mismatch"
	refusalPairingSignerReceiptIsInventory      = "provider-pairing-signer-receipt-signer-is-inventory-signer"
	refusalPairingSignerReceiptIsTargetAgent    = "provider-pairing-signer-receipt-signer-is-target-agent"
	refusalPairingSignerReceiptIsTargetIdentity = "provider-pairing-signer-receipt-signer-is-target-identity"
	refusalPairingSignerReceiptIsStoreOperator  = "provider-pairing-signer-receipt-signer-is-store-operator"
	refusalPairingSignerMessageNotV2            = "provider-pairing-signer-message-not-v2"
	refusalPairingSignerEnrollment              = "provider-pairing-signer-enrollment-not-verified"
	refusalPairingSignerPeer                    = "provider-pairing-signer-peer-not-store-user"
	refusalPairingSignerSocketUnsafe            = "provider-pairing-signer-socket-unsafe"
	refusalPairingSignerResponseInvalid         = "provider-pairing-signer-response-invalid"
)

// pairingProviderSpec mirrors installmodel.ProviderSpec
// (deploy-ui/internal/installmodel/types.go) field for field: the same order,
// names, types and omitempty. The provider digest in the signed message is
// sha256 of Go's json.Marshal of that struct, so the Store must produce the
// same bytes from the same value. Decoding is strict at every depth: a field
// this copy does not know is refused rather than dropped, and a field the
// deployer adds without omitempty changes its bytes, so the deployer then
// refuses the signature. Drift fails closed on both sides.
type pairingProviderSpec struct {
	ID              string                               `json:"id"`
	Kind            string                               `json:"kind"`
	Ownership       string                               `json:"ownership"`
	Identity        string                               `json:"identity"`
	Endpoint        string                               `json:"endpoint,omitempty"`
	TrustPin        string                               `json:"trustPin,omitempty"`
	ReceiptSigner   string                               `json:"receiptSigner,omitempty"`
	InventorySigner string                               `json:"inventorySigner,omitempty"`
	CredentialRef   string                               `json:"credentialRef,omitempty"`
	Description     string                               `json:"description,omitempty"`
	Control         *pairingProviderControlPrerequisites `json:"control,omitempty"`
	ACMEResponder   *pairingProviderACMEResponderSpec    `json:"acmeResponder,omitempty"`
	MXCertificate   *pairingProviderMXCertificateSpec    `json:"mxCertificate,omitempty"`
	BackupStore     *pairingProviderBackupStoreSpec      `json:"backupStore,omitempty"`
	MailRelay       *pairingProviderMailRelaySpec        `json:"mailRelay,omitempty"`
}

type pairingProviderControlPrerequisites struct {
	OwnershipHandoff *pairingProviderOwnershipHandoffSpec `json:"ownershipHandoff,omitempty"`
	RFC2136Policy    *pairingProviderRFC2136PolicySpec    `json:"rfc2136Policy,omitempty"`
}

type pairingProviderFileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}

type pairingProviderOwnershipHandoffSpec struct {
	Schema             string                      `json:"schema"`
	ProviderRef        string                      `json:"providerRef"`
	ProviderIdentity   string                      `json:"providerIdentity"`
	ContractGeneration string                      `json:"contractGeneration"`
	LegacyService      string                      `json:"legacyService"`
	UnitFile           pairingProviderFileDigest   `json:"unitFile"`
	ArchivedUnitPath   string                      `json:"archivedUnitPath"`
	DropIns            []pairingProviderFileDigest `json:"dropIns"`
	ManagedFiles       []pairingProviderFileDigest `json:"managedFiles"`
	InitialActiveState string                      `json:"initialActiveState"`
	InitialUnitState   string                      `json:"initialUnitState"`
	DesiredActiveState string                      `json:"desiredActiveState"`
	DesiredUnitState   string                      `json:"desiredUnitState"`
}

type pairingProviderRFC2136PolicySpec struct {
	Schema                 string                    `json:"schema"`
	ProviderRef            string                    `json:"providerRef"`
	ProviderIdentity       string                    `json:"providerIdentity"`
	ContractGeneration     string                    `json:"contractGeneration"`
	Zone                   string                    `json:"zone"`
	Nameservers            []string                  `json:"nameservers"`
	KeyName                string                    `json:"keyName"`
	KeyAlgorithm           string                    `json:"keyAlgorithm"`
	KeyPath                string                    `json:"keyPath"`
	PolicyPath             string                    `json:"policyPath"`
	NamedConfigPath        string                    `json:"namedConfigPath"`
	NamedConfigBefore      pairingProviderFileDigest `json:"namedConfigBefore"`
	NamedConfigAfterSHA256 string                    `json:"namedConfigAfterSha256"`
	PolicySHA256           string                    `json:"policySha256"`
	AllowedRecordTypes     []string                  `json:"allowedRecordTypes"`
	LegacyACMEKeyName      string                    `json:"legacyAcmeKeyName"`
	LegacyACMERecordType   string                    `json:"legacyAcmeRecordType"`
	KeyFileMode            uint32                    `json:"keyFileMode"`
	ACMEResponderKeyName   string                    `json:"acmeResponderKeyName"`
	ACMEResponderKeyPath   string                    `json:"acmeResponderKeyPath"`
	ACMEChallengeZone      string                    `json:"acmeChallengeZone"`
	DNSSECSigning          bool                      `json:"dnssecSigning,omitempty"`
}

type pairingProviderACMEResponderSpec struct {
	Schema           string `json:"schema"`
	ProviderRef      string `json:"providerRef"`
	ProviderIdentity string `json:"providerIdentity"`
	Endpoint         string `json:"endpoint"`
	TLSSPKISHA256    string `json:"tlsSpkiSha256"`
	ChallengeZone    string `json:"challengeZone"`
}

type pairingProviderMXCertificateSpec struct {
	Schema              string `json:"schema"`
	ProviderRef         string `json:"providerRef"`
	ProviderIdentity    string `json:"providerIdentity"`
	DelegationPublicKey string `json:"delegationPublicKey"`
}

type pairingProviderBackupStoreSpec struct {
	Schema           string `json:"schema"`
	ProviderRef      string `json:"providerRef"`
	ProviderIdentity string `json:"providerIdentity"`
	Endpoint         string `json:"endpoint"`
	TrustPin         string `json:"trustPin"`
	ReceiptSigner    string `json:"receiptSigner"`
}

type pairingProviderMailRelaySpec struct {
	Schema             string `json:"schema"`
	ProviderRef        string `json:"providerRef"`
	ProviderIdentity   string `json:"providerIdentity"`
	Hostname           string `json:"hostname"`
	EgressIPv4         string `json:"egressIpv4"`
	SubmissionAddress  string `json:"submissionAddress"`
	SubmissionPort     int    `json:"submissionPort"`
	TLSSPKISHA256      string `json:"tlsSpkiSha256"`
	BaseContractSHA256 string `json:"baseContractSha256"`
	HourlyMessageLimit int    `json:"hourlyMessageLimit"`
	FCrDNSObservedAt   string `json:"fcrdnsObservedAt"`
}

// providerPairingSignRequest is the whole request. It names the provider
// exactly as the owner-signed install spec declares it; the Store takes the
// provider's identity, trust pin and receipt signer from there, as the target
// agent does. TargetAgentIdentity is not signed: it names the target agent's
// key so the signer can refuse a receipt signer equal to it.
type providerPairingSignRequest struct {
	Schema                   string              `json:"schema"`
	Kind                     string              `json:"kind"`
	Provider                 pairingProviderSpec `json:"provider"`
	TargetIdentity           string              `json:"targetIdentity"`
	TargetAgentIdentity      string              `json:"targetAgentIdentity"`
	DelegatedInventorySigner string              `json:"delegatedInventorySigner"`
}

// providerOperatorPairingAttestation is the deployer's
// OperatorPairingAttestation as a V2 record: its delegatedReceiptSigner
// exists only for V1 and is never emitted.
type providerOperatorPairingAttestation struct {
	Algorithm                string `json:"algorithm"`
	KeyID                    string `json:"keyId"`
	DelegatedInventorySigner string `json:"delegatedInventorySigner"`
	Signature                string `json:"signature"`
}

type providerPairingSignResponse struct {
	Schema         string                              `json:"schema"`
	OperatorKeyID  string                              `json:"operatorKeyId,omitempty"`
	ProviderDigest string                              `json:"providerDigest,omitempty"`
	MessageSHA256  string                              `json:"messageSha256,omitempty"`
	Attestation    *providerOperatorPairingAttestation `json:"attestation,omitempty"`
	Error          string                              `json:"error,omitempty"`
}

var (
	providerPairingIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	// signingDomainTagPattern finds a Melusina signing-domain tag anywhere in
	// a request string. The signer chooses its own domain, so a request that
	// carries one is refused whatever it is.
	signingDomainTagPattern = regexp.MustCompile(`MELUSINA_[A-Z0-9_]*_V[0-9]+`)
)

var providerPairingRequestFields = map[string]bool{
	"schema": true, "kind": true, "provider": true,
	"targetIdentity": true, "targetAgentIdentity": true, "delegatedInventorySigner": true,
}

// providerPairingControlFields are top-level fields of the deployer's
// ProviderControlContract, ProviderTargetBinding, WorkOrder and
// OperationReceipt. A request carrying one is some other document.
var providerPairingControlFields = map[string]bool{
	"apiVersion": true, "contractId": true, "workOrderId": true, "planId": true,
	"operations": true, "bindingId": true, "bindingKind": true, "receiptId": true,
	"receiptSigner": true, "attestation": true, "hostMachineIdHash": true,
}

// classifySigningDomain names the refusal for a signing-domain tag found in a
// request.
func classifySigningDomain(tag string) string {
	switch {
	case tag == strings.TrimSuffix(providerOperatorAttestationDomainV1, "\n"):
		return refusalPairingSignerV1
	case strings.Contains(tag, "WORK_ORDER"), strings.Contains(tag, "CONTROL"),
		strings.Contains(tag, "TARGET_BINDING"), strings.Contains(tag, "RECEIPT"),
		strings.Contains(tag, "ACTIVATION"):
		return refusalPairingSignerNoControlSurface
	default:
		return refusalPairingSignerCarriesDomain
	}
}

// classifyUnsignableKind names the refusal for any kind but the V2 kind.
func classifyUnsignableKind(kind string) string {
	lower := strings.ToLower(kind)
	for _, marker := range []string{"control", "work-order", "workorder", "work_order", "receipt", "binding", "activation"} {
		if strings.Contains(lower, marker) {
			return refusalPairingSignerNoControlSurface
		}
	}
	if strings.Contains(lower, "v1") {
		return refusalPairingSignerV1
	}
	return refusalPairingSignerKindNotSignable
}

// decodeProviderPairingSignRequest applies every request-shape refusal, then
// decodes the request strictly. It holds no key.
func decodeProviderPairingSignRequest(raw []byte) (providerPairingSignRequest, error) {
	var zero providerPairingSignRequest
	if len(raw) == 0 || len(raw) > providerPairingSignerMaxMessage {
		return zero, fmt.Errorf("%s:size", refusalPairingSignerRequestInvalid)
	}
	generic := json.NewDecoder(bytes.NewReader(raw))
	generic.UseNumber()
	var document any
	if err := generic.Decode(&document); err != nil {
		return zero, fmt.Errorf("%s:json", refusalPairingSignerRequestInvalid)
	}
	if generic.More() {
		return zero, fmt.Errorf("%s:trailing-data", refusalPairingSignerRequestInvalid)
	}
	if tag := firstSigningDomainTag(document); tag != "" {
		return zero, fmt.Errorf("%s:%s", classifySigningDomain(tag), tag)
	}
	top, ok := document.(map[string]any)
	if !ok {
		return zero, fmt.Errorf("%s:not-an-object", refusalPairingSignerRequestInvalid)
	}
	keys := make([]string, 0, len(top))
	for key := range top {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		switch {
		case key == "delegatedReceiptSigner":
			return zero, fmt.Errorf("%s:delegatedReceiptSigner", refusalPairingSignerV1)
		case providerPairingControlFields[key]:
			return zero, fmt.Errorf("%s:field:%s", refusalPairingSignerNoControlSurface, key)
		case !providerPairingRequestFields[key]:
			return zero, fmt.Errorf("%s:unknown-field:%s", refusalPairingSignerRequestInvalid, key)
		}
	}
	kind, _ := top["kind"].(string)
	if kind != providerPairingSignerKindV2 {
		return zero, fmt.Errorf("%s:kind:%q", classifyUnsignableKind(kind), kind)
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	var request providerPairingSignRequest
	if err := strict.Decode(&request); err != nil {
		return zero, fmt.Errorf("%s:%v", refusalPairingSignerRequestInvalid, err)
	}
	if request.Schema != providerPairingSignerSchema {
		return zero, fmt.Errorf("%s:schema", refusalPairingSignerRequestInvalid)
	}
	return request, nil
}

// firstSigningDomainTag returns the first signing-domain tag found in any key
// or string value of a decoded JSON document, in a stable order.
func firstSigningDomainTag(value any) string {
	switch typed := value.(type) {
	case string:
		return signingDomainTagPattern.FindString(typed)
	case []any:
		for _, item := range typed {
			if tag := firstSigningDomainTag(item); tag != "" {
				return tag
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if tag := signingDomainTagPattern.FindString(key); tag != "" {
				return tag
			}
			if tag := firstSigningDomainTag(typed[key]); tag != "" {
				return tag
			}
		}
	}
	return ""
}

func pairingEd25519KeyID(publicKey ed25519.PublicKey) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(publicKey)
}

// decodeCanonicalPairingKeyID accepts only the canonical spelling of an
// "ed25519:" key ID. The deployer compares key IDs as strings, so two
// spellings of one key would pass its receipt/inventory split; the Store
// refuses the second spelling instead.
func decodeCanonicalPairingKeyID(value string) (ed25519.PublicKey, bool) {
	if !strings.HasPrefix(value, "ed25519:") {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(value, "ed25519:"))
	if err != nil || len(raw) != ed25519.PublicKeySize || pairingEd25519KeyID(raw) != value {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}

// samePairingKey reports whether other names the same Ed25519 key as the
// canonical key ID want, in any base64url spelling, or is the same string.
func samePairingKey(want, other string) bool {
	if want == other {
		return true
	}
	wantRaw, ok := decodeCanonicalPairingKeyID(want)
	if !ok || !strings.HasPrefix(other, "ed25519:") {
		return false
	}
	otherRaw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(other, "ed25519:"))
	return err == nil && bytes.Equal(wantRaw, otherRaw)
}

// providerPairingDigest is the deployer's pairingDigest(provider).
func providerPairingDigest(provider pairingProviderSpec) (string, error) {
	raw, err := json.Marshal(provider)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// providerOperatorInventoryAttestationMessage builds the bytes the deployer's
// installengine.ProviderOperatorInventoryAttestationMessage builds for the
// same arguments. It is the only message builder in this signer.
func providerOperatorInventoryAttestationMessage(provider pairingProviderSpec, targetIdentity, identity, trustPin, operationReceiptSigner, delegatedInventorySigner string) ([]byte, error) {
	providerDigest, err := providerPairingDigest(provider)
	if err != nil {
		return nil, err
	}
	material := struct {
		ProviderDigest           string `json:"providerDigest"`
		ProviderID               string `json:"providerId"`
		Kind                     string `json:"kind"`
		Ownership                string `json:"ownership"`
		TargetIdentity           string `json:"targetIdentity"`
		Identity                 string `json:"identity"`
		TrustPin                 string `json:"trustPin"`
		OperationReceiptSigner   string `json:"operationReceiptSigner"`
		DelegatedInventorySigner string `json:"delegatedInventorySigner"`
	}{providerDigest, provider.ID, provider.Kind, provider.Ownership, targetIdentity, identity, trustPin, operationReceiptSigner, delegatedInventorySigner}
	raw, err := json.Marshal(material)
	if err != nil {
		return nil, err
	}
	return append([]byte(providerOperatorInventoryAttestationDomainV2), raw...), nil
}

// planProviderPairingAttestation applies every semantic refusal and returns
// the exact V2 message and provider digest to sign. storeOperatorKeyID is this
// Store's own operator key ID.
func planProviderPairingAttestation(request providerPairingSignRequest, storeOperatorKeyID string) ([]byte, string, error) {
	provider := request.Provider
	switch {
	case !providerPairingIDPattern.MatchString(provider.ID):
		return nil, "", fmt.Errorf("%s:id", refusalPairingSignerProviderInvalid)
	case strings.TrimSpace(provider.Kind) == "":
		return nil, "", fmt.Errorf("%s:kind", refusalPairingSignerProviderInvalid)
	case provider.Ownership != providerPairingOwnershipShared:
		return nil, "", fmt.Errorf("%s:ownership:%q is not %q", refusalPairingSignerProviderInvalid, provider.Ownership, providerPairingOwnershipShared)
	case provider.Identity == "":
		return nil, "", fmt.Errorf("%s:identity", refusalPairingSignerProviderInvalid)
	case provider.TrustPin == "":
		return nil, "", fmt.Errorf("%s:trustPin", refusalPairingSignerProviderInvalid)
	case strings.TrimSpace(request.TargetIdentity) == "":
		return nil, "", fmt.Errorf("%s:targetIdentity", refusalPairingSignerRequestInvalid)
	}
	for _, field := range []struct{ name, value string }{
		{"provider.receiptSigner", provider.ReceiptSigner},
		{"provider.inventorySigner", provider.InventorySigner},
		{"delegatedInventorySigner", request.DelegatedInventorySigner},
		{"targetAgentIdentity", request.TargetAgentIdentity},
		{"storeOperatorKeyId", storeOperatorKeyID},
	} {
		if _, ok := decodeCanonicalPairingKeyID(field.value); !ok {
			return nil, "", fmt.Errorf("%s:%s", refusalPairingSignerKeyIDInvalid, field.name)
		}
	}
	receipt := provider.ReceiptSigner
	switch {
	case samePairingKey(receipt, request.DelegatedInventorySigner):
		return nil, "", errors.New(refusalPairingSignerReceiptIsInventory)
	case samePairingKey(receipt, request.TargetAgentIdentity):
		return nil, "", errors.New(refusalPairingSignerReceiptIsTargetAgent)
	case samePairingKey(receipt, request.TargetIdentity):
		return nil, "", errors.New(refusalPairingSignerReceiptIsTargetIdentity)
	case samePairingKey(receipt, storeOperatorKeyID):
		return nil, "", errors.New(refusalPairingSignerReceiptIsStoreOperator)
	case provider.InventorySigner != request.DelegatedInventorySigner:
		// The deployer requires the signed spec's inventory signer to be the
		// delegated one (verifyOperatorPairingAttestation).
		return nil, "", errors.New(refusalPairingSignerInventorySignerMismatch)
	}
	message, err := providerOperatorInventoryAttestationMessage(provider, request.TargetIdentity, provider.Identity, provider.TrustPin, receipt, request.DelegatedInventorySigner)
	if err != nil {
		return nil, "", fmt.Errorf("%s:%v", refusalPairingSignerRequestInvalid, err)
	}
	digest, err := providerPairingDigest(provider)
	if err != nil {
		return nil, "", fmt.Errorf("%s:%v", refusalPairingSignerRequestInvalid, err)
	}
	return message, digest, nil
}

// signProviderPairingMessage is the one place this file signs. It signs only
// bytes under the V2 domain whose remainder is one JSON object.
func signProviderPairingMessage(operator *identity.Private, message []byte) (string, error) {
	body, ok := bytes.CutPrefix(message, []byte(providerOperatorInventoryAttestationDomainV2))
	if !ok || !json.Valid(body) || len(body) == 0 || body[0] != '{' {
		return "", errors.New(refusalPairingSignerMessageNotV2)
	}
	return base64.RawURLEncoding.EncodeToString(operator.Sign(message)), nil
}

// providerPairingSigner is the socket's request handler. reverify re-runs the
// enrollment gate before each signature and returns the operator it derived.
type providerPairingSigner struct {
	operator *identity.Private
	reverify func(context.Context) (*identity.Private, error)
}

func storeOperatorPairingKeyID(operator *identity.Private) (string, error) {
	publicKey, err := operator.Public().SignPublicKey()
	if err != nil {
		return "", err
	}
	return pairingEd25519KeyID(publicKey), nil
}

func (s *providerPairingSigner) sign(ctx context.Context, raw []byte) providerPairingSignResponse {
	refuse := func(err error) providerPairingSignResponse {
		return providerPairingSignResponse{Schema: providerPairingSignerSchema, Error: err.Error()}
	}
	if s == nil || s.operator == nil || s.reverify == nil {
		return refuse(fmt.Errorf("%s:signer-not-initialized", refusalPairingSignerEnrollment))
	}
	operatorKeyID, err := storeOperatorPairingKeyID(s.operator)
	if err != nil {
		return refuse(fmt.Errorf("%s:%v", refusalPairingSignerEnrollment, err))
	}
	request, err := decodeProviderPairingSignRequest(raw)
	if err != nil {
		return refuse(err)
	}
	message, digest, err := planProviderPairingAttestation(request, operatorKeyID)
	if err != nil {
		return refuse(err)
	}
	current, err := s.reverify(ctx)
	if err != nil {
		return refuse(fmt.Errorf("%s:%v", refusalPairingSignerEnrollment, err))
	}
	if current == nil || current.Public().SignPubkeyB58 != s.operator.Public().SignPubkeyB58 {
		return refuse(fmt.Errorf("%s:operator-changed", refusalPairingSignerEnrollment))
	}
	signature, err := signProviderPairingMessage(s.operator, message)
	if err != nil {
		return refuse(err)
	}
	sum := sha256.Sum256(message)
	return providerPairingSignResponse{
		Schema:         providerPairingSignerSchema,
		OperatorKeyID:  operatorKeyID,
		ProviderDigest: digest,
		MessageSHA256:  hex.EncodeToString(sum[:]),
		Attestation: &providerOperatorPairingAttestation{
			Algorithm:                "ed25519",
			KeyID:                    operatorKeyID,
			DelegatedInventorySigner: request.DelegatedInventorySigner,
			Signature:                signature,
		},
	}
}

// runProviderPairingSignerSubcommand serves the signer on one local socket.
// Its first action past the enrollment gate is checking the socket path.
func runProviderPairingSignerSubcommand(args []string) {
	fs := flag.NewFlagSet("provider-pairing-signer", flag.ContinueOnError)
	configPath := fs.String("config", "store.config.json", "path to the rendered Store config (JSON)")
	socketPath := fs.String("socket", "", "absolute Unix socket path in a directory only this user can enter")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("provider-pairing-signer: %v", err)
	}
	if fs.NArg() != 0 || strings.TrimSpace(*socketPath) == "" {
		log.Fatalf("provider-pairing-signer: -socket is required and no other arguments are accepted")
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("provider-pairing-signer: config: %v", err)
	}
	if err := setProgramIDFromConfig(cfg.ProgramID); err != nil {
		log.Fatalf("provider-pairing-signer: config: %v", err)
	}
	if cfg.RPCURL == "" {
		log.Fatalf("provider-pairing-signer: requires rpc_url")
	}
	cr := newConfiguredStoreRPCReader(cfg)
	gate := func(ctx context.Context) (*identity.Private, error) {
		gateCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		verified, state, err := deriveEnrolledBootIdentity(gateCtx, cfg, *configPath, cr)
		if err != nil {
			return nil, err
		}
		if err := requireProviderPairingSignerEnrollment(verified, state); err != nil {
			return nil, err
		}
		return verified.operator, nil
	}
	operator, err := gate(context.Background())
	if err != nil {
		log.Fatalf("provider-pairing-signer: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	signer := &providerPairingSigner{operator: operator, reverify: gate}
	if err := serveProviderPairingSignerSocket(ctx, *socketPath, signer); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatalf("provider-pairing-signer: %v", err)
	}
}

// requireProviderPairingSignerEnrollment refuses a legacy, unenrolled Store:
// the standard build's gate returns a nil state for one, and this signer acts
// only for an owner-enrolled Store in either build.
func requireProviderPairingSignerEnrollment(verified *verifiedBootIdentity, state *storeEnrollmentState) error {
	if verified == nil || verified.operator == nil {
		return errors.New(refusalPairingSignerEnrollment + ":no-write-capable-boot-identity")
	}
	if state == nil {
		return errors.New(refusalPairingSignerEnrollment + ":store-not-owner-enrolled")
	}
	return nil
}

// prepareProviderPairingSignerSocket checks the socket's directory and clears
// a stale socket this user owns. The directory must exist, be a real
// directory owned by this user, and admit neither group nor others.
func prepareProviderPairingSignerSocket(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s:socket path must be absolute and clean", refusalPairingSignerSocketUnsafe)
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%s:socket directory: %v", refusalPairingSignerSocketUnsafe, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || int(stat.Uid) != os.Getuid() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s:socket directory %s must be a directory owned by this user with no group or other access", refusalPairingSignerSocketUnsafe, dir)
	}
	existing, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s:%v", refusalPairingSignerSocketUnsafe, err)
	}
	existingStat, ok := existing.Sys().(*syscall.Stat_t)
	if existing.Mode()&os.ModeSocket == 0 || !ok || int(existingStat.Uid) != os.Getuid() {
		return fmt.Errorf("%s:refusing to replace a non-socket or foreign path at %s", refusalPairingSignerSocketUnsafe, path)
	}
	return os.Remove(path)
}

func serveProviderPairingSignerSocket(ctx context.Context, path string, signer *providerPairingSigner) error {
	if err := prepareProviderPairingSignerSocket(path); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close(); _ = os.Remove(path) }()
	if err := os.Chmod(path, providerPairingSignerSocketMode); err != nil {
		return err
	}
	log.Printf("provider-pairing-signer: serving %s on %s", providerPairingSignerKindV2, path)
	for {
		if err := listener.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return err
		}
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					continue
				}
			}
			return err
		}
		go serveProviderPairingSignerConnection(ctx, conn, signer)
	}
}

func serveProviderPairingSignerConnection(ctx context.Context, conn *net.UnixConn, signer *providerPairingSigner) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(providerPairingSignerTimeout))
	respond := func(response providerPairingSignResponse) { _ = json.NewEncoder(conn).Encode(response) }
	if err := requireSameUserUnixPeer(conn); err != nil {
		respond(providerPairingSignResponse{Schema: providerPairingSignerSchema, Error: refusalPairingSignerPeer + ":" + err.Error()})
		return
	}
	var raw json.RawMessage
	decoder := json.NewDecoder(io.LimitReader(conn, providerPairingSignerMaxMessage+1))
	if err := decoder.Decode(&raw); err != nil {
		respond(providerPairingSignResponse{Schema: providerPairingSignerSchema, Error: refusalPairingSignerRequestInvalid + ":json"})
		return
	}
	requestCtx, cancel := context.WithTimeout(ctx, providerPairingSignerTimeout)
	defer cancel()
	response := signer.sign(requestCtx, raw)
	if response.Error != "" {
		log.Printf("provider-pairing-signer: refused: %s", response.Error)
	} else {
		log.Printf("provider-pairing-signer: signed V2 attestation %s for %s", response.MessageSHA256, response.ProviderDigest)
	}
	respond(response)
}

// requireSameUserUnixPeer accepts only a peer running as this process's user.
func requireSameUserUnixPeer(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var peer *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		peer, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if controlErr != nil || peer == nil || int(peer.Uid) != os.Getuid() {
		return errors.New("peer is not the local store user")
	}
	return nil
}

// runProviderPairingAttestSubcommand is the operator's client. It derives no
// operator: it sends one request file to the signer, verifies the returned
// attestation against the expected Store operator key and the V2 message it
// rebuilds itself, and prints the attestation the target pairing rail takes.
func runProviderPairingAttestSubcommand(args []string) {
	fs := flag.NewFlagSet("provider-pairing-attest", flag.ContinueOnError)
	socketPath := fs.String("socket", "", "the provider-pairing-signer's absolute Unix socket path")
	requestPath := fs.String("request", "", "the "+providerPairingSignerSchema+" request JSON")
	expectKeyID := fs.String("expect-keyid", "", "the enrolled Store operator key, as an ed25519: key ID")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("provider-pairing-attest: %v", err)
	}
	if fs.NArg() != 0 || *socketPath == "" || *requestPath == "" || *expectKeyID == "" {
		log.Fatalf("provider-pairing-attest: -socket, -request and -expect-keyid are required")
	}
	raw, err := readBoundedInput(*requestPath, providerPairingSignerMaxMessage)
	if err != nil {
		log.Fatalf("provider-pairing-attest: read request: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), providerPairingSignerTimeout+5*time.Second)
	defer cancel()
	report, err := requestProviderPairingAttestation(ctx, *socketPath, raw, *expectKeyID)
	if err != nil {
		log.Fatalf("provider-pairing-attest: %v", err)
	}
	printJSONReport("provider-pairing-attest", report)
}

// requestProviderPairingAttestation checks the request locally, asks the
// signer, and accepts only an attestation that verifies against expectKeyID
// over the message it rebuilds from the request.
func requestProviderPairingAttestation(ctx context.Context, socketPath string, raw []byte, expectKeyID string) (providerPairingSignResponse, error) {
	var zero providerPairingSignResponse
	operatorKey, ok := decodeCanonicalPairingKeyID(expectKeyID)
	if !ok {
		return zero, fmt.Errorf("%s:expect-keyid", refusalPairingSignerKeyIDInvalid)
	}
	request, err := decodeProviderPairingSignRequest(raw)
	if err != nil {
		return zero, err
	}
	message, digest, err := planProviderPairingAttestation(request, expectKeyID)
	if err != nil {
		return zero, err
	}
	if err := verifyProviderPairingSignerSocket(socketPath); err != nil {
		return zero, err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return zero, fmt.Errorf("connect provider pairing signer: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(raw); err != nil {
		return zero, fmt.Errorf("write provider pairing signer request: %w", err)
	}
	var response providerPairingSignResponse
	decoder := json.NewDecoder(io.LimitReader(conn, providerPairingSignerMaxMessage))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return zero, fmt.Errorf("%s:read: %v", refusalPairingSignerResponseInvalid, err)
	}
	if response.Schema != providerPairingSignerSchema {
		return zero, fmt.Errorf("%s:schema", refusalPairingSignerResponseInvalid)
	}
	if response.Error != "" {
		return zero, errors.New(response.Error)
	}
	sum := sha256.Sum256(message)
	attestation := response.Attestation
	if attestation == nil || attestation.Algorithm != "ed25519" || attestation.KeyID != expectKeyID || response.OperatorKeyID != expectKeyID ||
		attestation.DelegatedInventorySigner != request.DelegatedInventorySigner || response.ProviderDigest != digest || response.MessageSHA256 != hex.EncodeToString(sum[:]) {
		return zero, fmt.Errorf("%s:binding", refusalPairingSignerResponseInvalid)
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(attestation.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(operatorKey, message, signature) {
		return zero, fmt.Errorf("%s:signature", refusalPairingSignerResponseInvalid)
	}
	return response, nil
}

// verifyProviderPairingSignerSocket accepts only a mode-0600 socket owned by
// this user.
func verifyProviderPairingSignerSocket(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s:socket path is not absolute", refusalPairingSignerSocketUnsafe)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s:%v", refusalPairingSignerSocketUnsafe, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != providerPairingSignerSocketMode || !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("%s:%s must be a mode-0600 socket owned by this user", refusalPairingSignerSocketUnsafe, path)
	}
	return nil
}
