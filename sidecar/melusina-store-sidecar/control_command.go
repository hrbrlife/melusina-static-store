package main

// Typed Bazaar Control commands.
//
// This is the sidecar boundary for the Pearl, not a second general publishing
// API. A command describes one exact release and the sidecar independently
// verifies it against the active on-chain policy and publisher grant before it
// can call the existing package/chain/catalog gates.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	controlCommandSchema          = "bazaar-control-command-v1"
	controlCommandSchemaV2        = "bazaar-control-command-v2"
	pearlCommandSignatureSchema   = "bazaar-control-pearl-signature-v1"
	offlineApprovalSchema         = "bazaar-control-offline-approval-v1"
	controlCommandActionPrepare   = "prepare_release"
	controlCommandActionPublish   = "publish_release"
	maxControlCommandTTL          = 15 * time.Minute
	controlCommandClockSkew       = 2 * time.Minute
	controlCommandSignaturePrefix = "bazaar-control-sidecar-command-v1\x00"
)

type controlCommand struct {
	Schema              string `json:"schema"`
	CommandID           string `json:"commandId"`
	DossierID           string `json:"dossierId"`
	Action              string `json:"action"`
	Route               string `json:"route"`
	Method              string `json:"method"`
	StorePolicy         string `json:"storePolicy"`
	PolicyEpoch         uint64 `json:"policyEpoch"`
	PublisherGrant      string `json:"publisherGrant"`
	GrantEpoch          uint64 `json:"grantEpoch"`
	PublisherIntentHash string `json:"publisherIntentHash"`
	// ReleaseAuthorizationDigest appears only in v2. It binds a stable
	// human approval that deliberately excludes the short-lived publisher
	// envelope represented by PublisherIntentHash.
	ReleaseAuthorizationDigest string    `json:"releaseAuthorizationDigest,omitempty"`
	AppID                      string    `json:"appId"`
	Version                    string    `json:"version"`
	ArtifactSHA256             string    `json:"artifactSha256"`
	AppHash                    string    `json:"appHash"`
	ReleaseHash                string    `json:"releaseHash"`
	ExpectedPriorAppHash       string    `json:"expectedPriorAppHash"`
	StageID                    string    `json:"stageId"`
	IssuedAt                   time.Time `json:"issuedAt"`
	ExpiresAt                  time.Time `json:"expiresAt"`
	Nonce                      string    `json:"nonce"`
}

// pearlCommandSignature is the Pearl's machine signature. It is distinct from
// the human offline approval: the former proves this restricted control path
// produced the command; the latter proves a human approved the exact release.
type pearlCommandSignature struct {
	Schema        string    `json:"schema"`
	CommandDigest string    `json:"commandDigest"`
	Signature     string    `json:"signature"`
	SignedAt      time.Time `json:"signedAt"`
}

// offlineControlApproval is supplied by an offline signer after the Pearl has
// prepared the exact command. Its public key is chain-bound in the store
// policy; the Pearl machine key is deliberately insufficient on its own.
type offlineControlApproval struct {
	Schema          string    `json:"schema"`
	CommandDigest   string    `json:"commandDigest"`
	SignerPublicKey string    `json:"signerPublicKey"`
	Signature       string    `json:"signature"`
	SignedAt        time.Time `json:"signedAt"`
}

type storeControlPolicyMeta struct {
	PDA                        string
	LicenseNFTMint             [32]byte
	StoreDomainHash            [32]byte
	StoreAuthority             [32]byte
	StoreOperatorAuthorization [32]byte
	PearlCommandPublicKey      [32]byte
	HumanApprovalPublicKey     [32]byte
	PolicyEpoch                uint64
	Active                     bool
}

type storePublisherGrantMeta struct {
	PDA                    string
	Policy                 string
	AppID                  [32]byte
	PublisherSquadsVault   [32]byte
	PublisherEd25519Pubkey [32]byte
	Actions                uint16
	NotBefore              time.Time
	ExpiresAt              time.Time
	GrantEpoch             uint64
	Active                 bool
}

type controlCommandFacts struct {
	PolicyPDA                 string
	AppID                     [32]byte
	PublisherSquadsVault      [32]byte
	PublisherEd25519PublicKey [32]byte
}

func (c controlCommand) Validate(now time.Time) error {
	if c.Schema != controlCommandSchema && c.Schema != controlCommandSchemaV2 {
		return errors.New("unknown control command schema")
	}
	for label, value := range map[string]string{
		"command id": c.CommandID, "dossier id": c.DossierID, "store policy": c.StorePolicy,
		"publisher grant": c.PublisherGrant, "app": c.AppID, "version": c.Version,
		"publisher intent": c.PublisherIntentHash, "artifact digest": c.ArtifactSHA256,
		"app hash": c.AppHash, "release hash": c.ReleaseHash, "stage id": c.StageID,
		"nonce": c.Nonce,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("control command %s is required", label)
		}
	}
	if c.Schema == controlCommandSchemaV2 && !isLowerHex(c.ReleaseAuthorizationDigest, 64) {
		return errors.New("control command stable release authorization is not canonical")
	}
	if c.Schema == controlCommandSchemaV2 && c.Action != controlCommandActionPublish {
		return errors.New("v2 control command is valid only for final publication")
	}
	if c.Schema == controlCommandSchema && c.ReleaseAuthorizationDigest != "" {
		return errors.New("v1 control command carries a v2 stable release authorization")
	}
	if !isLowerHex(c.CommandID, 24) || !isLowerHex(c.Nonce, 24) {
		return errors.New("control command id or nonce is not canonical")
	}
	if c.Method != "POST" || !c.hasExpectedRoute() {
		return errors.New("control command has an invalid action target")
	}
	if c.PolicyEpoch == 0 || c.GrantEpoch == 0 {
		return errors.New("control command has no policy or grant epoch")
	}
	for label, value := range map[string]string{
		"publisher intent": c.PublisherIntentHash, "artifact digest": c.ArtifactSHA256,
		"app hash": c.AppHash, "release hash": c.ReleaseHash, "stage id": c.StageID,
	} {
		if !isLowerHex(value, 64) {
			return fmt.Errorf("control command %s is not a canonical digest", label)
		}
	}
	if c.ExpectedPriorAppHash != "" && !isLowerHex(c.ExpectedPriorAppHash, 64) {
		return errors.New("control command previous release hash is not canonical")
	}
	now = now.UTC()
	if c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() || c.IssuedAt.After(now.Add(controlCommandClockSkew)) || !c.ExpiresAt.After(c.IssuedAt) || !c.ExpiresAt.After(now) || c.ExpiresAt.Sub(c.IssuedAt) > maxControlCommandTTL {
		return errors.New("control command is expired or has an invalid time window")
	}
	return nil
}

func (c controlCommand) hasExpectedRoute() bool {
	switch c.Action {
	case controlCommandActionPrepare:
		return c.Route == "/control/v1/releases/"+c.DossierID+"/prepare"
	case controlCommandActionPublish:
		return c.Route == "/control/v1/releases/"+c.DossierID+"/publish"
	default:
		return false
	}
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// Digest mirrors Bazaar Control's length-delimited canonical digest. It avoids
// JSON field-order ambiguity across the Pearl and sidecar implementations.
func (c controlCommand) Digest() string {
	parts := []string{
		c.Schema, c.CommandID, c.DossierID, c.Action, c.Route, c.Method, c.StorePolicy,
		fmt.Sprint(c.PolicyEpoch), c.PublisherGrant, fmt.Sprint(c.GrantEpoch), c.PublisherIntentHash,
		c.AppID, c.Version, c.ArtifactSHA256, c.AppHash, c.ReleaseHash, c.ExpectedPriorAppHash,
		c.StageID, c.IssuedAt.UTC().Format(time.RFC3339Nano), c.ExpiresAt.UTC().Format(time.RFC3339Nano), c.Nonce,
	}
	if c.Schema == controlCommandSchemaV2 {
		parts = append(parts, c.ReleaseAuthorizationDigest)
	}
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(fmt.Sprintf("%d:", len(part))))
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func pearlCommandSignaturePayload(command controlCommand) []byte {
	return []byte(controlCommandSignaturePrefix + command.Digest())
}

// HumanSigningText deliberately describes the release a person is approving,
// not transaction bytes or sidecar implementation details. It is identical to
// the Pearl's offline-signature payload and ends in the complete command
// digest, which binds every omitted-looking field too.
func (c controlCommand) HumanSigningText() string {
	action := "publish this exact release"
	if c.Action == controlCommandActionPrepare {
		action = "prepare this exact release"
	}
	return strings.Join([]string{
		"Bazaar release approval",
		"Action: " + action,
		"Store: " + c.StorePolicy,
		"App: " + c.AppID,
		"Version: " + c.Version,
		"Artifact: " + c.ArtifactSHA256,
		"Release: " + c.ReleaseHash,
		"Previous release: " + c.ExpectedPriorAppHash,
		"Expires: " + c.ExpiresAt.UTC().Format(time.RFC3339),
		"Approval digest: " + c.Digest(),
	}, "\n")
}

func verifyOfflineControlApproval(command controlCommand, approval offlineControlApproval, policy storeControlPolicyMeta, now time.Time) error {
	if command.Action != controlCommandActionPublish {
		return errors.New("offline approval is required only for publish_release")
	}
	if approval.Schema != offlineApprovalSchema || approval.CommandDigest != command.Digest() || approval.SignedAt.IsZero() || approval.SignedAt.Before(command.IssuedAt.Add(-controlCommandClockSkew)) || approval.SignedAt.After(command.ExpiresAt) || approval.SignedAt.After(now.UTC().Add(controlCommandClockSkew)) {
		return errors.New("offline approval does not bind this exact live command")
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(approval.SignerPublicKey))
	if err != nil || len(key) != ed25519.PublicKeySize || !equal32(key, policy.HumanApprovalPublicKey[:]) {
		return errors.New("offline approval is not from the store policy's human signer")
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(approval.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(policy.HumanApprovalPublicKey[:]), []byte(command.HumanSigningText()), signature) {
		return errors.New("offline approval signature does not match this command")
	}
	return nil
}

func equal32(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func verifyPearlControlCommand(command controlCommand, signature pearlCommandSignature, policy storeControlPolicyMeta, grant storePublisherGrantMeta, facts controlCommandFacts, now time.Time) error {
	if err := command.Validate(now); err != nil {
		return err
	}
	if !policy.Active || policy.PolicyEpoch != command.PolicyEpoch || policy.PDA != command.StorePolicy || facts.PolicyPDA != command.StorePolicy {
		return errors.New("control command does not match the active store policy")
	}
	if signature.Schema != pearlCommandSignatureSchema || signature.CommandDigest != command.Digest() || signature.SignedAt.IsZero() || signature.SignedAt.Before(command.IssuedAt.Add(-controlCommandClockSkew)) || signature.SignedAt.After(command.ExpiresAt) || signature.SignedAt.After(now.UTC().Add(controlCommandClockSkew)) {
		return errors.New("control command signature does not bind this exact command")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signature.Signature))
	if err != nil || len(sigBytes) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(policy.PearlCommandPublicKey[:]), pearlCommandSignaturePayload(command), sigBytes) {
		return errors.New("control command signature is not valid for the active Pearl key")
	}
	requiredAction := storePublisherActionForControl(command.Action)
	if requiredAction == 0 || !grant.Active || grant.Policy != command.StorePolicy || grant.PDA != command.PublisherGrant || grant.GrantEpoch != command.GrantEpoch || grant.AppID != facts.AppID || grant.PublisherSquadsVault != facts.PublisherSquadsVault || grant.PublisherEd25519Pubkey != facts.PublisherEd25519PublicKey || grant.Actions&requiredAction == 0 || now.UTC().Before(grant.NotBefore) || !now.UTC().Before(grant.ExpiresAt) {
		return errors.New("control command publisher grant is not active for this release")
	}
	return nil
}

func storePublisherActionForControl(action string) uint16 {
	switch action {
	case controlCommandActionPrepare:
		return storePublisherActionPrepareRelease
	case controlCommandActionPublish:
		return storePublisherActionPublishRelease
	default:
		return 0
	}
}

const storePublisherActionPrepareRelease uint16 = 1 << 0
const storePublisherActionPublishRelease uint16 = 1 << 1
