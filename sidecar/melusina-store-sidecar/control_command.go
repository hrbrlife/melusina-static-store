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
	pearlCommandSignatureSchema   = "bazaar-control-pearl-signature-v1"
	controlCommandActionPublish   = "publish_release"
	maxControlCommandTTL          = 15 * time.Minute
	controlCommandClockSkew       = 2 * time.Minute
	controlCommandSignaturePrefix = "bazaar-control-sidecar-command-v1\x00"
)

type controlCommand struct {
	Schema               string    `json:"schema"`
	CommandID            string    `json:"commandId"`
	DossierID            string    `json:"dossierId"`
	Action               string    `json:"action"`
	Route                string    `json:"route"`
	Method               string    `json:"method"`
	StorePolicy          string    `json:"storePolicy"`
	PolicyEpoch          uint64    `json:"policyEpoch"`
	PublisherGrant       string    `json:"publisherGrant"`
	GrantEpoch           uint64    `json:"grantEpoch"`
	PublisherIntentHash  string    `json:"publisherIntentHash"`
	AppID                string    `json:"appId"`
	Version              string    `json:"version"`
	ArtifactSHA256       string    `json:"artifactSha256"`
	AppHash              string    `json:"appHash"`
	ReleaseHash          string    `json:"releaseHash"`
	ExpectedPriorAppHash string    `json:"expectedPriorAppHash"`
	StageID              string    `json:"stageId"`
	IssuedAt             time.Time `json:"issuedAt"`
	ExpiresAt            time.Time `json:"expiresAt"`
	Nonce                string    `json:"nonce"`
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

type storeControlPolicyMeta struct {
	PDA                        string
	LicenseNFTMint             [32]byte
	StoreDomainHash            [32]byte
	StoreAuthority             [32]byte
	StoreOperatorAuthorization [32]byte
	PearlCommandPublicKey      [32]byte
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
	if c.Schema != controlCommandSchema {
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
	if !isLowerHex(c.CommandID, 24) || !isLowerHex(c.Nonce, 24) {
		return errors.New("control command id or nonce is not canonical")
	}
	if c.Action != controlCommandActionPublish || c.Method != "POST" || c.Route != "/control/v1/releases/"+c.DossierID+"/publish" {
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
	if !grant.Active || grant.Policy != command.StorePolicy || grant.PDA != command.PublisherGrant || grant.GrantEpoch != command.GrantEpoch || grant.AppID != facts.AppID || grant.PublisherSquadsVault != facts.PublisherSquadsVault || grant.PublisherEd25519Pubkey != facts.PublisherEd25519PublicKey || grant.Actions&storePublisherActionPublishRelease == 0 || now.UTC().Before(grant.NotBefore) || !now.UTC().Before(grant.ExpiresAt) {
		return errors.New("control command publisher grant is not active for this release")
	}
	return nil
}

const storePublisherActionPublishRelease uint16 = 1 << 1
