package main

// Stable release authorization separates a human release decision from the
// short-lived publisher envelope used at final transport. The latter expires
// within 30 minutes; a real Squads quorum may not. This type intentionally
// binds the staged/proposed release and omits every ephemeral transport field.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	stableReleaseAuthorizationSchema = "bazaar-control-release-authorization-v1"
	maxStableReleaseAuthorizationTTL = 30 * 24 * time.Hour
	stableAuthorizationClockSkew     = 2 * time.Minute
)

type stableReleaseAuthorization struct {
	Schema               string    `json:"schema"`
	DossierID            string    `json:"dossierId"`
	StorePolicy          string    `json:"storePolicy"`
	PolicyEpoch          uint64    `json:"policyEpoch"`
	PublisherGrant       string    `json:"publisherGrant"`
	GrantEpoch           uint64    `json:"grantEpoch"`
	AppID                string    `json:"appId"`
	Version              string    `json:"version"`
	ArtifactSHA256       string    `json:"artifactSha256"`
	AppHash              string    `json:"appHash"`
	ReleaseHash          string    `json:"releaseHash"`
	ExpectedPriorAppHash string    `json:"expectedPriorAppHash"`
	StageID              string    `json:"stageId"`
	ProposalDigest       string    `json:"proposalDigest"`
	IssuedAt             time.Time `json:"issuedAt"`
	ExpiresAt            time.Time `json:"expiresAt"`
	SignerPublicKey      string    `json:"signerPublicKey"`
	Signature            string    `json:"signature"`
	SignedAt             time.Time `json:"signedAt"`
}

func (a stableReleaseAuthorization) Digest() string {
	return releaseAuthorizationDigest([]string{
		a.Schema, a.DossierID, a.StorePolicy, fmt.Sprint(a.PolicyEpoch),
		a.PublisherGrant, fmt.Sprint(a.GrantEpoch), a.AppID, a.Version,
		a.ArtifactSHA256, a.AppHash, a.ReleaseHash, a.ExpectedPriorAppHash,
		a.StageID, a.ProposalDigest, a.IssuedAt.UTC().Format(time.RFC3339Nano),
		a.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

func releaseAuthorizationDigest(parts []string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(fmt.Sprintf("%d:", len(part))))
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (a stableReleaseAuthorization) HumanSigningText() string {
	return strings.Join([]string{
		"Bazaar release authorization",
		"Action: authorize this exact release after its recorded Squads proposal executes",
		"Store: " + a.StorePolicy,
		"App: " + a.AppID,
		"Version: " + a.Version,
		"Artifact: " + a.ArtifactSHA256,
		"Release: " + a.ReleaseHash,
		"Previous release: " + a.ExpectedPriorAppHash,
		"Proposal: " + a.ProposalDigest,
		"Expires: " + a.ExpiresAt.UTC().Format(time.RFC3339),
		"Authorization digest: " + a.Digest(),
	}, "\n")
}

func (a stableReleaseAuthorization) Validate(now time.Time) error {
	if a.Schema != stableReleaseAuthorizationSchema {
		return errors.New("unknown stable release authorization schema")
	}
	for label, value := range map[string]string{
		"dossier id": a.DossierID, "store policy": a.StorePolicy,
		"publisher grant": a.PublisherGrant, "app": a.AppID,
		"version": a.Version, "artifact digest": a.ArtifactSHA256,
		"app hash": a.AppHash, "release hash": a.ReleaseHash,
		"stage": a.StageID, "proposal digest": a.ProposalDigest,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("stable release authorization %s is required", label)
		}
	}
	if !isLowerHex(a.DossierID, 24) || a.PolicyEpoch == 0 || a.GrantEpoch == 0 {
		return errors.New("stable release authorization has an invalid identity or policy binding")
	}
	for label, value := range map[string]string{
		"artifact digest": a.ArtifactSHA256, "app hash": a.AppHash,
		"release hash": a.ReleaseHash, "stage": a.StageID,
		"proposal digest": a.ProposalDigest,
	} {
		if !isLowerHex(value, 64) {
			return fmt.Errorf("stable release authorization %s is not canonical", label)
		}
	}
	if a.ExpectedPriorAppHash != "" && !isLowerHex(a.ExpectedPriorAppHash, 64) {
		return errors.New("stable release authorization previous release hash is not canonical")
	}
	now = now.UTC()
	if a.IssuedAt.IsZero() || a.ExpiresAt.IsZero() || a.IssuedAt.After(now.Add(stableAuthorizationClockSkew)) || !a.ExpiresAt.After(a.IssuedAt) || !a.ExpiresAt.After(now) || a.ExpiresAt.Sub(a.IssuedAt) > maxStableReleaseAuthorizationTTL {
		return errors.New("stable release authorization is expired or has an invalid time window")
	}
	return nil
}

func verifyStableReleaseAuthorization(authorization stableReleaseAuthorization, command controlCommand, policy storeControlPolicyMeta, now time.Time) error {
	if command.Schema != controlCommandSchemaV2 || command.Action != controlCommandActionPublish || command.ReleaseAuthorizationDigest != authorization.Digest() {
		return errors.New("stable release authorization does not bind this final control command")
	}
	if err := authorization.Validate(now); err != nil {
		return err
	}
	if authorization.DossierID != command.DossierID || authorization.StorePolicy != command.StorePolicy || authorization.PolicyEpoch != command.PolicyEpoch || authorization.PublisherGrant != command.PublisherGrant || authorization.GrantEpoch != command.GrantEpoch || authorization.AppID != command.AppID || authorization.Version != command.Version || authorization.ArtifactSHA256 != command.ArtifactSHA256 || authorization.AppHash != command.AppHash || authorization.ReleaseHash != command.ReleaseHash || authorization.ExpectedPriorAppHash != command.ExpectedPriorAppHash || authorization.StageID != command.StageID {
		return errors.New("stable release authorization does not bind the submitted release facts")
	}
	if authorization.SignedAt.IsZero() || authorization.SignedAt.Before(authorization.IssuedAt.Add(-stableAuthorizationClockSkew)) || authorization.SignedAt.After(authorization.ExpiresAt) || authorization.SignedAt.After(now.UTC().Add(stableAuthorizationClockSkew)) {
		return errors.New("stable release authorization has an invalid signing time")
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(authorization.SignerPublicKey))
	if err != nil || len(key) != ed25519.PublicKeySize || subtle.ConstantTimeCompare(key, policy.HumanApprovalPublicKey[:]) != 1 {
		return errors.New("stable release authorization is not from the policy human signer")
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(authorization.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), []byte(authorization.HumanSigningText()), signature) {
		return errors.New("stable release authorization signature is invalid")
	}
	return nil
}
