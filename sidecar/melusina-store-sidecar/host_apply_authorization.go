package main

// Host-apply authorization is deliberately distinct from Bazaar app-release
// authorization.  An app release is a catalog selection; this authorizes the
// Store to issue one short-lived controller receipt for an already-attested
// Fineract binary.  Reusing a publisher grant, controlCommand, or
// stableReleaseAuthorization here would be authority type confusion.

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

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const (
	hostApplyAuthorizationSchema = "bazaar-control-host-apply-authorization-v1"
	// A governance decision may outlive its short transport envelope while a
	// Squads/browser review completes.  The Store still rebinds it to the
	// current verified generation and current chain state at issuance; the
	// downstream one-shot receipt is only fifteen minutes.
	maxHostApplyAuthorizationTTL = 30 * 24 * time.Hour
	hostApplyAuthorizationSkew   = 2 * time.Minute

	hostApplyFineractControllerID = "fineract-controller"
	hostApplyFineractComponentID  = "fineract-sidecar"
)

// hostApplyAuthorization is the policy-human approval supplied to the private
// Store control surface. ProposalDigest is an audit binding for the governing
// external decision; the current StoreControlPolicy exposes one human approval
// key, so this verifier deliberately calls it policy-human authorization rather
// than claiming it independently proves a Squads quorum.
type hostApplyAuthorization struct {
	Schema                 string    `json:"schema"`
	DossierID              string    `json:"dossierId"`
	StorePolicy            string    `json:"storePolicy"`
	PolicyEpoch            uint64    `json:"policyEpoch"`
	TargetControllerID     string    `json:"targetControllerId"`
	TargetLicenseNftMint   string    `json:"targetLicenseNftMint"`
	ComponentID            string    `json:"componentId"`
	GenerationID           uint64    `json:"generationId"`
	GenerationHash         string    `json:"generationHash"`
	RawGenerationSHA256    string    `json:"rawGenerationSha256"`
	ComponentDigest        string    `json:"componentDigest"`
	ComponentSHA256        string    `json:"componentSha256"`
	ComponentVersion       string    `json:"componentVersion"`
	ExpectedPreviousSHA256 string    `json:"expectedPreviousSha256"`
	ProposalDigest         string    `json:"proposalDigest"`
	IssuedAt               time.Time `json:"issuedAt"`
	ExpiresAt              time.Time `json:"expiresAt"`
	SignerPublicKey        string    `json:"signerPublicKey"`
	Signature              string    `json:"signature"`
	SignedAt               time.Time `json:"signedAt"`
}

func hostApplyDigest(parts []string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(fmt.Sprintf("%d:", len(part))))
		_, _ = h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (a hostApplyAuthorization) Digest() string {
	return hostApplyDigest([]string{
		a.Schema, a.DossierID, a.StorePolicy, fmt.Sprint(a.PolicyEpoch),
		a.TargetControllerID, a.TargetLicenseNftMint, a.ComponentID,
		fmt.Sprint(a.GenerationID), a.GenerationHash, a.RawGenerationSHA256,
		a.ComponentDigest, a.ComponentSHA256, a.ComponentVersion,
		a.ExpectedPreviousSHA256, a.ProposalDigest,
		a.IssuedAt.UTC().Format(time.RFC3339Nano), a.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
}

func (a hostApplyAuthorization) HumanSigningText() string {
	return strings.Join([]string{
		"Bazaar host apply authorization",
		"Action: authorize ONE controlled Fineract binary apply",
		"Store policy: " + a.StorePolicy,
		"Controller: " + a.TargetControllerID,
		"Component: " + a.ComponentID,
		"Generation: " + fmt.Sprint(a.GenerationID),
		"Served generation: " + a.RawGenerationSHA256,
		"Artifact: " + a.ComponentSHA256,
		"Previous artifact: " + a.ExpectedPreviousSHA256,
		"Governance proposal: " + a.ProposalDigest,
		"Expires: " + a.ExpiresAt.UTC().Format(time.RFC3339),
		"Authorization digest: " + a.Digest(),
	}, "\n")
}

func safeHostApplyToken(s string) bool {
	if s == "" || len(s) > 128 || s[0] == '.' || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

func (a hostApplyAuthorization) Validate(now time.Time) error {
	if a.Schema != hostApplyAuthorizationSchema {
		return errors.New("unknown host apply authorization schema")
	}
	if !isLowerHex(a.DossierID, 24) || a.PolicyEpoch == 0 || a.GenerationID == 0 {
		return errors.New("host apply authorization has invalid dossier, policy epoch, or generation id")
	}
	for label, value := range map[string]string{
		"store policy": a.StorePolicy, "target license mint": a.TargetLicenseNftMint,
		"component version": a.ComponentVersion,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("host apply authorization %s is required", label)
		}
	}
	if !safeHostApplyToken(a.TargetControllerID) || !safeHostApplyToken(a.ComponentID) ||
		a.TargetControllerID != hostApplyFineractControllerID || a.ComponentID != hostApplyFineractComponentID {
		return errors.New("host apply authorization is not scoped to the governed Fineract controller/component")
	}
	for label, value := range map[string]string{
		"generation hash": a.GenerationHash, "raw generation sha256": a.RawGenerationSHA256,
		"component digest": a.ComponentDigest, "component sha256": a.ComponentSHA256,
		"expected previous sha256": a.ExpectedPreviousSHA256, "proposal digest": a.ProposalDigest,
	} {
		if !isLowerHex(value, 64) {
			return fmt.Errorf("host apply authorization %s is not canonical", label)
		}
	}
	now = now.UTC()
	if a.IssuedAt.IsZero() || a.ExpiresAt.IsZero() || a.IssuedAt.After(now.Add(hostApplyAuthorizationSkew)) ||
		!a.ExpiresAt.After(a.IssuedAt) || !a.ExpiresAt.After(now) || a.ExpiresAt.Sub(a.IssuedAt) > maxHostApplyAuthorizationTTL {
		return errors.New("host apply authorization is expired or has an invalid time window")
	}
	return nil
}

// verifyHostApplyAuthorization verifies the current policy's human approval
// key against one exact host-apply decision.  The caller separately re-reads
// StoreOperator authorization, the desired generation, and chain attestation
// under the Store single-writer lock before issuing a controller receipt.
func verifyHostApplyAuthorization(a hostApplyAuthorization, policy storeControlPolicyMeta, now time.Time) error {
	if err := a.Validate(now); err != nil {
		return err
	}
	if !policy.Active || policy.PolicyEpoch != a.PolicyEpoch || policy.PDA != a.StorePolicy {
		return errors.New("host apply authorization does not match the active Store control policy")
	}
	if a.SignedAt.IsZero() || a.SignedAt.Before(a.IssuedAt.Add(-hostApplyAuthorizationSkew)) ||
		a.SignedAt.After(a.ExpiresAt) || a.SignedAt.After(now.UTC().Add(hostApplyAuthorizationSkew)) {
		return errors.New("host apply authorization has an invalid signing time")
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(a.SignerPublicKey))
	if err != nil || len(key) != ed25519.PublicKeySize || subtle.ConstantTimeCompare(key, policy.HumanApprovalPublicKey[:]) != 1 {
		return errors.New("host apply authorization is not from the active policy human signer")
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(a.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), []byte(a.HumanSigningText()), sig) {
		return errors.New("host apply authorization signature is invalid")
	}
	return nil
}

// oneShotFromHostApply maps only Store-derived facts into the downstream
// controller receipt.  The caller supplies the fresh nonce/times and signs it
// with the Store operator after independently proving the current generation.
func oneShotFromHostApply(a hostApplyAuthorization, storeID, authorizationID string, issuedAtUnix, expiresAtUnix int64) componentrelease.OneShotApplyAuthorization {
	return componentrelease.OneShotApplyAuthorization{
		AuthorizationID:         authorizationID,
		StoreID:                 storeID,
		TargetControllerID:      a.TargetControllerID,
		TargetLicenseNftMint:    a.TargetLicenseNftMint,
		ComponentID:             a.ComponentID,
		GenerationID:            a.GenerationID,
		GenerationHash:          a.GenerationHash,
		RawGenerationSHA256:     a.RawGenerationSHA256,
		ComponentDigest:         a.ComponentDigest,
		ComponentSHA256:         a.ComponentSHA256,
		ComponentVersion:        a.ComponentVersion,
		PreviousSHA256:          a.ExpectedPreviousSHA256,
		IssuedAtUnix:            issuedAtUnix,
		ExpiresAtUnix:           expiresAtUnix,
		GovernanceReceiptID:     a.DossierID,
		GovernanceReceiptSHA256: a.Digest(),
	}
}
