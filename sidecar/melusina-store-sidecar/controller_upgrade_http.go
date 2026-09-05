package main

// This file owns the only HTTP surface for a first-class Fineract controller
// replacement. It is deliberately separate from the historical host-apply
// route: that route can only derive a Fineract-v2 sidecar plan and one-shot
// sidecar receipt. A controller replacement has a different component class,
// a receiver-local freshness challenge, and a different signed wire contract.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/pkg/controllerupgrade"
)

const (
	controllerUpgradeIssuePathPrefix   = "/control/v1/controller-upgrades/"
	controllerUpgradeReceiptPathPrefix = "/update/controller-upgrades/"
	controllerUpgradePlanPathSuffix    = "/plan"
	controllerUpgradeProofPathSuffix   = "/proof"

	controllerUpgradePlanResultSchema  = "bazaar-control-controller-upgrade-plan-result-v1"
	controllerUpgradeProofResultSchema = "bazaar-control-controller-upgrade-proof-result-v1"
	controllerUpgradeFreshnessHeader   = "X-Melusina-Controller-Upgrade-Challenge"
)

type controllerUpgradePlanResult struct {
	Schema     string        `json:"schema"`
	DossierID  string        `json:"dossierId"`
	Plan       hostApplyPlan `json:"plan"`
	PlanDigest string        `json:"planDigest"`
	Memo       string        `json:"memo"`
	ExpiresAt  time.Time     `json:"expiresAt"`
}

type controllerUpgradeProofResult struct {
	Schema      string    `json:"schema"`
	DossierID   string    `json:"dossierId"`
	PlanDigest  string    `json:"planDigest"`
	ProofDigest string    `json:"proofDigest"`
	ReceiptID   string    `json:"receiptId"`
	ReceiptURL  string    `json:"receiptUrl"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

func controllerUpgradePlanDossier(path, rawQuery, suffix string) (string, error) {
	if rawQuery != "" || !strings.HasPrefix(path, controllerUpgradeIssuePathPrefix) || !strings.HasSuffix(path, suffix) {
		return "", errors.New("not a controller upgrade route")
	}
	dossier := strings.TrimSuffix(strings.TrimPrefix(path, controllerUpgradeIssuePathPrefix), suffix)
	if strings.Contains(dossier, "/") || !isLowerHex(dossier, 24) {
		return "", errors.New("controller upgrade route must name one canonical dossier")
	}
	return dossier, nil
}

func controllerUpgradeReceiptID(path, rawQuery string) (string, error) {
	if rawQuery != "" || !strings.HasPrefix(path, controllerUpgradeReceiptPathPrefix) {
		return "", errors.New("not a controller upgrade receipt route")
	}
	name := strings.TrimPrefix(path, controllerUpgradeReceiptPathPrefix)
	if strings.Contains(name, "/") || !strings.HasSuffix(name, ".json") {
		return "", errors.New("controller upgrade receipt route must name one file")
	}
	id := strings.TrimSuffix(name, ".json")
	if !isLowerHex(id, 64) {
		return "", errors.New("controller upgrade receipt name is not canonical")
	}
	return id, nil
}

func controllerUpgradeReceiptReferenceID(plan hostApplyPlan, proof hostApplySquadsProof) string {
	return hostApplyDigest([]string{controllerUpgradeReceiptReferenceSchema, plan.Digest(), proof.Digest()})
}

func controllerUpgradePlanResultFromRecord(record hostApplyPlanRecord) controllerUpgradePlanResult {
	return controllerUpgradePlanResult{
		Schema: controllerUpgradePlanResultSchema, DossierID: record.Plan.DossierID,
		Plan: record.Plan, PlanDigest: record.PlanDigest, Memo: record.Plan.Memo(), ExpiresAt: record.Plan.ExpiresAt,
	}
}

func (s *publishService) handleControllerUpgradeRoute(w http.ResponseWriter, r *http.Request) {
	if err := s.hostApplyPlanReadinessError(); err != nil {
		http.Error(w, "controller upgrade plan is unavailable", http.StatusServiceUnavailable)
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		http.Error(w, "check=request: content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if rejectReceiveBypass(w) {
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, controllerUpgradePlanPathSuffix):
		s.handleControllerUpgradePlan(w, r)
	case strings.HasSuffix(r.URL.Path, controllerUpgradeProofPathSuffix):
		s.handleControllerUpgradeProof(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *publishService) handleControllerUpgradePlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dossierID, err := controllerUpgradePlanDossier(r.URL.Path, r.URL.RawQuery, controllerUpgradePlanPathSuffix)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := parseExactHostApplyPlanBody(r); err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.currentTime().UTC().Truncate(time.Second)
	facts, err := fetchControllerUpgradeCurrentFacts(r.Context(), s)
	if err != nil {
		http.Error(w, "check=current_facts: "+err.Error(), http.StatusConflict)
		return
	}
	if record, found, err := s.hostApplyPlans.loadPlan(dossierID); err != nil {
		http.Error(w, "check=plan: "+err.Error(), http.StatusConflict)
		return
	} else if found {
		if err := verifyControllerUpgradePlanAgainstFacts(record.Plan, facts, now); err != nil {
			http.Error(w, "check=current_facts: "+err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(controllerUpgradePlanResultFromRecord(record))
		return
	}
	plan, err := controllerUpgradePlanFromFacts(dossierID, facts, now)
	if err != nil {
		http.Error(w, "check=plan: "+err.Error(), http.StatusConflict)
		return
	}
	record := hostApplyPlanRecord{Schema: hostApplyPlanRecordSchema, Plan: plan, PlanDigest: plan.Digest(), CreatedAt: now}
	record, _, err = s.hostApplyPlans.createPlan(record)
	if err != nil {
		http.Error(w, "check=plan: "+err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(controllerUpgradePlanResultFromRecord(record))
}

func (s *publishService) handleControllerUpgradeProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dossierID, err := controllerUpgradePlanDossier(r.URL.Path, r.URL.RawQuery, controllerUpgradeProofPathSuffix)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	request, err := parseHostApplyProofRequest(r)
	if err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.currentTime().UTC().Truncate(time.Second)
	planRecord, found, err := s.hostApplyPlans.loadPlan(dossierID)
	if err != nil || !found {
		if err != nil {
			http.Error(w, "check=plan: "+err.Error(), http.StatusConflict)
		} else {
			http.NotFound(w, r)
		}
		return
	}
	if planRecord.PlanDigest != request.PlanDigest {
		http.Error(w, "check=plan: supplied plan digest does not match dossier", http.StatusForbidden)
		return
	}
	facts, err := fetchControllerUpgradeCurrentFacts(r.Context(), s)
	if err != nil {
		http.Error(w, "check=current_facts: "+err.Error(), http.StatusConflict)
		return
	}
	if err := verifyControllerUpgradePlanAgainstFacts(planRecord.Plan, facts, now); err != nil {
		http.Error(w, "check=current_facts: "+err.Error(), http.StatusConflict)
		return
	}
	proof, err := verifyHostApplySquadsProof(r.Context(), s.cr, planRecord.Plan, request.ExecutionSignature, now)
	if err != nil {
		http.Error(w, "check=squads_proof: "+err.Error(), http.StatusForbidden)
		return
	}
	proofRecord := hostApplyProofRecord{Schema: hostApplyProofRecordSchema, Proof: proof, ProofDigest: proof.Digest(), CreatedAt: now}
	if existing, found, err := s.hostApplyPlans.loadProof(planRecord.PlanDigest, planRecord.Plan); err != nil {
		http.Error(w, "check=proof: "+err.Error(), http.StatusConflict)
		return
	} else if found {
		if existing.Proof.ExecutionSignature != request.ExecutionSignature || existing.ProofDigest != proofRecord.ProofDigest {
			http.Error(w, "check=proof: plan is already bound to different immutable proof facts", http.StatusConflict)
			return
		}
		proofRecord = existing
	} else if proofRecord, _, err = s.hostApplyPlans.createProof(proofRecord, planRecord.Plan); err != nil {
		http.Error(w, "check=proof: "+err.Error(), http.StatusConflict)
		return
	}
	reference := controllerUpgradeReceiptReference{
		Schema:    controllerUpgradeReceiptReferenceSchema,
		ReceiptID: controllerUpgradeReceiptReferenceID(planRecord.Plan, proofRecord.Proof),
		DossierID: dossierID, PlanDigest: planRecord.PlanDigest, ProofDigest: proofRecord.ProofDigest,
		CreatedAt: now,
	}
	reference, _, err = s.hostApplyPlans.createControllerUpgradeReceiptReference(reference, planRecord.Plan, proofRecord.Proof)
	if err != nil {
		http.Error(w, "check=receipt_reference: "+err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(controllerUpgradeProofResult{
		Schema: controllerUpgradeProofResultSchema, DossierID: dossierID,
		PlanDigest: planRecord.PlanDigest, ProofDigest: proofRecord.ProofDigest,
		ReceiptID:  reference.ReceiptID,
		ReceiptURL: strings.TrimRight(s.cfg.PublicBaseURL, "/") + controllerUpgradeReceiptPathPrefix + reference.ReceiptID + ".json",
		ExpiresAt:  planRecord.Plan.ExpiresAt,
	})
}

func validControllerUpgradeChallenge(r *http.Request) (string, bool) {
	values := r.Header.Values(controllerUpgradeFreshnessHeader)
	if len(values) != 1 || !isLowerHex(values[0], 64) {
		return "", false
	}
	return values[0], true
}

func (s *publishService) makeControllerUpgradeReceipt(plan hostApplyPlan, proof hostApplySquadsProof, receiptID, challenge string, now time.Time) (controllerupgrade.Receipt, error) {
	var zero controllerupgrade.Receipt
	if !isLowerHex(receiptID, 64) || !isLowerHex(challenge, 64) {
		return zero, errors.New("controller upgrade receipt has an invalid identity or receiver challenge")
	}
	expiresAtUnix, err := minHostApplyReceiptExpiry(now, plan.ExpiresAt)
	if err != nil {
		return zero, err
	}
	operatorKey, err := operatorSignPublicKey(s.operator)
	if err != nil {
		return zero, err
	}
	receipt := controllerupgrade.Receipt{
		Schema:                 controllerupgrade.ReceiptSchema,
		ReceiptID:              receiptID,
		TenantLicenseNftMint:   plan.TargetLicenseNftMint,
		TargetControllerID:     controllerupgrade.TargetControllerID,
		CandidateVersion:       plan.ComponentVersion,
		CandidateArtifactName:  plan.CandidateArtifactName,
		CandidateSHA256:        plan.ComponentSHA256,
		CandidateSizeBytes:     plan.CandidateSizeBytes,
		ExpectedPreviousSHA256: plan.ExpectedPreviousSHA256,
		InstallerReleasePDA:    plan.InstallerReleasePDA,
		InstallerReleaseSHA256: plan.InstallerReleaseSHA256,
		PlanDigest:             plan.Digest(),
		SquadsProofDigest:      proof.Digest(),
		RequiredFlags:          append([]string(nil), controllerupgrade.RequiredControllerFlags...),
		Challenge:              challenge,
		IssuedAtUnix:           now.Unix(),
		ExpiresAtUnix:          expiresAtUnix,
		SignerPublicKey:        base64.RawURLEncoding.EncodeToString(operatorKey),
	}
	signature := s.operator.Sign([]byte(receipt.SigningText()))
	if len(signature) != ed25519.SignatureSize {
		return zero, errors.New("Store operator returned an invalid controller receipt signature")
	}
	receipt.Signature = base64.RawURLEncoding.EncodeToString(signature)
	if err := receipt.Verify(controllerupgrade.VerificationConfig{
		TenantLicenseNftMint:  plan.TargetLicenseNftMint,
		StoreReceiptPublicKey: receipt.SignerPublicKey,
		Now:                   func() time.Time { return now },
	}, challenge); err != nil {
		return zero, fmt.Errorf("self-verify controller upgrade receipt: %w", err)
	}
	return receipt, nil
}

func (s *publishService) loadAndRevalidateControllerUpgradeReceipt(ctx context.Context, receiptID, challenge string, now time.Time) (controllerupgrade.Receipt, error) {
	var zero controllerupgrade.Receipt
	reference, found, err := s.hostApplyPlans.loadControllerUpgradeReceiptReference(receiptID)
	if err != nil || !found {
		if err != nil {
			return zero, err
		}
		return zero, errors.New("controller upgrade receipt reference is not found")
	}
	planRecord, found, err := s.hostApplyPlans.loadPlan(reference.DossierID)
	if err != nil || !found || planRecord.PlanDigest != reference.PlanDigest {
		return zero, errors.New("controller upgrade receipt reference has no matching immutable plan")
	}
	proofRecord, found, err := s.hostApplyPlans.loadProof(reference.PlanDigest, planRecord.Plan)
	if err != nil || !found || proofRecord.ProofDigest != reference.ProofDigest {
		return zero, errors.New("controller upgrade receipt reference has no matching immutable Squads proof")
	}
	if err := reference.Validate(planRecord.Plan, proofRecord.Proof); err != nil {
		return zero, err
	}
	facts, err := fetchControllerUpgradeCurrentFacts(ctx, s)
	if err != nil {
		return zero, err
	}
	if err := verifyControllerUpgradePlanAgainstFacts(planRecord.Plan, facts, now); err != nil {
		return zero, err
	}
	observedProof, err := verifyHostApplySquadsProof(ctx, s.cr, planRecord.Plan, proofRecord.Proof.ExecutionSignature, now)
	if err != nil || observedProof.Digest() != proofRecord.ProofDigest {
		if err == nil {
			err = errors.New("finalized Squads proof no longer matches its retained immutable record")
		}
		return zero, err
	}
	return s.makeControllerUpgradeReceipt(planRecord.Plan, proofRecord.Proof, reference.ReceiptID, challenge, now)
}

// handleControllerUpgradeReceipt is the sole public leg of the controller
// upgrade process. It has no browser-supplied target data: the receiver knows
// the fixed origin and sends its locally generated challenge. Every GET
// rechecks the plan, active generation, artifact attestations, and finalized
// Squads proof before Store signs a response bound to that exact challenge.
func (s *publishService) handleControllerUpgradeReceipt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	receiptID, err := controllerUpgradeReceiptID(r.URL.Path, r.URL.RawQuery)
	challenge, challengeOK := validControllerUpgradeChallenge(r)
	if err != nil || !challengeOK || s == nil || s.hostApplyPlans == nil || s.hostApplyPlanErr != nil {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.loadAndRevalidateControllerUpgradeReceipt(r.Context(), receiptID, challenge, s.currentTime().UTC().Truncate(time.Second))
	if err != nil {
		// The endpoint deliberately does not reveal whether a historic receipt
		// reference exists, expired, was revoked, or failed live verification.
		http.NotFound(w, r)
		return
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		http.Error(w, "controller upgrade receipt unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Vary", controllerUpgradeFreshnessHeader)
	w.Header().Set(controllerUpgradeFreshnessHeader, challenge)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
