package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const (
	hostApplyPlanPathSuffix    = "/plan"
	hostApplyProofPathSuffix   = "/proof"
	hostApplyPlanResultSchema  = "bazaar-control-host-apply-plan-result-v1"
	hostApplyProofResultSchema = "bazaar-control-host-apply-proof-result-v1"
	hostApplyFreshnessHeader   = "X-Melusina-One-Shot-Freshness"
)

type hostApplyPlanResult struct {
	Schema     string        `json:"schema"`
	DossierID  string        `json:"dossierId"`
	Plan       hostApplyPlan `json:"plan"`
	PlanDigest string        `json:"planDigest"`
	Memo       string        `json:"memo"`
	ExpiresAt  time.Time     `json:"expiresAt"`
}

type hostApplyProofRequest struct {
	PlanDigest         string `json:"planDigest"`
	ExecutionSignature string `json:"executionSignature"`
}

type hostApplyProofResult struct {
	Schema          string    `json:"schema"`
	DossierID       string    `json:"dossierId"`
	PlanDigest      string    `json:"planDigest"`
	ProofDigest     string    `json:"proofDigest"`
	AuthorizationID string    `json:"authorizationId"`
	ReceiptURL      string    `json:"receiptUrl"`
	ReceiptSHA256   string    `json:"receiptSha256"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

func hostApplyPlanDossier(path, rawQuery, suffix string) (string, error) {
	if rawQuery != "" || !strings.HasPrefix(path, hostApplyIssuePathPrefix) || !strings.HasSuffix(path, suffix) {
		return "", errors.New("not a host apply plan route")
	}
	dossier := strings.TrimSuffix(strings.TrimPrefix(path, hostApplyIssuePathPrefix), suffix)
	if strings.Contains(dossier, "/") || !isLowerHex(dossier, 24) {
		return "", errors.New("host apply plan route must name one canonical dossier")
	}
	return dossier, nil
}

func parseExactHostApplyPlanBody(r *http.Request) error {
	if err := limitPublishBody(r, maxHostApplyIssueBody); err != nil {
		return err
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	if err := assertNoDuplicateJSONKeys(raw); err != nil {
		return err
	}
	if string(bytes.TrimSpace(raw)) != "{}" {
		return errors.New("host apply plan request must be the exact empty JSON object")
	}
	return nil
}

func parseHostApplyProofRequest(r *http.Request) (hostApplyProofRequest, error) {
	var out hostApplyProofRequest
	if err := limitPublishBody(r, maxHostApplyIssueBody); err != nil {
		return out, err
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return out, err
	}
	if err := assertNoDuplicateJSONKeys(raw); err != nil {
		return out, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, err
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return out, errors.New("host apply proof request has trailing data")
	}
	if !isLowerHex(out.PlanDigest, 64) || !isCanonicalBase58(out.ExecutionSignature, 64) {
		return out, errors.New("host apply proof request has invalid canonical plan or execution reference")
	}
	return out, nil
}

func (s *publishService) hostApplyPlanReadinessError() error {
	if s == nil || s.operator == nil || s.cr == nil || s.hostApplyPlans == nil || s.hostApplyPlanErr != nil {
		return errors.New("host apply plan dependencies are unavailable")
	}
	return nil
}

func hostApplyPlanResultFromRecord(record hostApplyPlanRecord) hostApplyPlanResult {
	return hostApplyPlanResult{
		Schema: hostApplyPlanResultSchema, DossierID: record.Plan.DossierID, Plan: record.Plan,
		PlanDigest: record.PlanDigest, Memo: record.Plan.Memo(), ExpiresAt: record.Plan.ExpiresAt,
	}
}

func (s *publishService) handleHostApplyPlanRoute(w http.ResponseWriter, r *http.Request) {
	if err := s.hostApplyPlanReadinessError(); err != nil {
		http.Error(w, "host apply plan is unavailable", http.StatusServiceUnavailable)
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
	case strings.HasSuffix(r.URL.Path, hostApplyPlanPathSuffix):
		s.handleHostApplyPlan(w, r)
	case strings.HasSuffix(r.URL.Path, hostApplyProofPathSuffix):
		s.handleHostApplyProof(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *publishService) handleHostApplyPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dossierID, err := hostApplyPlanDossier(r.URL.Path, r.URL.RawQuery, hostApplyPlanPathSuffix)
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
	facts, err := fetchHostApplyCurrentFacts(r.Context(), s)
	if err != nil {
		http.Error(w, "check=current_facts: "+err.Error(), http.StatusConflict)
		return
	}
	if record, found, err := s.hostApplyPlans.loadPlan(dossierID); err != nil {
		http.Error(w, "check=plan: "+err.Error(), http.StatusConflict)
		return
	} else if found {
		if err := verifyHostApplyPlanAgainstFacts(record.Plan, facts, now); err != nil {
			http.Error(w, "check=current_facts: "+err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(hostApplyPlanResultFromRecord(record))
		return
	}
	plan, err := hostApplyPlanFromFacts(dossierID, facts, now)
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
	_ = json.NewEncoder(w).Encode(hostApplyPlanResultFromRecord(record))
}

func oneShotFromHostApplyPlan(plan hostApplyPlan, storeID, authorizationID string, issuedAtUnix, expiresAtUnix int64) componentrelease.OneShotApplyAuthorization {
	return componentrelease.OneShotApplyAuthorization{
		AuthorizationID: authorizationID, StoreID: storeID, TargetControllerID: plan.TargetControllerID,
		TargetLicenseNftMint: plan.TargetLicenseNftMint, ComponentID: plan.ComponentID,
		GenerationID: plan.GenerationID, GenerationHash: plan.GenerationHash, RawGenerationSHA256: plan.RawGenerationSHA256,
		ComponentDigest: plan.ComponentDigest, ComponentSHA256: plan.ComponentSHA256,
		ComponentVersion: plan.ComponentVersion, PreviousSHA256: plan.ExpectedPreviousSHA256,
		IssuedAtUnix: issuedAtUnix, ExpiresAtUnix: expiresAtUnix,
		GovernanceReceiptID: plan.DossierID, GovernanceReceiptSHA256: plan.Digest(),
	}
}

func (s *publishService) mintOrLoadHostApplyPlanIssuance(ctx context.Context, plan hostApplyPlan, proof hostApplySquadsProof, facts hostApplyCurrentFacts, now time.Time) (hostApplyPlanIssuance, componentrelease.OneShotApplyAuthorization, error) {
	var zero hostApplyPlanIssuance
	if existing, found, err := s.hostApplyPlans.loadIssuance(plan.DossierID, plan, proof); err != nil {
		return zero, componentrelease.OneShotApplyAuthorization{}, err
	} else if found {
		raw, err := existing.receiptBytes()
		if err != nil {
			return zero, componentrelease.OneShotApplyAuthorization{}, err
		}
		receipt, err := decodeOneShotApplyReceipt(raw)
		return existing, receipt, err
	}
	id, err := newHostApplyAuthorizationID()
	if err != nil {
		return zero, componentrelease.OneShotApplyAuthorization{}, err
	}
	expiresAtUnix, err := minHostApplyReceiptExpiry(now, plan.ExpiresAt)
	if err != nil {
		return zero, componentrelease.OneShotApplyAuthorization{}, err
	}
	receipt := oneShotFromHostApplyPlan(plan, s.cfg.StoreID, id, now.Unix(), expiresAtUnix)
	receipt, err = componentrelease.SignOneShotApplyAuthorization(s.operator, receipt)
	if err != nil {
		return zero, componentrelease.OneShotApplyAuthorization{}, err
	}
	raw, err := marshalBoundedJSON(receipt, maxHostApplyReceiptBytes)
	if err != nil {
		return zero, componentrelease.OneShotApplyAuthorization{}, err
	}
	sum := sha256.Sum256(raw)
	candidate := hostApplyPlanIssuance{
		Schema: hostApplyPlanIssuanceSchema, DossierID: plan.DossierID, PlanDigest: plan.Digest(), ProofDigest: proof.Digest(),
		AuthorizationID: id, ReceiptSHA256: hex.EncodeToString(sum[:]), ReceiptB64: base64.RawURLEncoding.EncodeToString(raw), CreatedAt: now,
	}
	issuance, _, err := s.hostApplyPlans.createIssuance(candidate, plan, proof)
	if err != nil {
		return zero, componentrelease.OneShotApplyAuthorization{}, err
	}
	if issuance.AuthorizationID != id {
		raw, err = issuance.receiptBytes()
		if err != nil {
			return zero, componentrelease.OneShotApplyAuthorization{}, err
		}
		receipt, err = decodeOneShotApplyReceipt(raw)
		if err != nil {
			return zero, componentrelease.OneShotApplyAuthorization{}, err
		}
	}
	if err := s.verifyHostApplyPlanReceipt(receipt, plan, facts, now); err != nil {
		return zero, componentrelease.OneShotApplyAuthorization{}, err
	}
	raw, err = issuance.receiptBytes()
	if err != nil {
		return zero, componentrelease.OneShotApplyAuthorization{}, err
	}
	if err := publishHostApplyReceipt(s.cfg.DistDir, issuance.AuthorizationID, raw); err != nil {
		return zero, componentrelease.OneShotApplyAuthorization{}, err
	}
	return issuance, receipt, nil
}

func (s *publishService) verifyHostApplyPlanReceipt(receipt componentrelease.OneShotApplyAuthorization, plan hostApplyPlan, facts hostApplyCurrentFacts, now time.Time) error {
	operatorKey, err := operatorSignPublicKey(s.operator)
	if err != nil {
		return err
	}
	return componentrelease.VerifyOneShotApplyAuthorization(operatorKey, componentrelease.OneShotApplyExpectation{
		ExpectedStoreID: s.cfg.StoreID, TargetControllerID: hostApplyFineractControllerID,
		TargetLicenseNftMint: facts.TargetLicense.Base58(), ComponentID: hostApplyFineractComponentID,
		GenerationID: facts.Document.GenerationID, GenerationHash: facts.Document.GenerationHash,
		RawGenerationSHA256: plan.RawGenerationSHA256, Component: facts.Component, NowUnix: now.Unix(),
	}, receipt)
}

func (s *publishService) handleHostApplyProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dossierID, err := hostApplyPlanDossier(r.URL.Path, r.URL.RawQuery, hostApplyProofPathSuffix)
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
	facts, err := fetchHostApplyCurrentFacts(r.Context(), s)
	if err != nil {
		http.Error(w, "check=current_facts: "+err.Error(), http.StatusConflict)
		return
	}
	if err := verifyHostApplyPlanAgainstFacts(planRecord.Plan, facts, now); err != nil {
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
	issuance, receipt, err := s.mintOrLoadHostApplyPlanIssuance(r.Context(), planRecord.Plan, proofRecord.Proof, facts, now)
	if err != nil {
		http.Error(w, "check=issuance: "+err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(hostApplyProofResult{
		Schema: hostApplyProofResultSchema, DossierID: dossierID, PlanDigest: planRecord.PlanDigest, ProofDigest: proofRecord.ProofDigest,
		AuthorizationID: issuance.AuthorizationID, ReceiptURL: strings.TrimRight(s.cfg.PublicBaseURL, "/") + hostApplyReceiptPathPrefix + issuance.AuthorizationID + ".json",
		ReceiptSHA256: issuance.ReceiptSHA256, ExpiresAt: time.Unix(receipt.ExpiresAtUnix, 0).UTC(),
	})
}

func (s *publishService) loadAndRevalidateHostApplyPlanIssuance(ctx context.Context, id string, now time.Time) (hostApplyPlanIssuance, []byte, error) {
	var zero hostApplyPlanIssuance
	issuance, found, err := s.hostApplyPlans.findIssuanceByAuthorizationID(id)
	if err != nil || !found {
		if err != nil {
			return zero, nil, err
		}
		return zero, nil, os.ErrNotExist
	}
	planRecord, found, err := s.hostApplyPlans.loadPlan(issuance.DossierID)
	if err != nil || !found || planRecord.PlanDigest != issuance.PlanDigest {
		return zero, nil, errors.New("host apply receipt has no matching immutable plan")
	}
	proofRecord, found, err := s.hostApplyPlans.loadProof(issuance.PlanDigest, planRecord.Plan)
	if err != nil || !found || proofRecord.ProofDigest != issuance.ProofDigest {
		return zero, nil, errors.New("host apply receipt has no matching immutable Squads proof")
	}
	facts, err := fetchHostApplyCurrentFacts(ctx, s)
	if err != nil {
		return zero, nil, err
	}
	if err := verifyHostApplyPlanAgainstFacts(planRecord.Plan, facts, now); err != nil {
		return zero, nil, err
	}
	observedProof, err := verifyHostApplySquadsProof(ctx, s.cr, planRecord.Plan, proofRecord.Proof.ExecutionSignature, now)
	if err != nil || observedProof.Digest() != proofRecord.ProofDigest {
		if err == nil {
			err = errors.New("finalized Squads proof no longer matches its retained immutable record")
		}
		return zero, nil, err
	}
	if err := issuance.Validate(planRecord.Plan, proofRecord.Proof); err != nil {
		return zero, nil, err
	}
	raw, err := issuance.receiptBytes()
	if err != nil {
		return zero, nil, err
	}
	receipt, err := decodeOneShotApplyReceipt(raw)
	if err != nil || receipt.ExpiresAtUnix <= now.Unix() {
		return zero, nil, errors.New("host apply receipt is expired or malformed")
	}
	if err := s.verifyHostApplyPlanReceipt(receipt, planRecord.Plan, facts, now); err != nil {
		return zero, nil, err
	}
	return issuance, raw, nil
}

func validHostApplyFreshnessChallenge(r *http.Request) (string, bool) {
	values := r.Header.Values(hostApplyFreshnessHeader)
	if len(values) != 1 || !isLowerHex(values[0], 64) {
		return "", false
	}
	return values[0], true
}

// handleHostApplyPlanReceipt is public only in the narrow sense that the root
// controller can fetch its origin-pinned signed receipt. A fresh CSPRNG header
// challenge is required and echoed only after every live revalidation succeeds;
// a stale intermediary cannot fabricate that response for the controller's
// last-moment pre-mutation fetch.
func (s *publishService) handleHostApplyPlanReceipt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := hostApplyReceiptID(r.URL.Path, r.URL.RawQuery)
	challenge, challengeOK := validHostApplyFreshnessChallenge(r)
	if err != nil || !challengeOK || s == nil || s.hostApplyPlans == nil || s.hostApplyPlanErr != nil {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	issuance, raw, err := s.loadAndRevalidateHostApplyPlanIssuance(r.Context(), id, s.currentTime().UTC().Truncate(time.Second))
	if err != nil {
		// Do not disclose whether an old receipt existed, expired, was revoked,
		// or failed a live chain check.
		http.NotFound(w, r)
		return
	}
	dir, err := openHostApplyPublicDir(s.cfg.DistDir)
	if err != nil {
		http.Error(w, "one-shot receipt unavailable", http.StatusServiceUnavailable)
		return
	}
	defer dir.Close()
	served, err := readHostApplyPublicReceipt(dir, issuance.AuthorizationID)
	if err != nil || !bytes.Equal(served, raw) {
		http.Error(w, "one-shot receipt unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Vary", hostApplyFreshnessHeader)
	w.Header().Set(hostApplyFreshnessHeader, challenge)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
