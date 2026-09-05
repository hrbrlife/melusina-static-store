package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/pkg/controllerupgrade"
)

func controllerUpgradePlanRequest(t *testing.T, dossier string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, controllerUpgradeIssuePathPrefix+dossier+controllerUpgradePlanPathSuffix, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func controllerUpgradeProofHTTPReq(t *testing.T, dossier, digest, signature string) *http.Request {
	t.Helper()
	body, err := json.Marshal(hostApplyProofRequest{PlanDigest: digest, ExecutionSignature: signature})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, controllerUpgradeIssuePathPrefix+dossier+controllerUpgradeProofPathSuffix, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestControllerUpgradeRouteIsPrivateAndSignsOnlyFreshReceiverChallenges(t *testing.T) {
	f := newHostApplyPlanFixture(t)
	candidate := f.addControllerUpgradeCandidate(t)
	const dossier = "0123456789abcdef01234567"
	public := newPublicRouterWithService(f.svc.cfg, f.svc.operator, f.chain, nil, catalogRuntime{}, f.svc, true)
	private := newControlReleaseRouter(f.svc)

	publicPlan := httptest.NewRecorder()
	public.ServeHTTP(publicPlan, controllerUpgradePlanRequest(t, dossier))
	if publicPlan.Code != http.StatusNotFound {
		t.Fatalf("public controller plan route = %d: %s", publicPlan.Code, publicPlan.Body.String())
	}

	planResponse := httptest.NewRecorder()
	private.ServeHTTP(planResponse, controllerUpgradePlanRequest(t, dossier))
	if planResponse.Code != http.StatusOK {
		t.Fatalf("controller plan = %d: %s", planResponse.Code, planResponse.Body.String())
	}
	var planned controllerUpgradePlanResult
	if err := json.Unmarshal(planResponse.Body.Bytes(), &planned); err != nil {
		t.Fatal(err)
	}
	if planned.Schema != controllerUpgradePlanResultSchema || planned.Plan.Action != controllerUpgradeAction ||
		planned.PlanDigest != planned.Plan.Digest() || planned.Memo != planned.Plan.Memo() ||
		planned.Plan.TargetLicenseNftMint != f.targetLicense || planned.Plan.TargetLicenseNftMint == f.storeLicense ||
		planned.Plan.ComponentID != controllerUpgradeComponentID || planned.Plan.CandidateArtifactName != candidate.ArtifactName ||
		planned.Plan.ComponentSHA256 != candidate.SHA256 || planned.Plan.CandidateSizeBytes != candidate.SizeBytes {
		t.Fatalf("controller plan lost governed facts: %+v", planned)
	}

	// A controller plan cannot be recovered through the historical sidecar
	// route even if a caller knows its dossier. The action-class verifier is
	// deliberately different, rather than sharing field overlap.
	historicalRoute := httptest.NewRecorder()
	private.ServeHTTP(historicalRoute, hostApplyPlanRequest(t, dossier))
	if historicalRoute.Code == http.StatusOK {
		t.Fatal("historical sidecar route accepted a controller upgrade plan")
	}

	f.armProof(t, planned.Plan)
	proofResponse := httptest.NewRecorder()
	private.ServeHTTP(proofResponse, controllerUpgradeProofHTTPReq(t, dossier, planned.PlanDigest, f.signature))
	if proofResponse.Code != http.StatusOK {
		t.Fatalf("controller proof = %d: %s", proofResponse.Code, proofResponse.Body.String())
	}
	var proof controllerUpgradeProofResult
	if err := json.Unmarshal(proofResponse.Body.Bytes(), &proof); err != nil {
		t.Fatal(err)
	}
	proofRecord, found, err := f.svc.hostApplyPlans.loadProof(planned.PlanDigest, planned.Plan)
	if err != nil || !found {
		t.Fatalf("load persisted controller proof: found=%t err=%v", found, err)
	}
	if proof.Schema != controllerUpgradeProofResultSchema || proof.PlanDigest != planned.PlanDigest ||
		proof.ProofDigest != proofRecord.ProofDigest || proof.ReceiptID != controllerUpgradeReceiptReferenceID(planned.Plan, proofRecord.Proof) ||
		proof.ReceiptURL != f.svc.cfg.PublicBaseURL+controllerUpgradeReceiptPathPrefix+proof.ReceiptID+".json" {
		t.Fatalf("controller proof returned unsafe or unbound receipt reference: %+v", proof)
	}

	missingChallenge := httptest.NewRecorder()
	public.ServeHTTP(missingChallenge, httptest.NewRequest(http.MethodGet, controllerUpgradeReceiptPathPrefix+proof.ReceiptID+".json", nil))
	if missingChallenge.Code != http.StatusNotFound {
		t.Fatalf("receipt without receiver challenge = %d", missingChallenge.Code)
	}
	invalidChallenge := httptest.NewRecorder()
	badRequest := httptest.NewRequest(http.MethodGet, controllerUpgradeReceiptPathPrefix+proof.ReceiptID+".json", nil)
	badRequest.Header.Set(controllerUpgradeFreshnessHeader, "not-a-controller-challenge")
	public.ServeHTTP(invalidChallenge, badRequest)
	if invalidChallenge.Code != http.StatusNotFound {
		t.Fatalf("receipt with invalid receiver challenge = %d", invalidChallenge.Code)
	}

	challenge := strings.Repeat("a", 64)
	receiptRequest := httptest.NewRequest(http.MethodGet, controllerUpgradeReceiptPathPrefix+proof.ReceiptID+".json", nil)
	receiptRequest.Header.Set(controllerUpgradeFreshnessHeader, challenge)
	receiptResponse := httptest.NewRecorder()
	public.ServeHTTP(receiptResponse, receiptRequest)
	if receiptResponse.Code != http.StatusOK {
		t.Fatalf("fresh controller receipt = %d: %s", receiptResponse.Code, receiptResponse.Body.String())
	}
	if receiptResponse.Header().Get(controllerUpgradeFreshnessHeader) != challenge {
		t.Fatalf("response did not echo receiver challenge: %q", receiptResponse.Header().Get(controllerUpgradeFreshnessHeader))
	}
	receipt, err := controllerupgrade.DecodeReceipt(receiptResponse.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	operatorKey, err := operatorSignPublicKey(f.svc.operator)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.Verify(controllerupgrade.VerificationConfig{
		TenantLicenseNftMint:  f.targetLicense,
		StoreReceiptPublicKey: base64.RawURLEncoding.EncodeToString(operatorKey),
		Now:                   func() time.Time { return f.now },
	}, challenge); err != nil {
		t.Fatalf("fresh receipt does not verify: %v", err)
	}
	if receipt.ReceiptID != proof.ReceiptID || receipt.PlanDigest != planned.PlanDigest ||
		receipt.CandidateArtifactName != candidate.ArtifactName || receipt.CandidateSHA256 != candidate.SHA256 ||
		receipt.ExpectedPreviousSHA256 != candidate.PreviousSHA256 {
		t.Fatalf("receipt did not bind controller candidate and proof: %+v", receipt)
	}

	// A current generation/artifact change invalidates the public response rather
	// than serving a receipt selected by a retained file or stale plan.
	if err := os.WriteFile(filepath.Join(f.svc.cfg.DistDir, "releases", "data", candidate.ArtifactName), []byte("substituted-controller"), 0o644); err != nil {
		t.Fatal(err)
	}
	staleResponse := httptest.NewRecorder()
	public.ServeHTTP(staleResponse, receiptRequest)
	if staleResponse.Code != http.StatusNotFound {
		t.Fatalf("stale controller receipt = %d: %s", staleResponse.Code, staleResponse.Body.String())
	}
}
