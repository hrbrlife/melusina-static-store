package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type hostApplyIssueFixture struct {
	svc           *publishService
	chain         *mockChainReader
	authorization hostApplyAuthorization
	component     componentrelease.ComponentRelease
	doc           componentrelease.DesiredGeneration
	now           time.Time
	humanPrivate  ed25519.PrivateKey
}

func newHostApplyIssueFixture(t *testing.T) hostApplyIssueFixture {
	t.Helper()
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	cfg, _ := testConfig(t)
	cfg.ProgramID = programID.Base58()
	cfg.PublicBaseURL = "https://bazaar.melusina-os.org"
	cfg.PrivateStageDir = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	cfg.StoreAuthority = op.Public().SignPubkeyB58
	chain := newMockChainReader()
	license, err := primitives.PubkeyFromBase58(cfg.LicenseNFTMint)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := primitives.PubkeyFromBase58(cfg.StoreAuthority)
	if err != nil {
		t.Fatal(err)
	}
	authz, _, err := pda.StoreOperatorAuthorization(license, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	operatorRaw := operatorSignPub32(t, op)
	chain.storeAuthz[authz.Base58()] = mockStoreAuthz{
		status: verify.AuthorizationStatusActive, authority: verify.Pubkey(operatorRaw),
		tierMask: 0xff, domainHash: primitives.StoreDomainHash(cfg.Domain),
	}
	policyPDA, err := deriveStoreControlPolicy(license, primitives.StoreDomainHash(cfg.Domain), programID)
	if err != nil {
		t.Fatal(err)
	}
	humanPublic, humanPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var humanRaw [32]byte
	copy(humanRaw[:], humanPublic)
	chain.rawAccounts[policyPDA.Base58()] = controlPolicyBlob(license, primitives.StoreDomainHash(cfg.Domain), authority, authz, [32]byte{9}, humanRaw, 7)

	artifact := []byte("fineract-v2-governed-candidate")
	sum := sha256.Sum256(artifact)
	sha := hex.EncodeToString(sum[:])
	name := "fineract-sidecar-" + sha[:16] + ".bin"
	if err := os.MkdirAll(filepath.Join(cfg.DistDir, "releases", "sidecar"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DistDir, "releases", "sidecar", name), artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	identityPDA, _, err := pda.SidecarIdentity(license, hostApplyFineractSidecarID, 1, programID)
	if err != nil {
		t.Fatal(err)
	}
	globalPDA, _, err := primitives.DeriveGlobalSidecar(mustTestPubkey(t, testMaster), hostApplyFineractSidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	localPDA, _, err := primitives.DeriveLocalSidecar(license, hostApplyFineractSidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	component := componentrelease.ComponentRelease{
		ComponentID:     hostApplyFineractComponentID,
		ComponentClass:  componentrelease.ClassSidecar,
		Version:         "0.1.38-contract",
		Build:           1,
		ArtifactName:    name,
		SHA256:          sha,
		SizeBytes:       int64(len(artifact)),
		BundleURL:       cfg.PublicBaseURL + "/releases/sidecar/" + name,
		ReleaseHash:     strings.Repeat("d", 64),
		StageID:         strings.Repeat("e", 64),
		PreviousSHA256:  strings.Repeat("f", 64),
		PreviousVersion: "0.1.37-contract",
		Chain: componentrelease.ChainAuthority{
			Kind:              componentrelease.AuthoritySidecarIdentity,
			Program:           programID.Base58(),
			LicenseNftMint:    cfg.LicenseNFTMint,
			MasterNftMint:     testMaster,
			SidecarID:         hostApplyFineractSidecarID,
			KeyVersion:        1,
			IdentityPDA:       identityPDA.Base58(),
			GlobalApprovalPDA: globalPDA.Base58(),
			LocalApprovalPDA:  localPDA.Base58(),
		},
	}
	chain.sidecarIdentity[identityPDA.Base58()] = mockSidecarIdentity{sid: verify.SidecarIdentity{Status: verify.AttestationStatusActive, BinaryHash: sum}}
	seedValidCascade(t, chain, license, hostApplyFineractSidecarID, sum)

	doc := componentrelease.DesiredGeneration{
		GenerationID:       77,
		StoreID:            cfg.StoreID,
		BundleOrigin:       cfg.PublicBaseURL,
		Channel:            "dev",
		SignedAtUnix:       now.Add(-time.Minute).Unix(),
		PreviousGeneration: 76,
		Components:         []componentrelease.ComponentRelease{component},
	}
	doc, err = componentrelease.Sign(op, doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(cfg.DistDir, raw); err != nil {
		t.Fatal(err)
	}
	svc := newTestService(t, cfg, chain, op)
	svc.now = func() time.Time { return now }
	rawHash := sha256.Sum256(raw)
	authorization := hostApplyAuthorization{
		Schema:                 hostApplyAuthorizationSchema,
		DossierID:              "0123456789abcdef01234567",
		StorePolicy:            policyPDA.Base58(),
		PolicyEpoch:            7,
		TargetControllerID:     hostApplyFineractControllerID,
		TargetLicenseNftMint:   cfg.LicenseNFTMint,
		ComponentID:            hostApplyFineractComponentID,
		GenerationID:           doc.GenerationID,
		GenerationHash:         doc.GenerationHash,
		RawGenerationSHA256:    hex.EncodeToString(rawHash[:]),
		ComponentDigest:        componentrelease.ComponentReleaseDigestHex(component),
		ComponentSHA256:        component.SHA256,
		ComponentVersion:       component.Version,
		ExpectedPreviousSHA256: component.PreviousSHA256,
		ProposalDigest:         strings.Repeat("a", 64),
		IssuedAt:               now.Add(-time.Minute),
		ExpiresAt:              now.Add(time.Hour),
		SignerPublicKey:        base64.RawURLEncoding.EncodeToString(humanPublic),
		SignedAt:               now,
	}
	authorization.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(humanPrivate, []byte(authorization.HumanSigningText())))
	return hostApplyIssueFixture{svc: svc, chain: chain, authorization: authorization, component: component, doc: doc, now: now, humanPrivate: humanPrivate}
}

func mustTestPubkey(t *testing.T, value string) primitives.Pubkey {
	t.Helper()
	key, err := primitives.PubkeyFromBase58(value)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func hostApplyIssueRequest(t *testing.T, a hostApplyAuthorization) *http.Request {
	t.Helper()
	body, err := json.Marshal(hostApplyIssueBody{HostApplyAuthorization: a})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, hostApplyIssuePathPrefix+a.DossierID+hostApplyIssuePathSuffix, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func issueHostApply(t *testing.T, f hostApplyIssueFixture, a hostApplyAuthorization) (hostApplyIssueResult, *httptest.ResponseRecorder) {
	t.Helper()
	response := httptest.NewRecorder()
	newControlReleaseRouter(f.svc).ServeHTTP(response, hostApplyIssueRequest(t, a))
	var result hostApplyIssueResult
	if response.Code == http.StatusOK {
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
	}
	return result, response
}

func TestHostApplyIssueIsPrivateBindsCurrentFineractV2AndRetriesExactly(t *testing.T) {
	f := newHostApplyIssueFixture(t)
	public := newPublicRouterWithService(f.svc.cfg, f.svc.operator, f.chain, nil, catalogRuntime{}, f.svc, true)
	private := newControlReleaseRouter(f.svc)

	// The public catalog listener must not reveal the private host-apply route.
	publicResponse := httptest.NewRecorder()
	public.ServeHTTP(publicResponse, hostApplyIssueRequest(t, f.authorization))
	if publicResponse.Code != http.StatusNotFound {
		t.Fatalf("public host-apply route = %d: %s", publicResponse.Code, publicResponse.Body.String())
	}

	result, response := issueHostApply(t, f, f.authorization)
	if response.Code != http.StatusOK {
		t.Fatalf("private host-apply issue = %d: %s", response.Code, response.Body.String())
	}
	if result.Schema != hostApplyIssueResultSchema || !isLowerHex(result.AuthorizationID, 64) || result.ReceiptURL != strings.TrimRight(f.svc.cfg.PublicBaseURL, "/")+hostApplyReceiptPathPrefix+result.AuthorizationID+".json" || result.ReceiptSHA256 == "" {
		t.Fatalf("invalid issue result: %+v", result)
	}

	receiptPath := hostApplyReceiptPathPrefix + result.AuthorizationID + ".json"
	served := httptest.NewRecorder()
	public.ServeHTTP(served, httptest.NewRequest(http.MethodGet, receiptPath, nil))
	if served.Code != http.StatusOK || served.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("public one-shot receipt = %d headers=%#v body=%s", served.Code, served.Header(), served.Body.String())
	}
	var receipt componentrelease.OneShotApplyAuthorization
	if err := json.Unmarshal(served.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.AuthorizationID != result.AuthorizationID || receipt.ComponentID != hostApplyFineractComponentID || receipt.TargetControllerID != hostApplyFineractControllerID || receipt.ComponentSHA256 != f.component.SHA256 {
		t.Fatalf("receipt lost governed bindings: %+v", receipt)
	}

	// Replaying the exact policy-human decision returns exactly the same
	// immutable receipt rather than minting a second controller authority.
	retry, retryResponse := issueHostApply(t, f, f.authorization)
	if retryResponse.Code != http.StatusOK || retry.AuthorizationID != result.AuthorizationID || retry.ReceiptSHA256 != result.ReceiptSHA256 {
		t.Fatalf("exact retry changed issuance: status=%d first=%+v retry=%+v", retryResponse.Code, result, retry)
	}

	// The only public path is the exact canonical receipt filename: directory
	// listing, query smuggling, and a private-control route all stay absent.
	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, hostApplyReceiptPathPrefix, nil),
		httptest.NewRequest(http.MethodGet, receiptPath+"?cache=1", nil),
		httptest.NewRequest(http.MethodGet, hostApplyReceiptPathPrefix+"not-a-receipt.json", nil),
	} {
		w := httptest.NewRecorder()
		public.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("noncanonical public receipt route %s = %d", req.URL.String(), w.Code)
		}
	}
	_ = private // Explicitly keep the test's private/public split visible.
}

func TestHostApplyIssueRefusesChangedDossierFactsAndCurrentGenerationDrift(t *testing.T) {
	f := newHostApplyIssueFixture(t)
	if _, response := issueHostApply(t, f, f.authorization); response.Code != http.StatusOK {
		t.Fatalf("initial issue = %d: %s", response.Code, response.Body.String())
	}

	// A new purpose proposal with the same dossier is not a retry. Re-sign it so
	// the denial comes from immutable dossier binding, not a broken signature.
	changed := f.authorization
	changed.ProposalDigest = strings.Repeat("b", 64)
	resignHostApplyAuthorization(t, &changed, f.humanPrivate)
	if _, response := issueHostApply(t, f, changed); response.Code != http.StatusConflict {
		t.Fatalf("changed same-dossier authorization = %d: %s, want 409", response.Code, response.Body.String())
	}

	// A stale generation commitment never reaches the ledger/publish step.
	stale := f.authorization
	stale.ComponentSHA256 = strings.Repeat("0", 64)
	resignHostApplyAuthorization(t, &stale, f.humanPrivate)
	if _, response := issueHostApply(t, f, stale); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "generation_binding") {
		t.Fatalf("stale generation binding = %d: %s", response.Code, response.Body.String())
	}
}

func TestHostApplyIssueRejectsMalformedOrUnauthorizedRequestBeforeReceipt(t *testing.T) {
	f := newHostApplyIssueFixture(t)
	control := newControlReleaseRouter(f.svc)

	wrongMethod := httptest.NewRecorder()
	control.ServeHTTP(wrongMethod, httptest.NewRequest(http.MethodGet, hostApplyIssuePathPrefix+f.authorization.DossierID+hostApplyIssuePathSuffix, nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method = %d", wrongMethod.Code)
	}

	duplicate := httptest.NewRecorder()
	good, err := json.Marshal(f.authorization)
	if err != nil {
		t.Fatal(err)
	}
	duplicateBody := []byte(`{"hostApplyAuthorization":` + string(good) + `,"hostApplyAuthorization":{}}`)
	req := httptest.NewRequest(http.MethodPost, hostApplyIssuePathPrefix+f.authorization.DossierID+hostApplyIssuePathSuffix, bytes.NewReader(duplicateBody))
	req.Header.Set("Content-Type", "application/json")
	control.ServeHTTP(duplicate, req)
	if duplicate.Code != http.StatusBadRequest {
		t.Fatalf("duplicate JSON key = %d: %s", duplicate.Code, duplicate.Body.String())
	}

	unauthorized := f.authorization
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unauthorized.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(wrongKey, []byte(unauthorized.HumanSigningText())))
	if _, response := issueHostApply(t, f, unauthorized); response.Code != http.StatusForbidden {
		t.Fatalf("wrong policy-human signature = %d: %s", response.Code, response.Body.String())
	}
}

func TestHostApplyReceiptReconcilesPersistedIntentAndExpires(t *testing.T) {
	f := newHostApplyIssueFixture(t)
	// First issue persists the immutable ledger record and public byte. Remove
	// only the public byte to simulate a process dying after O_EXCL intent but
	// before the public hard-link commit. The same request must reconcile it.
	result, response := issueHostApply(t, f, f.authorization)
	if response.Code != http.StatusOK {
		t.Fatalf("initial issue = %d: %s", response.Code, response.Body.String())
	}
	path := filepath.Join(f.svc.cfg.DistDir, "update", "one-shot", result.AuthorizationID+".json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, retry := issueHostApply(t, f, f.authorization); retry.Code != http.StatusOK {
		t.Fatalf("intent reconciliation retry = %d: %s", retry.Code, retry.Body.String())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("reconciled public receipt missing: %v", err)
	}

	public := newPublicRouterWithService(f.svc.cfg, f.svc.operator, f.chain, nil, catalogRuntime{}, f.svc, true)
	f.svc.now = func() time.Time { return f.now.Add(16 * time.Minute) }
	expired := httptest.NewRecorder()
	public.ServeHTTP(expired, httptest.NewRequest(http.MethodGet, hostApplyReceiptPathPrefix+result.AuthorizationID+".json", nil))
	if expired.Code != http.StatusNotFound {
		t.Fatalf("expired receipt = %d: %s", expired.Code, expired.Body.String())
	}
}

func resignHostApplyAuthorization(t *testing.T, a *hostApplyAuthorization, private ed25519.PrivateKey) {
	t.Helper()
	if len(private) != ed25519.PrivateKeySize {
		t.Fatal("missing fixture policy-human private key")
	}
	a.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(a.HumanSigningText())))
}
