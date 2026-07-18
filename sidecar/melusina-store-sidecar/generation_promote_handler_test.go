package main

import (
	"bytes"
	"context"
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

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestVerifyComponentServedBytes(t *testing.T) {
	dist := t.TempDir()
	content := []byte("shell-bundle-bytes-for-serve-check")
	sum := sha256.Sum256(content)
	shaHex := hex.EncodeToString(sum[:])
	name := "sandstorm-served.tar.xz"
	dir := filepath.Join(dist, "releases", "shell")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
		t.Fatal(err)
	}
	svc := &publishService{cfg: Config{DistDir: dist, PublicBaseURL: "https://bazaar.melusina-os.org"}}

	ok := componentrelease.ComponentRelease{
		ComponentID: "sandstorm-shell",
		BundleURL:   "https://bazaar.melusina-os.org/releases/shell/" + name,
		SHA256:      shaHex,
	}
	if err := svc.verifyComponentServedBytes(ok); err != nil {
		t.Fatalf("valid served bytes rejected: %v", err)
	}
	// Wrong sha — the served bytes don't match the component's claimed hash.
	wrong := ok
	wrong.SHA256 = strings.Repeat("0", 64)
	if err := svc.verifyComponentServedBytes(wrong); err == nil {
		t.Fatal("accepted a served artifact whose sha256 does not match the component")
	}
	// Missing file — the generation points at bytes that were never published.
	missing := componentrelease.ComponentRelease{
		ComponentID: "x",
		BundleURL:   "https://bazaar.melusina-os.org/releases/shell/never-published.bin",
		SHA256:      shaHex,
	}
	if err := svc.verifyComponentServedBytes(missing); err == nil {
		t.Fatal("accepted a component whose served artifact is absent")
	}
	// Off-origin bundleUrl is refused before any filesystem access.
	off := ok
	off.BundleURL = "https://elsewhere.example/releases/shell/" + name
	if err := svc.verifyComponentServedBytes(off); err == nil {
		t.Fatal("accepted a bundleUrl outside the store origin")
	}
}

func TestVerifyComponentReleaseOnChainFailClosed(t *testing.T) {
	svc := &publishService{cfg: Config{PublicBaseURL: "https://bazaar.melusina-os.org"}}
	ctx := context.Background()

	// app (release_v2) must fail closed without a real chain reader.
	app := shellComp("x-app", strings.Repeat("a", 64), "1")
	app.ComponentClass = componentrelease.ClassApp
	app.Chain.Kind = componentrelease.AuthorityReleaseV2
	if err := svc.verifyComponentReleaseOnChain(ctx, app); err == nil {
		t.Fatal("app-class component accepted without an app ReleaseEntry re-verify")
	}
	// Unknown authority kind -> refused.
	unk := shellComp("x-unk", strings.Repeat("a", 64), "1")
	unk.Chain.Kind = "bogus-authority"
	if err := svc.verifyComponentReleaseOnChain(ctx, unk); err == nil {
		t.Fatal("unknown authority kind accepted")
	}
}

func TestVerifyAppComponentOnChain(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.Domain = "bazaar.melusina-os.org"
	cfg.PublicBaseURL = "https://bazaar.melusina-os.org"
	f := buildValidFixture(t, cfg, testMaster)
	m := newMockChainReader()
	m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: f.appHashBytes, appID: f.appID, version: f.rel.Version, status: verify.AttestationStatusActive}
	dist := t.TempDir()
	spkSum := sha256.Sum256(f.spk)
	packageID := hex.EncodeToString(spkSum[:])[:32]
	dir := filepath.Join(dist, "packages")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, packageID), f.spk, 0o644); err != nil {
		t.Fatal(err)
	}
	appID := "test-app"
	indexBody := []byte(`{"apps":[{"appId":"` + appID + `","packageId":"` + packageID + `"}]}`)
	if err := os.MkdirAll(filepath.Join(dist, "apps", "pointers"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "apps", "index.json"), indexBody, 0o644); err != nil {
		t.Fatal(err)
	}
	indexHash := sha256.Sum256(indexBody)
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	pointer := AppCatalogPointer{
		Schema:            appCatalogPointerSchema,
		AppID:             appID,
		PackageID:         packageID,
		Version:           f.rel.Version,
		AppHash:           f.rel.AppHash,
		ReleaseHash:       f.rel.ReleaseHash,
		StageID:           strings.Repeat("1", 64),
		CatalogSHA256:     hex.EncodeToString(indexHash[:]),
		ServingDomainHash: hex.EncodeToString(domainHash[:]),
		PublishedAt:       1,
	}
	message, err := appCatalogPointerMessage(pointer)
	if err != nil {
		t.Fatal(err)
	}
	pointer.OperatorSignature = primitives.EncodeBase58(op.Sign(message))
	pointerBody, err := json.Marshal(pointer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "apps", "pointers", appID+".json"), pointerBody, 0o644); err != nil {
		t.Fatal(err)
	}
	c := componentrelease.ComponentRelease{
		ComponentID: appID, ComponentClass: componentrelease.ClassApp, Version: f.rel.Version,
		SHA256: hex.EncodeToString(spkSum[:]), ContentSHA256: f.rel.AppHash, SizeBytes: int64(len(f.spk)),
		ArtifactName: packageID, BundleURL: cfg.PublicBaseURL + "/packages/" + packageID,
		ReleaseHash: f.rel.ReleaseHash, StageID: pointer.StageID,
		Chain: componentrelease.ChainAuthority{Kind: componentrelease.AuthorityReleaseV2, Program: programID.Base58(), MasterNftMint: testMaster, ReleasePDA: f.relPDA},
	}
	svc := &publishService{cfg: Config{DistDir: dist, Domain: cfg.Domain, PublicBaseURL: cfg.PublicBaseURL}, operator: op, cr: m}
	if err := svc.verifyComponentReleaseOnChain(context.Background(), c); err != nil {
		t.Fatalf("valid app component refused: %v", err)
	}
	// A valid ReleaseEntry plus a separately signed pointer to another package is
	// still not this component. The app selection is part of the authority.
	wrongPointer := pointer
	wrongPointer.PackageID = strings.Repeat("0", 32)
	message, err = appCatalogPointerMessage(wrongPointer)
	if err != nil {
		t.Fatal(err)
	}
	wrongPointer.OperatorSignature = primitives.EncodeBase58(op.Sign(message))
	wrongPointerBody, err := json.Marshal(wrongPointer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "apps", "pointers", appID+".json"), wrongPointerBody, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := svc.verifyComponentReleaseOnChain(context.Background(), c); err == nil {
		t.Fatal("accepted app ReleaseEntry with signed pointer to a different package")
	}
	if err := os.WriteFile(filepath.Join(dist, "apps", "pointers", appID+".json"), pointerBody, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*componentrelease.ComponentRelease){
		func(x *componentrelease.ComponentRelease) { x.Chain.ReleasePDA = testProg },
		func(x *componentrelease.ComponentRelease) { x.ContentSHA256 = strings.Repeat("0", 64) },
		func(x *componentrelease.ComponentRelease) { x.Chain.Program = testMaster },
	} {
		bad := c
		mutate(&bad)
		if err := svc.verifyComponentReleaseOnChain(context.Background(), bad); err == nil {
			t.Fatal("accepted forged app authority")
		}
	}
}

func TestVerifySidecarComponentOnChain(t *testing.T) {
	dist := t.TempDir()
	content := []byte("swaprail-elf-bytes-for-sidecar-reverify")
	sum := sha256.Sum256(content)
	shaHex := hex.EncodeToString(sum[:])
	name := "swaprail-" + shaHex[:8] + ".bin"
	dir := filepath.Join(dist, "releases", "sidecar")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
		t.Fatal(err)
	}

	licenseMint, err := primitives.PubkeyFromBase58(testLicenseMint)
	if err != nil {
		t.Fatal(err)
	}
	sidPDA, _, err := pda.SidecarIdentity(licenseMint, "swaprail", 1, programID)
	if err != nil {
		t.Fatal(err)
	}

	c := componentrelease.ComponentRelease{
		ComponentID:    "swaprail",
		ComponentClass: componentrelease.ClassSidecar,
		SHA256:         shaHex,
		BundleURL:      "https://bazaar.melusina-os.org/releases/sidecar/" + name,
		Chain: componentrelease.ChainAuthority{
			Kind:           componentrelease.AuthoritySidecarIdentity,
			LicenseNftMint: testLicenseMint,
			SidecarID:      "swaprail",
			KeyVersion:     1,
		},
	}
	cfg := Config{DistDir: dist, PublicBaseURL: "https://bazaar.melusina-os.org"}
	svcWith := func(sid verify.SidecarIdentity, seed bool) *publishService {
		m := newMockChainReader()
		if seed {
			m.sidecarIdentity[sidPDA.Base58()] = mockSidecarIdentity{sid: sid}
			// Seed an all-Active 5-fact cascade so the require_active_sidecar_cascade
			// mirror passes on the happy path (refuse-cases fail earlier, at the
			// identity/hash check, before the cascade is reached).
			seedValidCascade(t, m, licenseMint, "swaprail", sum)
		}
		return &publishService{cfg: cfg, cr: m}
	}
	ctx := context.Background()

	// Active + binary_hash == served sha256 -> accepted.
	if err := svcWith(verify.SidecarIdentity{Status: verify.AttestationStatusActive, BinaryHash: sum}, true).verifyComponentReleaseOnChain(ctx, c); err != nil {
		t.Fatalf("valid sidecar re-verify rejected: %v", err)
	}
	// On-chain binary_hash differs from the served artifact -> refused.
	if err := svcWith(verify.SidecarIdentity{Status: verify.AttestationStatusActive, BinaryHash: sha256.Sum256([]byte("different"))}, true).verifyComponentReleaseOnChain(ctx, c); err == nil {
		t.Fatal("accepted a sidecar whose on-chain binary_hash differs from the served bytes")
	}
	// Non-Active identity -> refused.
	if err := svcWith(verify.SidecarIdentity{Status: verify.AttestationStatusRevoked, BinaryHash: sum}, true).verifyComponentReleaseOnChain(ctx, c); err == nil {
		t.Fatal("accepted a non-Active sidecar identity")
	}
	// No on-chain identity at the derived PDA -> refused.
	if err := svcWith(verify.SidecarIdentity{}, false).verifyComponentReleaseOnChain(ctx, c); err == nil {
		t.Fatal("accepted a sidecar with no on-chain identity")
	}
}

func TestHandleGeneratePromoteRejectPaths(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	svc := &publishService{
		cfg:      Config{DistDir: t.TempDir(), PublicBaseURL: "https://bazaar.melusina-os.org", StoreID: "melusina-os-root-store"},
		operator: op,
		cr:       &mockChainReader{},
		nonces:   envelope.NewMemoryNonceCache(),
	}

	// 405 wrong method.
	rec := httptest.NewRecorder()
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodGet, "/publish/generation", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET want 405 got %d", rec.Code)
	}

	// 503 when the chain reader / operator is unwired.
	rec = httptest.NewRecorder()
	(&publishService{cfg: Config{}}).handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", strings.NewReader("{}")))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired want 503 got %d", rec.Code)
	}

	// 400 malformed body.
	rec = httptest.NewRecorder()
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", strings.NewReader("not json")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body want 400 got %d", rec.Code)
	}

	// 401 when the envelope is absent.
	reqJSON, _ := json.Marshal(promoteReq(0, shellComp("sandstorm-shell", strings.Repeat("a", 64), "build-1")))
	noEnv, _ := json.Marshal(generationPromoteBody{RequestB64: base64.StdEncoding.EncodeToString(reqJSON)})
	rec = httptest.NewRecorder()
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", bytes.NewReader(noEnv)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-envelope want 401 got %d: %s", rec.Code, rec.Body.String())
	}

	// 403 when the publisher is not in accept_publishers.
	publisher := newTestIdentity(t, "rogue-publisher", testLicenseMint, "bazaar.melusina-os.org")
	sum := sha256.Sum256(reqJSON)
	sig, err := envelope.Sign(envelope.KindPublishRequest, publisher, op.Public(), envelope.SignOptions{
		RequestHash: hex.EncodeToString(sum[:]),
		TTL:         5 * 60 * 1e9, // 5m in ns
		Chain: envelope.ChainEvidence{
			ChainID:      "solana:devnet",
			ProgramID:    "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
			VerifiedSlot: 12345,
		},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	body, _ := json.Marshal(generationPromoteBody{Envelope: sig, RequestB64: base64.StdEncoding.EncodeToString(reqJSON)})
	rec = httptest.NewRecorder()
	// AcceptPublishers is empty -> the publisher is not accepted.
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", bytes.NewReader(body)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-accepted publisher want 403 got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGeneratePromoteRejectsCrossRouteEnvelopeAndDuplicateJSON(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	publisher := newTestIdentity(t, "generation-publisher", testLicenseMint, "publisher.example.org")
	svc := &publishService{
		cfg: Config{
			DistDir:       t.TempDir(),
			PublicBaseURL: "https://bazaar.melusina-os.org",
			StoreID:       "melusina-os-root-store",
			Policy:        Policy{AcceptPublishers: []string{publisher.Public().SignPubkeyB58}},
		},
		operator: op,
		cr:       &mockChainReader{},
		nonces:   envelope.NewMemoryNonceCache(),
	}

	reqJSON, err := json.Marshal(promoteReq(0, shellComp("sandstorm-shell", strings.Repeat("a", 64), "build-1")))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(reqJSON)
	sign := func(target string) envelope.Signed {
		t.Helper()
		sig, err := envelope.Sign(envelope.KindPublishRequest, publisher, op.Public(), envelope.SignOptions{
			Method:      http.MethodPost,
			Target:      target,
			Body:        reqJSON,
			BodyHash:    hex.EncodeToString(sum[:]),
			RequestHash: hex.EncodeToString(sum[:]),
			TTL:         5 * time.Minute,
			Chain: envelope.ChainEvidence{
				ChainID:      "solana:devnet",
				ProgramID:    "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
				VerifiedSlot: 12345,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}

	// A publisher accepted by policy still cannot replay a signed /publish
	// request to the generation route. The chain reader is deliberately empty;
	// a 401 proves purpose is checked before any chain/persist mutation.
	crossRoute, err := json.Marshal(generationPromoteBody{
		Envelope:   sign("/publish"),
		RequestB64: base64.StdEncoding.EncodeToString(reqJSON),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", bytes.NewReader(crossRoute)))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "envelope_purpose") {
		t.Fatalf("cross-route envelope got %d: %s", rec.Code, rec.Body.String())
	}

	// Duplicated wrapper keys are rejected before auth extraction, so a parser
	// cannot choose a different envelope/request pairing than an auditor.
	duplicateOuter := []byte(`{"envelope":{},"envelope":{},"request_b64":""}`)
	rec = httptest.NewRecorder()
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", bytes.NewReader(duplicateOuter)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "duplicate JSON key") {
		t.Fatalf("duplicate outer got %d: %s", rec.Code, rec.Body.String())
	}

	// A correctly route-bound envelope carrying an ambiguous promote request is
	// also refused before the chain reader could inspect a normalized component.
	duplicateRequest := []byte(`{"schema":"melusina-generation-promote-v1","schema":"melusina-generation-promote-v1"}`)
	dupSum := sha256.Sum256(duplicateRequest)
	dupSig, err := envelope.Sign(envelope.KindPublishRequest, publisher, op.Public(), envelope.SignOptions{
		Method:      http.MethodPost,
		Target:      "/publish/generation",
		Body:        duplicateRequest,
		BodyHash:    hex.EncodeToString(dupSum[:]),
		RequestHash: hex.EncodeToString(dupSum[:]),
		TTL:         5 * time.Minute,
		Chain:       envelope.ChainEvidence{ChainID: "solana:devnet", ProgramID: "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb", VerifiedSlot: 12346},
	})
	if err != nil {
		t.Fatal(err)
	}
	dupBody, err := json.Marshal(generationPromoteBody{Envelope: dupSig, RequestB64: base64.StdEncoding.EncodeToString(duplicateRequest)})
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodPost, "/publish/generation", bytes.NewReader(dupBody)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "promote_request") || !strings.Contains(rec.Body.String(), "duplicate JSON key") {
		t.Fatalf("duplicate promote request got %d: %s", rec.Code, rec.Body.String())
	}
}
