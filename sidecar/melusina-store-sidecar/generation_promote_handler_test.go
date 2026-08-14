package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
		SizeBytes:   int64(len(content)),
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

func TestGenerationPromoteRequiresRootOnlyForInstallerArtifacts(t *testing.T) {
	installer := shellComp("sandstorm-shell", strings.Repeat("a", 64), "build-1")
	installer.Chain.Kind = componentrelease.AuthorityInstallerRelease
	if !generationPromoteRequiresRoot([]componentrelease.ComponentRelease{installer}) {
		t.Fatal("installer generation must require root store authority")
	}

	sidecar := installer
	sidecar.ComponentClass = componentrelease.ClassSidecar
	sidecar.Chain.Kind = componentrelease.AuthoritySidecarIdentity
	if generationPromoteRequiresRoot([]componentrelease.ComponentRelease{sidecar}) {
		t.Fatal("sidecar-only generation must use its active domain-scoped store operator authorization")
	}

	app := installer
	app.ComponentClass = componentrelease.ClassApp
	app.Chain.Kind = componentrelease.AuthorityReleaseV2
	if generationPromoteRequiresRoot([]componentrelease.ComponentRelease{app}) {
		t.Fatal("app-only generation must use its active domain-scoped store operator authorization")
	}
	if !generationPromoteRequiresRoot([]componentrelease.ComponentRelease{sidecar, installer}) {
		t.Fatal("mixed generation containing an installer must require root store authority")
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

// TestAppComponentIsRefusedOnChainAndSkippedOnServeSurface replaces the former
// TestVerifyAppComponentOnChain. Apps are no longer generation components, so
// there is no app projection left for a generation to re-verify: the promote
// path refuses an app outright, and the public serve surface treats an app entry
// carried by a generation signed before the change as inert.
func TestAppComponentIsRefusedOnChainAndSkippedOnServeSurface(t *testing.T) {
	const origin = "https://bazaar.melusina-os.org"
	svc := &publishService{cfg: Config{DistDir: t.TempDir(), Domain: "bazaar.melusina-os.org", PublicBaseURL: origin}}
	app := appComponentFixture("test-app", "1.0.0", origin)

	// Promote side: refused by name, carrying the reason.
	err := svc.verifyComponentReleaseOnChain(context.Background(), app)
	if err == nil {
		t.Fatal("app component accepted into a generation promote")
	}
	if !errors.Is(err, componentrelease.ErrAppNotAGenerationComponent) {
		t.Fatalf("app refusal is not the app-class refusal: %v", err)
	}

	// Serve side: NOTHING for this app exists anywhere under dist — no package, no
	// pointer, no index. Under the old whole-generation gate that was a guaranteed
	// 503. It must now be inert.
	doc := componentrelease.DesiredGeneration{Components: []componentrelease.ComponentRelease{app}}
	if err := svc.verifyDesiredGenerationServeSurface(doc); err != nil {
		t.Fatalf("legacy app entry gated the serve surface: %v", err)
	}

	// MUTATION CONTROL: the same surface still fails closed for a HOST component
	// whose served bytes are absent, so the skip above is app-scoped and the gate
	// has been narrowed rather than disabled.
	doc.Components = append(doc.Components, sampleShellGeneration().Components[0])
	if err := svc.verifyDesiredGenerationServeSurface(doc); err == nil {
		t.Fatal("serve surface accepted a host component with no served bytes")
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
		SizeBytes:      int64(len(content)),
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

	// Read-only readiness lets publish refuse an old store before it creates a
	// private stage or an unexecuted ReleaseEntry proposal.
	rec := httptest.NewRecorder()
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodGet, "/publish/generation", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET readiness want 200 got %d", rec.Code)
	}
	var readiness generationPromoteReadiness
	if err := json.Unmarshal(rec.Body.Bytes(), &readiness); err != nil {
		t.Fatalf("decode readiness: %v", err)
	}
	if readiness.Schema != "melusina-generation-promote-readiness-v1" || readiness.Status != "ready" {
		t.Fatalf("unexpected readiness: %#v", readiness)
	}
	if readiness.CurrentGenerationID != nil {
		t.Fatalf("readiness exposed a generation floor without a locally verified persisted generation: %#v", readiness)
	}

	// A verified persisted generation may disclose only its CAS floor. This is
	// sufficient for the normal signed promote request to repair a public
	// serve-surface mismatch without disclosing the generation contents.
	doc := sampleShellGeneration()
	doc.GenerationID = 61
	doc.PreviousGeneration = 60
	signed, err := componentrelease.Sign(op, doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(svc.cfg.DistDir, raw); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodGet, "/publish/generation", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("verified generation readiness want 200 got %d: %s", rec.Code, rec.Body.String())
	}
	readiness = generationPromoteReadiness{}
	if err := json.Unmarshal(rec.Body.Bytes(), &readiness); err != nil {
		t.Fatalf("decode verified readiness: %v", err)
	}
	if readiness.CurrentGenerationID == nil || *readiness.CurrentGenerationID != 61 {
		t.Fatalf("verified readiness generation floor = %#v, want 61", readiness.CurrentGenerationID)
	}

	// A persisted document whose signer binding is not the active operator must
	// not become a CAS oracle, even though it remains structurally valid JSON.
	foreign, err := componentrelease.Sign(op, doc)
	if err != nil {
		t.Fatal(err)
	}
	foreign.OperatorPubkey = strings.Repeat("1", 32)
	opPub, err := operatorSignPublicKey(op)
	if err != nil {
		t.Fatal(err)
	}
	if err := componentrelease.Verify(opPub, svc.cfg.StoreID, foreign); err == nil {
		t.Fatal("test mutation did not break the persisted generation signer binding")
	}
	raw, err = json.Marshal(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(svc.cfg.DistDir, raw); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	svc.handleGeneratePromote(rec, httptest.NewRequest(http.MethodGet, "/publish/generation", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("foreign generation readiness want 200 got %d: %s", rec.Code, rec.Body.String())
	}
	readiness = generationPromoteReadiness{}
	if err := json.Unmarshal(rec.Body.Bytes(), &readiness); err != nil {
		t.Fatalf("decode foreign readiness: %v", err)
	}
	if readiness.CurrentGenerationID != nil {
		t.Fatalf("readiness exposed foreign-signed generation floor: %#v", readiness.CurrentGenerationID)
	}

	// Readiness must refuse a store whose deployer omitted the public origin.
	// Such a store could accept an approval ceremony but could never serve the
	// signed DesiredGeneration because its bundle URLs have no trusted origin.
	rec = httptest.NewRecorder()
	(&publishService{
		cfg:      Config{StoreID: "melusina-os-root-store"},
		operator: op,
		cr:       &mockChainReader{},
	}).handleGeneratePromote(rec, httptest.NewRequest(http.MethodGet, "/publish/generation", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "public_base_url") {
		t.Fatalf("missing public origin readiness want 503/public_base_url got %d: %s", rec.Code, rec.Body.String())
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
