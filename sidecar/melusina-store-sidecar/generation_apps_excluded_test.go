package main

// Apps are not DesiredGeneration components (N-023 / F-199, Option A).
//
// These are the regression tests for the estate-wide outage of 2026-08-14:
// publishing MiniGit 0.2.11 moved that app's per-app signed catalog pointer, so
// generation 174 — which still named MiniGit 0.2.10 — stopped binding it. The
// whole-generation serve-surface gate re-checked EVERY component and returned on
// the FIRST failure, so BOTH shell-update endpoints (/update/generation.json and
// /update/manifest.json) went HTTP 503 estate-wide while /apps/index.json served
// perfectly. An app in a generation is un-appliable anyway: there is no ApplyKind
// for a Sandstorm app, so the host update controller could never install one.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// appComponentFixture is the app-class ComponentRelease shape a pre-Option-A
// generation carried. Every field satisfies componentrelease validation, so any
// refusal a test observes is the app-class refusal and never a malformed entry.
func appComponentFixture(appID, version, origin string) componentrelease.ComponentRelease {
	sum := sha256.Sum256([]byte(appID + "@" + version))
	packageID := hex.EncodeToString(sum[:])[:32]
	return componentrelease.ComponentRelease{
		ComponentID:     appID,
		ComponentClass:  componentrelease.ClassApp,
		Version:         version,
		ArtifactName:    packageID,
		SHA256:          strings.Repeat("a", 64),
		ContentSHA256:   strings.Repeat("b", 64),
		SizeBytes:       4096,
		BundleURL:       strings.TrimRight(origin, "/") + "/packages/" + packageID,
		ReleaseHash:     strings.Repeat("c", 64),
		StageID:         strings.Repeat("d", 64),
		PreviousSHA256:  strings.Repeat("e", 64),
		PreviousVersion: "0.0.1",
		Chain: componentrelease.ChainAuthority{
			Kind:          componentrelease.AuthorityReleaseV2,
			Program:       programID.Base58(),
			MasterNftMint: testMaster,
			ReleasePDA:    "FMRFyGPzrefaYiETSLTDw8fHqix8GVcGuri31qTZVtgY",
		},
	}
}

// TestGenerationRefusesAppComponentAtSubmission proves a submitted app component
// is refused outright — the store never mints a generation that names an app.
func TestGenerationRefusesAppComponentAtSubmission(t *testing.T) {
	const origin = "https://bazaar.melusina-os.org"
	policy := GenerationPolicy{StoreID: "melusina-os-root-store", BundleOrigin: origin, Channel: "dev"}
	app := appComponentFixture("minigit", "0.2.11", origin)

	// compose (the deterministic engine)
	if _, err := composeNextGeneration(nil, policy, 1784281900, []componentrelease.ComponentRelease{app}); err == nil {
		t.Fatal("composeNextGeneration accepted an app-class component: apps must never enter a generation")
	} else if !strings.Contains(err.Error(), "minigit") {
		t.Fatalf("compose refusal does not name the offending component: %v", err)
	}

	// submission (the store's promote engine, one layer above compose)
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	dist := t.TempDir()
	svc := &publishService{cfg: Config{StoreID: policy.StoreID, DistDir: dist, PublicBaseURL: origin}, operator: op}
	appReq := GenerationPromoteRequest{
		Schema:                    generationPromoteSchema,
		Channel:                   "dev",
		ExpectedCurrentGeneration: 0,
		Components:                []componentrelease.ComponentRelease{app},
	}
	if _, err := svc.promoteGeneration(appReq, time.Unix(1784281900, 0)); err == nil {
		t.Fatal("promoteGeneration accepted an app-class component")
	}
	if _, err := os.Stat(filepath.Join(dist, "update", "generation.json")); err == nil {
		t.Fatal("a refused app promote still persisted a generation")
	}

	// POSITIVE CONTROL: the identical submission carrying a HOST component is
	// accepted and persisted, so the refusal above is about app class and not a
	// broken promote path.
	host := sampleShellGeneration().Components[0]
	hostReq := appReq
	hostReq.Components = []componentrelease.ComponentRelease{host}
	if _, err := svc.promoteGeneration(hostReq, time.Unix(1784281900, 0)); err != nil {
		t.Fatalf("host-component promote refused: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dist, "update", "generation.json")); err != nil {
		t.Fatalf("accepted host promote did not persist a generation: %v", err)
	}
}

// TestComposeDropsLegacyAppComponentsOnCarryForward proves the next promote after
// this change composes a HOST-ONLY generation: the app entries an older
// generation carried are dropped rather than preserved verbatim.
func TestComposeDropsLegacyAppComponentsOnCarryForward(t *testing.T) {
	const origin = "https://bazaar.melusina-os.org"
	policy := GenerationPolicy{StoreID: "melusina-os-root-store", BundleOrigin: origin, Channel: "dev"}

	current := sampleShellGeneration() // generation 63, one shell component
	current.Components = append(current.Components, appComponentFixture("minigit", "0.2.10", origin))

	update := sampleShellGeneration().Components[0]
	update.Version = "build-64"
	update.Build = 64

	next, err := composeNextGeneration(&current, policy, 1784281900, []componentrelease.ComponentRelease{update})
	if err != nil {
		t.Fatalf("compose over a legacy app-bearing generation failed: %v", err)
	}
	for _, c := range next.Components {
		if c.ComponentClass == componentrelease.ClassApp || c.Chain.Kind == componentrelease.AuthorityReleaseV2 {
			t.Fatalf("carry-forward preserved app component %q — the next generation must be host-only", c.ComponentID)
		}
	}
	if _, ok := next.Component("sandstorm-shell"); !ok {
		t.Fatal("carry-forward dropped the host shell component")
	}
	if next.GenerationID != current.GenerationID+1 {
		t.Fatalf("composed generation %d, want %d", next.GenerationID, current.GenerationID+1)
	}
}

// TestComposeRefusesHostDependencyOnDroppedApp proves the dropped-app filter never
// silently rewrites the dependency graph: a retained host component that still
// declares a requires[] edge to an app is refused by name.
func TestComposeRefusesHostDependencyOnDroppedApp(t *testing.T) {
	const origin = "https://bazaar.melusina-os.org"
	policy := GenerationPolicy{StoreID: "melusina-os-root-store", BundleOrigin: origin, Channel: "dev"}

	current := sampleShellGeneration()
	current.Components[0].Requires = []componentrelease.ComponentDependency{{ComponentID: "minigit"}}
	current.Components = append(current.Components, appComponentFixture("minigit", "0.2.10", origin))

	update := sampleShellGeneration().Components[0]
	update.ComponentID = "melusina-store-sidecar"
	update.ComponentClass = componentrelease.ClassSidecar
	update.Chain = componentrelease.ChainAuthority{
		Kind:              componentrelease.AuthoritySidecarIdentity,
		Program:           programID.Base58(),
		LicenseNftMint:    testLicenseMint,
		MasterNftMint:     testMaster,
		SidecarID:         "melusina-store-sidecar",
		IdentityPDA:       "FMRFyGPzrefaYiETSLTDw8fHqix8GVcGuri31qTZVtgY",
		GlobalApprovalPDA: "FMRFyGPzrefaYiETSLTDw8fHqix8GVcGuri31qTZVtgY",
		LocalApprovalPDA:  "FMRFyGPzrefaYiETSLTDw8fHqix8GVcGuri31qTZVtgY",
	}

	_, err := composeNextGeneration(&current, policy, 1784281900, []componentrelease.ComponentRelease{update})
	if err == nil {
		t.Fatal("compose silently rewrote the dependency graph instead of refusing a retained requires[] edge to a dropped app")
	}
	if !strings.Contains(err.Error(), "minigit") || !strings.Contains(err.Error(), "sandstorm-shell") {
		t.Fatalf("refusal does not name both the dependent and the dropped app: %v", err)
	}
}

// movedAppPointer writes an app's per-app operator-signed catalog pointer that is
// VALID and CURRENT for a NEWER release than `component` names. This is exactly
// what publishing MiniGit 0.2.11 did to generation 174: the signature verifies,
// the app serves perfectly over /apps/*, but the generation's own binding
// predicate (appId, packageId, version, appHash, servingDomainHash) no longer
// holds.
func movedAppPointer(t *testing.T, dist, domain string, op *identity.Private, component componentrelease.ComponentRelease) {
	t.Helper()
	newer := appComponentFixture(component.ComponentID, component.Version+"-superseded", "https://bazaar.melusina-os.org")
	domainHash := primitives.StoreDomainHash(domain)
	pointer := AppCatalogPointer{
		Schema:            appCatalogPointerSchema,
		AppID:             component.ComponentID,
		PackageID:         newer.ArtifactName,
		Version:           newer.Version,
		AppHash:           newer.ContentSHA256,
		ReleaseHash:       newer.ReleaseHash,
		StageID:           newer.StageID,
		CatalogSHA256:     strings.Repeat("f", 64),
		ServingDomainHash: hex.EncodeToString(domainHash[:]),
		PublishedAt:       1784281900,
	}
	message, err := appCatalogPointerMessage(pointer)
	if err != nil {
		t.Fatal(err)
	}
	pointer.OperatorSignature = primitives.EncodeBase58(op.Sign(message))
	body, err := json.Marshal(pointer)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dist, "apps", "pointers"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "apps", "pointers", component.ComponentID+".json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestShellUpdateEndpointsServeWhileAppPointerMoved is THE regression test for the
// 2026-08-14 outage. A signed generation carries host components AND (as
// generation 174 did) a legacy app component whose signed pointer has since moved.
// Both shell-update endpoints must serve 200: an app can never gate a host update.
func TestShellUpdateEndpointsServeWhileAppPointerMoved(t *testing.T) {
	const domain = "bazaar.melusina-os.org"
	op := newTestIdentity(t, "store-operator", testLicenseMint, domain)
	dist := t.TempDir()

	doc, artifact := servableShellGeneration(t)
	writeReleaseArtifact(t, dist, "shell", doc.Components[0].ArtifactName, artifact)

	app := appComponentFixture("minigit", "0.2.10", doc.BundleOrigin)
	doc.Components = append(doc.Components, app)
	movedAppPointer(t, dist, domain, op, app)

	signed, err := componentrelease.Sign(op, doc)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistDesiredGeneration(dist, raw); err != nil {
		t.Fatalf("persist: %v", err)
	}

	svc := &publishService{cfg: Config{
		StoreID:       doc.StoreID,
		Domain:        domain,
		DistDir:       dist,
		PublicBaseURL: doc.BundleOrigin,
	}, operator: op}

	get := func(path string, h func(http.ResponseWriter, *http.Request)) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	if rec := get("/update/generation.json", svc.handleDesiredGeneration); rec.Code != http.StatusOK {
		t.Fatalf("/update/generation.json = %d (%s) — a moved APP pointer must never take the shell-update surface down",
			rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	if rec := get("/update/manifest.json", svc.handleLegacyManifest); rec.Code != http.StatusOK {
		t.Fatalf("/update/manifest.json = %d (%s) — a moved APP pointer must never take the legacy manifest down",
			rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	// The app pointer disappearing entirely is equally inert.
	if err := os.Remove(filepath.Join(dist, "apps", "pointers", app.ComponentID+".json")); err != nil {
		t.Fatal(err)
	}
	if rec := get("/update/generation.json", svc.handleDesiredGeneration); rec.Code != http.StatusOK {
		t.Fatalf("/update/generation.json = %d (%s) with no app pointer at all", rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	// MUTATION CONTROL: the serve-surface gate is still armed for HOST
	// components. Corrupt the shell artifact and both endpoints must fail closed
	// — otherwise this change would have disabled the gate rather than narrowed
	// it to the components it actually governs.
	writeReleaseArtifact(t, dist, "shell", doc.Components[0].ArtifactName, []byte("tampered shell bundle"))
	rec := get("/update/generation.json", svc.handleDesiredGeneration)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "check=serve_surface") {
		t.Fatalf("host serve-surface gate no longer fails closed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = get("/update/manifest.json", svc.handleLegacyManifest)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "check=serve_surface") {
		t.Fatalf("legacy manifest host gate no longer fails closed: status=%d body=%s", rec.Code, rec.Body.String())
	}
}
