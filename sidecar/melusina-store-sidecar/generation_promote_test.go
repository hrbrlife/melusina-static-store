package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

func promoteTestService(t *testing.T) *publishService {
	t.Helper()
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	return &publishService{
		cfg: Config{
			StoreID:       "melusina-os-root-store",
			DistDir:       t.TempDir(),
			PublicBaseURL: "https://bazaar.melusina-os.org",
		},
		operator: op,
	}
}

func promoteReq(expected uint64, comps ...componentrelease.ComponentRelease) GenerationPromoteRequest {
	return GenerationPromoteRequest{
		Schema:                    generationPromoteSchema,
		Channel:                   "dev",
		ExpectedCurrentGeneration: expected,
		Components:                comps,
	}
}

// promotableShellComp makes a real public artifact for tests that assert the
// full promote -> persisted generation -> GET path. A signed generation with a
// synthetic hash is deliberately no longer enough for that path: the producer
// must fail closed unless its named public bytes are present and exact.
func promotableShellComp(t *testing.T, svc *publishService, tag, version string) componentrelease.ComponentRelease {
	t.Helper()
	body := []byte("generation-promote-public-bundle:" + tag)
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	component := shellComp("sandstorm-shell", sha, version)
	component.SizeBytes = int64(len(body))
	component.ArtifactName = "sandstorm-shell-" + sha[:8] + ".tar.xz"
	component.BundleURL = svc.cfg.PublicBaseURL + "/releases/shell/" + component.ArtifactName
	writeReleaseArtifact(t, svc.cfg.DistDir, "shell", component.ArtifactName, body)
	return component
}

// servedGeneration drives the producer over the same service and returns the
// decoded served generation + HTTP status — proving promote -> serve agreement.
func servedGeneration(t *testing.T, svc *publishService) (componentrelease.DesiredGeneration, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	svc.handleDesiredGeneration(rec, httptest.NewRequest(http.MethodGet, "/update/generation.json", nil))
	var doc componentrelease.DesiredGeneration
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("served body not json: %v", err)
		}
	}
	return doc, rec.Code
}

func TestPromoteGenerationGenesisThenServe(t *testing.T) {
	svc := promoteTestService(t)
	req := promoteReq(0, promotableShellComp(t, svc, "build-1", "build-1"))
	raw, err := svc.promoteGeneration(req, time.Unix(1784281821, 0))
	if err != nil {
		t.Fatalf("promote genesis: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("empty promote bytes")
	}
	// The producer must now serve exactly this generation and it must verify.
	doc, code := servedGeneration(t, svc)
	if code != http.StatusOK {
		t.Fatalf("producer did not serve promoted generation: %d", code)
	}
	if doc.GenerationID != 1 || doc.PreviousGeneration != 0 {
		t.Fatalf("genesis generation ids: id=%d prev=%d", doc.GenerationID, doc.PreviousGeneration)
	}
	pub, _ := operatorSignPublicKey(svc.operator)
	if err := componentrelease.Verify(pub, "melusina-os-root-store", doc); err != nil {
		t.Fatalf("served promoted generation does not verify: %v", err)
	}
}

func TestPromoteGenerationAdvancesWithCAS(t *testing.T) {
	svc := promoteTestService(t)
	// Genesis -> gen 1.
	gen1 := promotableShellComp(t, svc, "build-1", "build-1")
	if _, err := svc.promoteGeneration(promoteReq(0, gen1), time.Unix(1784281821, 0)); err != nil {
		t.Fatalf("promote gen1: %v", err)
	}
	// Advance -> gen 2 (expected current = 1).
	if _, err := svc.promoteGeneration(promoteReq(1, promotableShellComp(t, svc, "build-2", "build-2")), time.Unix(1784281900, 0)); err != nil {
		t.Fatalf("promote gen2: %v", err)
	}
	doc, code := servedGeneration(t, svc)
	if code != http.StatusOK || doc.GenerationID != 2 || doc.PreviousGeneration != 1 {
		t.Fatalf("after advance: code=%d id=%d prev=%d", code, doc.GenerationID, doc.PreviousGeneration)
	}
	// The changed shell's rollback floor is the gen-1 artifact.
	if doc.Components[0].PreviousSHA256 != gen1.SHA256 {
		t.Fatalf("rollback floor not the prior artifact: %s", doc.Components[0].PreviousSHA256)
	}
}

func TestPromoteGenerationPreservesSignedTargetRollbackFloor(t *testing.T) {
	svc := promoteTestService(t)
	gen1 := promotableShellComp(t, svc, "build-1", "build-1")
	if _, err := svc.promoteGeneration(promoteReq(0,
		gen1), time.Unix(1784281821, 0)); err != nil {
		t.Fatalf("promote gen1: %v", err)
	}
	if _, err := svc.promoteGeneration(promoteReq(1,
		promotableShellComp(t, svc, "build-2", "build-2")), time.Unix(1784281900, 0)); err != nil {
		t.Fatalf("promote gen2: %v", err)
	}

	// Gen2 was advertised but never committed by this target. The next signed
	// request must retain the target's actual build-1 floor, rather than silently
	// replacing it with the merely advertised build-2 artifact.
	retry := promotableShellComp(t, svc, "build-3", "build-3")
	retry.PreviousSHA256 = gen1.SHA256
	retry.PreviousVersion = "build-1"
	if _, err := svc.promoteGeneration(promoteReq(2, retry), time.Unix(1784282000, 0)); err != nil {
		t.Fatalf("promote retry: %v", err)
	}
	doc, code := servedGeneration(t, svc)
	if code != http.StatusOK || doc.GenerationID != 3 {
		t.Fatalf("after retry: code=%d id=%d", code, doc.GenerationID)
	}
	if got := doc.Components[0].PreviousSHA256; got != gen1.SHA256 {
		t.Fatalf("target rollback floor was overwritten: got %s", got)
	}
	if got := doc.Components[0].PreviousVersion; got != "build-1" {
		t.Fatalf("target rollback version was overwritten: got %q", got)
	}
}

func TestPromoteGenerationRejectsPartialTargetRollbackFloor(t *testing.T) {
	svc := promoteTestService(t)
	if _, err := svc.promoteGeneration(promoteReq(0,
		promotableShellComp(t, svc, "build-1", "build-1")), time.Unix(1784281821, 0)); err != nil {
		t.Fatalf("promote gen1: %v", err)
	}
	bad := promotableShellComp(t, svc, "build-2", "build-2")
	bad.PreviousSHA256 = strings.Repeat("a", 64)
	if _, err := svc.promoteGeneration(promoteReq(1, bad), time.Unix(1784281900, 0)); err == nil {
		t.Fatal("promote accepted a partial target rollback floor")
	}
}

func TestPromoteGenerationRejectsStaleCAS(t *testing.T) {
	svc := promoteTestService(t)
	gen1 := promotableShellComp(t, svc, "build-1", "build-1")
	if _, err := svc.promoteGeneration(promoteReq(0, gen1), time.Unix(1784281821, 0)); err != nil {
		t.Fatalf("promote gen1: %v", err)
	}
	// A second publisher still believes current is 0 (stale) -> must be refused,
	// and the current generation must be left untouched.
	if _, err := svc.promoteGeneration(promoteReq(0, promotableShellComp(t, svc, "build-x", "build-x")), time.Unix(1784281950, 0)); err == nil {
		t.Fatal("promote accepted a stale expected-current generation")
	}
	doc, _ := servedGeneration(t, svc)
	if doc.GenerationID != 1 || doc.Components[0].SHA256 != gen1.SHA256 {
		t.Fatalf("stale promote mutated the current generation: id=%d sha=%s", doc.GenerationID, doc.Components[0].SHA256)
	}
}

func TestPromoteGenerationRejectsBadSchema(t *testing.T) {
	svc := promoteTestService(t)
	req := promoteReq(0, promotableShellComp(t, svc, "build-1", "build-1"))
	req.Schema = "wrong"
	if _, err := svc.promoteGeneration(req, time.Unix(1784281821, 0)); err == nil {
		t.Fatal("promote accepted a wrong request schema")
	}
}

func TestPromoteGenerationMintsVersionWhenAbsent(t *testing.T) {
	svc := promoteTestService(t)
	// No version supplied -> composer mints one bound to the artifact hash.
	component := promotableShellComp(t, svc, "build-1", "")
	req := promoteReq(0, component)
	if _, err := svc.promoteGeneration(req, time.Unix(1784281821, 0)); err != nil {
		t.Fatalf("promote: %v", err)
	}
	doc, _ := servedGeneration(t, svc)
	if doc.Components[0].Version != mintComponentVersion(1, component.SHA256) {
		t.Fatalf("version not minted: %q", doc.Components[0].Version)
	}
}
