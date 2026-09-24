package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// Gate 2 for an enrolled Store (seam audit round 2, finding 10; spec
// amendment, Store commit 10). The controller never applies the Store binary,
// so its runtime marker has no producer on an enrolled Store. /release-info
// there reports the identity the enrollment gate verified instead.

const storeEnrollmentRuntimeVectorsPath = "testdata/store-enrollment-runtime-v1-vectors.json"

type storeEnrollmentRuntimeVectors struct {
	Schema            string `json:"schema"`
	Note              string `json:"note"`
	ControllerRefusal string `json:"controllerRefusal"`
	Vectors           []struct {
		Name   string                       `json:"name"`
		Report storeEnrollmentRuntimeReport `json:"report"`
		Body   string                       `json:"body"`
	} `json:"vectors"`
}

func noRuntimeMarker() []string { return []string{"PATH=/usr/bin", "LANG=C.UTF-8"} }

// enrolledReleaseInfoFixture passes the real startup gate: a durable state
// file, the strict config declaration and the genesis check, then builds the
// self-report from exactly what that gate returned.
func enrolledReleaseInfoFixture(t *testing.T) (storeEnrollmentRuntimeFixture, *storeEnrollmentState, *enrolledRuntimeReleaseInfo) {
	t.Helper()
	f := newStoreEnrollmentRuntimeFixture(t)
	target := newStoreEnrollmentSuccessorTarget(t, &f, true)
	state, err := verifyConfiguredStoreEnrollment(context.Background(), f.cfg, target.configPath, f.identity, newFixedStoreGenesisChainReader(f.genesis))
	if err != nil || state == nil {
		t.Fatalf("positive control: the enrolled Store did not pass its startup gate: state=%v err=%v", state, err)
	}
	enrolled, err := enrolledRuntimeReleaseInfoFor(state, f.identity, 4242)
	if err != nil || enrolled == nil {
		t.Fatalf("enrolled self-report refused: %v", err)
	}
	return f, state, enrolled
}

func getReleaseInfo(t *testing.T, handler http.Handler, method string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(method, "/release-info", nil))
	return rec
}

func TestReleaseInfoEnrolledStoreReportsEnrollmentBinary(t *testing.T) {
	f, state, enrolled := enrolledReleaseInfoFixture(t)
	// Through the public router, as the listener serves it, not the handler
	// alone: the route must reach the enrolled report.
	router := newRouterWithCatalogRuntime(f.cfg, nil, nil, nil, catalogRuntime{enrolledReleaseInfo: enrolled})
	rec := getReleaseInfo(t, router, http.MethodGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("enrolled /release-info HTTP=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", got)
	}
	var got storeEnrollmentRuntimeReport
	dec := json.NewDecoder(strings.NewReader(rec.Body.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("decode enrolled report: %v", err)
	}
	measured := hex.EncodeToString(f.identity.facts.binaryHash[:])
	want := storeEnrollmentRuntimeReport{
		Schema:             storeEnrollmentRuntimeSchema,
		Source:             "enrollment",
		StoreID:            f.cfg.StoreID,
		EnrollmentSequence: 1,
		EnrollmentSHA256:   f.state.EnrollmentSHA256,
		BinarySHA256:       measured,
		PID:                4242,
	}
	if got != want {
		t.Fatalf("enrolled report = %+v, want %+v", got, want)
	}
	if got.BinarySHA256 != state.Enrollment.BinarySHA256 {
		t.Fatalf("reported binary %s is not the enrolled %s", got.BinarySHA256, state.Enrollment.BinarySHA256)
	}
	// Not a controller tuple: a different schema and none of its fields.
	if got.Schema == componentrelease.RuntimeReleaseInfoSchema {
		t.Fatalf("enrolled report claims the controller runtime schema")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"componentId", "generationId", "version", "artifactSha256"} {
		if _, ok := raw[field]; ok {
			t.Fatalf("enrolled report carries controller field %q: %s", field, rec.Body.String())
		}
	}
	if head := getReleaseInfo(t, router, http.MethodHead); head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD HTTP=%d body=%q", head.Code, head.Body.String())
	}
	if post := getReleaseInfo(t, router, http.MethodPost); post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST HTTP=%d, want 405", post.Code)
	}
}

func TestReleaseInfoUnenrolledWithoutMarkerIs503(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	for _, key := range []string{"RRS_RUNTIME_SCHEMA", "RRS_COMPONENT_ID", "RRS_GENERATION_ID", "RRS_SIDECAR_VERSION", "RRS_ARTIFACT_SHA256"} {
		t.Setenv(key, "")
	}
	// An unenrolled Store has a boot identity but no enrollment state. It must
	// get no self-report, however valid its measured binary is.
	enrolled, err := enrolledRuntimeReleaseInfoFor(nil, f.identity, 4242)
	if err != nil {
		t.Fatalf("unenrolled Store refused: %v", err)
	}
	if enrolled != nil {
		t.Fatalf("unenrolled Store got an enrollment self-report: %s", enrolled.body)
	}
	router := newRouterWithCatalogRuntime(f.cfg, nil, nil, nil, catalogRuntime{enrolledReleaseInfo: enrolled})
	rec := getReleaseInfo(t, router, http.MethodGet)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unenrolled Store without a marker: /release-info HTTP=%d body=%s, want 503", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), storeEnrollmentRuntimeSchema) || strings.Contains(rec.Body.String(), "binarySha256") {
		t.Fatalf("unenrolled 503 reflects an identity: %s", rec.Body.String())
	}
}

func TestReleaseInfoMarkerOnEnrolledStoreRefused(t *testing.T) {
	_, _, enrolled := enrolledReleaseInfoFixture(t)
	if rec := getReleaseInfo(t, newRuntimeReleaseInfoHandler(enrolled, noRuntimeMarker), http.MethodGet); rec.Code != http.StatusOK {
		t.Fatalf("positive control: enrolled Store without a marker HTTP=%d body=%s", rec.Code, rec.Body.String())
	}
	complete := []string{
		"RRS_RUNTIME_SCHEMA=" + componentrelease.RuntimeReleaseInfoSchema,
		"RRS_COMPONENT_ID=" + storeRuntimeComponentID,
		"RRS_GENERATION_ID=7",
		"RRS_SIDECAR_VERSION=gen-7-aabbccdd",
		"RRS_ARTIFACT_SHA256=" + strings.Repeat("c", 64),
	}
	for name, environ := range map[string][]string{
		"complete controller marker": append(noRuntimeMarker(), complete...),
		"one marker key":             append(noRuntimeMarker(), "RRS_GENERATION_ID=7"),
		"empty marker key":           append(noRuntimeMarker(), "RRS_COMPONENT_ID="),
	} {
		t.Run(name, func(t *testing.T) {
			environ := environ
			rec := getReleaseInfo(t, newRuntimeReleaseInfoHandler(enrolled, func() []string { return environ }), http.MethodGet)
			if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), refusalReleaseInfoMarkerOnEnrolledStore) {
				t.Fatalf("marker on an enrolled Store: HTTP=%d body=%s, want 503 %s", rec.Code, rec.Body.String(), refusalReleaseInfoMarkerOnEnrolledStore)
			}
			if strings.Contains(rec.Body.String(), "gen-7") || strings.Contains(rec.Body.String(), strings.Repeat("c", 64)) || strings.Contains(rec.Body.String(), enrolled.report.BinarySHA256) {
				t.Fatalf("refusal reflects a marker value or the self-report: %s", rec.Body.String())
			}
		})
	}
	// The production route reads the process environment.
	t.Setenv("RRS_GENERATION_ID", "7")
	router := newRouterWithCatalogRuntime(Config{}, nil, nil, nil, catalogRuntime{enrolledReleaseInfo: enrolled})
	if rec := getReleaseInfo(t, router, http.MethodGet); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), refusalReleaseInfoMarkerOnEnrolledStore+": RRS_GENERATION_ID") {
		t.Fatalf("router with a marker in the process environment: HTTP=%d body=%s", rec.Code, rec.Body.String())
	}
}

// The unenrolled Store's controller-marker path is unchanged: with a valid
// marker it still reports the controller tuple, not an enrollment.
func TestReleaseInfoUnenrolledMarkerPathUnchanged(t *testing.T) {
	t.Setenv("RRS_RUNTIME_SCHEMA", componentrelease.RuntimeReleaseInfoSchema)
	t.Setenv("RRS_COMPONENT_ID", storeRuntimeComponentID)
	t.Setenv("RRS_GENERATION_ID", "42")
	t.Setenv("RRS_SIDECAR_VERSION", "gen-42-bbbbbbbb")
	t.Setenv("RRS_ARTIFACT_SHA256", strings.Repeat("b", 64))
	router := newRouterWithCatalogRuntime(Config{}, nil, nil, nil, catalogRuntime{})
	rec := getReleaseInfo(t, router, http.MethodGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("unenrolled marker HTTP=%d body=%s", rec.Code, rec.Body.String())
	}
	var got runtimeReleaseInfo
	dec := json.NewDecoder(strings.NewReader(rec.Body.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&got); err != nil || got.GenerationID != 42 || got.ComponentID != storeRuntimeComponentID {
		t.Fatalf("unenrolled marker report = %+v, %v", got, err)
	}
}

func TestReleaseInfoEnrolledStoreRefusesBinaryOtherThanEnrolled(t *testing.T) {
	f, state, _ := enrolledReleaseInfoFixture(t)
	rebuilt := runtimeIdentityWith(f, "rebuilt-binary", "", 0, "")
	if _, err := enrolledRuntimeReleaseInfoFor(state, rebuilt, 4242); err == nil || !strings.Contains(err.Error(), refusalReleaseInfoEnrollmentBinaryMismatch) {
		t.Fatalf("a binary the enrollment does not bind got a self-report: %v", err)
	}
	if _, err := enrolledRuntimeReleaseInfoFor(state, nil, 4242); err == nil || !strings.Contains(err.Error(), refusalReleaseInfoEnrollmentIncomplete) {
		t.Fatalf("an enrollment without a boot identity got a self-report: %v", err)
	}
	if _, err := enrolledRuntimeReleaseInfoFor(state, f.identity, 0); err == nil || !strings.Contains(err.Error(), refusalReleaseInfoEnrollmentIncomplete) {
		t.Fatalf("pid 0 got a self-report: %v", err)
	}
}

// After an owner-signed successor the report names the successor and the
// rebuilt binary it binds, and the superseded binary is refused.
func TestReleaseInfoEnrolledStoreFollowsSuccessorBinding(t *testing.T) {
	f := newStoreEnrollmentRuntimeFixture(t)
	rebuilt := runtimeIdentityWith(f, "rebuilt-binary", "", 0, "")
	held, second := requestStoreEnrollmentSuccessorFromState(t, f, f.state, rebuilt, storeEnrollmentSuccessorNow, "owner-a", "owner-b")
	next, err := advanceStoreEnrollmentState(held, second, storeEnrollmentSuccessorNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("advance to the owner-signed successor: %v", err)
	}
	enrolled, err := enrolledRuntimeReleaseInfoFor(&next, rebuilt, 4242)
	if err != nil {
		t.Fatalf("successor self-report refused: %v", err)
	}
	rebuiltHash := sha256.Sum256([]byte("rebuilt-binary"))
	if got := enrolled.report; got.EnrollmentSequence != 2 || got.EnrollmentSHA256 != mustStoreEnrollmentSuccessorDigest(t, second) || got.BinarySHA256 != hex.EncodeToString(rebuiltHash[:]) || got.BinarySHA256 != second.BinarySHA256 || got.StoreID != second.StoreID {
		t.Fatalf("successor self-report = %+v", got)
	}
	if _, err := enrolledRuntimeReleaseInfoFor(&next, f.identity, 4242); err == nil || !strings.Contains(err.Error(), refusalReleaseInfoEnrollmentBinaryMismatch) {
		t.Fatalf("the superseded binary got a self-report under the successor: %v", err)
	}
}

// The shared vector: the Store writes each body byte for byte. The update
// controller's decoder test reads the same file and refuses every body.
func TestStoreEnrollmentRuntimeReportMatchesSharedVector(t *testing.T) {
	raw, err := os.ReadFile(storeEnrollmentRuntimeVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc storeEnrollmentRuntimeVectors
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode %s: %v", storeEnrollmentRuntimeVectorsPath, err)
	}
	if doc.Schema != "melusina.store-enrollment-runtime-vectors.v1" || len(doc.Vectors) < 2 {
		t.Fatalf("%s: schema %q with %d vectors", storeEnrollmentRuntimeVectorsPath, doc.Schema, len(doc.Vectors))
	}
	for _, vector := range doc.Vectors {
		report := vector.Report
		if report.Schema != "" || report.Source != "" {
			t.Fatalf("vector %s: schema and source are the Store's constants, not inputs", vector.Name)
		}
		report.Schema, report.Source = storeEnrollmentRuntimeSchema, storeEnrollmentRuntimeSource
		body, err := encodeStoreEnrollmentRuntimeReport(report)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != vector.Body {
			t.Fatalf("vector %s:\n got  %s\n want %s", vector.Name, body, vector.Body)
		}
		enrolled := &enrolledRuntimeReleaseInfo{report: report, body: body}
		rec := getReleaseInfo(t, newRuntimeReleaseInfoHandler(enrolled, noRuntimeMarker), http.MethodGet)
		if rec.Code != http.StatusOK || rec.Body.String() != vector.Body {
			t.Fatalf("vector %s served HTTP=%d %q", vector.Name, rec.Code, rec.Body.String())
		}
	}
}

// The deployment contract states the enrolled rule in both gates and no
// longer records the gap as open.
func TestDeploymentContractStatesEnrolledStoreReleaseInfo(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	contractPath := filepath.Join(root, "deploy", "store-generation", "DEPLOYMENT-CONTRACT.md")
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatal(err)
	}
	contract := strings.Join(strings.Fields(string(raw)), " ")
	for _, required := range []string{
		storeEnrollmentRuntimeSchema,
		`"source": "enrollment"`,
		refusalReleaseInfoMarkerOnEnrolledStore,
		"install-bootstrap journal",
		storeEnrollmentRuntimeVectorsPath,
	} {
		if !strings.Contains(contract, required) {
			t.Fatalf("%s omits the enrolled-Store release-info rule %q", contractPath, required)
		}
	}
	for _, stale := range []string{
		"has no producer yet",
		"because the controller has not written a runtime tuple yet",
	} {
		if strings.Contains(contract, stale) {
			t.Fatalf("%s still states %q", contractPath, stale)
		}
	}
}

// Server startup builds the self-report from what the enrollment gate returned
// and hands it to the router before the router is built. main() cannot run in
// a unit test, so this reads main.go: the assignment must take
// deriveEnrolledBootIdentity's enrolledState and bootIdentity, and must come
// before newGovernedRouterSurfaces receives catalogState.
func TestServerStartupWiresEnrolledReleaseInfo(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	identName := func(expr ast.Expr) string {
		if ident, ok := expr.(*ast.Ident); ok {
			return ident.Name
		}
		return ""
	}
	var assigned, derived, routed token.Pos
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "main" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.AssignStmt:
				if len(n.Rhs) != 1 {
					return true
				}
				call, ok := n.Rhs[0].(*ast.CallExpr)
				if !ok {
					return true
				}
				switch identName(call.Fun) {
				case "deriveEnrolledBootIdentity":
					if len(n.Lhs) == 3 && identName(n.Lhs[0]) == "bootIdentity" && identName(n.Lhs[1]) == "enrolledState" {
						derived = n.Pos()
					}
				case "enrolledRuntimeReleaseInfoFor":
					sel, ok := n.Lhs[0].(*ast.SelectorExpr)
					if ok && identName(sel.X) == "catalogState" && sel.Sel.Name == "enrolledReleaseInfo" &&
						len(call.Args) == 3 && identName(call.Args[0]) == "enrolledState" && identName(call.Args[1]) == "bootIdentity" {
						assigned = n.Pos()
					}
				}
			case *ast.CallExpr:
				if identName(n.Fun) == "newGovernedRouterSurfaces" {
					for _, arg := range n.Args {
						if identName(arg) == "catalogState" {
							routed = n.Pos()
						}
					}
				}
			}
			return true
		})
	}
	if derived == token.NoPos || assigned == token.NoPos || routed == token.NoPos {
		t.Fatalf("main.go: enrollment gate at %v, self-report assignment at %v, router at %v; startup must build catalogState.enrolledReleaseInfo from enrolledState and bootIdentity", fset.Position(derived), fset.Position(assigned), fset.Position(routed))
	}
	if !(derived < assigned && assigned < routed) {
		t.Fatalf("main.go: the self-report is not built between the enrollment gate (%v) and the router (%v): %v", fset.Position(derived), fset.Position(routed), fset.Position(assigned))
	}
}
