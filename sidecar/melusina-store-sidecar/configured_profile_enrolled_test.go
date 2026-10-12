package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

func namedStoreEstateProfileVector(t *testing.T, name string) estateprofile.EstateProfileV1 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "estate-profile-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors storeEstateProfileVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors.Profiles {
		if vector.Name == name {
			return vector.Profile
		}
	}
	t.Fatalf("profile vector %q is absent", name)
	return estateprofile.EstateProfileV1{}
}

// The accept_publishers guard is only as strong as the profile it reads. The
// serving config's profile must be the enrolled one; another validly signed
// profile, even of the same estate, is refused by name.
func TestRequireConfiguredProfileIsEnrolled(t *testing.T) {
	enrolled := storeEstateProfileFixture(t)
	digest, err := estateprofile.VerifyProfile(enrolled)
	if err != nil {
		t.Fatal(err)
	}
	state := &storeEnrollmentState{Profile: enrolled, ProfilePin: estateprofile.Pin{ProfileSHA256: digest}}
	if err := requireConfiguredProfileIsEnrolled(Config{EstateProfile: &enrolled}, state); err != nil {
		t.Fatalf("configured-profile-enrolled-positive: %v", err)
	}
	for _, name := range []string{"new-estate-revision-2-migrate", "paype-devnet-revision-1"} {
		other := namedStoreEstateProfileVector(t, name)
		if _, err := estateprofile.VerifyProfile(other); err != nil {
			t.Fatalf("vector %s is not a validly signed profile: %v", name, err)
		}
		err := requireConfiguredProfileIsEnrolled(Config{EstateProfile: &other}, state)
		if err == nil || !strings.Contains(err.Error(), "is not the enrolled profile pin") || !strings.Contains(err.Error(), checkAcceptPublishersProfile) {
			t.Fatalf("configured-profile-%s-accepted: %v", name, err)
		}
	}
	if err := requireConfiguredProfileIsEnrolled(Config{}, state); err == nil || !strings.Contains(err.Error(), "carries no estate profile") {
		t.Fatalf("configured-profile-absent-accepted: %v", err)
	}
	if err := requireConfiguredProfileIsEnrolled(Config{EstateProfile: &enrolled}, nil); err == nil || !strings.Contains(err.Error(), "no enrolled estate profile") {
		t.Fatalf("configured-profile-unenrolled-accepted: %v", err)
	}
}

// main() must refuse to start on the binding error, after enrollment is
// proven and before any router surface is built from cfg.
func TestStoreMainBindsConfiguredProfileToEnrollmentBeforeServing(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "main" && fn.Recv == nil {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("main.go has no main()")
	}
	var calls []string
	fatal := false
	ast.Inspect(body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.IfStmt:
			assign, ok := n.Init.(*ast.AssignStmt)
			if !ok || len(assign.Rhs) != 1 {
				return true
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			fun, ok := call.Fun.(*ast.Ident)
			if !ok || fun.Name != "requireConfiguredProfileIsEnrolled" || len(call.Args) != 2 {
				return true
			}
			cfg, cfgOK := call.Args[0].(*ast.Ident)
			state, stateOK := call.Args[1].(*ast.Ident)
			if !cfgOK || !stateOK || cfg.Name != "cfg" || state.Name != "enrolledState" {
				return true
			}
			ast.Inspect(n.Body, func(inner ast.Node) bool {
				if c, ok := inner.(*ast.CallExpr); ok {
					if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Fatalf" {
						fatal = true
					}
				}
				return true
			})
		case *ast.CallExpr:
			switch fun := n.Fun.(type) {
			case *ast.Ident:
				calls = append(calls, fun.Name)
			case *ast.SelectorExpr:
				calls = append(calls, fun.Sel.Name)
			}
		}
		return true
	})
	index := func(name string) int {
		for i, call := range calls {
			if call == name {
				return i
			}
		}
		return -1
	}
	enrollment, bind, surfaces := index("deriveEnrolledBootIdentity"), index("requireConfiguredProfileIsEnrolled"), index("newGovernedRouterSurfaces")
	if bind < 0 || !fatal {
		t.Fatalf("store-main-configured-profile-unbound: main() binds it=%t, refuses to start on its error=%t", bind >= 0, fatal)
	}
	if enrollment < 0 || surfaces < 0 || bind < enrollment || bind > surfaces {
		t.Fatalf("store-main-configured-profile-out-of-order: enrollment at %d, bind at %d, router surfaces at %d", enrollment, bind, surfaces)
	}
}
