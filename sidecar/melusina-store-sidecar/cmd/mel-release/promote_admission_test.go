package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// callSite is one call in this package's production source.
type callSite struct {
	caller, callee string
	pos            token.Position
}

// productionCalls parses every non-test Go file of this package and returns
// each call expression with the top-level function that contains it. A
// method call x.Promote(...) is recorded under the callee "Promote".
func productionCalls(t *testing.T) []callSite {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var sites []callSite
	parsed := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		parsed++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var callee string
				switch f := call.Fun.(type) {
				case *ast.Ident:
					callee = f.Name
				case *ast.SelectorExpr:
					callee = f.Sel.Name
				default:
					return true
				}
				sites = append(sites, callSite{caller: fn.Name.Name, callee: callee, pos: fset.Position(call.Pos())})
				return true
			})
		}
	}
	if parsed == 0 {
		t.Fatal("no production Go files parsed; the guard would pass vacuously")
	}
	return sites
}

// Every promote goes through promoteAdmitted, which runs the Go ReleaseEntry
// admission immediately before it, and every promote path calls it. A new
// path that calls SignerProvider.Promote itself, a promoteAdmitted that stops
// admitting first, or a path that stops using it fails here by name. The
// behavioural tests (TestRepairCatalogRunsTheSharedPromoteAdmission,
// TestApproveRefusesAnEntryRecalledBeforePromote,
// TestApproveResumesACommittedPromoteOnlyForAnAdmittedEntry) prove what the
// admission refuses on each path.
func TestEveryPromoteGoesThroughTheSharedAdmission(t *testing.T) {
	sites := productionCalls(t)

	var promotes []callSite
	firstAdmit := map[string]token.Position{}
	callsShared := map[string]bool{}
	for _, s := range sites {
		switch s.callee {
		case "Promote":
			promotes = append(promotes, s)
		case "admitForPromote":
			if _, seen := firstAdmit[s.caller]; !seen {
				firstAdmit[s.caller] = s.pos
			}
		case "promoteAdmitted":
			callsShared[s.caller] = true
		}
	}

	// Positive control: the one sanctioned call site is found, so an empty
	// result can never pass.
	if len(promotes) == 0 {
		t.Fatal("promote-call-site-missing: no call of Promote found in production source; the guard cannot see promote paths")
	}
	for _, s := range promotes {
		if s.caller != "promoteAdmitted" {
			t.Errorf("promote-outside-shared-admission: %s calls Promote at %s; every promote must go through promoteAdmitted", s.caller, s.pos)
		}
	}
	if len(promotes) != 1 {
		t.Errorf("promote-outside-shared-admission: %d calls of Promote, want exactly the one in promoteAdmitted: %v", len(promotes), promotes)
	}
	for _, s := range promotes {
		if s.caller != "promoteAdmitted" {
			continue
		}
		admit, ok := firstAdmit["promoteAdmitted"]
		if !ok || admit.Offset > s.pos.Offset {
			t.Errorf("promote-admission-not-first: promoteAdmitted calls Promote at %s without admitForPromote before it", s.pos)
		}
	}

	// Each promote path uses the shared entry point.
	for _, path := range []string{"ensurePromoted", "runRepairCatalog"} {
		if !callsShared[path] {
			t.Errorf("promote-path-bypasses-shared-admission: %s does not call promoteAdmitted", path)
		}
	}
}
