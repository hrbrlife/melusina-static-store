package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
)

// The Store bootstrap component ships exactly these four programs (see
// scripts/build-store-bootstrap-component.sh). The scan covers every Go file
// and embedded file the toolchain compiles into them, vendored code included.
var bootstrapComponentPackages = []string{
	".",
	"./cmd/boot-identity-prep",
	"./cmd/melusina-update-controller",
	"./cmd/verify-installer-release",
}

const (
	retiringEstateVector          = "paype-devnet-revision-1"
	retiringLicenseRegistryField  = "retiring/" + "programs." + estateprofile.ProgramRoleLicenseRegistry + ".programId"
	retiringEstateTenantHostField = "retiring/tenant-host"
)

// retiringEstateValues is the retiring estate's forbid set, derived from its
// committed profile vector rather than written by hand: every projected value
// except the fields the vector itself marks as illustrative placeholders, plus
// the tenant hosts the profile does not project.
func retiringEstateValues(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "estate-profile-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Profiles []struct {
			Name               string                        `json:"name"`
			IllustrativeFields []string                      `json:"illustrativeFields"`
			Profile            estateprofile.EstateProfileV1 `json:"profile"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors.Profiles {
		if vector.Name != retiringEstateVector {
			continue
		}
		projection, err := estateprofile.Projection(vector.Profile)
		if err != nil {
			t.Fatalf("retiring profile vector: %v", err)
		}
		values := map[string]string{}
		for field, value := range projection {
			illustrative := false
			for _, pattern := range vector.IllustrativeFields {
				if matched, _ := path.Match(pattern, field); matched {
					illustrative = true
				}
			}
			if !illustrative && value != "" {
				values["retiring/"+field] = value
			}
		}
		for index, host := range []string{"paype.cc", "us.paype.cc"} {
			values[fmt.Sprintf("%s-%d", retiringEstateTenantHostField, index)] = host
		}
		if values[retiringLicenseRegistryField] == "" {
			t.Fatalf("retiring profile projects no %s", retiringLicenseRegistryField)
		}
		return values
	}
	t.Fatalf("%s profile vector missing", retiringEstateVector)
	return nil
}

type componentSource struct {
	path   string
	goFile bool
}

// bootstrapComponentSources asks the toolchain, not a directory walk, which
// files the release build compiles for the given build tags.
func bootstrapComponentSources(t *testing.T, tags string) []componentSource {
	t.Helper()
	args := []string{"list", "-mod=vendor", "-deps", "-json"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.Command("go", append(args, bootstrapComponentPackages...)...)
	cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	var sources []componentSource
	decoder := json.NewDecoder(bytes.NewReader(out))
	for {
		var pkg struct {
			Dir        string
			Standard   bool
			GoFiles    []string
			CgoFiles   []string
			EmbedFiles []string
		}
		if err := decoder.Decode(&pkg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode go list: %v", err)
		}
		if pkg.Standard {
			continue
		}
		for _, name := range append(append([]string{}, pkg.GoFiles...), pkg.CgoFiles...) {
			sources = append(sources, componentSource{path: filepath.Join(pkg.Dir, name), goFile: true})
		}
		for _, name := range pkg.EmbedFiles {
			sources = append(sources, componentSource{path: filepath.Join(pkg.Dir, name)})
		}
	}
	return sources
}

// retiringValueHits reports every compiled occurrence of a forbidden value:
// a Go string literal, or the bytes of an embedded file. Comments are not
// compiled and are not reported.
func retiringValueHits(t *testing.T, sources []componentSource, forbidden map[string]string) []string {
	t.Helper()
	names := make([]string, 0, len(forbidden))
	for name := range forbidden {
		names = append(names, name)
	}
	sort.Strings(names)
	var hits []string
	// Hostnames compare case-insensitively; folding every value only widens
	// the net, and any hit is a loud, reviewable failure.
	match := func(where, text string) {
		lower := strings.ToLower(text)
		for _, name := range names {
			if strings.Contains(text, forbidden[name]) || strings.Contains(lower, strings.ToLower(forbidden[name])) {
				hits = append(hits, name+" in "+where)
			}
		}
	}
	files := token.NewFileSet()
	for _, source := range sources {
		raw, err := os.ReadFile(source.path)
		if err != nil {
			t.Fatal(err)
		}
		if !source.goFile {
			match(source.path, string(raw))
			continue
		}
		file, err := parser.ParseFile(files, source.path, raw, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", source.path, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatalf("unquote %s: %v", files.Position(literal.Pos()), err)
			}
			match(files.Position(literal.Pos()).String(), value)
			return true
		})
	}
	return hits
}

func sourceSetIncludes(sources []componentSource, suffix string) bool {
	for _, source := range sources {
		if strings.HasSuffix(filepath.ToSlash(source.path), suffix) {
			return true
		}
	}
	return false
}

// The Store's bootstrap programs take every estate fact from the configuration
// rendered from the owner-signed profile. None of them may compile a value of
// the estate being retired. In the estate-bootstrap build that is the whole
// retiring forbid set; in the standard build, which deliberately keeps the
// legacy Bazaar authority pins, it is the retiring license-registry program.
func TestBootstrapComponentSourceCompilesNoRetiringEstateValue(t *testing.T) {
	retiring := retiringEstateValues(t)
	registryOnly := map[string]string{retiringLicenseRegistryField: retiring[retiringLicenseRegistryField]}

	// Known-positive control for the matcher itself: a literal carrying the
	// retiring registry is found, and the same value in a comment is not.
	control := filepath.Join(t.TempDir(), "control.go")
	if err := os.WriteFile(control, []byte("package control\n\n// "+retiring[retiringLicenseRegistryField]+"\nconst registry = \"id:"+retiring[retiringLicenseRegistryField]+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hits := retiringValueHits(t, []componentSource{{path: control, goFile: true}}, registryOnly); len(hits) != 1 || !strings.HasPrefix(hits[0], retiringLicenseRegistryField+" in "+control+":4:") {
		t.Fatalf("matcher control = %q, want exactly the literal on line 4", hits)
	}

	for _, flavor := range []struct {
		name      string
		tags      string
		forbidden map[string]string
	}{
		{name: "estate-bootstrap", tags: "estatebootstrap", forbidden: retiring},
		{name: "standard", forbidden: registryOnly},
	} {
		t.Run(flavor.name, func(t *testing.T) {
			sources := bootstrapComponentSources(t, flavor.tags)
			for _, required := range []string{"/verify.go", "/config.go", "/cmd/boot-identity-prep/main.go", "/ui/assets/index-C5SMNmPA.js"} {
				if !sourceSetIncludes(sources, required) {
					t.Fatalf("scan never reached %s; it cannot vouch for the component", required)
				}
			}
			t.Logf("%s build: %d compiled files scanned for %d retiring values", flavor.name, len(sources), len(flavor.forbidden))
			if hits := retiringValueHits(t, sources, flavor.forbidden); len(hits) != 0 {
				t.Fatalf("the %s bootstrap build compiles retiring-estate values:\n%s", flavor.name, strings.Join(hits, "\n"))
			}
		})
	}

	// Coverage control: the standard build does reach the legacy Bazaar pins,
	// so the estate-bootstrap result above is an exclusion, not a blind spot.
	legacy := retiringValueHits(t, bootstrapComponentSources(t, ""), retiring)
	t.Logf("standard build, full retiring set (expected legacy pins):\n%s", strings.Join(legacy, "\n"))
	if !strings.Contains(strings.Join(legacy, "\n"), "squads_authority_legacy.go") {
		t.Fatalf("standard build scan found no legacy Bazaar pin; the scan is not reaching tagged files: %q", legacy)
	}
}
