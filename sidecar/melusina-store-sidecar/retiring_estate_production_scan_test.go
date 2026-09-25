package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file extends the retiring-estate guards from the Store component and
// the release tools to the whole of the Store's production source: every
// program the sidecar module builds, in both build flavors, and every
// production file in the repository. A new estate's Store takes every estate
// fact from its profile-rendered configuration, so no production path may
// compile or carry a value of the estate being retired, except in the
// explicitly declared retiring-estate paths below, none of which the Store
// bootstrap component ships.

const (
	retiringRootDomainField  = "retiring/root-domain"
	retiringUIPlaceholder    = "example.melusina-os.org"
	generationReleaseScript  = "scripts/build-store-generation-release.sh"
	bootstrapComponentScript = "scripts/build-store-bootstrap-component.sh"
	sidecarModuleDir         = "sidecar/melusina-store-sidecar/"
)

// storeProductionForbiddenValues is the retiring estate's forbid set: the
// profile vector's projected values and the catalog ledger's Store and release
// authority (releaseToolForbiddenValues), plus retiring facts the profile does
// not project. Each extra names where the retiring estate used it.
func storeProductionForbiddenValues(t *testing.T) map[string]string {
	t.Helper()
	values := releaseToolForbiddenValues(t)
	rootDomain := "melusina-os.org"
	rootDomainHash := sha256.Sum256([]byte(rootDomain))
	for field, value := range map[string]string{
		// The retiring estate's registrable domain. It was the root_store_url
		// default the Store compiled until 45e5a31. Its hash was the licence
		// registry's ROOT_STORE_DOMAIN_HASH only until contracts ba2e327
		// ("store: bind root authority to Bazaar origin"). Since then the
		// registry pins sha256("bazaar.melusina-os.org") (constants.rs
		// ROOT_STORE_DOMAIN_HASH, 1bdcbe62...6592), which is forbidden as
		// retiring/store.rootDomainSha256, projected from the paype-devnet
		// profile vector. Both values stay forbidden.
		retiringRootDomainField:          rootDomain,
		"retiring/root-domain-sha256":    hex.EncodeToString(rootDomainHash[:]),
		"retiring/tenant-host-dev":       "dev.paype.cc",
		"retiring/store.sidecarId":       "melusina-os-root-store-v2",
		"retiring/store.operatorBoxKey":  "D62iWtghh4s6majv1xm5bbeTnLmzrkycF1tA9bgcnKJ5",
		"retiring/store.operatorIdPDA":   "7eESnZ9hvVAVTDCwSq73FGygqhp9bQZ5jF672NZsSKr6",
		"retiring/store.priorLicenseNft": "35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN",
	} {
		if existing, ok := values[field]; ok && existing != value {
			t.Fatalf("forbid field %s defined twice", field)
		}
		values[field] = value
	}
	return values
}

// retiringOnlyGoFiles are the only Go files that may compile a retiring value:
// each is excluded from the estate-bootstrap build by its build constraint, so
// only the retiring estate's own (standard-flavor) Store build carries it.
var retiringOnlyGoFiles = map[string]string{
	"squads_authority_legacy.go":                    "the retiring Bazaar's fixed release Squads authority, enforced only by its standard-flavor Store",
	"internal/runtimecontract/schema_url_legacy.go": "the historical runtime-contract $schema identifier the standard-flavor Store validates retiring releases against",
}

// retiringEstatePaths are the repository files that belong to the retiring
// estate's own tooling. They may carry its values; the Store bootstrap
// component ships none of them (TestStoreRetiringPathsAreNotShipped).
var retiringEstatePaths = map[string]string{
	"build-store.sh":                                                 "the retiring Bazaar's static catalog assembler (make build/plan); its publish and deploy writers are already retired",
	"scripts/default-bazaar-release.sh":                              "the retiring Bazaar's release wrapper; it pins that Store so it can drive only a profile for it",
	"scripts/preflight.sh":                                           "gate for build-store.sh's dist-publish against the live Bazaar catalog",
	"scripts/doctor.sh":                                              "readiness report for the static Bazaar pipeline",
	"scripts/validate-runtime-contract.py":                           "validates legacy runtime contracts against the Bazaar schema identifier for build-store.sh",
	"schemas/melusina-app-runtime-contract-v1.schema.json":           "the legacy runtime-contract schema with the Bazaar $id that build-store.sh serves",
	"schemas/melusina-release-v1.schema.json":                        "the Bazaar release-attestation schema pinning its Squads authority, used by build-store.sh",
	"deploy/store-generation/store.config.template.json":             "the retiring Store's update-path config template; the bootstrap component strips it",
	"deploy/store-generation/update-controller.config.template.json": "the retiring Store's controller config template; the bootstrap component strips it",
	"verifier/index.html":                                            "the Bazaar's static verifier page that build-store.sh copies into its dist-publish",
}

// retiringValueExceptions are exact texts, in named files, that are blanked
// before the search. Each must still occur where it is declared, so a fixed
// source forces its exception out.
var retiringValueExceptions = []struct {
	name, glob, text, reason string
}{
	{"ui-source", "src/main.jsx", retiringUIPlaceholder, "an input placeholder in the Store UI source; remove it with the next UI rebuild"},
	{"ui-bundle", sidecarModuleDir + "ui/assets/index-*.js", retiringUIPlaceholder, "the same placeholder in the committed UI bundle the sidecar embeds"},
}

// nonProductionReason says why a repository path is not production source,
// or returns "" when it is.
func nonProductionReason(rel string) string {
	base := path.Base(rel)
	switch {
	case strings.HasPrefix(rel, "fleet/"):
		return "catalog membership ledger and recorded fleet observations"
	case strings.HasPrefix(rel, "packages/"):
		return "recorded catalog releases of published apps"
	case strings.HasPrefix(rel, "app_icons/"), strings.HasPrefix(rel, "icons_split/"), strings.HasPrefix(rel, "public/icons/"):
		return "icon images"
	case strings.HasPrefix(rel, "riker-test-deploys/"):
		return "recorded test deployments"
	case strings.HasPrefix(rel, "e2e/"):
		return "end-to-end tests"
	case strings.HasPrefix(rel, "docs/"), strings.HasSuffix(rel, ".md"), rel == "LICENSE", rel == "NOTICE":
		return "documentation"
	case strings.HasSuffix(rel, "_test.go"), strings.Contains("/"+rel, "/testdata/"),
		strings.HasPrefix(base, "test-"), strings.HasSuffix(rel, ".test.mjs"), rel == "Makefile.test":
		return "tests and fixtures"
	case strings.HasPrefix(rel, sidecarModuleDir+"vendor/"):
		return "vendored third-party code; its compiled part is in the compiled scans"
	case strings.HasPrefix(rel, sidecarModuleDir) && strings.HasSuffix(rel, ".go"):
		return "Go source of the sidecar module; the compiled-literal and built-binary scans cover it"
	}
	return ""
}

type repoFile struct {
	rel  string
	data []byte
}

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("git rev-parse: %v (the production-file scan needs the repository)", err)
	}
	return strings.TrimSpace(string(out))
}

// repositoryFiles returns every tracked file and every untracked file that is
// not ignored and that keep selects, read from the working tree when present
// and otherwise (sparse checkouts) from the index, so a file absent on disk is
// still scanned.
func repositoryFiles(t *testing.T, root string, keep func(string) bool) []repoFile {
	t.Helper()
	git := func(args ...string) []byte {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
		}
		return out
	}
	var files []repoFile
	var missing []string
	blobs := map[string]string{}
	for _, record := range bytes.Split(git("ls-files", "-s", "-z"), []byte{0}) {
		if len(record) == 0 {
			continue
		}
		meta, rel, ok := strings.Cut(string(record), "\t")
		fields := strings.Fields(meta)
		if !ok || len(fields) != 3 {
			t.Fatalf("unexpected ls-files record %q", record)
		}
		if fields[0] == "160000" || !keep(rel) {
			continue // a submodule gitlink has no content here
		}
		if data, err := readNoFollow(filepath.Join(root, rel)); err == nil {
			files = append(files, repoFile{rel: rel, data: data})
			continue
		}
		missing = append(missing, rel)
		blobs[rel] = fields[1]
	}
	for _, rel := range bytes.Split(git("ls-files", "-z", "--others", "--exclude-standard"), []byte{0}) {
		if len(rel) == 0 || !keep(string(rel)) {
			continue
		}
		data, err := readNoFollow(filepath.Join(root, string(rel)))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, repoFile{rel: string(rel), data: data})
	}
	if len(missing) != 0 {
		cmd := exec.Command("git", "-C", root, "cat-file", "--batch")
		var input bytes.Buffer
		for _, rel := range missing {
			input.WriteString(blobs[rel] + "\n")
		}
		cmd.Stdin = &input
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git cat-file: %v", err)
		}
		reader := bufio.NewReader(bytes.NewReader(out))
		for _, rel := range missing {
			header, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Fields(header)
			if len(parts) != 3 || parts[0] != blobs[rel] {
				t.Fatalf("cat-file header %q for %s", header, rel)
			}
			size, err := strconv.Atoi(parts[2])
			if err != nil {
				t.Fatal(err)
			}
			data := make([]byte, size+1)
			if _, err := io.ReadFull(reader, data); err != nil {
				t.Fatal(err)
			}
			files = append(files, repoFile{rel: rel, data: data[:size]})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	return files
}

// readNoFollow reads a regular file, or a symlink's own target text (as Git
// stores it) rather than the file it points to.
func readNoFollow(name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(name)
		return []byte(target), err
	}
	return os.ReadFile(name)
}

// blankExceptions removes each declared exception text from data when the
// file matches its glob, reporting which exceptions applied.
func blankExceptions(rel string, data []byte) ([]byte, []string) {
	var used []string
	for _, exception := range retiringValueExceptions {
		if matched, _ := path.Match(exception.glob, rel); !matched || !bytes.Contains(data, []byte(exception.text)) {
			continue
		}
		data = bytes.ReplaceAll(data, []byte(exception.text), bytes.Repeat([]byte{' '}, len(exception.text)))
		used = append(used, exception.name)
	}
	return data, used
}

// textHits reports each forbidden field whose value text occurs in data,
// comparing case-insensitively.
func textHits(where string, data []byte, forbidden map[string]string) []string {
	folded := asciiLower(data)
	fields := make([]string, 0, len(forbidden))
	for field := range forbidden {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	var hits []string
	for _, field := range fields {
		if bytes.Contains(folded, asciiLower([]byte(forbidden[field]))) {
			hits = append(hits, field+" in "+where)
		}
	}
	return hits
}

// Every production file in the repository is searched, comments included:
// scripts, templates, units, schemas, examples, the UI source and bundle, and
// the Go of other modules. A hit fails by field and path unless the path is a
// declared retiring-estate path.
func TestStoreProductionFilesCarryNoRetiringEstateValue(t *testing.T) {
	forbidden := storeProductionForbiddenValues(t)
	root := repoRoot(t)
	shipped, _ := componentShippedSources(t, root)
	excluded := 0
	files := repositoryFiles(t, root, func(rel string) bool {
		// A file the component ships is production whatever its class.
		if nonProductionReason(rel) != "" && !containsString(shipped, rel) {
			excluded++
			return false
		}
		return true
	})

	// Matcher controls: a planted value is found by its field, the declared
	// placeholder is not, and the root domain outside it still is.
	registry := forbidden[retiringLicenseRegistryField]
	if hits := textHits("plant", []byte("DEFAULT="+registry), forbidden); strings.Join(hits, "|") != retiringLicenseRegistryField+" in plant" {
		t.Fatalf("matcher control: hits %q", hits)
	}
	if data, used := blankExceptions("src/main.jsx", []byte("placeholder=\"https://"+retiringUIPlaceholder+"\"")); len(used) != 1 || len(textHits("placeholder", data, forbidden)) != 0 {
		t.Fatalf("exception control: the declared placeholder was not excepted (used %v)", used)
	}
	if data, _ := blankExceptions("src/main.jsx", []byte(retiringUIPlaceholder+" https://melusina-os.org")); !strings.Contains(strings.Join(textHits("mixed", data, forbidden), "|"), retiringRootDomainField+" in mixed") {
		t.Fatal("exception control: the root domain outside the placeholder was excepted too")
	}

	scanned := map[string]bool{}
	usedExceptions := map[string]bool{}
	retiringHits := map[string]int{}
	var hits []string
	for _, file := range files {
		scanned[file.rel] = true
		data, used := blankExceptions(file.rel, file.data)
		for _, name := range used {
			usedExceptions[name] = true
		}
		found := textHits(file.rel, data, forbidden)
		if _, declared := retiringEstatePaths[file.rel]; declared {
			retiringHits[file.rel] = len(found)
			continue
		}
		hits = append(hits, found...)
	}
	t.Logf("%d production files scanned for %d retiring values (%d non-production files excluded by class)", len(scanned), len(forbidden), excluded)
	if len(hits) != 0 {
		t.Fatalf("production files carry retiring-estate values:\n%s", strings.Join(hits, "\n"))
	}

	// Coverage: the scan reached the files that ship or render estate facts.
	for _, required := range []string{
		"scripts/build-store-bootstrap-component.sh", "scripts/materialize-governed-cohort.py",
		"scripts/bazaar-installation-policy.py", "scripts/generate-app-icon-lock.py", "scripts/mel-release-provider.py",
		"scripts/project-estate-catalog.py",
		"deploy/store-generation/store-config-render-input.template.json", "deploy/store-generation/melusina-store-sidecar.service",
		"deploy/store-generation/DEPLOYMENT-CONTRACT.md", sidecarModuleDir + "store.config.example.json",
		sidecarModuleDir + "ui/installation-policy.json", "sidecar/bazaar-store-link/config.example.json",
		"sidecar/bazaar-store-link/config.go", "src/main.jsx", "update/install.sh",
	} {
		if !scanned[required] {
			t.Errorf("scan never reached %s", required)
		}
	}
	for _, rel := range shipped {
		if !scanned[rel] {
			t.Errorf("the component ships %s but the scan never reached it", rel)
		}
	}
	// Every declared retiring path exists and still carries a retiring value;
	// one that no longer does must leave the list.
	for rel := range retiringEstatePaths {
		count, ok := retiringHits[rel]
		if !ok {
			t.Errorf("declared retiring-estate path %s is not a scanned repository file", rel)
		} else if count == 0 {
			t.Errorf("declared retiring-estate path %s carries no retiring value; remove it from the list", rel)
		}
	}
	for _, exception := range retiringValueExceptions {
		if !usedExceptions[exception.name] {
			t.Errorf("exception %q in %s no longer occurs; remove it", exception.text, exception.glob)
		}
	}
}

// storeMainPackages lists every program the sidecar module builds, asking the
// toolchain rather than a hand-kept list.
func storeMainPackages(t *testing.T, tags string) []string {
	t.Helper()
	args := []string{"list", "-mod=vendor", "-f", `{{if eq .Name "main"}}{{.ImportPath}}{{end}}`}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.Command("go", append(args, "./...")...)
	cmd.Env = append(os.Environ(), "GOFLAGS=", "GOWORK=off", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	const module = "github.com/hrbrlife/melusina-store-sidecar"
	var packages []string
	for _, line := range strings.Fields(string(out)) {
		rel := strings.TrimPrefix(strings.TrimPrefix(line, module), "/")
		if rel == "" {
			packages = append(packages, ".")
		} else {
			packages = append(packages, "./"+rel)
		}
	}
	sort.Strings(packages)
	for _, required := range append(append([]string{}, bootstrapComponentPackages...), releaseToolPackages...) {
		if !containsString(packages, required) {
			t.Fatalf("%s is not among the module's programs %q; the scan cannot vouch for it", required, packages)
		}
	}
	return packages
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// retiringOnlyBuild reports whether a Go file is compiled only without the
// estatebootstrap tag, by evaluating its //go:build constraint.
func retiringOnlyBuild(t *testing.T, file string) bool {
	t.Helper()
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			break
		}
		if !constraint.IsGoBuild(line) {
			continue
		}
		expr, err := constraint.Parse(line)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		with := expr.Eval(func(tag string) bool { return tag == "estatebootstrap" || tag == "linux" || tag == "amd64" })
		without := expr.Eval(func(tag string) bool { return tag == "linux" || tag == "amd64" })
		return without && !with
	}
	return false
}

// Every Go string literal and embedded file compiled into any Store program,
// in both build flavors, vendored code included. Only the declared
// retiring-only files may hit, and only in the standard build that compiles
// them.
func TestStoreProgramsCompileNoRetiringEstateValue(t *testing.T) {
	forbidden := storeProductionForbiddenValues(t)
	root := repoRoot(t)
	module := filepath.Join(root, sidecarModuleDir)

	for rel := range retiringOnlyGoFiles {
		if !retiringOnlyBuild(t, filepath.Join(module, rel)) {
			t.Fatalf("%s is declared retiring-only but its build constraint does not exclude it from the estatebootstrap build", rel)
		}
	}
	for _, flavor := range []struct{ name, tags string }{{"estate-bootstrap", "estatebootstrap"}, {"standard", ""}} {
		t.Run(flavor.name, func(t *testing.T) {
			packages := storeMainPackages(t, flavor.tags)
			sources := compiledSources(t, flavor.tags, packages...)
			var hits []string
			retiringOnlyHits := map[string]bool{}
			usedExceptions := map[string]bool{}
			files := token.NewFileSet()
			for _, source := range sources {
				rel, err := filepath.Rel(root, source.path)
				if err != nil {
					t.Fatal(err)
				}
				rel = filepath.ToSlash(rel)
				moduleRel := strings.TrimPrefix(rel, sidecarModuleDir)
				raw, err := os.ReadFile(source.path)
				if err != nil {
					t.Fatal(err)
				}
				var found []string
				if !source.goFile {
					data, used := blankExceptions(rel, raw)
					for _, name := range used {
						usedExceptions[name] = true
					}
					found = textHits(rel, data, forbidden)
				} else {
					parsed, err := parser.ParseFile(files, source.path, raw, parser.SkipObjectResolution)
					if err != nil {
						t.Fatalf("parse %s: %v", rel, err)
					}
					ast.Inspect(parsed, func(node ast.Node) bool {
						literal, ok := node.(*ast.BasicLit)
						if !ok || literal.Kind != token.STRING {
							return true
						}
						value, err := strconv.Unquote(literal.Value)
						if err != nil {
							t.Fatalf("unquote %s: %v", files.Position(literal.Pos()), err)
						}
						position := files.Position(literal.Pos())
						found = append(found, textHits(fmt.Sprintf("%s:%d", rel, position.Line), []byte(value), forbidden)...)
						return true
					})
				}
				if _, declared := retiringOnlyGoFiles[moduleRel]; declared && strings.HasPrefix(rel, sidecarModuleDir) {
					if flavor.tags != "" {
						t.Fatalf("retiring-only %s is compiled into the %s build", rel, flavor.name)
					}
					if len(found) != 0 {
						retiringOnlyHits[moduleRel] = true
					}
					continue
				}
				hits = append(hits, found...)
			}
			t.Logf("%s: %d programs, %d compiled files scanned for %d retiring values", flavor.name, len(packages), len(sources), len(forbidden))
			if len(hits) != 0 {
				t.Fatalf("the %s Store programs compile retiring-estate values:\n%s", flavor.name, strings.Join(hits, "\n"))
			}
			// The retiring-only files are live exactly where they apply, so the
			// exclusion is not a blind spot and a stale entry is caught.
			for rel := range retiringOnlyGoFiles {
				if retiringOnlyHits[rel] != (flavor.tags == "") {
					t.Fatalf("%s: retiring-only %s carried a retiring value = %v", flavor.name, rel, retiringOnlyHits[rel])
				}
			}
			if !usedExceptions["ui-bundle"] {
				t.Fatalf("%s: the embedded UI bundle was not scanned (its declared placeholder never occurred)", flavor.name)
			}
		})
	}
}

// retiringOnlyLiterals returns the string literals of the declared
// retiring-only files that carry a retiring value, longest first.
func retiringOnlyLiterals(t *testing.T, module string, forbidden map[string]string) []string {
	t.Helper()
	var literals []string
	for rel := range retiringOnlyGoFiles {
		parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(module, rel), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				if len(textHits(rel, []byte(value), forbidden)) != 0 {
					literals = append(literals, value)
				}
			}
			return true
		})
	}
	sort.Slice(literals, func(i, j int) bool { return len(literals[i]) > len(literals[j]) })
	return literals
}

// Built bytes, not only source: every Store program, built with -trimpath and
// -buildvcs=false in both flavors, carries no retiring value as text, raw 32
// bytes, hex or base64. The standard build's retiring-only literals and the
// declared UI placeholder are blanked by their exact bytes first; each must
// be present, so neither exception is vacuous.
func TestStoreProgramsCarryNoRetiringEstateValueInBuiltBytes(t *testing.T) {
	forbidden := storeProductionForbiddenValues(t)
	forms := retiringValueForms(forbidden)
	module := filepath.Join(repoRoot(t), sidecarModuleDir)
	legacyLiterals := retiringOnlyLiterals(t, module, forbidden)
	if len(legacyLiterals) == 0 {
		t.Fatal("the retiring-only files carry no retiring literal; the standard-build exception is stale")
	}
	env := append(os.Environ(), "GOFLAGS=", "GOWORK=off", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	for _, flavor := range []struct{ name, tags string }{{"estate-bootstrap", "estatebootstrap"}, {"standard", ""}} {
		t.Run(flavor.name, func(t *testing.T) {
			dir := t.TempDir()
			packages := storeMainPackages(t, flavor.tags)
			var hits []string
			for _, pkg := range packages {
				name := filepath.Base(pkg)
				if pkg == "." {
					name = "melusina-store-sidecar"
				}
				binary := filepath.Join(dir, name)
				args := []string{"build", "-mod=vendor", "-trimpath", "-buildvcs=false", "-ldflags=-buildid="}
				if flavor.tags != "" {
					args = append(args, "-tags", flavor.tags)
				}
				cmd := exec.Command("go", append(args, "-o", binary, pkg)...)
				cmd.Env = env
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("go build %s: %v\n%s", pkg, err, out)
				}
				raw, err := os.ReadFile(binary)
				if err != nil {
					t.Fatal(err)
				}
				// Coverage control: the file is the program under test.
				importPath := "github.com/hrbrlife/melusina-store-sidecar" + strings.TrimPrefix(pkg, ".")
				if !bytes.Contains(raw, []byte(importPath)) {
					t.Fatalf("%s does not name %s; the scan is not reading the built program", binary, importPath)
				}
				if pkg == "." {
					if !bytes.Contains(raw, []byte(retiringUIPlaceholder)) {
						t.Fatalf("%s sidecar lacks the declared UI placeholder; the exception is stale or the UI is not embedded", flavor.name)
					}
					raw = bytes.ReplaceAll(raw, []byte(retiringUIPlaceholder), bytes.Repeat([]byte{' '}, len(retiringUIPlaceholder)))
				}
				if flavor.tags == "" {
					for _, literal := range legacyLiterals {
						if pkg == "." && !bytes.Contains(raw, []byte(literal)) {
							t.Fatalf("standard sidecar lacks retiring-only literal %q; the scan is not reading the built program", literal)
						}
						raw = bytes.ReplaceAll(raw, []byte(literal), make([]byte, len(literal)))
					}
				}
				scanned := binary + ".scanned"
				if err := os.WriteFile(scanned, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				hits = append(hits, retiringArtifactHits(t, scanned, forms)...)
				if err := os.Remove(binary); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(scanned); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("%s: %d programs built with -trimpath -buildvcs=false and scanned for %d retiring values in %d forms", flavor.name, len(packages), len(forbidden), len(forms))
			if len(hits) != 0 {
				t.Fatalf("the built %s Store programs carry retiring-estate values:\n%s", flavor.name, strings.Join(hits, "\n"))
			}
		})
	}
}

var (
	generationInstallLine = regexp.MustCompile(`install -m 0644 "\$work/([^"]+)" \\\n\s+"\$stage/([^"]+)"`)
	legacyConfigNames     = regexp.MustCompile(`(?s)legacy_config_names = \{(.*?)\}`)
	quotedName            = regexp.MustCompile(`"([^"]+)"`)
	renderInputTemplate   = regexp.MustCompile(`RENDER_INPUT_TEMPLATE="\$ROOT/([^"]+)"`)
)

// componentShippedSources parses the two builders: the repository files the
// generation builder installs, minus the legacy templates the bootstrap
// builder strips, plus the render-input template it adds. It also returns
// each stripped source.
func componentShippedSources(t *testing.T, root string) ([]string, []string) {
	t.Helper()
	read := func(rel string) string {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	generation := read(generationReleaseScript)
	installs := generationInstallLine.FindAllStringSubmatch(generation, -1)
	if len(installs) == 0 || len(installs) != strings.Count(generation, "install -m 0644 \"$work/") {
		t.Fatalf("generation builder has %d source installs, the parse reads %d", strings.Count(generation, "install -m 0644 \"$work/"), len(installs))
	}
	component := read(bootstrapComponentScript)
	block := legacyConfigNames.FindStringSubmatch(component)
	if block == nil {
		t.Fatal("bootstrap builder no longer names legacy_config_names")
	}
	strip := map[string]bool{}
	for _, name := range quotedName.FindAllStringSubmatch(block[1], -1) {
		strip[name[1]] = true
	}
	template := renderInputTemplate.FindStringSubmatch(component)
	if template == nil {
		t.Fatal("bootstrap builder no longer names its render-input template")
	}
	shipped := []string{template[1]}
	var stripped []string
	for _, install := range installs {
		source, destination := install[1], install[2]
		if strip[destination] {
			stripped = append(stripped, source)
			delete(strip, destination)
			continue
		}
		shipped = append(shipped, source)
	}
	if len(strip) != 0 {
		t.Fatalf("the bootstrap builder strips %v, which the generation builder never installs", strip)
	}
	if len(shipped) < 5 || len(stripped) == 0 {
		t.Fatalf("shipped %q / stripped %q is implausible; the parse is not reading the builders", shipped, stripped)
	}
	sort.Strings(shipped)
	sort.Strings(stripped)
	return shipped, stripped
}

// The declared retiring-estate paths are separate from what the new estate's
// Store component ships: each declared path in the generation tree is one the
// bootstrap builder strips, and no declared path is shipped. The shipped files are production source
// and scanned by TestStoreProductionFilesCarryNoRetiringEstateValue.
func TestStoreRetiringPathsAreNotShipped(t *testing.T) {
	root := repoRoot(t)
	shipped, stripped := componentShippedSources(t, root)
	for rel := range retiringEstatePaths {
		if strings.HasPrefix(rel, "deploy/store-generation/") && !containsString(stripped, rel) {
			t.Errorf("declared retiring-estate path %s is in the generation tree but the bootstrap builder does not strip it", rel)
		}
	}
	for _, rel := range shipped {
		if _, declared := retiringEstatePaths[rel]; declared {
			t.Errorf("declared retiring-estate path %s is shipped in the Store component", rel)
		}
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("shipped %s: %v", rel, err)
		}
	}
	t.Logf("component ships %d non-program files: %s; strips %s", len(shipped), strings.Join(shipped, ", "), strings.Join(stripped, ", "))
}
