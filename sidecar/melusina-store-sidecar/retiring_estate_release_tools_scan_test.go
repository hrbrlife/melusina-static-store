package main

import (
	"bufio"
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The seed-catalogue release tools publish into whichever Store the
// owner-signed estate profile names: mel-release, the submit client it
// drives, and the provider scripts mel-release runs. None of them may carry a
// value of the estate being retired, in source or in built bytes.
var releaseToolPackages = []string{"./cmd/mel-release", "./cmd/submit"}

const (
	catalogLedgerPath       = "../../fleet/bazaar-catalog.yaml"
	legacySchemaURLFile     = "internal/runtimecontract/schema_url_legacy.go"
	releaseToolsStandard    = "standard"
	releaseToolsEstateBuild = "estate-bootstrap"
)

// releaseToolScripts is derived, not listed: every mel-release-* file in the
// sidecar's and the Store's scripts directories. Tests are named test-* and
// fall outside the pattern.
func releaseToolScripts(t *testing.T) []string {
	t.Helper()
	var scripts []string
	for _, pattern := range []string{"scripts/mel-release-*", "../../scripts/mel-release-*"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range matches {
			absolute, err := filepath.Abs(match)
			if err != nil {
				t.Fatal(err)
			}
			scripts = append(scripts, absolute)
		}
	}
	sort.Strings(scripts)
	return scripts
}

// releaseToolForbiddenValues is the retiring estate's profile-derived forbid
// set, widened by the Store and release authority the checked-in catalog
// ledger itself records. The retiring profile vector marks its store-release
// multisig and vault illustrative, so the real Bazaar authority comes from the
// ledger rather than a hand-written list; whichever estate the ledger names,
// the tools must not compile it.
func releaseToolForbiddenValues(t *testing.T) map[string]string {
	t.Helper()
	values := retiringEstateValues(t)
	file, err := os.Open(catalogLedgerPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	inAuthority := false
	ledger := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, _ := strings.Cut(trimmed, ":")
		value = strings.TrimSpace(value)
		switch {
		case !strings.HasPrefix(line, " "):
			inAuthority = key == "release_squads_authority"
			if key == "catalog_origin" {
				ledger["catalog-ledger/catalog_origin"] = strings.TrimPrefix(value, "https://")
			}
		case inAuthority && (key == "multisig" || key == "vault" || key == "program_id"):
			ledger["catalog-ledger/release_squads_authority."+key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(ledger) != 4 {
		t.Fatalf("catalog ledger yielded %v; the scan would silently lose width", ledger)
	}
	for field, value := range ledger {
		if value == "" {
			t.Fatalf("catalog ledger %s is empty", field)
		}
		values[field] = value
	}
	return values
}

// legacyRuntimeContractSchemaURL is the one retiring-estate text the standard
// (legacy) build of submit may carry: the historical runtime-contract $schema
// identifier, a protocol value the legacy Store validates releases against
// and the estate-bootstrap build replaces with a URN. It is read from its
// build-tagged source rather than restated, so the exception cannot widen.
func legacyRuntimeContractSchemaURL(t *testing.T) string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), legacySchemaURLFile, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var literals []string
	ast.Inspect(file, func(node ast.Node) bool {
		if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			literals = append(literals, value)
		}
		return true
	})
	if len(literals) != 1 || !strings.HasPrefix(literals[0], "https://") {
		t.Fatalf("%s holds %q; the exception expects exactly the legacy schema URL", legacySchemaURLFile, literals)
	}
	return literals[0]
}

// The tools' source names no retiring value: every Go string literal and
// embedded file the toolchain compiles into mel-release and submit, in both
// build flavors, and every byte of the provider scripts, comments included.
func TestReleaseToolsSourceCarriesNoRetiringEstateValue(t *testing.T) {
	forbidden := releaseToolForbiddenValues(t)
	scripts := releaseToolScripts(t)
	legacyURL := legacyRuntimeContractSchemaURL(t)
	legacyFile, err := filepath.Abs(legacySchemaURLFile)
	if err != nil {
		t.Fatal(err)
	}

	// Known-positive control: a provider-shaped script carrying the retiring
	// Store in text is found, by the field it came from.
	plant := filepath.Join(t.TempDir(), "mel-release-plant.py")
	root := forbidden["retiring/store.rootDomain"]
	if root == "" {
		t.Fatal("retiring profile projects no store.rootDomain")
	}
	if err := os.WriteFile(plant, []byte("# plant\nDEFAULT = \"https://"+root+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hits := retiringValueHits(t, []componentSource{{path: plant}}, forbidden); !strings.Contains(strings.Join(hits, "\n"), "retiring/store.rootDomain in "+plant) {
		t.Fatalf("plant control hits %q, want retiring/store.rootDomain", hits)
	}

	for _, flavor := range []struct{ name, tags string }{
		{name: releaseToolsEstateBuild, tags: "estatebootstrap"},
		{name: releaseToolsStandard},
	} {
		t.Run(flavor.name, func(t *testing.T) {
			sources := compiledSources(t, flavor.tags, releaseToolPackages...)
			for _, script := range scripts {
				sources = append(sources, componentSource{path: script})
			}
			for _, required := range []string{
				"/cmd/mel-release/config.go", "/cmd/mel-release/catalog.go", "/cmd/mel-release/estate.go",
				"/cmd/submit/main.go", "/internal/estateprofile/verify.go", "/internal/runtimecontract/runtimecontract.go",
				"/scripts/mel-release-provider.py", "/scripts/mel-release-catalog-provider.sh",
				"/scripts/mel-release-provider.sh", "/scripts/mel-release-squads-register.mjs",
			} {
				if !sourceSetIncludes(sources, required) {
					t.Fatalf("scan never reached %s; it cannot vouch for the release tools", required)
				}
			}
			t.Logf("%s: %d files scanned for %d retiring values", flavor.name, len(sources), len(forbidden))
			var hits, excepted []string
			for _, hit := range retiringValueHits(t, sources, forbidden) {
				// Excepted: a value inside the legacy identifier, found in its
				// one-literal file, in the build that compiles it.
				field, _, _ := strings.Cut(hit, " in ")
				if flavor.tags == "" && strings.Contains(hit, " in "+legacyFile+":") && strings.Contains(legacyURL, forbidden[field]) {
					excepted = append(excepted, hit)
					continue
				}
				hits = append(hits, hit)
			}
			if len(hits) != 0 {
				t.Fatalf("the %s release tools carry retiring-estate values:\n%s", flavor.name, strings.Join(hits, "\n"))
			}
			// The exception is live only where it applies: the standard build
			// reaches the legacy identifier, the estate-bootstrap build never does.
			if (flavor.tags == "") != (len(excepted) != 0) || sourceSetIncludes(sources, "/"+legacySchemaURLFile) != (flavor.tags == "") {
				t.Fatalf("%s: legacy runtime-contract schema exception hits %q; want exactly the standard build", flavor.name, excepted)
			}
		})
	}

	// Width control: the retiring estate's own release wrapper does carry its
	// pins, so a clean result above is an exclusion, not a narrow value set.
	wrapper := retiringValueHits(t, []componentSource{{path: "../../scripts/default-bazaar-release.sh"}}, forbidden)
	joined := strings.Join(wrapper, "\n")
	for _, field := range []string{
		retiringLicenseRegistryField, "retiring/store.rootDomain", "retiring/store.storeId",
		"retiring/anchors.masterMint", "catalog-ledger/release_squads_authority.vault",
	} {
		if !strings.Contains(joined, field+" in ") {
			t.Fatalf("width control: the retiring wrapper shows no %s (hits %q); the forbid set is not the retiring estate", field, wrapper)
		}
	}
}

// Built bytes, not only source: mel-release and submit, built as the provider
// builds them, carry no retiring value as text, raw 32 bytes, hex or base64.
// The standard build's legacy runtime-contract schema identifier is the one
// excepted text, blanked by its exact bytes before the search.
func TestReleaseToolBinariesCarryNoRetiringEstateValue(t *testing.T) {
	forbidden := releaseToolForbiddenValues(t)
	forms := retiringValueForms(forbidden)
	legacy := []byte(legacyRuntimeContractSchemaURL(t))
	env := append(os.Environ(), "GOFLAGS=", "GOWORK=off", "CGO_ENABLED=0")
	for _, flavor := range []struct{ name, tags string }{
		{name: releaseToolsEstateBuild, tags: "estatebootstrap"},
		{name: releaseToolsStandard},
	} {
		t.Run(flavor.name, func(t *testing.T) {
			dir := t.TempDir()
			var hits []string
			legacySeen := false
			for _, pkg := range releaseToolPackages {
				binary := filepath.Join(dir, filepath.Base(pkg))
				args := []string{"build", "-mod=vendor", "-trimpath", "-buildvcs=false"}
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
				// Coverage control: these are the programs under test, named by
				// a flag or variable only they define.
				marker := map[string]string{"./cmd/mel-release": "MEL_RELEASE_ESTATE_PROFILE_SHA256", "./cmd/submit": "there is no default registry"}[pkg]
				if !bytes.Contains(raw, []byte(marker)) {
					t.Fatalf("%s does not contain %q; the scan is not reading the built program", binary, marker)
				}
				if bytes.Contains(raw, legacy) {
					legacySeen = true
					raw = bytes.ReplaceAll(raw, legacy, make([]byte, len(legacy)))
				}
				scanned := binary + ".scanned"
				if err := os.WriteFile(scanned, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				hits = append(hits, retiringArtifactHits(t, scanned, forms)...)
			}
			t.Logf("%s: %d programs scanned for %d retiring values in %d forms", flavor.name, len(releaseToolPackages), len(forbidden), len(forms))
			if len(hits) != 0 {
				t.Fatalf("the built %s release tools carry retiring-estate values:\n%s", flavor.name, strings.Join(hits, "\n"))
			}
			if legacySeen != (flavor.tags == "") {
				t.Fatalf("%s: legacy runtime-contract schema identifier present=%v; want only in the standard build", flavor.name, legacySeen)
			}
		})
	}
}
