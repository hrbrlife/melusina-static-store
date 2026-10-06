package main

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
	catalogSnapshotPath     = "../../fleet/retiring-bazaar-snapshot.yaml"
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
// set, widened by the Store, catalog index digest and release authority the
// checked-in fleet records. The catalog ledger is membership only; its
// Store origin and index digest come from the retiring Bazaar's snapshot file
// (fleet/retiring-bazaar-snapshot.yaml), derived rather than hand-copied — a
// snapshot file missing either fails closed here. The retiring profile vector
// marks its store-release multisig and vault illustrative, so the real Bazaar
// authority comes from the ledger rather than a hand-written list; whichever
// estate the ledger names, the tools must not compile it.
func releaseToolForbiddenValues(t *testing.T) map[string]string {
	t.Helper()
	values := retiringEstateValues(t)
	snapshot := map[string]string{}
	snapshotFile, err := os.Open(catalogSnapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshotFile.Close()
	snapshotScanner := bufio.NewScanner(snapshotFile)
	for snapshotScanner.Scan() {
		line := snapshotScanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, _ := strings.Cut(trimmed, ":")
		snapshot[key] = strings.TrimSpace(value)
	}
	if err := snapshotScanner.Err(); err != nil {
		t.Fatal(err)
	}
	if snapshot["schema"] != "melusina-retiring-bazaar-snapshot/v1" {
		t.Fatalf("%s has schema %q; the scan cannot derive the retiring snapshot facts from it",
			catalogSnapshotPath, snapshot["schema"])
	}
	origin := strings.TrimPrefix(snapshot["snapshot_origin"], "https://")
	digest := snapshot["snapshot_index_sha256"]
	observed := snapshot["observed_live_app_count"]
	if origin == "" || origin == snapshot["snapshot_origin"] {
		t.Fatalf("%s has no snapshot_origin; the scan would silently lose the retiring Store", catalogSnapshotPath)
	}
	if len(digest) != 64 {
		t.Fatalf("%s has no snapshot_index_sha256; the scan would silently lose the retiring index digest", catalogSnapshotPath)
	}
	if observed == "" {
		t.Fatalf("%s has no observed_live_app_count; the snapshot record is incomplete", catalogSnapshotPath)
	}
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
			switch key {
			case "catalog_origin":
				ledger["catalog-ledger/catalog_origin"] = strings.TrimPrefix(value, "https://")
			case "catalog_index_sha256":
				ledger["catalog-ledger/catalog_index_sha256"] = value
			}
		case inAuthority && (key == "multisig" || key == "vault" || key == "program_id"):
			ledger["catalog-ledger/release_squads_authority."+key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	// The membership ledger carries no origin or index digest; those come from
	// the snapshot file above. Only the three authority values are ledger-
	// derived, and none may be empty.
	if len(ledger) != 3 {
		t.Fatalf("catalog ledger yielded %v; the scan would silently lose width", ledger)
	}
	for field, value := range ledger {
		if value == "" {
			t.Fatalf("catalog ledger %s is empty", field)
		}
		values[field] = value
	}
	for field, value := range map[string]string{
		"catalog-ledger/catalog_origin":       origin,
		"catalog-ledger/catalog_index_sha256": digest,
	} {
		if existing, ok := values[field]; ok && existing != value {
			t.Fatalf("forbid field %s defined twice", field)
		}
		values[field] = value
	}
	return values
}

// The tools' source names no retiring value: every Go string literal and
// embedded file the toolchain compiles into mel-release and submit, in both
// build flavors, and every byte of the provider scripts, comments included.
func TestReleaseToolsSourceCarriesNoRetiringEstateValue(t *testing.T) {
	forbidden := releaseToolForbiddenValues(t)
	scripts := releaseToolScripts(t)

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
			hits := retiringValueHits(t, sources, forbidden)
			if len(hits) != 0 {
				t.Fatalf("the %s release tools carry retiring-estate values:\n%s", flavor.name, strings.Join(hits, "\n"))
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
	env := append(os.Environ(), "GOFLAGS=", "GOWORK=off", "CGO_ENABLED=0")
	for _, flavor := range []struct{ name, tags string }{
		{name: releaseToolsEstateBuild, tags: "estatebootstrap"},
		{name: releaseToolsStandard},
	} {
		t.Run(flavor.name, func(t *testing.T) {
			dir := t.TempDir()
			var hits []string
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
		})
	}
}
