package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The release script is the one place that says how the Store component's
// programs are built. The artifact scan reads its build lines and environment
// instead of restating them, so it compiles the same programs the same way.
const storeGenerationReleaseScript = "../../scripts/build-store-generation-release.sh"

var (
	releaseScriptGoBuild = regexp.MustCompile(`go build -mod=vendor -trimpath "\$\{BUILD_TAGS\[@\]\}" -ldflags "([^"]*)" \\\n\s+-o "\$stage/bin/([A-Za-z0-9._-]+)" (\S+)\n`)
	releaseScriptExport  = regexp.MustCompile(`(?m)^\s*export ([^\n]+)$`)
	releaseScriptUnset   = regexp.MustCompile(`(?m)^\s*unset ([^\n]+)$`)
)

type releaseComponentBuild struct {
	binary  string
	pkg     string
	ldflags string
}

// releaseComponentBuilds returns the script's `go build` lines and the
// environment they run in, refusing any build line the pattern cannot read.
func releaseComponentBuilds(t *testing.T) ([]releaseComponentBuild, []string) {
	t.Helper()
	raw, err := os.ReadFile(storeGenerationReleaseScript)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, flavor := range []string{"BUILD_TAGS=()", "BUILD_TAGS=(-tags estatebootstrap)"} {
		if !strings.Contains(script, flavor) {
			t.Fatalf("release script no longer selects %s; the artifact scan must follow it", flavor)
		}
	}
	matches := releaseScriptGoBuild.FindAllStringSubmatch(script, -1)
	if len(matches) == 0 || len(matches) != strings.Count(script, "go build") {
		t.Fatalf("release script has %d go build lines, the scan reads %d; update the artifact scan with it", strings.Count(script, "go build"), len(matches))
	}
	var builds []releaseComponentBuild
	for _, match := range matches {
		ldflags := strings.ReplaceAll(match[1], "$VERSION", "0.0.0-retiring-estate-scan")
		if strings.Contains(ldflags, "$") {
			t.Fatalf("release ldflags %q reference a value the artifact scan cannot reproduce", match[1])
		}
		builds = append(builds, releaseComponentBuild{binary: match[2], pkg: match[3], ldflags: ldflags})
	}

	drop := map[string]bool{}
	var set []string
	for _, line := range releaseScriptUnset.FindAllStringSubmatch(script, -1) {
		for _, name := range strings.Fields(line[1]) {
			drop[name] = true
		}
	}
	for _, line := range releaseScriptExport.FindAllStringSubmatch(script, -1) {
		for _, assignment := range strings.Fields(line[1]) {
			name, value, ok := strings.Cut(assignment, "=")
			if !ok {
				t.Fatalf("release script export %q is not NAME=VALUE", assignment)
			}
			// Per-run values (source epoch, temporary directory) do not
			// change which bytes are compiled in.
			if strings.Contains(value, "$") {
				continue
			}
			drop[name] = true
			set = append(set, name+"="+value)
		}
	}
	if !releaseEnvSets(set, "GOOS=linux") || !releaseEnvSets(set, "CGO_ENABLED=0") || !releaseEnvSets(set, "GOFLAGS=") {
		t.Fatalf("release script environment %q no longer pins the target the scan reproduces", set)
	}
	var env []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !drop[name] {
			env = append(env, entry)
		}
	}
	return builds, append(env, set...)
}

func releaseEnvSets(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func goBuild(t *testing.T, dir string, env []string, args ...string) {
	t.Helper()
	cmd := exec.Command("go", append([]string{"build"}, args...)...)
	cmd.Dir = dir
	cmd.Env = env
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// retiringForm is one byte encoding under which a retiring value could be
// compiled into a program.
type retiringForm struct {
	field  string
	form   string
	needle []byte
	fold   bool // compare ASCII case-insensitively
}

// retiringValueForms expands each forbidden value into every form a program
// could carry it in: its text, and for a 32-byte key or digest also the raw
// bytes, their hex and their base64. A value assembled from several
// literals, or written as a byte array, is still one of these in the binary.
func retiringValueForms(forbidden map[string]string) []retiringForm {
	fields := make([]string, 0, len(forbidden))
	for field := range forbidden {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	var forms []retiringForm
	for _, field := range fields {
		value := forbidden[field]
		forms = append(forms, retiringForm{field: field, form: "text", needle: asciiLower([]byte(value)), fold: true})
		var raw []byte
		if key, err := primitives.PubkeyFromBase58(value); err == nil {
			raw = key[:]
		} else if digest, err := hex.DecodeString(value); err == nil && len(digest) == 32 {
			raw = digest
		}
		if raw == nil {
			continue
		}
		forms = append(forms,
			retiringForm{field: field, form: "raw", needle: raw},
			retiringForm{field: field, form: "hex", needle: []byte(hex.EncodeToString(raw)), fold: true},
			retiringForm{field: field, form: "base64", needle: []byte(base64.StdEncoding.EncodeToString(raw))},
		)
	}
	return forms
}

func asciiLower(data []byte) []byte {
	lower := make([]byte, len(data))
	for i, b := range data {
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		lower[i] = b
	}
	return lower
}

// retiringArtifactHits reports every form found in the built file.
func retiringArtifactHits(t *testing.T, path string, forms []retiringForm) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatalf("%s is empty; there is nothing to vouch for", path)
	}
	folded := asciiLower(data)
	var hits []string
	for _, form := range forms {
		haystack := data
		if form.fold {
			haystack = folded
		}
		if offset := bytes.Index(haystack, form.needle); offset >= 0 {
			hits = append(hits, fmt.Sprintf("%s (%s) in %s at offset %d", form.field, form.form, filepath.Base(path), offset))
		}
	}
	return hits
}

// The Store component's four programs, built exactly as the release script
// builds them, carry no retiring-estate value in any encoding. This is the
// built-artifact guard; the source scan beside it names the literal that
// caused a hit, but only this one sees values the compiler assembles.
func TestBootstrapComponentBinariesCarryNoRetiringEstateValue(t *testing.T) {
	retiring := retiringEstateValues(t)
	registryOnly := map[string]string{retiringLicenseRegistryField: retiring[retiringLicenseRegistryField]}
	builds, env := releaseComponentBuilds(t)

	var packages []string
	for _, build := range builds {
		packages = append(packages, build.pkg)
	}
	if strings.Join(packages, " ") != strings.Join(bootstrapComponentPackages, " ") {
		t.Fatalf("release script builds %q, the source scan covers %q", packages, bootstrapComponentPackages)
	}

	// Known-positive controls for the scanner itself, in the artifact
	// domain: one program per encoding, each carrying the retiring registry
	// only in that form, and one carrying nothing.
	t.Run("scanner-controls", func(t *testing.T) {
		registry := registryOnly[retiringLicenseRegistryField]
		key, err := primitives.PubkeyFromBase58(registry)
		if err != nil {
			t.Fatal(err)
		}
		split := func(value string) string {
			return fmt.Sprintf("%q + %q", value[:len(value)/2], value[len(value)/2:])
		}
		var byteArray []string
		for _, b := range key {
			byteArray = append(byteArray, fmt.Sprintf("0x%02x", b))
		}
		controls := map[string]string{
			"text":   "const value = " + split(registry) + "\n\nfunc main() { os.Stdout.WriteString(value) }\n",
			"raw":    "var value = [32]byte{" + strings.Join(byteArray, ", ") + "}\n\nfunc main() { os.Stdout.Write(value[:]) }\n",
			"hex":    "const value = " + split(strings.ToUpper(hex.EncodeToString(key[:]))) + "\n\nfunc main() { os.Stdout.WriteString(value) }\n",
			"base64": "const value = " + split(base64.StdEncoding.EncodeToString(key[:])) + "\n\nfunc main() { os.Stdout.WriteString(value) }\n",
			"clean":  "func main() { os.Stdout.WriteString(\"no estate value\") }\n",
		}
		forms := retiringValueForms(registryOnly)
		for _, form := range []string{"text", "raw", "hex", "base64", "clean"} {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module retiringscancontrol\n\ngo 1.24\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nimport \"os\"\n\n"+controls[form]), 0o600); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(dir, form)
			goBuild(t, dir, env, "-trimpath", "-ldflags=-buildid=", "-o", binary, ".")
			hits := retiringArtifactHits(t, binary, forms)
			want := []string{}
			if form != "clean" {
				want = []string{retiringLicenseRegistryField + " (" + form + ") in " + form}
			}
			var got []string
			for _, hit := range hits {
				got = append(got, hit[:strings.Index(hit, " at offset")])
			}
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("scanner control %s: hits %q, want %q", form, hits, want)
			}
		}
	})

	// Built programs live under the parent test's directory so the coverage
	// control below can read the standard build after its subtest ends.
	buildRoot := t.TempDir()
	built := map[string]map[string]string{}
	for _, flavor := range []struct {
		name      string
		tags      string
		forbidden map[string]string
	}{
		{name: "estate-bootstrap", tags: "estatebootstrap", forbidden: retiring},
		{name: "standard", forbidden: registryOnly},
	} {
		t.Run(flavor.name, func(t *testing.T) {
			dir := filepath.Join(buildRoot, flavor.name)
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			built[flavor.name] = map[string]string{}
			forms := retiringValueForms(flavor.forbidden)
			var hits []string
			for _, build := range builds {
				output := filepath.Join(dir, build.binary)
				args := []string{"-mod=vendor", "-trimpath"}
				if flavor.tags != "" {
					args = append(args, "-tags", flavor.tags)
				}
				goBuild(t, ".", env, append(args, "-ldflags", build.ldflags, "-o", output, build.pkg)...)
				built[flavor.name][build.binary] = output
				hits = append(hits, retiringArtifactHits(t, output, forms)...)
			}
			t.Logf("%s build: %d programs scanned for %d retiring values in %d forms", flavor.name, len(builds), len(flavor.forbidden), len(forms))
			if len(hits) != 0 {
				t.Fatalf("the %s Store component carries retiring-estate values:\n%s", flavor.name, strings.Join(hits, "\n"))
			}
		})
	}

	// Coverage control: the standard build keeps the legacy Bazaar pins, and
	// the scan must see them in the built sidecar when asked for the full
	// retiring set; a scan of the wrong bytes would see nothing.
	t.Run("coverage", func(t *testing.T) {
		sidecar := built["standard"]["melusina-store-sidecar"]
		if sidecar == "" {
			t.Fatal("standard sidecar was not built")
		}
		hits := retiringArtifactHits(t, sidecar, retiringValueForms(retiring))
		t.Logf("standard sidecar, full retiring set (expected legacy pins):\n%s", strings.Join(hits, "\n"))
		want := "retiring/" + estateprofile.FieldStoreRootDomain + " (text) in melusina-store-sidecar"
		if !strings.Contains(strings.Join(hits, "\n"), want) {
			t.Fatalf("artifact scan found no legacy root-domain pin in the standard sidecar (%q); it is not reading the built program", hits)
		}
	})
}
