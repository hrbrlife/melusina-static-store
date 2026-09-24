package main

import (
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/hrbrlife/melusina-attest/pda"
)

// storeStartupChildArgs makes this test binary run the Store's real main()
// with the JSON-encoded arguments instead of the test suite, so a startup
// refusal is observed as the process exit it is in production.
const storeStartupChildArgs = "MELUSINA_STORE_TEST_STARTUP_CHILD_ARGS"

func TestStoreStartupChild(t *testing.T) {
	raw := os.Getenv(storeStartupChildArgs)
	if raw == "" {
		t.Skip("only runs as the startup child of a startup test")
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		fmt.Fprintf(os.Stderr, "startup child args: %v\n", err)
		os.Exit(3)
	}
	// The package init pins a fixture registry for in-process tests. A real
	// Store process starts with none, so the child clears it: an entry point
	// that does not pin its own registry from config cannot inherit the
	// fixture's and pass.
	programID = pda.Pubkey{}
	os.Args = append([]string{"melusina-store-sidecar"}, args...)
	main()
	fmt.Fprintln(os.Stderr, "startup child: main returned")
	os.Exit(4)
}

func runStoreStartup(t *testing.T, args ...string) (int, string) {
	t.Helper()
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestStoreStartupChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), storeStartupChildArgs+"="+string(encoded))
	cmd.Dir = t.TempDir()
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("startup child did not exit with a status: %v\n%s", err, out)
	}
	return exit.ExitCode(), string(out)
}

// A Store whose config does not name its license-registry program refuses to
// start, by name, before it pins anything or opens a chain reader. The same
// config naming the program is the positive control: the process, which
// starts with no registry, pins exactly the configured one and is refused
// later, for an unrelated reason, by the enrollment boundary.
func TestStoreStartupRefusesConfigWithoutLicenseRegistryProgramID(t *testing.T) {
	dir := t.TempDir()
	config := profileEnrolledStoreConfig(t, filepath.Join(dir, "estate-enrollment.json"))
	config["dist_dir"] = filepath.Join(dir, "dist")
	config["catalog_repo_root"] = filepath.Join(dir, "catalog")
	const chainReader = "chain reader: 1 trusted endpoint(s)"
	pinned := fmt.Sprintf(licenseRegistryPinnedLog, config["program_id"].(string))

	withProgram := writeJSONConfig(t, config)
	code, out := runStoreStartup(t, "-config", withProgram)
	if code != 1 || !strings.Contains(out, pinned) || !strings.Contains(out, chainReader) || strings.Contains(out, "program_id") || !strings.Contains(out, "store startup: estate enrollment: store-estate-profile-not-enrolled") {
		t.Fatalf("positive control: startup with program_id exited %d without pinning %q from config:\n%s", code, pinned, out)
	}

	delete(config, "program_id")
	withoutProgram := writeJSONConfig(t, config)
	code, out = runStoreStartup(t, "-config", withoutProgram)
	if code != 1 || !strings.Contains(out, "config: config: program_id is required") {
		t.Fatalf("startup without program_id exited %d without the named refusal:\n%s", code, out)
	}
	if strings.Contains(out, "license registry: program") || strings.Contains(out, chainReader) {
		t.Fatalf("startup without program_id pinned a registry or reached the chain reader:\n%s", out)
	}
}

// registryFreeStoreSubcommands are the dispatched subcommands that read no
// chain state and therefore pin no registry. Each is an offline document
// check or renderer; a registry read from one would panic by name.
var registryFreeStoreSubcommands = map[string]string{
	"estate-profile-check":         "offline profile/config comparison",
	"estate-store-config-render":   "offline profile-bound config renderer",
	"estate-profile-review":        "offline signed-profile review",
	"store-state-verify":           "offline store-state stream verification",
	"store-recovery-keygen":        "offline recovery key generation",
	"store-identity-escrow-reseal": "a holder's offline reseal of one escrowed shard",
	"genesis-dist-init":            "offline producer of the empty first-install dist snapshot",
	"provider-pairing-attest":      "client of the local provider pairing signer socket; reads no chain state",
}

// storeMainSubcommands derives the dispatched subcommands from main() itself,
// so a new entry point cannot be added without being classified below.
func storeMainSubcommands(t *testing.T) []string {
	t.Helper()
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "main" || fn.Recv != nil {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			compare, ok := node.(*ast.BinaryExpr)
			if !ok || compare.Op != token.EQL {
				return true
			}
			index, ok := compare.X.(*ast.IndexExpr)
			literal, isLiteral := compare.Y.(*ast.BasicLit)
			if !ok || !isLiteral || literal.Kind != token.STRING {
				return true
			}
			selector, ok := index.X.(*ast.SelectorExpr)
			position, isPosition := index.Index.(*ast.BasicLit)
			if !ok || !isPosition || selector.Sel.Name != "Args" || position.Value != "1" {
				return true
			}
			name, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			names = append(names, name)
			return true
		})
	}
	if len(names) == 0 {
		t.Fatal("found no subcommand dispatch in main()")
	}
	sort.Strings(names)
	return names
}

// Every Store entry point that reads chain state pins the license-registry
// program from its validated config. Each subtest runs the real main() in a
// child process that starts with no registry, and requires the pin line
// naming the configured program before the entry point's next, unrelated,
// refusal. Removing any one entry point's pin fails its subtest by name.
func TestEveryStoreEntryPointPinsItsConfiguredLicenseRegistry(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := profileEnrolledStoreConfig(t, filepath.Join(stateDir, "estate-enrollment.json"))
	config["dist_dir"] = filepath.Join(dir, "dist")
	config["catalog_repo_root"] = filepath.Join(dir, "catalog")
	configured := config["program_id"].(string)
	if configured == testLicenseProgramID {
		t.Fatalf("entry-point config names the package fixture registry %s; it must be distinct to prove the pin", configured)
	}
	configPath := writeJSONConfig(t, config)
	signerConfig := make(map[string]any, len(config)+1)
	for key, value := range config {
		signerConfig[key] = value
	}
	signerConfig["listing_signer_socket"] = filepath.Join(dir, "listing-signer.sock")
	signerConfigPath := writeJSONConfig(t, signerConfig)

	writeDocument := func(name string, value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	requestProfile := writeDocument("request-profile.json", storeEstateProfileFixture(t))
	enrollment := newStoreEnrollmentRuntimeFixture(t)
	enrollProfile := writeDocument("enroll-profile.json", enrollment.profile)
	enrollDocument := writeDocument("enrollment.json", enrollment.state.Enrollment)
	// A decodable, owner-signed successor for the enrollment above. The shared
	// config holds no enrollment state and names no writer lock, so both
	// successor entry points reach a refusal only after pinning.
	_, successor := requestStoreEnrollmentSuccessorFromState(t, enrollment, enrollment.state, runtimeIdentityWith(enrollment, "entry-point-rebuilt-binary", "", 0, ""), storeEnrollmentSuccessorNow, "owner-a", "owner-b")
	successorDocument := writeDocument("enrollment-successor.json", successor)
	cohortDir := filepath.Join(dir, "cohort")
	indexSHA256 := strings.Repeat("ab", 32)

	entryPoints := []struct {
		name  string
		args  []string
		after string
	}{
		{name: "", args: []string{"-config", configPath}, after: "store startup: estate enrollment: store-estate-profile-not-enrolled"},
		{name: "genesis-bootstrap", args: []string{"-config", configPath}, after: "genesis-bootstrap: estate enrollment: store-estate-profile-not-enrolled"},
		{name: "estate-enrollment-request", args: []string{"-config", configPath, "-estate-profile", requestProfile}, after: "boot_identity.shards_dir is required"},
		{name: "estate-enroll", args: []string{"-config", configPath, "-estate-profile", enrollProfile, "-enrollment", enrollDocument}, after: "boot_identity.shards_dir is required"},
		{name: "estate-enrollment-successor-request", args: []string{"-config", configPath}, after: "store-estate-profile-not-enrolled: enrollment state is absent"},
		{name: "estate-enroll-successor", args: []string{"-config", configPath, "-enrollment", successorDocument}, after: "store estate enrollment successor requires an absolute catalog_migration_state_dir"},
		{name: "listing-bootstrap", args: []string{"-config", configPath, "-expected-index-sha256", indexSHA256, "-expected-app-count", "1", "-dry-run"}, after: "listing-bootstrap: estate enrollment: store-estate-profile-not-enrolled"},
		{name: "listing-signer", args: []string{"-config", signerConfigPath}, after: "listing-signer: estate enrollment: store-estate-profile-not-enrolled"},
		{name: "provider-pairing-signer", args: []string{"-config", configPath, "-socket", filepath.Join(dir, "absent-runtime-directory", "signer.sock")}, after: "provider-pairing-signer: estate enrollment: store-estate-profile-not-enrolled"},
		{name: "catalog-retire", args: []string{"-config", configPath, "-app-id", "pin-probe", "-reason", "entry-point pin probe", "-expected-index-sha256", indexSHA256, "-expected-app-count", "1", "-dry-run"}, after: "catalog-retire: estate enrollment: store-estate-profile-not-enrolled"},
		{name: "catalog-reconcile-retirement", args: []string{"-config", configPath, "-dry-run"}, after: "catalog-reconcile-retirement: estate enrollment: store-estate-profile-not-enrolled"},
		{name: "catalog-reconcile-unserved", args: []string{"-config", configPath, "-app-id", "pin-probe", "-reason", "entry-point pin probe", "-expected-index-sha256", indexSHA256, "-expected-app-count", "1", "-dry-run"}, after: "catalog-reconcile-unserved: estate enrollment: store-estate-profile-not-enrolled"},
		{name: "catalog-rehydrate", args: []string{"-config", configPath, "-cohort-dir", cohortDir, "-expected-app-count", "1", "-expected-rollout-count", "1", "-dry-run"}, after: "catalog-rehydrate: estate enrollment: store-estate-profile-not-enrolled"},
		{name: "store-state-export", args: []string{"-config", configPath, "-out", filepath.Join(dir, "store-state.tar")}, after: "store-state-export: estate enrollment: store-estate-profile-not-enrolled"},
		{name: "store-state-import", args: []string{"-config", configPath, "-in", filepath.Join(dir, "absent-store-state.tar"), "-operator-key", configured}, after: "store-state-import: open " + filepath.Join(dir, "absent-store-state.tar")},
		{name: "store-identity-escrow-seal", args: []string{"-config", configPath, "-recipients", filepath.Join(dir, "absent-recipients.json"), "-out-dir", filepath.Join(dir, "escrow")}, after: "store-identity-escrow-seal: estate enrollment: store-estate-profile-not-enrolled"},
		{name: "store-identity-restore", args: []string{"-config", configPath, "-manifest", filepath.Join(dir, "absent-manifest.json"), "-session-key", filepath.Join(dir, "absent-session.key"), "-operator-key", configured, "-handoff", filepath.Join(dir, "absent-handoff.json")}, after: "store-identity-restore: read manifest"},
	}

	// Coverage: the table and the registry-free list together are exactly the
	// subcommands main() dispatches, plus the server path.
	covered := map[string]bool{}
	for _, entry := range entryPoints {
		if entry.name != "" {
			covered[entry.name] = true
		}
	}
	for _, name := range storeMainSubcommands(t) {
		_, registryFree := registryFreeStoreSubcommands[name]
		if covered[name] == registryFree {
			t.Fatalf("main() subcommand %q must be exactly one of: a registry-pinning entry point in this table, or registry-free", name)
		}
		delete(covered, name)
	}
	if len(covered) != 0 {
		t.Fatalf("table names entry points main() does not dispatch: %v", covered)
	}

	pinned := fmt.Sprintf(licenseRegistryPinnedLog, configured)
	for _, entry := range entryPoints {
		name := entry.name
		if name == "" {
			name = "server"
		}
		t.Run(name, func(t *testing.T) {
			args := entry.args
			if entry.name != "" {
				args = append([]string{entry.name}, args...)
			}
			code, out := runStoreStartup(t, args...)
			if strings.Contains(out, "read before it was pinned") {
				t.Fatalf("%s read the registry without pinning it from config (exit %d):\n%s", name, code, out)
			}
			if !strings.Contains(out, pinned) {
				t.Fatalf("%s did not pin the configured registry %s from config (exit %d):\n%s", name, configured, code, out)
			}
			if code == 0 || !strings.Contains(out, entry.after) {
				t.Fatalf("%s exited %d without reaching its post-pin refusal %q; the probe no longer proves the pin:\n%s", name, code, entry.after, out)
			}
			if strings.Index(out, pinned) > strings.Index(out, entry.after) {
				t.Fatalf("%s pinned the registry only after %q:\n%s", name, entry.after, out)
			}
		})
	}
}
