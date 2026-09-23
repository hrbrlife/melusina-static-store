package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
// config naming the program is the positive control: it passes the pin and is
// refused later, for an unrelated reason, by the enrollment boundary.
func TestStoreStartupRefusesConfigWithoutLicenseRegistryProgramID(t *testing.T) {
	dir := t.TempDir()
	config := profileEnrolledStoreConfig(t, filepath.Join(dir, "estate-enrollment.json"))
	config["dist_dir"] = filepath.Join(dir, "dist")
	config["catalog_repo_root"] = filepath.Join(dir, "catalog")
	const pinned = "chain reader: 1 trusted endpoint(s)"

	withProgram := writeJSONConfig(t, config)
	code, out := runStoreStartup(t, "-config", withProgram)
	if code != 1 || !strings.Contains(out, pinned) || strings.Contains(out, "program_id") || !strings.Contains(out, "boot identity / estate enrollment:") {
		t.Fatalf("positive control: startup with program_id exited %d without passing the registry pin:\n%s", code, out)
	}

	delete(config, "program_id")
	withoutProgram := writeJSONConfig(t, config)
	code, out = runStoreStartup(t, "-config", withoutProgram)
	if code != 1 || !strings.Contains(out, "config: config: program_id is required") {
		t.Fatalf("startup without program_id exited %d without the named refusal:\n%s", code, out)
	}
	if strings.Contains(out, pinned) {
		t.Fatalf("startup without program_id reached the chain reader:\n%s", out)
	}
}
