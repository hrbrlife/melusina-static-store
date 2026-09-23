package main

// scripts/run-tests.sh is the module's documented test entry point. These
// tests run it in --plan mode, which resolves the mode and the contracts
// checkout exactly as a real run does and then stops before go test.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type runTestsPlan struct {
	exit   int
	stdout string
	stderr string
}

// runTestsScriptPlan runs the entry point with a hermetic environment: the
// caller's CI, mode and contracts variables are removed, and the git config key
// is pinned through GIT_CONFIG_* (which outranks the checkout's own config).
func runTestsScriptPlan(t *testing.T, gitConfigValue string, extraEnv []string, args ...string) runTestsPlan {
	t.Helper()
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case name == "CI", name == "MELUSINA_STORE_TEST_MODE", name == "MELUSINA_CONTRACTS_GIT_DIR", strings.HasPrefix(name, "GIT_CONFIG_"):
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=melusina.contractsGitDir", "GIT_CONFIG_VALUE_0="+gitConfigValue)
	env = append(env, extraEnv...)
	cmd := exec.Command("bash", append([]string{filepath.Join("scripts", "run-tests.sh"), "--plan"}, args...)...)
	cmd.Env = env
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	plan := runTestsPlan{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		plan.exit = exitErr.ExitCode()
	default:
		t.Fatalf("run scripts/run-tests.sh: %v", err)
	}
	return plan
}

func requireRunTestsRefusal(t *testing.T, plan runTestsPlan, name string) {
	t.Helper()
	if plan.exit != 2 || !strings.Contains(plan.stderr, name+":") {
		t.Fatalf("want refusal %s with exit 2, got exit %d\nstdout:\n%s\nstderr:\n%s", name, plan.exit, plan.stdout, plan.stderr)
	}
	if strings.Contains(plan.stdout, "run: go test") {
		t.Fatalf("refused run %s still planned go test:\n%s", name, plan.stdout)
	}
}

func requireRunTestsPlanLines(t *testing.T, plan runTestsPlan, lines ...string) {
	t.Helper()
	if plan.exit != 0 {
		t.Fatalf("want a plan, got exit %d\nstderr:\n%s", plan.exit, plan.stderr)
	}
	got := strings.Split(strings.TrimSpace(plan.stdout), "\n")
	for _, line := range lines {
		found := false
		for _, g := range got {
			found = found || g == line
		}
		if !found {
			t.Fatalf("plan lacks %q:\n%s", line, plan.stdout)
		}
	}
}

func storeCheckoutTopLevel(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("the module's tests run from its git checkout: %v", err)
	}
	top, err := filepath.EvalSymlinks(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatal(err)
	}
	return top
}

// A dev run without a contracts checkout still runs both flavors; only the
// contracts main-line check skips.
func TestRunTestsDevRunWithoutContractsCloneRunsBothFlavors(t *testing.T) {
	plan := runTestsScriptPlan(t, "", nil)
	requireRunTestsPlanLines(t, plan,
		"mode=dev",
		"MELUSINA_CONTRACTS_GIT_DIR=",
		"MELUSINA_STORE_TEST_MODE=",
		"run: go test -count=1 ./...",
		"run: go test -tags estatebootstrap -count=1 ./...",
	)
}

func TestRunTestsReleaseRunRefusesWithoutContractsClone(t *testing.T) {
	requireRunTestsRefusal(t, runTestsScriptPlan(t, "", nil, "--release"), "contracts-clone-required")
	requireRunTestsRefusal(t, runTestsScriptPlan(t, "", []string{"MELUSINA_STORE_TEST_MODE=release"}), "contracts-clone-required")
	requireRunTestsRefusal(t, runTestsScriptPlan(t, "", []string{"CI=true"}), "contracts-clone-required")
	requireRunTestsRefusal(t, runTestsScriptPlan(t, "", []string{"CI=1"}), "contracts-clone-required")
}

func TestRunTestsRefusesAnUndeclaredMode(t *testing.T) {
	requireRunTestsRefusal(t, runTestsScriptPlan(t, "", []string{"MELUSINA_STORE_TEST_MODE=relase"}), "store-test-mode-unknown")
}

// A configured checkout reaches the tests as an absolute
// MELUSINA_CONTRACTS_GIT_DIR, with release mode declared to the Go test too.
// The Store's own checkout stands in for a git repository here: the script
// checks only that the path is one, and the Go test checks which repository.
func TestRunTestsExportsTheConfiguredContractsClone(t *testing.T) {
	top := storeCheckoutTopLevel(t)
	want := []string{"mode=release", "MELUSINA_CONTRACTS_GIT_DIR=" + top, "MELUSINA_STORE_TEST_MODE=release"}
	requireRunTestsPlanLines(t, runTestsScriptPlan(t, top, nil, "--release"), want...)
	requireRunTestsPlanLines(t, runTestsScriptPlan(t, "", []string{"MELUSINA_CONTRACTS_GIT_DIR=" + top}, "--release"), want...)
	requireRunTestsPlanLines(t, runTestsScriptPlan(t, "", []string{"CI=true"}, "--contracts-git-dir", top), want...)
	// The flag outranks the environment, which outranks git config.
	notRepo := t.TempDir()
	ceiling := "GIT_CEILING_DIRECTORIES=" + filepath.Dir(notRepo)
	requireRunTestsPlanLines(t, runTestsScriptPlan(t, "", []string{ceiling, "MELUSINA_CONTRACTS_GIT_DIR=" + notRepo}, "--release", "--contracts-git-dir", top), want...)
	requireRunTestsRefusal(t, runTestsScriptPlan(t, top, []string{ceiling, "MELUSINA_CONTRACTS_GIT_DIR=" + notRepo}), "contracts-git-dir-not-a-repository")
	// A relative flag is resolved from the caller's directory, not from each
	// package's directory as go test would.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if cwd, err = filepath.EvalSymlinks(cwd); err != nil {
		t.Fatal(err)
	}
	requireRunTestsPlanLines(t, runTestsScriptPlan(t, "", nil, "--release", "--contracts-git-dir", "."), "MELUSINA_CONTRACTS_GIT_DIR="+cwd)
}

func TestRunTestsRefusesAContractsPathThatIsNotARepository(t *testing.T) {
	notRepo := t.TempDir()
	ceiling := []string{"GIT_CEILING_DIRECTORIES=" + filepath.Dir(notRepo)}
	requireRunTestsRefusal(t, runTestsScriptPlan(t, "", ceiling, "--release", "--contracts-git-dir", notRepo), "contracts-git-dir-not-a-repository")
	requireRunTestsRefusal(t, runTestsScriptPlan(t, "", ceiling, "--contracts-git-dir", filepath.Join(notRepo, "absent")), "contracts-git-dir-missing")
	requireRunTestsRefusal(t, runTestsScriptPlan(t, "relative/contracts", nil, "--release"), "contracts-git-dir-not-absolute")
}
