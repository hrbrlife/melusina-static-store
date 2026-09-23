package main

// scripts/run-tests.sh is the module's documented test entry point. These
// tests run it for real, with a stand-in go first on PATH. The stand-in records
// the arguments, the working directory and the whole environment of every call,
// so the tests assert what go test is actually handed rather than what the
// script says about itself: a variable the script assigns but does not export
// never reaches go test, and only the recorded environment shows that.

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// runTestsFakeGo stands in for go. Call n records its NUL-separated arguments,
// its NUL-separated environment and its working directory under
// $RUN_TESTS_FAKE_GO_RECORD/<n>/, and exits 1, as a failing go test would, when
// n is $RUN_TESTS_FAKE_GO_FAIL_CALL.
const runTestsFakeGo = `#!/bin/sh
set -eu
n=$(ls "$RUN_TESTS_FAKE_GO_RECORD" | wc -l)
n=$((n))
call="$RUN_TESTS_FAKE_GO_RECORD/$n"
mkdir "$call"
printf '%s\0' "$@" >"$call/args"
env -0 >"$call/env"
pwd -P >"$call/dir"
if [ "$n" = "${RUN_TESTS_FAKE_GO_FAIL_CALL:-}" ]; then
  exit 1
fi
exit 0
`

type goTestCall struct {
	args []string
	dir  string
	env  map[string]string
}

type runTestsRun struct {
	exit   int
	stdout string
	stderr string
	calls  []goTestCall
}

type runTestsOptions struct {
	// gitConfig is the value pinned for melusina.contractsGitDir; empty means
	// no checkout is configured.
	gitConfig string
	env       []string
	// dir is the caller's working directory; empty means the module directory.
	dir string
	// failCall is the number of the go call that fails; empty means none.
	failCall string
}

func runTestsModuleDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// runTestsScript runs the entry point for real with a hermetic environment: the
// caller's CI, mode and contracts variables are removed, the git config key is
// pinned through GIT_CONFIG_* (which outranks any checkout's own config), and
// go resolves to runTestsFakeGo.
func runTestsScript(t *testing.T, opts runTestsOptions, args ...string) runTestsRun {
	t.Helper()
	moduleDir := runTestsModuleDir(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(runTestsFakeGo), 0o755); err != nil {
		t.Fatal(err)
	}
	record := t.TempDir()
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case name == "CI", name == "MELUSINA_STORE_TEST_MODE", name == "MELUSINA_CONTRACTS_GIT_DIR", name == "PATH",
			strings.HasPrefix(name, "GIT_CONFIG_"), strings.HasPrefix(name, "RUN_TESTS_FAKE_GO_"):
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"RUN_TESTS_FAKE_GO_RECORD="+record,
		"RUN_TESTS_FAKE_GO_FAIL_CALL="+opts.failCall,
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=melusina.contractsGitDir", "GIT_CONFIG_VALUE_0="+opts.gitConfig,
	)
	env = append(env, opts.env...)
	cmd := exec.Command("bash", append([]string{filepath.Join(moduleDir, "scripts", "run-tests.sh")}, args...)...)
	cmd.Env = env
	cmd.Dir = moduleDir
	if opts.dir != "" {
		cmd.Dir = opts.dir
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	run := runTestsRun{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		run.exit = exitErr.ExitCode()
	default:
		t.Fatalf("run scripts/run-tests.sh: %v", err)
	}
	entries, err := os.ReadDir(record)
	if err != nil {
		t.Fatal(err)
	}
	for n := range entries {
		callDir := filepath.Join(record, strconv.Itoa(n))
		call := goTestCall{env: map[string]string{}}
		for _, name := range []string{"args", "env", "dir"} {
			raw, err := os.ReadFile(filepath.Join(callDir, name))
			if err != nil {
				t.Fatalf("stand-in go call %d left no %s: %v", n, name, err)
			}
			switch name {
			case "args":
				call.args = strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
			case "env":
				for _, kv := range bytes.Split(bytes.TrimSuffix(raw, []byte{0}), []byte{0}) {
					key, value, _ := strings.Cut(string(kv), "=")
					call.env[key] = value
				}
			case "dir":
				call.dir = strings.TrimSpace(string(raw))
			}
		}
		run.calls = append(run.calls, call)
	}
	return run
}

var runTestsFlavorArgs = [][]string{
	{"test", "-count=1", "./..."},
	{"test", "-tags", "estatebootstrap", "-count=1", "./..."},
}

func describeGoTestEnv(env map[string]string, name string) string {
	value, ok := env[name]
	if !ok {
		return "unset"
	}
	return strconv.Quote(value)
}

// requireGoTestReceived requires a successful run that called go test once per
// flavor from the module directory, and that each call received contracts as
// MELUSINA_CONTRACTS_GIT_DIR and mode as MELUSINA_STORE_TEST_MODE. An empty
// want requires the variable to be absent from the call's environment.
func requireGoTestReceived(t *testing.T, run runTestsRun, contracts, mode string) {
	t.Helper()
	if run.exit != 0 {
		t.Fatalf("run-tests-exit: want exit 0, got %d\nstderr:\n%s", run.exit, run.stderr)
	}
	if len(run.calls) != len(runTestsFlavorArgs) {
		t.Fatalf("run-tests-flavors-wrong: go was called %d times, want %d (one per flavor)\nstderr:\n%s", len(run.calls), len(runTestsFlavorArgs), run.stderr)
	}
	moduleDir := runTestsModuleDir(t)
	for n, call := range run.calls {
		if !slices.Equal(call.args, runTestsFlavorArgs[n]) {
			t.Fatalf("run-tests-flavors-wrong: go call %d received %q, want %q", n, call.args, runTestsFlavorArgs[n])
		}
		if call.dir != moduleDir {
			t.Fatalf("run-tests-go-dir-wrong: go call %d ran in %s, want the module directory %s", n, call.dir, moduleDir)
		}
		for _, v := range []struct{ name, want string }{
			{"MELUSINA_CONTRACTS_GIT_DIR", contracts},
			{"MELUSINA_STORE_TEST_MODE", mode},
		} {
			got, ok := call.env[v.name]
			if v.want == "" && !ok || v.want != "" && ok && got == v.want {
				continue
			}
			want := "unset"
			if v.want != "" {
				want = strconv.Quote(v.want)
			}
			t.Fatalf("run-tests-go-env-wrong: go call %d (%s) received %s %s, want %s", n, strings.Join(call.args, " "), v.name, describeGoTestEnv(call.env, v.name), want)
		}
	}
}

func requireRunTestsRefusal(t *testing.T, run runTestsRun, name string) {
	t.Helper()
	if run.exit != 2 || !strings.Contains(run.stderr, "run-tests: "+name+":") {
		t.Fatalf("want refusal %s with exit 2, got exit %d\nstdout:\n%s\nstderr:\n%s", name, run.exit, run.stdout, run.stderr)
	}
	if len(run.calls) != 0 {
		t.Fatalf("run-tests-refusal-ran-go: refused run %s still called go %d times: %q", name, len(run.calls), run.calls[0].args)
	}
}

// A dev run without a contracts checkout still runs both flavors, and go test
// sees neither variable, so only the contracts main-line check skips.
func TestRunTestsDevRunWithoutContractsCloneRunsBothFlavors(t *testing.T) {
	requireGoTestReceived(t, runTestsScript(t, runTestsOptions{}), "", "")
}

// A dev run with a configured checkout hands it to go test without declaring
// release mode.
func TestRunTestsDevRunHandsAConfiguredContractsCloneToGoTest(t *testing.T) {
	repo := initThrowawayGitRepo(t, "")
	requireGoTestReceived(t, runTestsScript(t, runTestsOptions{gitConfig: repo}), repo, "")
}

func TestRunTestsReleaseRunRefusesWithoutContractsClone(t *testing.T) {
	requireRunTestsRefusal(t, runTestsScript(t, runTestsOptions{}, "--release"), "contracts-clone-required")
	requireRunTestsRefusal(t, runTestsScript(t, runTestsOptions{env: []string{"MELUSINA_STORE_TEST_MODE=release"}}), "contracts-clone-required")
	requireRunTestsRefusal(t, runTestsScript(t, runTestsOptions{env: []string{"CI=true"}}), "contracts-clone-required")
	requireRunTestsRefusal(t, runTestsScript(t, runTestsOptions{env: []string{"CI=1"}}), "contracts-clone-required")
}

func TestRunTestsRefusesAnUndeclaredMode(t *testing.T) {
	requireRunTestsRefusal(t, runTestsScript(t, runTestsOptions{env: []string{"MELUSINA_STORE_TEST_MODE=relase"}}), "store-test-mode-unknown")
}

// Whichever way the checkout and the release declaration arrive, every go test
// call receives the checkout as an absolute MELUSINA_CONTRACTS_GIT_DIR and
// MELUSINA_STORE_TEST_MODE=release. The cases where neither variable is in the
// caller's environment are the ones only an export can satisfy. The script
// checks only that the path is a git repository; the Go test checks which one.
func TestRunTestsHandsTheContractsCloneAndReleaseModeToGoTest(t *testing.T) {
	repo := initThrowawayGitRepo(t, "")
	notRepo := t.TempDir()
	ceiling := "GIT_CEILING_DIRECTORIES=" + filepath.Dir(notRepo)
	for _, tc := range []struct {
		label string
		opts  runTestsOptions
		args  []string
	}{
		{"git config and --release", runTestsOptions{gitConfig: repo}, []string{"--release"}},
		{"flag and --release", runTestsOptions{}, []string{"--release", "--contracts-git-dir", repo}},
		{"environment and --release", runTestsOptions{env: []string{"MELUSINA_CONTRACTS_GIT_DIR=" + repo}}, []string{"--release"}},
		{"git config and declared mode", runTestsOptions{gitConfig: repo, env: []string{"MELUSINA_STORE_TEST_MODE=release"}}, nil},
		{"flag and CI=true", runTestsOptions{env: []string{"CI=true"}}, []string{"--contracts-git-dir", repo}},
		{"git config and CI=1", runTestsOptions{gitConfig: repo, env: []string{"CI=1"}}, nil},
		// The flag outranks the environment, which outranks git config.
		{"flag over environment", runTestsOptions{env: []string{ceiling, "MELUSINA_CONTRACTS_GIT_DIR=" + notRepo}}, []string{"--release", "--contracts-git-dir", repo}},
		{"environment over git config", runTestsOptions{gitConfig: notRepo, env: []string{ceiling, "MELUSINA_CONTRACTS_GIT_DIR=" + repo}}, []string{"--release"}},
		// A relative flag is resolved from the caller's directory, not from
		// each package's directory as go test would.
		{"relative flag", runTestsOptions{dir: filepath.Dir(repo)}, []string{"--release", "--contracts-git-dir", filepath.Base(repo)}},
	} {
		t.Run(tc.label, func(t *testing.T) {
			requireGoTestReceived(t, runTestsScript(t, tc.opts, tc.args...), repo, "release")
		})
	}
	requireRunTestsRefusal(t, runTestsScript(t, runTestsOptions{gitConfig: repo, env: []string{ceiling, "MELUSINA_CONTRACTS_GIT_DIR=" + notRepo}}), "contracts-git-dir-not-a-repository")
}

func TestRunTestsRefusesAContractsPathThatIsNotARepository(t *testing.T) {
	notRepo := t.TempDir()
	ceiling := []string{"GIT_CEILING_DIRECTORIES=" + filepath.Dir(notRepo)}
	requireRunTestsRefusal(t, runTestsScript(t, runTestsOptions{env: ceiling}, "--release", "--contracts-git-dir", notRepo), "contracts-git-dir-not-a-repository")
	requireRunTestsRefusal(t, runTestsScript(t, runTestsOptions{env: ceiling}, "--contracts-git-dir", filepath.Join(notRepo, "absent")), "contracts-git-dir-missing")
	requireRunTestsRefusal(t, runTestsScript(t, runTestsOptions{gitConfig: "relative/contracts"}, "--release"), "contracts-git-dir-not-absolute")
}

// A failing flavor fails the run, and does not stop the other flavor from
// running. The run where no call fails is the positive control.
func TestRunTestsFailsTheRunWhenEitherFlavorFails(t *testing.T) {
	requireGoTestReceived(t, runTestsScript(t, runTestsOptions{}), "", "")
	for _, failCall := range []string{"0", "1"} {
		run := runTestsScript(t, runTestsOptions{failCall: failCall})
		if run.exit != 1 {
			t.Fatalf("run-tests-flavor-failure-hidden: go call %s failed and the run exited %d, want 1\nstderr:\n%s", failCall, run.exit, run.stderr)
		}
		if len(run.calls) != len(runTestsFlavorArgs) {
			t.Fatalf("run-tests-flavors-wrong: go call %s failed and go was called %d times, want %d", failCall, len(run.calls), len(runTestsFlavorArgs))
		}
	}
}
