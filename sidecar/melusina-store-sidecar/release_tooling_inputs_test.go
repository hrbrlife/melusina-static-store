package main

// The Store's release and generation tooling reads nothing outside this
// repository by default. Every input it needs from elsewhere is declared once
// in scripts/release-inputs.json, named by the variable its consumers read,
// and resolved by scripts/release-inputs.py, which refuses by name: a missing
// input as release-input-missing:NAME, an unpinned or changed one as
// release-input-sha256-*:NAME, a retired one as release-input-retired:NAME.
//
// These tests run that resolution with no input set, in an environment with
// an empty HOME and none of the caller's release variables, against the
// resolver itself and against every entry point that reads such an input. A
// read of the Melusina working tree restored in any tooling file fails the
// source scan by name; restored in an entry point, it also stops the entry
// point refusing its input by name.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const releaseInputsManifestPath = "scripts/release-inputs.json"

type releaseInputCompanion struct {
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

type releaseInputSpec struct {
	Kind              string                           `json:"kind"`
	Pin               string                           `json:"pin"`
	SHA256            string                           `json:"sha256"`
	Companions        map[string]releaseInputCompanion `json:"companions"`
	RepositoryDefault string                           `json:"repositoryDefault"`
	Consumers         []string                         `json:"consumers"`
	Reason            string                           `json:"reason"`
	Source            *struct {
		Repository string            `json:"repository"`
		Commit     string            `json:"commit"`
		Path       string            `json:"path"`
		GitObjects map[string]string `json:"gitObjects"`
	} `json:"source"`
}

type releaseInputsManifest struct {
	Schema     string `json:"schema"`
	Toolchains map[string]struct {
		Version   string   `json:"version"`
		Consumers []string `json:"consumers"`
	} `json:"toolchains"`
	Inputs map[string]releaseInputSpec `json:"inputs"`
}

func releaseToolingRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, releaseInputsManifestPath)); err != nil {
		t.Fatalf("repository root %s has no %s: %v", root, releaseInputsManifestPath, err)
	}
	return root
}

func loadReleaseInputsManifest(t *testing.T) releaseInputsManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(releaseToolingRoot(t), releaseInputsManifestPath))
	if err != nil {
		t.Fatal(err)
	}
	var manifest releaseInputsManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != "melusina-store-release-inputs-v1" || len(manifest.Inputs) == 0 {
		t.Fatalf("release inputs manifest is not the v1 declaration: %+v", manifest.Schema)
	}
	return manifest
}

// hermeticReleaseEnv is the environment of an operator who has set nothing:
// the caller's PATH, an empty HOME and TMPDIR, and none of the caller's
// release variables.
func hermeticReleaseEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	return append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"TMPDIR=" + t.TempDir(),
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
	}, extra...)
}

type toolRun struct {
	exit           int
	stdout, stderr string
}

func runReleaseTool(t *testing.T, env []string, dir string, stdin string, name string, args ...string) toolRun {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = env
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	run := toolRun{stdout: stdout.String(), stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		run.exit = exitErr.ExitCode()
	default:
		t.Fatalf("run %s %v: %v", name, args, err)
	}
	return run
}

func resolverRun(t *testing.T, env []string, args ...string) toolRun {
	t.Helper()
	root := releaseToolingRoot(t)
	return runReleaseTool(t, env, root, "", "python3", append([]string{filepath.Join(root, "scripts", "release-inputs.py")}, args...)...)
}

// refusalNames returns reason:NAME for every release-input refusal line.
func refusalNames(text string) []string {
	var names []string
	for _, line := range strings.Split(text, "\n") {
		index := strings.Index(line, "release-input-")
		if index < 0 {
			continue
		}
		head := line[index:]
		if first := strings.Index(head, ":"); first >= 0 {
			rest := head[first+1:]
			if second := strings.Index(rest, ":"); second >= 0 {
				head = head[:first+1+second]
			}
		}
		names = append(names, head)
	}
	sort.Strings(names)
	return names
}

func requireRefusals(t *testing.T, subject string, run toolRun, want ...string) {
	t.Helper()
	sort.Strings(want)
	got := refusalNames(run.stdout + run.stderr)
	if run.exit == 0 || strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%s: exit %d, refusals %q; want a non-zero exit refusing exactly %q\nstdout: %s\nstderr: %s",
			subject, run.exit, got, want, run.stdout, run.stderr)
	}
}

func writeReleaseFixture(t *testing.T, path string, content string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func releaseDigest(t *testing.T, path string) string {
	t.Helper()
	run := resolverRun(t, hermeticReleaseEnv(t), "digest", path)
	digest := strings.TrimSpace(run.stdout)
	if run.exit != 0 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(digest) {
		t.Fatalf("digest %s: exit %d stdout %q stderr %q", path, run.exit, run.stdout, run.stderr)
	}
	return digest
}

// releaseToolingFiles is derived, not listed: every file under the
// repository's scripts/ and the sidecar's scripts/, and the root build files.
func releaseToolingFiles(t *testing.T) []string {
	t.Helper()
	root := releaseToolingRoot(t)
	var files []string
	for _, dir := range []string{"scripts", "sidecar/melusina-store-sidecar/scripts"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() && (entry.Name() == "node_modules" || entry.Name() == "__pycache__") {
				return filepath.SkipDir
			}
			if !entry.IsDir() {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"build-store.sh", "build-store", "Makefile", "Makefile.test", "package.json"} {
		if _, err := os.Lstat(filepath.Join(root, name)); err == nil {
			files = append(files, filepath.Join(root, name))
		}
	}
	sort.Strings(files)
	return files
}

// outsideReadPatterns name a place outside this repository. The measured
// working-tree reads were absolute /home/.../Desktop/... paths, sibling
// checkouts reached through ../, and defaults under the caller's home.
var outsideReadPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"home-directory-path", regexp.MustCompile(`/home/`)},
	{"desktop-path", regexp.MustCompile(`Desktop/`)},
	{"caller-home", regexp.MustCompile(`\$\{?HOME\b|~/|expanduser|Path\.home\(|UserHomeDir`)},
	{"sibling-checkout", regexp.MustCompile(`\.\./(sandstorm|Melusina|deployer|test-wallets|melusina[-_A-Za-z0-9]*)\b`)},
	{"monorepo-tree", regexp.MustCompile(`Melusina/(deployer|sandstorm|shared|test-wallets|lib)\b`)},
	{"retired-sibling-repository", regexp.MustCompile(`melusina_solana_dev-license104|melusina-attestdeployer-tool`)},
}

func outsideReadHits(t *testing.T, files []string) []string {
	t.Helper()
	root := releaseToolingRoot(t)
	var hits []string
	for _, path := range files {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := filepath.EvalSymlinks(path)
			if err != nil || !strings.HasPrefix(target, root+string(filepath.Separator)) {
				hits = append(hits, "symlink-outside-repository in "+path+" -> "+target)
			}
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.IndexByte(raw, 0) >= 0 {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
		for number := 1; scanner.Scan(); number++ {
			line := scanner.Text()
			for _, pattern := range outsideReadPatterns {
				if pattern.re.MatchString(line) {
					hits = append(hits, pattern.name+" in "+path+":"+strconv.Itoa(number)+": "+strings.TrimSpace(line))
				}
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
	}
	return hits
}

// Every byte of the tooling, comments included: no tooling file names a
// place outside this repository.
func TestReleaseToolingNamesNoPathOutsideTheRepository(t *testing.T) {
	root := releaseToolingRoot(t)
	files := releaseToolingFiles(t)
	for _, required := range []string{
		"build-store.sh", "Makefile",
		"scripts/build-store-generation-release.sh", "scripts/build-store-release.sh",
		"scripts/build-store-bootstrap-component.sh", "scripts/build-sidecar-ui.sh",
		"scripts/default-bazaar-release.sh", "scripts/mel-release-provider.py",
		"scripts/stage-into-catalog.sh", "scripts/preflight.sh", "scripts/doctor.sh",
		"scripts/manifest-merge.sh", "scripts/release-inputs.py", "scripts/release-inputs.json",
		"sidecar/melusina-store-sidecar/scripts/mel-release-provider.sh",
		"sidecar/melusina-store-sidecar/scripts/mel-release-catalog-provider.sh",
		"sidecar/melusina-store-sidecar/scripts/node-module-confinement.cjs",
	} {
		found := false
		for _, file := range files {
			found = found || file == filepath.Join(root, required)
		}
		if !found {
			t.Fatalf("the scan never reached %s; it cannot vouch for the release tooling", required)
		}
	}

	// Known-positive control: each working-tree read this repository used to
	// make is found, by the pattern that names it.
	plants := map[string]string{
		`readonly DEFAULT_RUNTIME_ENV="/home/operator/Desktop/Melusina/deployer/state/default-bazaar-release.env"`: "home-directory-path",
		`executor="${MEL_RELEASE_SQUADS_EXECUTOR:-/srv/Desktop/Melusina/deployer/scripts/squads-vault-exec.js}"`:   "desktop-path",
		`SANDSTORM_SRC="${SANDSTORM_SRC:-../sandstorm}"`:                                                           "sibling-checkout",
		`DEPLOY_UI_SRC="../Melusina/deployer/deploy-ui"`:                                                           "sibling-checkout",
		`PATCHED_SPK=/srv/Melusina/sandstorm/bin/spk`:                                                              "monorepo-tree",
		`default="/srv/melusina_solana_dev-license104/frontend-vite/node_modules",`:                                "retired-sibling-repository",
		`STATE="${HOME}/.mel-release"`:                                                                             "caller-home",
	}
	plantDir := t.TempDir()
	index := 0
	for line, pattern := range plants {
		index++
		plant := writeReleaseFixture(t, filepath.Join(plantDir, "plant-"+strconv.Itoa(index)+".sh"), "#!/bin/sh\n"+line+"\n", 0o644)
		hits := strings.Join(outsideReadHits(t, []string{plant}), "\n")
		if !strings.Contains(hits, pattern+" in "+plant+":2: "+line) {
			t.Fatalf("plant control: %q was not found as %s; hits:\n%s", line, pattern, hits)
		}
	}
	link := filepath.Join(plantDir, "outside-link")
	if err := os.Symlink(os.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	if hits := outsideReadHits(t, []string{link}); len(hits) != 1 || !strings.HasPrefix(hits[0], "symlink-outside-repository in ") {
		t.Fatalf("plant control: a symlink leaving the repository gave %q", hits)
	}

	if hits := outsideReadHits(t, files); len(hits) != 0 {
		t.Fatalf("release tooling names a path outside the repository:\n%s", strings.Join(hits, "\n"))
	}
	t.Logf("%d tooling files scanned", len(files))
}

// The declaration is live: every consumer it names exists and reads the
// input by name, and the resolver refuses every required input by name when
// nothing is set.
func TestReleaseInputsAreRefusedByNameWhenUnset(t *testing.T) {
	root := releaseToolingRoot(t)
	manifest := loadReleaseInputsManifest(t)
	var required, retired []string
	for name, spec := range manifest.Inputs {
		if len(spec.Consumers) == 0 || strings.TrimSpace(spec.Reason) == "" {
			t.Fatalf("%s names no consumer or reason", name)
		}
		for _, consumer := range spec.Consumers {
			raw, err := os.ReadFile(filepath.Join(root, consumer))
			if err != nil {
				t.Fatalf("%s names consumer %s: %v", name, consumer, err)
			}
			if !bytes.Contains(raw, []byte(name)) {
				t.Fatalf("%s names consumer %s, which never reads it", name, consumer)
			}
		}
		switch {
		case spec.Kind == "retired":
			retired = append(retired, name)
		case spec.RepositoryDefault == "":
			required = append(required, name)
		}
	}
	for tool, spec := range manifest.Toolchains {
		for _, consumer := range spec.Consumers {
			raw, err := os.ReadFile(filepath.Join(root, consumer))
			if err != nil || !bytes.Contains(raw, []byte("check-toolchain "+tool)) {
				t.Fatalf("toolchain %s names consumer %s, which does not check it (%v)", tool, consumer, err)
			}
		}
	}
	sort.Strings(required)
	sort.Strings(retired)
	if len(required) < 15 || len(retired) != 2 {
		t.Fatalf("declaration shrank: %d required, %d retired inputs", len(required), len(retired))
	}

	var want []string
	for _, name := range required {
		want = append(want, "release-input-missing:"+name)
	}
	requireRefusals(t, "check with nothing set", resolverRun(t, hermeticReleaseEnv(t), append([]string{"check"}, required...)...), want...)

	// An input with a default inside the repository resolves there unset.
	registerDefault := filepath.Join(root, manifest.Inputs["MEL_RELEASE_REGISTER_EXECUTOR"].RepositoryDefault)
	if run := resolverRun(t, hermeticReleaseEnv(t), "resolve", "MEL_RELEASE_REGISTER_EXECUTOR"); run.exit != 0 || strings.TrimSpace(run.stdout) != registerDefault {
		t.Fatalf("unset register executor resolved to %q (exit %d, %s); want this repository's %s", run.stdout, run.exit, run.stderr, registerDefault)
	}
	other := writeReleaseFixture(t, filepath.Join(t.TempDir(), "register.mjs"), "// another helper\n", 0o644)
	requireRefusals(t, "register executor outside the repository without a pin",
		resolverRun(t, hermeticReleaseEnv(t, "MEL_RELEASE_REGISTER_EXECUTOR="+other), "resolve", "MEL_RELEASE_REGISTER_EXECUTOR"),
		"release-input-sha256-missing:MEL_RELEASE_REGISTER_EXECUTOR")

	if run := resolverRun(t, hermeticReleaseEnv(t), append([]string{"check-retired"}, retired...)...); run.exit != 0 {
		t.Fatalf("unset retired inputs were refused: %s", run.stderr)
	}
	var setRetired, wantRetired []string
	for _, name := range retired {
		setRetired = append(setRetired, name+"=/anywhere")
		wantRetired = append(wantRetired, "release-input-retired:"+name)
	}
	requireRefusals(t, "retired inputs set", resolverRun(t, hermeticReleaseEnv(t, setRetired...), append([]string{"check-retired"}, retired...)...), wantRetired...)
	requireRefusals(t, "check-retired on a live input", resolverRun(t, hermeticReleaseEnv(t), "check-retired", "MEL_RELEASE_PEARL_TOOL"),
		"release-input-undeclared:MEL_RELEASE_PEARL_TOOL")
	requireRefusals(t, "an undeclared input", resolverRun(t, hermeticReleaseEnv(t), "resolve", "MEL_RELEASE_NOT_DECLARED"),
		"release-input-undeclared:MEL_RELEASE_NOT_DECLARED")
}

// An operator pin is checked before use: absent, malformed, wrong or stale is
// refused by name; the pinned bytes resolve.
func TestReleaseInputOperatorPinsAreCheckedBeforeUse(t *testing.T) {
	dir := t.TempDir()
	tool := writeReleaseFixture(t, filepath.Join(dir, "melusina-pearl-tool"), "#!/bin/sh\necho pearl\n", 0o755)
	toolPin := releaseDigest(t, tool)
	link := filepath.Join(dir, "pearl-link")
	if err := os.Symlink(tool, link); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		subject string
		env     []string
		want    string
	}{
		{"unpinned", []string{"MEL_RELEASE_PEARL_TOOL=" + tool}, "release-input-sha256-missing:MEL_RELEASE_PEARL_TOOL"},
		{"malformed pin", []string{"MEL_RELEASE_PEARL_TOOL=" + tool, "MEL_RELEASE_PEARL_TOOL_SHA256=" + strings.ToUpper(toolPin)}, "release-input-sha256-malformed:MEL_RELEASE_PEARL_TOOL"},
		{"other bytes", []string{"MEL_RELEASE_PEARL_TOOL=" + tool, "MEL_RELEASE_PEARL_TOOL_SHA256=" + strings.Repeat("0", 64)}, "release-input-sha256-mismatch:MEL_RELEASE_PEARL_TOOL"},
		{"relative path", []string{"MEL_RELEASE_PEARL_TOOL=melusina-pearl-tool", "MEL_RELEASE_PEARL_TOOL_SHA256=" + toolPin}, "release-input-not-absolute:MEL_RELEASE_PEARL_TOOL"},
		{"unclean path", []string{"MEL_RELEASE_PEARL_TOOL=" + dir + "/../" + filepath.Base(dir) + "/melusina-pearl-tool", "MEL_RELEASE_PEARL_TOOL_SHA256=" + toolPin}, "release-input-not-absolute:MEL_RELEASE_PEARL_TOOL"},
		{"symlink", []string{"MEL_RELEASE_PEARL_TOOL=" + link, "MEL_RELEASE_PEARL_TOOL_SHA256=" + toolPin}, "release-input-not-regular-file:MEL_RELEASE_PEARL_TOOL"},
		{"absent", []string{"MEL_RELEASE_PEARL_TOOL=" + filepath.Join(dir, "absent"), "MEL_RELEASE_PEARL_TOOL_SHA256=" + toolPin}, "release-input-not-regular-file:MEL_RELEASE_PEARL_TOOL"},
	} {
		requireRefusals(t, c.subject, resolverRun(t, hermeticReleaseEnv(t, c.env...), "resolve", "MEL_RELEASE_PEARL_TOOL"), c.want)
	}
	if run := resolverRun(t, hermeticReleaseEnv(t, "MEL_RELEASE_PEARL_TOOL="+tool, "MEL_RELEASE_PEARL_TOOL_SHA256="+toolPin), "resolve", "MEL_RELEASE_PEARL_TOOL"); run.exit != 0 || strings.TrimSpace(run.stdout) != tool {
		t.Fatalf("pinned tool: exit %d stdout %q stderr %q", run.exit, run.stdout, run.stderr)
	}

	// A tree pin covers every file's bytes, its execute bit and every link.
	tree := filepath.Join(dir, "node_modules")
	writeReleaseFixture(t, filepath.Join(tree, "@sqds", "multisig", "package.json"), "{\"name\":\"@sqds/multisig\"}\n", 0o644)
	cli := writeReleaseFixture(t, filepath.Join(tree, "@solana", "web3.js", "bin", "cli.js"), "#!/usr/bin/env node\n", 0o644)
	if err := os.MkdirAll(filepath.Join(tree, ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../@solana/web3.js/bin/cli.js", filepath.Join(tree, ".bin", "web3")); err != nil {
		t.Fatal(err)
	}
	treePin := releaseDigest(t, tree)
	treeEnv := func(pin string) []string {
		return hermeticReleaseEnv(t, "MEL_RELEASE_SQUADS_NODE_MODULES="+tree, "MEL_RELEASE_SQUADS_NODE_MODULES_SHA256="+pin)
	}
	if run := resolverRun(t, treeEnv(treePin), "resolve", "MEL_RELEASE_SQUADS_NODE_MODULES"); run.exit != 0 {
		t.Fatalf("pinned tree refused: %s", run.stderr)
	}
	for _, mutate := range []struct {
		subject string
		apply   func()
		undo    func()
	}{
		{"an added file", func() { writeReleaseFixture(t, filepath.Join(tree, "extra.js"), "x\n", 0o644) }, func() { os.Remove(filepath.Join(tree, "extra.js")) }},
		{"an execute bit", func() { os.Chmod(cli, 0o755) }, func() { os.Chmod(cli, 0o644) }},
		{"a retargeted link", func() {
			os.Remove(filepath.Join(tree, ".bin", "web3"))
			os.Symlink("../@sqds/multisig/package.json", filepath.Join(tree, ".bin", "web3"))
		}, func() {
			os.Remove(filepath.Join(tree, ".bin", "web3"))
			os.Symlink("../@solana/web3.js/bin/cli.js", filepath.Join(tree, ".bin", "web3"))
		}},
	} {
		mutate.apply()
		requireRefusals(t, "tree with "+mutate.subject, resolverRun(t, treeEnv(treePin), "resolve", "MEL_RELEASE_SQUADS_NODE_MODULES"),
			"release-input-sha256-mismatch:MEL_RELEASE_SQUADS_NODE_MODULES")
		mutate.undo()
		if got := releaseDigest(t, tree); got != treePin {
			t.Fatalf("undoing %s did not restore the tree digest", mutate.subject)
		}
	}

	// digest-git, which derives a pin from a source commit, agrees with the
	// digest of a checkout of that commit.
	repo := filepath.Join(dir, "repo")
	gitEnv := hermeticReleaseEnv(t, "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid", "GIT_CONFIG_NOSYSTEM=1")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"commit", "-q", "-m", "fixture"}} {
		if run := runReleaseTool(t, gitEnv, repo, "", "git", args...); run.exit != 0 {
			t.Fatalf("git %v: %s", args, run.stderr)
		}
		if args[0] == "init" {
			if err := os.Rename(tree, filepath.Join(repo, "node_modules")); err != nil {
				t.Fatal(err)
			}
		}
	}
	fromGit := resolverRun(t, hermeticReleaseEnv(t), "digest-git", repo, "HEAD:node_modules")
	if fromGit.exit != 0 || strings.TrimSpace(fromGit.stdout) != treePin {
		t.Fatalf("digest-git gave %q (%s); the checkout digest is %s", fromGit.stdout, fromGit.stderr, treePin)
	}
}

const repositoryPinDriver = `
import importlib.util, json, os, sys
from pathlib import Path
root, work = sys.argv[1], Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("ri", os.path.join(root, "scripts", "release-inputs.py"))
ri = importlib.util.module_from_spec(spec); spec.loader.exec_module(ri)
executor = work / "scripts" / "squads-vault-exec.js"
manifest = {"schema": ri.SCHEMA, "inputs": {"MEL_RELEASE_SQUADS_EXECUTOR": {
    "kind": "file", "pin": "repository", "sha256": ri.digest(executor),
    "companions": {
        "lib/reduced-mode-guard.cjs": {"kind": "file", "sha256": ri.digest(executor.parent / "lib" / "reduced-mode-guard.cjs")},
        "node_modules": {"kind": "tree", "sha256": ri.digest(executor.parent / "node_modules")}},
    "consumers": ["fixture"], "reason": "fixture"}}}
env = {"MEL_RELEASE_SQUADS_EXECUTOR": str(executor)}
def attempt():
    try:
        return "ok:" + str(ri.resolve("MEL_RELEASE_SQUADS_EXECUTOR", env, manifest))
    except ri.InputRefused as exc:
        return str(exc)
results = {"canonical": attempt()}
guard = executor.parent / "lib" / "reduced-mode-guard.cjs"
original = guard.read_text()
guard.write_text("function rejectReducedModeInstruction() {}\nmodule.exports = { rejectReducedModeInstruction };\n")
results["guard-without-check"] = attempt()
guard.unlink()
results["guard-absent"] = attempt()
guard.write_text(original)
extra = executor.parent / "node_modules" / "@sqds" / "multisig" / "patched.js"
extra.write_text("module.exports = {};\n")
results["sdk-tree-changed"] = attempt()
extra.unlink()
results["restored"] = attempt()
executor.write_text(executor.read_text() + "// another copy\n")
results["another-copy"] = attempt()
print(json.dumps(results))
`

// A repository pin admits exactly the canonical copy: the executor, the
// reduced-mode guard it loads and the SDK tree it resolves, each unchanged.
func TestReleaseInputRepositoryPinAdmitsOnlyTheCanonicalCopy(t *testing.T) {
	root := releaseToolingRoot(t)
	manifest := loadReleaseInputsManifest(t)
	spec := manifest.Inputs["MEL_RELEASE_SQUADS_EXECUTOR"]
	if spec.Pin != "repository" || len(spec.Companions) != 2 || spec.Source == nil || spec.Source.Commit == "" {
		t.Fatalf("the Squads executor is not repository-pinned with its guard, SDK tree and source commit: %+v", spec)
	}
	if _, ok := spec.Companions["lib/reduced-mode-guard.cjs"]; !ok {
		t.Fatalf("the executor pin omits the reduced-mode guard it loads: %+v", spec.Companions)
	}

	// Any other copy of the executor, under the real declaration.
	other := writeReleaseFixture(t, filepath.Join(t.TempDir(), "squads-vault-exec.js"), "// an earlier copy\n", 0o644)
	requireRefusals(t, "a non-canonical executor", resolverRun(t, hermeticReleaseEnv(t, "MEL_RELEASE_SQUADS_EXECUTOR="+other), "resolve", "MEL_RELEASE_SQUADS_EXECUTOR"),
		"release-input-sha256-mismatch:MEL_RELEASE_SQUADS_EXECUTOR")

	// The companion checks, under a fixture declaration pinning a fixture copy.
	work := t.TempDir()
	writeReleaseFixture(t, filepath.Join(work, "scripts", "squads-vault-exec.js"), "require('./lib/reduced-mode-guard.cjs');\n", 0o644)
	writeReleaseFixture(t, filepath.Join(work, "scripts", "lib", "reduced-mode-guard.cjs"), "function rejectReducedModeInstruction(list) { throw new Error('reduced mode'); }\nmodule.exports = { rejectReducedModeInstruction };\n", 0o644)
	writeReleaseFixture(t, filepath.Join(work, "scripts", "node_modules", "@sqds", "multisig", "index.js"), "module.exports = {};\n", 0o644)
	run := runReleaseTool(t, hermeticReleaseEnv(t), root, "", "python3", "-c", repositoryPinDriver, root, work)
	if run.exit != 0 {
		t.Fatalf("driver: %s", run.stderr)
	}
	var results map[string]string
	if err := json.Unmarshal([]byte(run.stdout), &results); err != nil {
		t.Fatalf("driver output %q: %v", run.stdout, err)
	}
	for key, want := range map[string]string{
		"canonical":           "ok:",
		"guard-without-check": "release-input-companion-sha256-mismatch:MEL_RELEASE_SQUADS_EXECUTOR:",
		"guard-absent":        "release-input-companion-sha256-mismatch:MEL_RELEASE_SQUADS_EXECUTOR:",
		"sdk-tree-changed":    "release-input-companion-sha256-mismatch:MEL_RELEASE_SQUADS_EXECUTOR:",
		"restored":            "ok:",
		"another-copy":        "release-input-sha256-mismatch:MEL_RELEASE_SQUADS_EXECUTOR:",
	} {
		if !strings.HasPrefix(results[key], want) {
			t.Fatalf("%s: %q, want %q", key, results[key], want)
		}
	}
}

// Provenance: the pins name the deployer commit's bytes. It needs a deployer
// clone holding that commit, named by MELUSINA_DEPLOYER_GIT_DIR.
func TestReleaseInputExecutorPinIsTheDeployerCommitsCopy(t *testing.T) {
	gitDir := os.Getenv("MELUSINA_DEPLOYER_GIT_DIR")
	if gitDir == "" {
		t.Skip("MELUSINA_DEPLOYER_GIT_DIR is unset: the executor pin is not compared with the deployer commit it names")
	}
	spec := loadReleaseInputsManifest(t).Inputs["MEL_RELEASE_SQUADS_EXECUTOR"]
	base := filepath.Dir(spec.Source.Path)
	objects := map[string]string{spec.Source.Path: spec.SHA256}
	for relative, companion := range spec.Companions {
		objects[filepath.ToSlash(filepath.Join(base, relative))] = companion.SHA256
	}
	for path, pin := range objects {
		treeish := spec.Source.Commit + ":" + path
		run := resolverRun(t, hermeticReleaseEnv(t), "digest-git", gitDir, treeish)
		if run.exit != 0 || strings.TrimSpace(run.stdout) != pin {
			t.Fatalf("%s digests to %q (%s); scripts/release-inputs.json pins %s", treeish, run.stdout, run.stderr, pin)
		}
		object := runReleaseTool(t, hermeticReleaseEnv(t), gitDir, "", "git", "rev-parse", treeish)
		if strings.TrimSpace(object.stdout) != spec.Source.GitObjects[path] {
			t.Fatalf("%s is git object %q; the declaration records %q", treeish, object.stdout, spec.Source.GitObjects[path])
		}
	}
}

func releaseProviderCatalog(t *testing.T, dir string) (string, []string) {
	t.Helper()
	// Synthetic base58 addresses, 44 characters each.
	pad := func(prefix string) string { return prefix + strings.Repeat("1", 44-len(prefix)) }
	multisig, vault, program := pad("Fixture1Mu1tisig"), pad("Fixture1Vau1t"), pad("Fixture1Program")
	catalog := writeReleaseFixture(t, filepath.Join(dir, "catalog.yaml"),
		"schema: melusina-bazaar-catalog/v1\nrelease_squads_authority:\n  multisig: "+multisig+"\n  vault: "+vault+"\n  program_id: "+program+"\n", 0o644)
	return catalog, []string{
		"MEL_RELEASE_CONFIG=" + catalog, "MEL_RELEASE_SQUADS_MULTISIG=" + multisig,
		"MEL_RELEASE_SQUADS_VAULT=" + vault, "MEL_RELEASE_SQUADS_PROGRAM_ID=" + program,
	}
}

const pythonProviderDriver = `
import importlib.util, json, os, sys
from pathlib import Path
root, out = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("provider", os.path.join(root, "scripts", "mel-release-provider.py"))
provider = importlib.util.module_from_spec(spec); spec.loader.exec_module(provider)
authority = {"multisig": "m", "vault": "v", "programId": "p", "threshold": 1, "memberCount": 1}
provider.require_shared_squads_authority = lambda: authority
def chain_read(*args, **kwargs):
    raise AssertionError("revoke read the chain before resolving its executor")
provider.subprocess.run = chain_read
results = {}
for name, call in (
    ("generic_executor", provider.generic_executor),
    ("pearl_tool", provider.pearl_tool),
    ("policy_executor_env", provider.policy_executor_env),
    ("revoke", lambda: provider.revoke("PdaFixture", Path(out))),
):
    try:
        call()
        results[name] = "resolved"
    except provider.ProviderError as exc:
        results[name] = str(exc)
print(json.dumps(results))
`

// Every entry point that reads an input from outside the repository refuses
// it by name when an operator has set nothing, before it does anything else.
func TestReleaseToolingEntryPointsRefuseMissingInputsByName(t *testing.T) {
	root := releaseToolingRoot(t)
	script := func(path string) string { return filepath.Join(root, path) }

	t.Run("default-bazaar-release", func(t *testing.T) {
		requireRefusals(t, "publish with nothing set",
			runReleaseTool(t, hermeticReleaseEnv(t), root, "", "bash", script("scripts/default-bazaar-release.sh"), "publish", "--app", "fixture", "--version", "1.0.0"),
			"release-input-missing:MEL_RELEASE_RUNTIME_ENV")
		requireRefusals(t, "preflight with nothing set",
			runReleaseTool(t, hermeticReleaseEnv(t), root, "", "bash", script("scripts/default-bazaar-release.sh"), "preflight", "--app", "fixture", "--version", "1.0.0"),
			"release-input-missing:MEL_RELEASE_SOURCE_ROOT", "release-input-missing:MEL_RELEASE_STATE_DIR")

		dir := t.TempDir()
		runtimeEnv := writeReleaseFixture(t, filepath.Join(dir, "runtime.env"), "# names nothing\n", 0o600)
		requireRefusals(t, "an unpinned runtime module",
			runReleaseTool(t, hermeticReleaseEnv(t, "MEL_RELEASE_RUNTIME_ENV="+runtimeEnv), root, "", "bash", script("scripts/default-bazaar-release.sh"), "publish"),
			"release-input-sha256-missing:MEL_RELEASE_RUNTIME_ENV")
		pinnedRuntime := []string{"MEL_RELEASE_RUNTIME_ENV=" + runtimeEnv, "MEL_RELEASE_RUNTIME_ENV_SHA256=" + releaseDigest(t, runtimeEnv)}
		requireRefusals(t, "a pinned runtime module that names nothing",
			runReleaseTool(t, hermeticReleaseEnv(t, pinnedRuntime...), root, "", "bash", script("scripts/default-bazaar-release.sh"), "publish"),
			"release-input-missing:MEL_RELEASE_STORE_PUBKEY", "release-input-missing:MEL_RELEASE_PUBLISHER_KEY",
			"release-input-missing:MEL_RELEASE_STATE_DIR", "release-input-missing:MEL_RELEASE_AUTHOR_KEYPAIR",
			"release-input-missing:MEL_RELEASE_SQUADS_MEMBERS", "release-input-missing:MEL_RELEASE_SQUADS_NODE_MODULES",
			"release-input-missing:MEL_RELEASE_SQUADS_EXECUTOR", "release-input-missing:MEL_RELEASE_PEARL_TOOL")

		// Positive control: every input named and pinned but the executor,
		// which is not the canonical copy, leaves that one refusal only.
		tool := writeReleaseFixture(t, filepath.Join(dir, "pearl"), "#!/bin/sh\n", 0o755)
		modules := filepath.Join(dir, "node_modules")
		writeReleaseFixture(t, filepath.Join(modules, "@sqds", "multisig", "package.json"), "{}\n", 0o644)
		named := append(pinnedRuntime,
			"MEL_RELEASE_STORE_PUBKEY="+writeReleaseFixture(t, filepath.Join(dir, "store.pub.json"), "{}\n", 0o600),
			"MEL_RELEASE_PUBLISHER_KEY="+writeReleaseFixture(t, filepath.Join(dir, "publisher.key"), "{}\n", 0o600),
			"MEL_RELEASE_STATE_DIR="+filepath.Join(dir, "state"),
			"MEL_RELEASE_AUTHOR_KEYPAIR="+writeReleaseFixture(t, filepath.Join(dir, "author.json"), "[]\n", 0o600),
			"MEL_RELEASE_SQUADS_MEMBERS="+strings.Join([]string{
				writeReleaseFixture(t, filepath.Join(dir, "m1.json"), "[]\n", 0o600),
				writeReleaseFixture(t, filepath.Join(dir, "m2.json"), "[]\n", 0o600),
				writeReleaseFixture(t, filepath.Join(dir, "m3.json"), "[]\n", 0o600)}, ","),
			"MEL_RELEASE_SQUADS_NODE_MODULES="+modules, "MEL_RELEASE_SQUADS_NODE_MODULES_SHA256="+releaseDigest(t, modules),
			"MEL_RELEASE_SQUADS_EXECUTOR="+writeReleaseFixture(t, filepath.Join(dir, "squads-vault-exec.js"), "// not canonical\n", 0o644),
			"MEL_RELEASE_PEARL_TOOL="+tool, "MEL_RELEASE_PEARL_TOOL_SHA256="+releaseDigest(t, tool))
		requireRefusals(t, "every input named, a non-canonical executor",
			runReleaseTool(t, hermeticReleaseEnv(t, named...), root, "", "bash", script("scripts/default-bazaar-release.sh"), "publish"),
			"release-input-sha256-mismatch:MEL_RELEASE_SQUADS_EXECUTOR")
	})

	t.Run("mel-release-provider.sh", func(t *testing.T) {
		dir := t.TempDir()
		_, catalogEnv := releaseProviderCatalog(t, dir)
		env := hermeticReleaseEnv(t, append(catalogEnv, "MEL_RELEASE_STATE_DIR="+filepath.Join(dir, "state"))...)
		requireRefusals(t, "revoke with no executor named",
			runReleaseTool(t, env, root, "", "bash", script("sidecar/melusina-store-sidecar/scripts/mel-release-provider.sh"), "revoke"),
			"release-input-missing:MEL_RELEASE_SQUADS_EXECUTOR")
		other := writeReleaseFixture(t, filepath.Join(dir, "squads-vault-exec.js"), "// an earlier copy\n", 0o644)
		requireRefusals(t, "revoke with a non-canonical executor",
			runReleaseTool(t, append(env, "MEL_RELEASE_SQUADS_EXECUTOR="+other), root, "", "bash", script("sidecar/melusina-store-sidecar/scripts/mel-release-provider.sh"), "revoke"),
			"release-input-sha256-mismatch:MEL_RELEASE_SQUADS_EXECUTOR")
	})

	t.Run("mel-release-provider.py", func(t *testing.T) {
		dir := t.TempDir()
		run := runReleaseTool(t, hermeticReleaseEnv(t, "MEL_RELEASE_RPC_URL=https://rpc.example.invalid"), root, "", "python3", "-c", pythonProviderDriver, root, filepath.Join(dir, "receipt.json"))
		if run.exit != 0 {
			t.Fatalf("driver: %s", run.stderr)
		}
		var results map[string]string
		if err := json.Unmarshal([]byte(run.stdout), &results); err != nil {
			t.Fatalf("driver output %q: %v", run.stdout, err)
		}
		for call, want := range map[string]string{
			"generic_executor":    "release-input-missing:MEL_RELEASE_SQUADS_EXECUTOR:",
			"pearl_tool":          "release-input-missing:MEL_RELEASE_PEARL_TOOL:",
			"policy_executor_env": "release-input-missing:MEL_RELEASE_SQUADS_NODE_MODULES:",
			"revoke":              "release-input-missing:MEL_RELEASE_SQUADS_EXECUTOR:",
		} {
			if !strings.HasPrefix(results[call], want) {
				t.Fatalf("provider %s: %q, want %q", call, results[call], want)
			}
		}
	})

	t.Run("stage-into-catalog", func(t *testing.T) {
		requireRefusals(t, "stage with no release-json-stub named",
			runReleaseTool(t, hermeticReleaseEnv(t), root, "", "bash", script("scripts/stage-into-catalog.sh"), "/nonexistent/app.spk", "/nonexistent/pkg"),
			"release-input-missing:RELEASE_JSON_STUB")
	})

	t.Run("build-store", func(t *testing.T) {
		for _, name := range []string{"SANDSTORM_SRC", "DEPLOY_UI_SRC"} {
			requireRefusals(t, name+" set",
				runReleaseTool(t, hermeticReleaseEnv(t, name+"=/anywhere"), root, "", "bash", script("build-store.sh"), "--dry-run"),
				"release-input-retired:"+name)
		}
		requireRefusals(t, "a bundle named without its tool or keyring",
			runReleaseTool(t, hermeticReleaseEnv(t, "MELUSINA_BUNDLE_TARBALL="+filepath.Join(t.TempDir(), "sandstorm-7.tar.xz")), root, "", "bash", script("build-store.sh"), "--dry-run"),
			"release-input-not-regular-file:MELUSINA_BUNDLE_TARBALL", "release-input-missing:MELUSINA_BUNDLE_UPDATE_TOOL",
			"release-input-missing:MELUSINA_BUNDLE_UPDATE_KEYRING")
		// Each named with a trailing space, beside pins of the unspaced files:
		// refused by name, never trimmed into the pinned files.
		bundle := t.TempDir()
		var spaced []string
		for name, file := range map[string]string{
			"MELUSINA_BUNDLE_TARBALL": "sandstorm-7.tar.xz", "MELUSINA_BUNDLE_UPDATE_TOOL": "update-tool", "MELUSINA_BUNDLE_UPDATE_KEYRING": "keyring",
		} {
			path := writeReleaseFixture(t, filepath.Join(bundle, file), "fixture\n", 0o755)
			spaced = append(spaced, name+"="+path+" ", name+"_SHA256="+releaseDigest(t, path))
		}
		requireRefusals(t, "bundle inputs named with a trailing space",
			runReleaseTool(t, hermeticReleaseEnv(t, spaced...), root, "", "bash", script("build-store.sh"), "--dry-run"),
			"release-input-whitespace:MELUSINA_BUNDLE_TARBALL", "release-input-whitespace:MELUSINA_BUNDLE_UPDATE_TOOL",
			"release-input-whitespace:MELUSINA_BUNDLE_UPDATE_KEYRING")
	})

	t.Run("deployer-manifest", func(t *testing.T) {
		manifestFile := writeReleaseFixture(t, filepath.Join(t.TempDir(), "global-apps.json"), "{\"apps\":[]}\n", 0o644)
		requireRefusals(t, "manifest-merge with no manifest named",
			runReleaseTool(t, hermeticReleaseEnv(t), root, "", "bash", script("scripts/manifest-merge.sh"), "--stdin"),
			"release-input-missing:MELUSINA_DEPLOYER_MANIFEST")
		requireRefusals(t, "manifest-merge with an unpinned manifest",
			runReleaseTool(t, hermeticReleaseEnv(t), root, "", "bash", script("scripts/manifest-merge.sh"), "--manifest", manifestFile, "--stdin"),
			"release-input-sha256-missing:MELUSINA_DEPLOYER_MANIFEST")
		requireRefusals(t, "preflight with an unpinned manifest",
			runReleaseTool(t, hermeticReleaseEnv(t, "MELUSINA_DEPLOYER_MANIFEST="+manifestFile), root, "", "bash", script("scripts/preflight.sh")),
			"release-input-sha256-missing:MELUSINA_DEPLOYER_MANIFEST")
	})
}

// The release builders compile with the local go, so a go other than the
// pinned one is refused by name before the builder touches git or writes.
func TestReleaseBuildersRefuseAnUnpinnedGoByName(t *testing.T) {
	root := releaseToolingRoot(t)
	pinned := loadReleaseInputsManifest(t).Toolchains["go"].Version
	if !regexp.MustCompile(`^go1\.[0-9]+\.[0-9]+$`).MatchString(pinned) {
		t.Fatalf("the go toolchain pin %q is not a release version", pinned)
	}
	fakeBin := func(t *testing.T, version string) (string, string) {
		dir := t.TempDir()
		record := filepath.Join(dir, "git-called")
		if version != "" {
			writeReleaseFixture(t, filepath.Join(dir, "go"), "#!/bin/sh\n[ \"$1 $2\" = \"env GOVERSION\" ] && echo "+version+"\n", 0o755)
		}
		writeReleaseFixture(t, filepath.Join(dir, "git"), "#!/bin/sh\n: > "+record+"\nexit 1\n", 0o755)
		for _, tool := range []string{"bash", "dirname", "python3"} {
			path, err := exec.LookPath(tool)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path, filepath.Join(dir, tool)); err != nil {
				t.Fatal(err)
			}
		}
		return dir, record
	}

	// Positive control: the pinned version passes the check.
	bin, _ := fakeBin(t, pinned)
	if run := resolverRun(t, []string{"PATH=" + bin, "HOME=" + t.TempDir()}, "check-toolchain", "go"); run.exit != 0 {
		t.Fatalf("the pinned %s was refused: %s", pinned, run.stderr)
	}
	for _, builder := range []string{"scripts/build-store-generation-release.sh", "scripts/build-store-release.sh"} {
		for _, c := range []struct{ subject, version, want string }{
			{"another go", "go1.99.0", "release-input-toolchain-mismatch:go"},
			{"no go", "", "release-input-toolchain-missing:go"},
		} {
			bin, record := fakeBin(t, c.version)
			out := filepath.Join(t.TempDir(), "out")
			run := runReleaseTool(t, []string{"PATH=" + bin, "HOME=" + t.TempDir()}, root, "", filepath.Join(bin, "bash"),
				filepath.Join(root, builder), "--version", "1.2.3", "--out-dir", out)
			requireRefusals(t, builder+" with "+c.subject, run, c.want)
			if _, err := os.Stat(record); err == nil {
				t.Fatalf("%s with %s ran git before refusing the toolchain", builder, c.subject)
			}
			if _, err := os.Stat(filepath.Dir(out)); err == nil {
				if entries, _ := os.ReadDir(filepath.Dir(out)); len(entries) != 0 {
					t.Fatalf("%s with %s wrote %v before refusing the toolchain", builder, c.subject, entries)
				}
			}
		}
	}
}
