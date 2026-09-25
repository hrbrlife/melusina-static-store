package main

// A pinned input is only as good as the use that follows its check. These
// tests hold the consumers to three rules:
//
//   - the value checked is the value used: scripts/release-inputs.py refuses
//     a value, list item or pin with surrounding whitespace by name
//     (release-input-whitespace:NAME) instead of trimming it, and the shell
//     provider runs the path the resolver printed;
//   - the shell provider resolves the Pearl tool and the Squads SDK tree
//     before it runs either, and runs nothing when a pin is missing or wrong;
//   - Node loads nothing outside the pinned inputs: both providers run the
//     Squads helper and the vault executor under node-module-confinement.cjs
//     with NODE_OPTIONS and NODE_PATH cleared, so a module that resolves to an
//     ancestor node_modules, NODE_PATH, a global folder or a fallback the
//     script adds itself is refused as not found.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseInputsRefuseSurroundingWhitespaceByName(t *testing.T) {
	dir := t.TempDir()
	tool := writeReleaseFixture(t, filepath.Join(dir, "melusina-pearl-tool"), "#!/bin/sh\necho pinned\n", 0o755)
	pin := releaseDigest(t, tool)

	// Positive control: the exact value resolves, to itself.
	if run := resolverRun(t, hermeticReleaseEnv(t, "MEL_RELEASE_PEARL_TOOL="+tool, "MEL_RELEASE_PEARL_TOOL_SHA256="+pin), "resolve", "MEL_RELEASE_PEARL_TOOL"); run.exit != 0 || run.stdout != tool+"\n" {
		t.Fatalf("the exact pinned value: exit %d stdout %q stderr %q", run.exit, run.stdout, run.stderr)
	}
	for _, c := range []struct{ subject, value, pin string }{
		{"a trailing space", tool + " ", pin},
		{"a leading space", " " + tool, pin},
		{"a trailing newline", tool + "\n", pin},
		{"a leading tab", "\t" + tool, pin},
		{"only whitespace", "  ", pin},
		{"a pin with a trailing space", tool, pin + " "},
		{"a pin with a leading newline", tool, "\n" + pin},
	} {
		requireRefusals(t, c.subject,
			resolverRun(t, hermeticReleaseEnv(t, "MEL_RELEASE_PEARL_TOOL="+c.value, "MEL_RELEASE_PEARL_TOOL_SHA256="+c.pin), "resolve", "MEL_RELEASE_PEARL_TOOL"),
			"release-input-whitespace:MEL_RELEASE_PEARL_TOOL")
	}
	m1 := writeReleaseFixture(t, filepath.Join(dir, "m1.json"), "[]\n", 0o600)
	m2 := writeReleaseFixture(t, filepath.Join(dir, "m2.json"), "[]\n", 0o600)
	if run := resolverRun(t, hermeticReleaseEnv(t, "MEL_RELEASE_SQUADS_MEMBERS="+m1+","+m2), "resolve", "MEL_RELEASE_SQUADS_MEMBERS"); run.exit != 0 || run.stdout != m1+","+m2+"\n" {
		t.Fatalf("an exact member list: exit %d stdout %q stderr %q", run.exit, run.stdout, run.stderr)
	}
	requireRefusals(t, "a member list item with a space",
		resolverRun(t, hermeticReleaseEnv(t, "MEL_RELEASE_SQUADS_MEMBERS="+m1+", "+m2), "resolve", "MEL_RELEASE_SQUADS_MEMBERS"),
		"release-input-whitespace:MEL_RELEASE_SQUADS_MEMBERS")
	// A retired variable set to whitespace is set.
	requireRefusals(t, "a retired input set to whitespace",
		resolverRun(t, hermeticReleaseEnv(t, "SANDSTORM_SRC= "), "check-retired", "SANDSTORM_SRC"),
		"release-input-retired:SANDSTORM_SRC")
}

// shellProviderFixture is an app candidate the shell provider can finalize
// and propose: a pinned Pearl tool and a pinned Squads SDK tree that log what
// runs them, and a fake node first on PATH that logs how it was run.
type shellProviderFixture struct {
	dir, provider              string
	tool, toolPin, toolLog     string
	modules, modulesPin        string
	nodeLog, confinement, help string
	env                        []string
}

func newShellProviderFixture(t *testing.T) *shellProviderFixture {
	t.Helper()
	root := releaseToolingRoot(t)
	f := &shellProviderFixture{dir: t.TempDir()}
	f.provider = filepath.Join(root, "sidecar", "melusina-store-sidecar", "scripts", "mel-release-provider.sh")
	f.confinement = filepath.Join(root, "sidecar", "melusina-store-sidecar", "scripts", "node-module-confinement.cjs")
	f.help = filepath.Join(root, "sidecar", "melusina-store-sidecar", "scripts", "mel-release-squads-register.mjs")
	f.toolLog = filepath.Join(f.dir, "pearl.log")
	f.nodeLog = filepath.Join(f.dir, "node.log")
	const app = "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510"
	appHash, releaseHash := strings.Repeat("a", 64), strings.Repeat("b", 64)

	state := filepath.Join(f.dir, "state")
	provider := filepath.Join(state, "apps", app, "provider")
	writeReleaseFixture(t, filepath.Join(provider, "material", "app.spk"), "not-a-real-spk", 0o600)
	writeReleaseFixture(t, filepath.Join(provider, "material", "metadata.json"), `{"appId":"`+app+`","version":"1.2.3"}`+"\n", 0o600)
	writeReleaseFixture(t, filepath.Join(provider, "ceremony-state.json"), `{"appHash":"`+appHash+`","releaseHash":"`+releaseHash+`"}`+"\n", 0o600)
	writeReleaseFixture(t, filepath.Join(provider, "release.json"), `{"appHash":"`+appHash+`","releaseHash":"`+releaseHash+`"}`+"\n", 0o600)

	f.tool = writeReleaseFixture(t, filepath.Join(f.dir, "tools", "melusina-pearl-tool"), `#!/bin/sh
printf '%s %s\n' "$0" "$1" >> '`+f.toolLog+`'
if [ "$1" = propose-release ]; then
  while [ $# -gt 0 ]; do
    if [ "$1" = --state-out ]; then out="$2"; fi
    shift
  done
  printf '%s\n' '{"releaseEntryPda":"FixturePda","licenseSquadsVault":"FixtureVault","authorSig":"sig","quorumPolicy":{"threshold":1,"memberCount":1,"multisigPda":"FixtureMultisig"},"transactionPda":"FixtureTx","proposalPda":"FixtureProposal","transactionIndex":7}' > "$out"
fi
`, 0o755)
	f.toolPin = releaseDigest(t, f.tool)
	f.modules = filepath.Join(f.dir, "sdk", "node_modules")
	writeReleaseFixture(t, filepath.Join(f.modules, "@solana", "web3.js", "package.json"), "{\"name\":\"@solana/web3.js\"}\n", 0o644)
	writeReleaseFixture(t, filepath.Join(f.modules, "@sqds", "multisig", "package.json"), "{\"name\":\"@sqds/multisig\"}\n", 0o644)
	f.modulesPin = releaseDigest(t, f.modules)

	bin := filepath.Join(f.dir, "bin")
	writeReleaseFixture(t, filepath.Join(bin, "node"), `#!/bin/bash
{
  printf 'argv:'; printf ' %s' "$@"; printf '\n'
  printf 'MEL_RELEASE_NODE_MODULES=%s\n' "${MEL_RELEASE_NODE_MODULES-<unset>}"
  printf 'MEL_RELEASE_NODE_MODULE_ROOTS=%s\n' "${MEL_RELEASE_NODE_MODULE_ROOTS-<unset>}"
  printf 'NODE_OPTIONS=%s\n' "${NODE_OPTIONS-<unset>}"
  printf 'NODE_PATH=%s\n' "${NODE_PATH-<unset>}"
} >> '`+f.nodeLog+`'
for arg in "$@"; do
  case "$arg" in
    next-index) echo 7; exit 0 ;;
    propose) echo '{"proposalCreateSignature":"proposal","vaultTransactionCreateSignature":"create"}'; exit 0 ;;
  esac
done
exit 64
`, 0o755)

	_, catalogEnv := releaseProviderCatalog(t, f.dir)
	f.env = hermeticReleaseEnv(t, append(catalogEnv,
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"MEL_RELEASE_STATE_DIR="+state,
		"MEL_APP_ID="+app, "MEL_NEW_APP_HASH="+appHash, "MEL_RELEASE_HASH="+releaseHash,
		"MEL_NEW_VERSION=1.2.3", "MEL_RELEASE_NONCE=00112233445566778899aabbccddeeff",
		"MEL_RELEASE_RPC_URL=https://rpc.example.invalid", "MEL_PROGRAM_ID=Fixture1Program111111111111111111111111111111",
		"MEL_RELEASE_LICENSE_MINT=Fixture1License11111111111111111111111111111",
		"MEL_RELEASE_MASTER_NFT_MINT=Fixture1Master111111111111111111111111111111",
		"MEL_RELEASE_SQUADS_THRESHOLD=1", "MEL_RELEASE_SQUADS_MEMBER_COUNT=1",
		"MEL_RELEASE_AUTHOR_KEYPAIR="+writeReleaseFixture(t, filepath.Join(f.dir, "author.json"), "[]\n", 0o600),
		"MEL_RELEASE_MEMBER_KEYPAIR_1="+writeReleaseFixture(t, filepath.Join(f.dir, "member.json"), "[]\n", 0o600),
		"MEL_FINAL_RELEASE_JSON_OUT="+filepath.Join(f.dir, "out", "final-release.json"),
		"MEL_RELEASE_JSON_OUT="+filepath.Join(f.dir, "out", "release.json"),
		"MEL_PROPOSE_RECEIPT_OUT="+filepath.Join(f.dir, "out", "propose-receipt.json"),
		// A caller's preload and module path; the provider must clear both.
		"NODE_OPTIONS=--require "+filepath.Join(f.dir, "caller-preload.js"),
		"NODE_PATH="+filepath.Join(f.dir, "caller-node-path"),
	)...)
	return f
}

func (f *shellProviderFixture) run(t *testing.T, op string, extra ...string) toolRun {
	t.Helper()
	os.Remove(f.toolLog)
	os.Remove(f.nodeLog)
	return runReleaseTool(t, append(append([]string{}, f.env...), extra...), f.dir, "", "bash", f.provider, op)
}

func (f *shellProviderFixture) pinned() []string {
	return []string{
		"MEL_RELEASE_PEARL_TOOL=" + f.tool, "MEL_RELEASE_PEARL_TOOL_SHA256=" + f.toolPin,
		"MEL_RELEASE_NODE_MODULES=" + f.modules, "MEL_RELEASE_NODE_MODULES_SHA256=" + f.modulesPin,
	}
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func requireNothingRan(t *testing.T, subject string, f *shellProviderFixture, markers ...string) {
	t.Helper()
	if log := readLog(t, f.toolLog) + readLog(t, f.nodeLog); log != "" {
		t.Fatalf("%s: something ran before the refusal:\n%s", subject, log)
	}
	for _, marker := range markers {
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%s: %s was written: an unpinned file ran", subject, marker)
		}
	}
}

// The reviewer's reproduction, and the pins of the shell provider's two
// operations that run the Pearl tool.
func TestShellProviderRunsOnlyThePinnedPearlTool(t *testing.T) {
	f := newShellProviderFixture(t)

	// Positive control: pinned, the tool runs, once per step, by its path.
	if run := f.run(t, "finalize-release", f.pinned()...); run.exit != 0 {
		t.Fatalf("finalize-release with a pinned tool: exit %d\nstdout: %s\nstderr: %s", run.exit, run.stdout, run.stderr)
	}
	if got, want := readLog(t, f.toolLog), f.tool+" finalize-release\n"+f.tool+" verify-release\n"; got != want {
		t.Fatalf("finalize-release ran %q; want %q", got, want)
	}

	// A file whose name is the pinned path plus a space, which the provider
	// would run if the check trimmed what the use does not.
	unpinnedMarker := filepath.Join(f.dir, "UNPINNED-EXECUTED")
	writeReleaseFixture(t, f.tool+" ", "#!/bin/sh\n: > '"+unpinnedMarker+"'\n", 0o755)
	for _, c := range []struct {
		subject string
		env     []string
		want    string
	}{
		{"the pinned path plus a space", []string{"MEL_RELEASE_PEARL_TOOL=" + f.tool + " ", "MEL_RELEASE_PEARL_TOOL_SHA256=" + f.toolPin}, "release-input-whitespace:MEL_RELEASE_PEARL_TOOL"},
		{"an unpinned tool", []string{"MEL_RELEASE_PEARL_TOOL=" + f.tool, "MEL_RELEASE_PEARL_TOOL_SHA256="}, "release-input-sha256-missing:MEL_RELEASE_PEARL_TOOL"},
		{"another tool's pin", []string{"MEL_RELEASE_PEARL_TOOL=" + f.tool, "MEL_RELEASE_PEARL_TOOL_SHA256=" + strings.Repeat("0", 64)}, "release-input-sha256-mismatch:MEL_RELEASE_PEARL_TOOL"},
	} {
		for _, op := range []string{"finalize-release", "propose-register"} {
			run := f.run(t, op, append(f.pinned(), c.env...)...)
			if _, err := os.Stat(unpinnedMarker); err == nil {
				t.Fatalf("%s with %s ran the unpinned file %q", op, c.subject, f.tool+" ")
			}
			requireRefusals(t, op+" with "+c.subject, run, c.want)
			requireNothingRan(t, op+" with "+c.subject, f, unpinnedMarker)
		}
	}
}

// propose-register resolves the Squads SDK tree before anything runs, hands
// the helper the resolved tree, and runs the helper confined to it.
func TestShellProviderRunsTheSquadsHelperConfinedToThePinnedSDK(t *testing.T) {
	f := newShellProviderFixture(t)

	// Positive control.
	if run := f.run(t, "propose-register", f.pinned()...); run.exit != 0 {
		t.Fatalf("propose-register with pinned inputs: exit %d\nstdout: %s\nstderr: %s", run.exit, run.stdout, run.stderr)
	}
	if got, want := readLog(t, f.toolLog), f.tool+" propose-release\n"; got != want {
		t.Fatalf("propose-register ran the Pearl tool as %q; want %q", got, want)
	}
	roots, err := json.Marshal([]string{f.modules})
	if err != nil {
		t.Fatal(err)
	}
	invocation := func(op string) string {
		return "argv: --require " + f.confinement + " " + f.help + " " + op + "\n" +
			"MEL_RELEASE_NODE_MODULES=" + f.modules + "\n" +
			"MEL_RELEASE_NODE_MODULE_ROOTS=" + string(roots) + "\n" +
			"NODE_OPTIONS=<unset>\nNODE_PATH=<unset>\n"
	}
	state := filepath.Join(f.dir, "state", "apps", "uw0ukgm06584v9ggjqqqt4dqwy6r2kergqajgg6q1rt398dh2510", "provider", "ceremony-state.json")
	if got, want := readLog(t, f.nodeLog), invocation("next-index")+strings.Replace(invocation("propose"), " propose\n", " propose "+state+"\n", 1); got != want {
		t.Fatalf("the helper ran as\n%s\nwant\n%s", got, want)
	}
	for _, out := range []string{"release.json", "propose-receipt.json"} {
		if _, err := os.Stat(filepath.Join(f.dir, "out", out)); err != nil {
			t.Fatalf("propose-register wrote no %s: %v", out, err)
		}
	}

	other := filepath.Join(f.dir, "other-sdk", "node_modules")
	writeReleaseFixture(t, filepath.Join(other, "@solana", "web3.js", "package.json"), "{\"name\":\"@solana/web3.js\",\"patched\":true}\n", 0o644)
	writeReleaseFixture(t, filepath.Join(other, "@sqds", "multisig", "package.json"), "{\"name\":\"@sqds/multisig\"}\n", 0o644)
	spaced := f.modules + " "
	writeReleaseFixture(t, filepath.Join(spaced, "@solana", "web3.js", "package.json"), "{\"name\":\"@solana/web3.js\",\"patched\":true}\n", 0o644)
	writeReleaseFixture(t, filepath.Join(spaced, "@sqds", "multisig", "package.json"), "{\"name\":\"@sqds/multisig\"}\n", 0o644)
	for _, c := range []struct {
		subject string
		env     []string
		want    string
	}{
		{"another SDK tree under the pin", []string{"MEL_RELEASE_NODE_MODULES=" + other}, "release-input-sha256-mismatch:MEL_RELEASE_NODE_MODULES"},
		{"the pinned tree plus a space", []string{"MEL_RELEASE_NODE_MODULES=" + spaced}, "release-input-whitespace:MEL_RELEASE_NODE_MODULES"},
		{"an unpinned tree", []string{"MEL_RELEASE_NODE_MODULES_SHA256="}, "release-input-sha256-missing:MEL_RELEASE_NODE_MODULES"},
		{"no tree", []string{"MEL_RELEASE_NODE_MODULES="}, "release-input-missing:MEL_RELEASE_NODE_MODULES"},
	} {
		requireRefusals(t, "propose-register with "+c.subject, f.run(t, "propose-register", append(f.pinned(), c.env...)...), c.want)
		requireNothingRan(t, "propose-register with "+c.subject, f)
	}
}

// executorFixture is the executor's shape: a main script that loads a guard
// beside it and an SDK from node_modules beside it, and that adds the
// canonical executor's own fallback (deployer b2382396,
// scripts/squads-vault-exec.js, MODULE_SEARCH_DIRS) of a sibling tree when a
// module does not resolve. Around it, one planted module per way Node looks
// outside the pinned tree.
const executorFixture = `
const path = require("path");
const fs = require("fs");
const Module = require("module");
const MODULE_SEARCH_DIRS = [
  path.join(__dirname, "../../license104/node_modules"),
].filter((p) => fs.existsSync(p));
const originalResolve = Module._resolveFilename;
Module._resolveFilename = function (request, parent, isMain, options) {
  try {
    return originalResolve(request, parent, isMain, options);
  } catch (e) {
    for (const dir of MODULE_SEARCH_DIRS) {
      try {
        return originalResolve(request, { ...parent, paths: [dir] }, isMain, options);
      } catch (_) { /* try next */ }
    }
    throw e;
  }
};
const results = {};
for (const request of process.argv.slice(2)) {
  try {
    const loaded = require(request);
    results[request] = (loaded && loaded.origin) || "builtin";
  } catch (error) {
    results[request] = String(error.code) + ": " + String(error.message).split("\n")[0];
  }
}
console.log(JSON.stringify(results));
`

func TestNodeModuleConfinementAdmitsOnlyThePinnedInputs(t *testing.T) {
	root := releaseToolingRoot(t)
	confinement := filepath.Join(root, "sidecar", "melusina-store-sidecar", "scripts", "node-module-confinement.cjs")
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is required by both release providers: %v", err)
	}
	w := t.TempDir()
	module := func(dir, name, origin string) {
		writeReleaseFixture(t, filepath.Join(dir, name, "index.js"), "module.exports = { origin: "+strconvQuote(origin)+" };\n", 0o644)
	}
	scripts := filepath.Join(w, "deployer", "scripts")
	executor := writeReleaseFixture(t, filepath.Join(scripts, "squads-vault-exec.js"), executorFixture, 0o644)
	writeReleaseFixture(t, filepath.Join(scripts, "lib", "reduced-mode-guard.cjs"), "module.exports = { origin: \"guard\" };\n", 0o644)
	tree := filepath.Join(scripts, "node_modules")
	writeReleaseFixture(t, filepath.Join(tree, "sdk", "index.js"), "module.exports = { origin: require(\"sdk-dep\").origin === \"sdk-dep\" ? \"sdk\" : \"sdk-without-dep\" };\n", 0o644)
	module(tree, "sdk-dep", "sdk-dep")
	module(filepath.Join(w, "node_modules"), "ancestor-mod", "ancestor")
	module(filepath.Join(w, "node-path"), "node-path-mod", "node-path")
	module(filepath.Join(w, "home", ".node_modules"), "home-mod", "home")
	module(filepath.Join(w, "license104", "node_modules"), "fallback-mod", "fallback")
	module(filepath.Join(w, "outside"), "link-mod", "link")
	if err := os.Symlink(filepath.Join(w, "outside", "link-mod"), filepath.Join(tree, "link-mod")); err != nil {
		t.Fatal(err)
	}
	requests := []string{"./lib/reduced-mode-guard.cjs", "sdk", "crypto", "ancestor-mod", "node-path-mod", "home-mod", "fallback-mod", "link-mod"}
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(w, "home"), "NODE_PATH=" + filepath.Join(w, "node-path"), "LANG=C.UTF-8"}
	results := func(run toolRun) map[string]string {
		t.Helper()
		var out map[string]string
		if run.exit != 0 || json.Unmarshal([]byte(run.stdout), &out) != nil {
			t.Fatalf("executor fixture: exit %d\nstdout: %s\nstderr: %s", run.exit, run.stdout, run.stderr)
		}
		return out
	}

	// Control: unconfined, every planted module loads. Each is a live way out.
	open := results(runReleaseTool(t, env, w, "", node, append([]string{executor}, requests...)...))
	for request, origin := range map[string]string{
		"./lib/reduced-mode-guard.cjs": "guard", "sdk": "sdk", "crypto": "builtin",
		"ancestor-mod": "ancestor", "node-path-mod": "node-path", "home-mod": "home", "fallback-mod": "fallback", "link-mod": "link",
	} {
		if open[request] != origin {
			t.Fatalf("control: unconfined %s gave %q, want %q (the plant is not live)", request, open[request], origin)
		}
	}

	// The roots are the executor's pinned companions, as the resolver names them.
	rootsRun := resolverRun(t, hermeticReleaseEnv(t), "node-roots", "MEL_RELEASE_SQUADS_EXECUTOR", executor)
	var roots []string
	if rootsRun.exit != 0 || json.Unmarshal([]byte(rootsRun.stdout), &roots) != nil {
		t.Fatalf("node-roots: exit %d stdout %q stderr %q", rootsRun.exit, rootsRun.stdout, rootsRun.stderr)
	}
	if want := []string{filepath.Join(scripts, "lib", "reduced-mode-guard.cjs"), tree}; strings.Join(roots, "\n") != strings.Join(want, "\n") {
		t.Fatalf("node-roots for the executor gave %q, want its pinned companions %q", roots, want)
	}
	if run := resolverRun(t, hermeticReleaseEnv(t), "node-roots", "MEL_RELEASE_NODE_MODULES", tree); run.exit != 0 || strings.TrimSpace(run.stdout) != `["`+tree+`"]` {
		t.Fatalf("node-roots for an SDK tree: exit %d stdout %q stderr %q", run.exit, run.stdout, run.stderr)
	}
	requireRefusals(t, "node-roots for an input Node does not load",
		resolverRun(t, hermeticReleaseEnv(t), "node-roots", "MEL_RELEASE_PEARL_TOOL", executor),
		"release-input-undeclared:MEL_RELEASE_PEARL_TOOL")

	confined := results(runReleaseTool(t, append(env, "MEL_RELEASE_NODE_MODULE_ROOTS="+strings.TrimSpace(rootsRun.stdout)), w, "", node,
		append([]string{"--require", confinement, executor}, requests...)...))
	for request, origin := range map[string]string{"./lib/reduced-mode-guard.cjs": "guard", "sdk": "sdk", "crypto": "builtin"} {
		if confined[request] != origin {
			t.Fatalf("confined %s gave %q, want %q: a pinned input must still load", request, confined[request], origin)
		}
	}
	for _, request := range []string{"ancestor-mod", "node-path-mod", "home-mod", "link-mod"} {
		if !strings.HasPrefix(confined[request], "MODULE_NOT_FOUND: node-module-confinement: "+request+" resolves to ") {
			t.Fatalf("confined %s gave %q; a module outside the pinned inputs must be refused as not found", request, confined[request])
		}
	}
	// The executor's own fallback retries through the confinement, which
	// refuses the sibling tree; the executor then rethrows Node's first error.
	if !strings.HasPrefix(confined["fallback-mod"], "MODULE_NOT_FOUND: ") {
		t.Fatalf("confined fallback-mod gave %q; the executor's sibling-tree fallback must not load it", confined["fallback-mod"])
	}

	// The confinement refuses to start without its roots.
	for _, value := range []string{"", "not-json", "[]", `["relative/path"]`} {
		run := runReleaseTool(t, append(env, "MEL_RELEASE_NODE_MODULE_ROOTS="+value), w, "", node, "--require", confinement, executor, "sdk")
		if run.exit == 0 || !strings.Contains(run.stderr, "node-module-confinement: MEL_RELEASE_NODE_MODULE_ROOTS must be") {
			t.Fatalf("roots %q: exit %d stdout %q stderr %q; want a refusal to start", value, run.exit, run.stdout, run.stderr)
		}
	}
}

func strconvQuote(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
