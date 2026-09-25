package main

// The release tooling reads nothing outside this repository by default. The
// scan in release_tooling_inputs_test.go finds the named places the tooling
// used to read (a home directory, a Desktop checkout, a sibling repository by
// name). This scan finds the other way out: a path climbed above the
// repository from its own location -- `dirname "$ROOT"`, "$ROOT/..", a ".."
// held in a variable and joined on later, `cd ..`, Path(__file__).parents[2],
// ROOT.parent, path.join(__dirname, "..") -- whatever the directory it
// reaches is called.
//
// It denies by default. It evaluates the root derivations the tooling uses
// ("$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)", "$ROOT/sub",
// Path(__file__).resolve().parent.parent, ROOT / "fleet" / "x") to a
// repository-relative location, admits a climb that provably stays inside the
// repository, and reports every other climb applied to a path derived from
// the repository's location or the working directory. A reported line either
// goes, or is named in parentTraversalExceptions with the reason it reads
// nothing outside the repository.
//
// It is a guard against a restored or new sibling read, not a proof against a
// deliberately disguised one (a ".." assembled from characters is not
// recognised); the entry-point tests and review cover what a text scan cannot.

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// parentAnchorSourceRe names the expressions that denote this repository's own
// location: the running script, the caller's working directory, the Makefile.
var parentAnchorSourceRe = regexp.MustCompile(`BASH_SOURCE|\$0\b|\$\{0\}|__file__|__dirname|__filename|import\.meta|CURDIR|MAKEFILE_LIST|\$PWD\b|\$\{PWD\}|\$\(pwd\)|\bgetcwd\(|Path\.cwd\(|process\.cwd\(`)

// parentAssignmentRe matches NAME=..., NAME = ..., const NAME = ..., NAME := ...
var parentAssignmentRe = regexp.MustCompile(`^(\s*)(?:(?:readonly|local|export|declare|const|let|var)\s+(?:-[A-Za-z]+\s+)*)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]*)?[?+]?=([^=].*|)$`)

var (
	// A path that starts by climbing from the working directory.
	parentBareRe = regexp.MustCompile(`(?:^|[\s"'=(,:\[{])\.\./`)
	// A ".." path segment.
	parentSegmentRe = regexp.MustCompile(`(?:^|[/\s"'=(,:\[{])\.\.(?:[/\s"')\]},;:]|$)`)
	// The bare literal "..", a climb only where the line joins it into a path.
	parentLiteralRe      = regexp.MustCompile(`["']\.\.["']`)
	parentJoinRe         = regexp.MustCompile(`os\.path\.join\(|path\.join\(|path\.resolve\(|joinpath\(|/\s*["']\.\.["']|["']\.\.["']\s*/|\bcd\s`)
	parentShellDirnameRe = regexp.MustCompile(`\bdirname\s+("[^"]*"|\S+)`)
	parentCallDirnameRe  = regexp.MustCompile(`\bdirname\(([^)]*\)?)`)
	parentAttrRe         = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*|\))((?:\.parents?\b(?:\[\d+\])?)+)`)
	parentPardirRe       = regexp.MustCompile(`\bpardir\b`)
	// cd .. (or pushd ..) climbs the working directory.
	parentCdRe = regexp.MustCompile(`\b(?:cd|pushd)\s+\.\.(?:[/\s;&|)]|$)`)
	// A value that is itself a climb, to be joined onto a path later.
	parentClimbValueRe = regexp.MustCompile(`^["']?\.\.(?:/\.\.)*/?["']?$`)
	parentPyVarRootRe  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)((?:\.parent\b)+)$`)

	parentFileDirRe          = regexp.MustCompile(`\$\(dirname "(?:\$\{BASH_SOURCE\[0\]\}|\$BASH_SOURCE|\$0|\$\{0\})"\)`)
	parentVarUpsRe           = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?((?:/\.\.)+)`)
	parentVarDirnameRe       = regexp.MustCompile(`\$\(dirname "\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"\)`)
	parentPyFileRe           = regexp.MustCompile(`Path\(__file__\)\.resolve\(\)((?:\.parent\b)*)(?:\.parents\[(\d+)\])?`)
	parentPyVarRe            = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)((?:\.parent\b)+)`)
	parentUpRe               = regexp.MustCompile(`/\.\.`)
	parentShellCdRe          = regexp.MustCompile(`^"?\$\(cd "(\$\(dirname "(?:\$\{BASH_SOURCE\[0\]\}|\$BASH_SOURCE|\$0|\$\{0\})"\)|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)((?:/\.\.)*)"(?: >/dev/null)? && pwd(?: -P)?\)((?:/[A-Za-z0-9_.-]+)*)"?$`)
	parentShellFileDirOnlyRe = regexp.MustCompile(`^"?\$\(dirname "(?:\$\{BASH_SOURCE\[0\]\}|\$BASH_SOURCE|\$0|\$\{0\})"\)"?$`)
	parentShellJoinRe        = regexp.MustCompile(`^"?\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?((?:/[A-Za-z0-9_.-]+)+)"?$`)
	parentPyRootRe           = regexp.MustCompile(`^Path\(__file__\)\.resolve\(\)((?:\.parent\b)*)(?:\.parents\[(\d+)\])?(?:\.with_name\("([A-Za-z0-9_.-]+)"\))?$`)
	parentPyJoinRe           = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)((?:\s*/\s*"[A-Za-z0-9_.-]+")+)$`)
	parentPySegmentRe        = regexp.MustCompile(`"([A-Za-z0-9_.-]+)"`)
)

// parentScan follows one file: which variables hold a path derived from this
// repository's location, and, where the derivation is one it can evaluate,
// which repository-relative path each holds (nil: not evaluated).
type parentScan struct {
	dir       []string
	anchors   map[string]bool
	location  map[string][]string
	climbers  map[string]bool // variables whose value is itself a climb ("..")
	synthetic int
	patterns  map[string]*regexp.Regexp
}

// referencesVar: $NAME, ${NAME}, $(NAME) or the bare word NAME.
func (s *parentScan) referencesVar(line, name string) bool {
	re, ok := s.patterns[name]
	if !ok {
		quoted := regexp.QuoteMeta(name)
		re = regexp.MustCompile(`\$\{?` + quoted + `\b|\$\(` + quoted + `\)|(?:^|[^\w$.])` + quoted + `\b`)
		s.patterns[name] = re
	}
	return re.MatchString(line)
}

func (s *parentScan) referencesAnchor(text string) bool {
	if parentAnchorSourceRe.MatchString(text) {
		return true
	}
	for name := range s.anchors {
		if s.referencesVar(text, name) {
			return true
		}
	}
	return false
}

// parentClimb is BASE climbed UPS directories, if that stays in the repository.
func parentClimb(base []string, ups int) ([]string, bool) {
	if base == nil || ups > len(base) {
		return nil, false
	}
	return append([]string{}, base[:len(base)-ups]...), true
}

func parentAppend(base []string, segments []string) ([]string, bool) {
	out := append([]string{}, base...)
	for _, segment := range segments {
		switch segment {
		case "", ".":
		case "..":
			return nil, false
		default:
			out = append(out, segment)
		}
	}
	return out, true
}

func parentPyUps(parents string, index string) int {
	ups := strings.Count(parents, ".parent")
	if index != "" {
		n, _ := strconv.Atoi(index)
		ups += n + 1
	}
	return ups
}

func (s *parentScan) known(name string) []string {
	return s.location[name]
}

// evaluate returns the repository-relative location of a whole right-hand
// side the scan recognises.
func (s *parentScan) evaluate(rhs string) ([]string, bool) {
	rhs = strings.TrimSpace(rhs)
	if m := parentShellCdRe.FindStringSubmatch(rhs); m != nil {
		base := s.dir
		if !strings.HasPrefix(m[1], "$(dirname") {
			base = s.known(strings.Trim(m[1], "${}"))
		}
		loc, ok := parentClimb(base, len(parentUpRe.FindAllString(m[2], -1)))
		if !ok {
			return nil, false
		}
		return parentAppend(loc, strings.Split(m[3], "/"))
	}
	if parentShellFileDirOnlyRe.MatchString(rhs) {
		return append([]string{}, s.dir...), true
	}
	if m := parentShellJoinRe.FindStringSubmatch(rhs); m != nil {
		if base := s.known(m[1]); base != nil {
			return parentAppend(base, strings.Split(m[2], "/"))
		}
		return nil, false
	}
	if m := parentPyRootRe.FindStringSubmatch(rhs); m != nil {
		ups := parentPyUps(m[1], m[2])
		if ups == 0 {
			// The file itself; with_name names a file beside it.
			if m[3] == "" {
				return parentAppend(s.dir, []string{"__file__"})
			}
			return parentAppend(s.dir, []string{m[3]})
		}
		loc, ok := parentClimb(s.dir, ups-1)
		if !ok || m[3] != "" {
			return nil, false
		}
		return loc, true
	}
	if m := parentPyVarRootRe.FindStringSubmatch(rhs); m != nil {
		return parentClimb(s.known(m[1]), strings.Count(m[2], ".parent"))
	}
	if m := parentPyJoinRe.FindStringSubmatch(rhs); m != nil {
		if base := s.known(m[1]); base != nil {
			var segments []string
			for _, segment := range parentPySegmentRe.FindAllStringSubmatch(m[2], -1) {
				segments = append(segments, segment[1])
			}
			return parentAppend(base, segments)
		}
	}
	return nil, false
}

// placed stands for a climb the scan evaluated to LOC inside the
// repository: a synthetic anchor variable holding LOC, so a climb applied to
// it in turn is evaluated from there.
func (s *parentScan) placed(loc []string, shell bool) string {
	s.synthetic++
	name := "PLACED" + strconv.Itoa(s.synthetic)
	s.anchors[name] = true
	s.location[name] = loc
	if shell {
		return "$" + name
	}
	return name
}

// masked replaces, innermost first, each climb the scan can place inside the
// repository, so what remains is a climb it cannot.
func (s *parentScan) masked(line string) string {
	for {
		before := line
		line = parentFileDirRe.ReplaceAllStringFunc(line, func(string) string { return s.placed(s.dir, true) })
		line = parentVarUpsRe.ReplaceAllStringFunc(line, func(match string) string {
			m := parentVarUpsRe.FindStringSubmatch(match)
			if loc, ok := parentClimb(s.known(m[1]), len(parentUpRe.FindAllString(m[2], -1))); ok {
				return s.placed(loc, true)
			}
			return match
		})
		line = parentVarDirnameRe.ReplaceAllStringFunc(line, func(match string) string {
			m := parentVarDirnameRe.FindStringSubmatch(match)
			if loc, ok := parentClimb(s.known(m[1]), 1); ok {
				return s.placed(loc, true)
			}
			return match
		})
		line = parentPyFileRe.ReplaceAllStringFunc(line, func(match string) string {
			m := parentPyFileRe.FindStringSubmatch(match)
			ups := parentPyUps(m[1], m[2])
			if ups == 0 {
				return s.placed(append(append([]string{}, s.dir...), "__file__"), false)
			}
			if loc, ok := parentClimb(s.dir, ups-1); ok {
				return s.placed(loc, false)
			}
			return match
		})
		line = parentPyVarRe.ReplaceAllStringFunc(line, func(match string) string {
			m := parentPyVarRe.FindStringSubmatch(match)
			if loc, ok := parentClimb(s.known(m[1]), strings.Count(m[2], ".parent")); ok {
				return s.placed(loc, false)
			}
			return match
		})
		if line == before {
			return line
		}
	}
}

// climbs reports a climb the scan could not place inside the repository.
func (s *parentScan) climbs(line string) string {
	if parentBareRe.MatchString(line) || parentCdRe.MatchString(line) {
		return "a path climbing from the working directory"
	}
	for name := range s.climbers {
		if s.referencesVar(line, name) && s.referencesAnchor(line) {
			return "a climb held in " + name + " joined onto a path derived from the repository"
		}
	}
	literals := line
	if !parentJoinRe.MatchString(line) {
		literals = parentLiteralRe.ReplaceAllString(line, `"PARENT-LITERAL"`)
	}
	if parentSegmentRe.MatchString(literals) && s.referencesAnchor(line) {
		return "a .. segment on a path derived from the repository"
	}
	for _, m := range parentShellDirnameRe.FindAllStringSubmatch(line, -1) {
		if s.referencesAnchor(m[1]) {
			return "dirname of a path derived from the repository"
		}
	}
	for _, m := range parentCallDirnameRe.FindAllStringSubmatch(line, -1) {
		if s.referencesAnchor(m[1]) {
			return "dirname of a path derived from the repository"
		}
	}
	for _, m := range parentAttrRe.FindAllStringSubmatch(line, -1) {
		if (m[1] == ")" && strings.Contains(line, "__file__")) || s.anchors[m[1]] || parentAnchorSourceRe.MatchString(m[1]) {
			return ".parent of a path derived from the repository"
		}
	}
	if parentPardirRe.MatchString(line) && s.referencesAnchor(line) {
		return "os.pardir on a path derived from the repository"
	}
	return ""
}

// parentHit is one line naming a directory above this repository.
type parentHit struct {
	file string // repository-relative, slash-separated
	line int
	text string // the line, trimmed
	why  string
}

func (h parentHit) String() string {
	return "parent-traversal in " + h.file + ":" + strconv.Itoa(h.line) + ": " + h.text + " (" + h.why + ")"
}

// parentTraversalIn scans the text of the file at repository-relative REL:
// each line that names a directory above a path derived from this
// repository's own location, or above the working directory, unless the scan
// evaluates it to a place inside the repository. What it cannot evaluate it
// reports: the scan denies by default rather than listing the bad forms.
func parentTraversalIn(rel string, raw []byte) []parentHit {
	s := &parentScan{dir: []string{}, anchors: map[string]bool{}, location: map[string][]string{},
		climbers: map[string]bool{}, patterns: map[string]*regexp.Regexp{}}
	if dir := path.Dir(rel); dir != "." {
		s.dir = strings.Split(dir, "/")
	}
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	for _, line := range lines {
		if m := parentAssignmentRe.FindStringSubmatch(line); m != nil && parentClimbValueRe.MatchString(strings.TrimSpace(m[3])) {
			s.climbers[m[2]] = true
		}
	}
	// A top-level variable assigned from an anchor is an anchor, to a fixed
	// point. Function-local names are reused too freely to follow; a climb is
	// flagged where it is applied to an anchor.
	for changed := true; changed; {
		changed = false
		for _, line := range lines {
			m := parentAssignmentRe.FindStringSubmatch(line)
			if m == nil || m[1] != "" || s.anchors[m[2]] || !s.referencesAnchor(m[3]) {
				continue
			}
			s.anchors[m[2]] = true
			changed = true
		}
	}
	for _, line := range lines {
		m := parentAssignmentRe.FindStringSubmatch(line)
		if m == nil || m[1] != "" || !s.anchors[m[2]] {
			continue
		}
		loc, ok := s.evaluate(m[3])
		prior, seen := s.location[m[2]]
		switch {
		case !ok, seen && (prior == nil || strings.Join(prior, "/") != strings.Join(loc, "/")):
			s.location[m[2]] = nil
		default:
			s.location[m[2]] = loc
		}
	}
	var hits []parentHit
	for number, line := range lines {
		if why := s.climbs(s.masked(line)); why != "" {
			hits = append(hits, parentHit{file: rel, line: number + 1, text: strings.TrimSpace(line), why: why})
		}
	}
	return hits
}

// parentTraversalExceptions names each line the scan cannot place inside the
// repository that reads nothing outside it, keyed "file: line" with the line
// trimmed, and says why. A new climb fails the scan until it is removed or
// named here; an entry no line matches any longer fails too.
var parentTraversalExceptions = map[string]string{
	`scripts/build-store-release.sh: WORK_BASE="${MELUSINA_STORE_BUILD_ROOT:-$(dirname "$ROOT")}"`: "" +
		"scratch placement, not a read: the two detached worktrees of this repository's own HEAD are " +
		"created under a fresh mktemp directory beside the checkout unless MELUSINA_STORE_BUILD_ROOT names another",
	`scripts/build-store-generation-release.sh: WORK_BASE="${MELUSINA_STORE_GENERATION_BUILD_ROOT:-$(dirname "$ROOT")}"`: "" +
		"scratch placement, not a read: the two detached worktrees of this repository's own HEAD are " +
		"created under a fresh mktemp directory beside the checkout unless MELUSINA_STORE_GENERATION_BUILD_ROOT names another",
	`scripts/test-build-store-bootstrap-component.sh: header.linkname = "../../outside"`: "" +
		"a hostile tar member: the test proves the bootstrap component refuses a link leaving it",
	`scripts/test-mel-release-provider-cli-contract.py: "namedcoin": {"appId": app_id, "source_path": "../namedcoin"},`: "" +
		"a hostile catalog source_path: the test proves the provider refuses it as unsafe",
	`scripts/test-mel-release-provider-cli-contract.py: "screenshots": [{"url": "../outside.png"}],`: "" +
		"a hostile screenshot path: the test proves the candidate catalog refuses it as unsafe",
	`scripts/test-mel-release-provider-cli-contract.py: "metadata_path": "../metadata.json",`: "" +
		"a hostile metadata_path: the test proves the provider refuses it as unsafe",
}

func TestReleaseToolingClimbsNoDirectoryAboveTheRepository(t *testing.T) {
	root := releaseToolingRoot(t)

	// Known-positive control: each way out is reported, where the scan meets
	// it, in a file placed where the tooling lives.
	plants := []struct {
		rel     string
		content string
		want    []int // the lines reported, exactly
	}{
		{"scripts/plant.sh", `SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
for candidate in "$(dirname "$ROOT")"/*/spkmodule/bin/release-json-stub; do :; done
SIBLING="$ROOT/../sandstorm"
UP=..
STUB="$ROOT/$UP/spkmodule/bin/release-json-stub"
cd "$SCRIPT_DIR/../.." && ls
cd ..
PARENT="$(dirname "$(dirname "$SCRIPT_DIR")")"
INSIDE_ROOT="$(dirname "$SCRIPT_DIR")"
INSIDE_TOOL="$(cd "$SCRIPT_DIR/.." && pwd -P)/scripts/release-inputs.py"
`, []int{3, 4, 6, 7, 8, 9}},
		{"scripts/plant.py", `ROOT = Path(__file__).resolve().parent.parent
SIBLING = ROOT.parent / "Melusina"
DEPLOYER = Path(__file__).resolve().parents[2] / "deployer"
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UP = ".."
X = ROOT / UP / "x"
Y = Path(__file__).resolve().parent.parent.parent / "x"
INSIDE = Path(__file__).resolve().parents[1] / "fleet"
CATALOG = ROOT / "fleet" / "bazaar-catalog.yaml"
FLEET = CATALOG.parent
if ".." in Path(value).parts: raise SystemExit("refused")
`, []int{2, 3, 4, 6, 7}},
		{"scripts/plant.cjs", `const sdk = path.join(__dirname, "..", "..", "melusina-sdk");
const guard = path.join(__dirname, "lib", "guard.cjs");
`, []int{1}},
		{"sidecar/melusina-store-sidecar/scripts/plant.sh", `SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STORE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd -P)"
OUTSIDE="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
`, []int{3}},
	}
	for _, plant := range plants {
		var got []int
		for _, hit := range parentTraversalIn(plant.rel, []byte(plant.content)) {
			got = append(got, hit.line)
		}
		if fmt.Sprint(got) != fmt.Sprint(plant.want) {
			t.Fatalf("plant control %s: reported lines %v, want exactly %v\n%s", plant.rel, got, plant.want, plant.content)
		}
	}

	var hits []string
	matched := map[string]bool{}
	for _, file := range releaseToolingFiles(t) {
		info, err := os.Lstat(file)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue // the other scan requires every link to stay inside the repository
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.IndexByte(raw, 0) >= 0 {
			continue
		}
		rel, err := filepath.Rel(root, file)
		if err != nil {
			t.Fatal(err)
		}
		for _, hit := range parentTraversalIn(filepath.ToSlash(rel), raw) {
			key := hit.file + ": " + hit.text
			if _, excepted := parentTraversalExceptions[key]; excepted {
				matched[key] = true
				continue
			}
			hits = append(hits, hit.String())
		}
	}
	if len(hits) != 0 {
		t.Fatalf("release tooling climbs above the repository (remove the climb, or name it in parentTraversalExceptions with why it reads nothing outside):\n%s", strings.Join(hits, "\n"))
	}
	var stale []string
	for key := range parentTraversalExceptions {
		if !matched[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	if len(stale) != 0 {
		t.Fatalf("parentTraversalExceptions names lines the tooling no longer has:\n%s", strings.Join(stale, "\n"))
	}
}
