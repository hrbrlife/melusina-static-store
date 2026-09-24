package main

// vendor/ carries four modules of the Melusina monorepo. Every release build
// compiles them with -mod=vendor, so what the Store runs is these files, not
// any Melusina checkout. These tests bind each vendored file to the blob the
// named Melusina commit holds at the same path, through the commit's own
// trees, without a Melusina clone. A hand edit to a vendored file, a file go
// mod vendor never writes, a missing file, or a replace path the provenance
// does not name each fails by name.

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	melusinaVendorProvenancePath = "testdata/melusina-vendor/vendor.provenance.json"
	melusinaVendorGitObjectsDir  = "testdata/melusina-vendor/git-objects"
	melusinaVendorRoot           = "vendor"
	melusinaMonorepoReplacePath  = "../../../Melusina/"
	melusinaVendorSchema         = "melusina.store.vendor-provenance.v1"
	melusinaVendorRepository     = "https://github.com/hrbrlife/Melusina"
)

type melusinaVendorFile struct {
	Path string `json:"path"`
	Blob string `json:"blob"`
}

type melusinaVendorModule struct {
	Module     string               `json:"module"`
	Replace    string               `json:"replace"`
	SourcePath string               `json:"sourcePath"`
	Tree       string               `json:"tree"`
	Files      []melusinaVendorFile `json:"files"`
}

type melusinaVendorProvenance struct {
	Schema           string                 `json:"schema"`
	SourceRepository string                 `json:"sourceRepository"`
	SourceCommit     string                 `json:"sourceCommit"`
	Modules          []melusinaVendorModule `json:"modules"`
}

func loadMelusinaVendorProvenance(t *testing.T) melusinaVendorProvenance {
	t.Helper()
	raw, err := os.ReadFile(melusinaVendorProvenancePath)
	if err != nil {
		t.Fatalf("melusina-vendor-provenance-missing: %v", err)
	}
	var provenance melusinaVendorProvenance
	if err := json.Unmarshal(raw, &provenance); err != nil {
		t.Fatalf("melusina-vendor-provenance-wrong: decode %s: %v", melusinaVendorProvenancePath, err)
	}
	if provenance.Schema != melusinaVendorSchema || provenance.SourceRepository != melusinaVendorRepository {
		t.Fatalf("melusina-vendor-provenance-wrong: schema %q, repository %q", provenance.Schema, provenance.SourceRepository)
	}
	if !isLowerHex(provenance.SourceCommit, 40) {
		t.Fatalf("melusina-vendor-provenance-wrong: sourceCommit %q is not a full lowercase commit id", provenance.SourceCommit)
	}
	if len(provenance.Modules) == 0 {
		t.Fatalf("melusina-vendor-provenance-wrong: %s pins no module", melusinaVendorProvenancePath)
	}
	seen := map[string]bool{}
	for _, module := range provenance.Modules {
		name := path.Base(module.SourcePath)
		if module.Module == "" || seen[module.Module] {
			t.Fatalf("melusina-vendor-provenance-wrong: module %q is empty or repeated", module.Module)
		}
		seen[module.Module] = true
		if module.SourcePath != "shared/"+name || module.Replace != melusinaMonorepoReplacePath+module.SourcePath {
			t.Fatalf("melusina-vendor-provenance-wrong: %s: sourcePath %q and replace %q do not name one shared/ module", module.Module, module.SourcePath, module.Replace)
		}
		if !isLowerHex(module.Tree, 40) {
			t.Fatalf("melusina-vendor-provenance-wrong: %s: tree %q is not a full lowercase id", module.Module, module.Tree)
		}
		if len(module.Files) == 0 {
			t.Fatalf("melusina-vendor-provenance-wrong: %s records no vendored file", module.Module)
		}
		files := map[string]bool{}
		for _, file := range module.Files {
			if file.Path == "" || path.Clean(file.Path) != file.Path || path.IsAbs(file.Path) || file.Path == ".." || strings.HasPrefix(file.Path, "../") || files[file.Path] {
				t.Fatalf("melusina-vendor-provenance-wrong: %s: file path %q is not a clean, unique relative path", module.Module, file.Path)
			}
			files[file.Path] = true
			if !isLowerHex(file.Blob, 40) {
				t.Fatalf("melusina-vendor-provenance-wrong: %s/%s: blob %q is not a full lowercase id", module.Module, file.Path, file.Blob)
			}
		}
	}
	return provenance
}

// readMelusinaVendorGitObject reads git-objects/<id>.<kind> and requires that
// it hashes to id, so a file cannot stand in for another object.
func readMelusinaVendorGitObject(t *testing.T, used map[string]bool, kind, id, what string) []byte {
	t.Helper()
	name := id + "." + kind
	body, err := os.ReadFile(filepath.Join(melusinaVendorGitObjectsDir, name))
	if err != nil {
		t.Fatalf("melusina-vendor-git-object-missing: %s %s (%s); write it with git -C <Melusina clone> cat-file %s %s > %s/%s", kind, id, what, kind, id, melusinaVendorGitObjectsDir, name)
	}
	if got := gitObjectID(kind, body); got != id {
		t.Fatalf("melusina-vendor-git-object-altered: %s/%s hashes to %s", melusinaVendorGitObjectsDir, name, got)
	}
	used[name] = true
	return body
}

// melusinaTreeEntry returns the entry named name in tree id, reading the tree
// from git-objects/.
func melusinaTreeEntry(t *testing.T, used map[string]bool, treeID, treePath, name string) (gitTreeEntry, bool) {
	t.Helper()
	entries, err := parseGitTree(readMelusinaVendorGitObject(t, used, "tree", treeID, treePath))
	if err != nil {
		t.Fatalf("melusina-vendor-git-object-altered: tree %s (%s): %v", treeID, treePath, err)
	}
	for _, entry := range entries {
		if entry.Name == name {
			return entry, true
		}
	}
	return gitTreeEntry{}, false
}

// melusinaWalk follows components from treeID and returns the final entry.
// Every component but the last must be a directory.
func melusinaWalk(t *testing.T, used map[string]bool, commit, treeID, base string, components []string) (gitTreeEntry, bool) {
	t.Helper()
	at := base
	for index, component := range components {
		entry, ok := melusinaTreeEntry(t, used, treeID, commit+":"+at, component)
		if !ok {
			return gitTreeEntry{}, false
		}
		if at == "" {
			at = component
		} else {
			at += "/" + component
		}
		if index == len(components)-1 {
			return entry, true
		}
		if entry.Mode != "40000" {
			t.Fatalf("melusina-vendor-provenance-wrong: %s:%s is mode %s, not a directory", commit, at, entry.Mode)
		}
		treeID = entry.ID
	}
	return gitTreeEntry{}, false
}

// melusinaVendorNeverWritten names why go mod vendor never writes rel, or
// returns "" when it may. A file with one of these names under vendor/ was
// put there by hand (cmd/go/internal/modcmd/vendor.go: matchPotentialSourceFile
// drops _test.go, go.mod and go.sum; copyDir does not descend into testdata).
func melusinaVendorNeverWritten(rel string) string {
	base := path.Base(rel)
	switch {
	case strings.HasSuffix(base, "_test.go"):
		return "go mod vendor never writes _test.go files"
	case base == "go.mod" || base == "go.sum":
		return "go mod vendor never writes a dependency's go.mod or go.sum"
	}
	for _, component := range strings.Split(rel, "/") {
		if component == "testdata" {
			return "go mod vendor never writes testdata/"
		}
	}
	return ""
}

// TestVendoredMelusinaModulesAreTheNamedCommitsBlobs walks from the vendored
// Melusina commit object through its trees to every recorded file and
// requires the vendored file to be that blob. It then walks vendor/<module>/
// on disk so that no file is added or dropped around the records.
func TestVendoredMelusinaModulesAreTheNamedCommitsBlobs(t *testing.T) {
	provenance := loadMelusinaVendorProvenance(t)
	used := map[string]bool{}
	commit := readMelusinaVendorGitObject(t, used, "commit", provenance.SourceCommit, "sourceCommit")
	rootTree, err := gitCommitTree(commit)
	if err != nil {
		t.Fatalf("melusina-vendor-git-object-altered: commit %s: %v", provenance.SourceCommit, err)
	}
	checked := 0
	for _, module := range provenance.Modules {
		entry, ok := melusinaWalk(t, used, provenance.SourceCommit, rootTree, "", strings.Split(module.SourcePath, "/"))
		if !ok || entry.Mode != "40000" {
			t.Fatalf("melusina-vendor-provenance-wrong: commit %s has no directory %s", provenance.SourceCommit, module.SourcePath)
		}
		if entry.ID != module.Tree {
			t.Fatalf("melusina-vendor-provenance-wrong: commit %s holds tree %s at %s, provenance records %s", provenance.SourceCommit, entry.ID, module.SourcePath, module.Tree)
		}
		vendorDir := filepath.Join(melusinaVendorRoot, filepath.FromSlash(module.Module))
		recorded := map[string]bool{}
		for _, file := range module.Files {
			recorded[file.Path] = true
			vendored := melusinaVendorRoot + "/" + module.Module + "/" + file.Path
			source := provenance.SourceCommit + ":" + module.SourcePath + "/" + file.Path
			if why := melusinaVendorNeverWritten(file.Path); why != "" {
				t.Errorf("melusina-vendor-file-not-vendorable: %s is recorded, but %s", vendored, why)
				continue
			}
			blob, ok := melusinaWalk(t, used, provenance.SourceCommit, module.Tree, module.SourcePath, strings.Split(file.Path, "/"))
			if !ok {
				t.Errorf("melusina-vendor-provenance-wrong: %s is recorded, but %s does not exist", vendored, source)
				continue
			}
			if blob.Mode != "100644" && blob.Mode != "100755" {
				t.Errorf("melusina-vendor-provenance-wrong: %s is mode %s, not a regular file", source, blob.Mode)
				continue
			}
			if blob.ID != file.Blob {
				t.Errorf("melusina-vendor-provenance-wrong: %s is blob %s, provenance records %s for %s", source, blob.ID, file.Blob, vendored)
				continue
			}
			info, err := os.Lstat(filepath.FromSlash(vendored))
			if err != nil {
				t.Errorf("melusina-vendor-file-missing: %s is recorded as %s but is absent: %v", vendored, source, err)
				continue
			}
			if !info.Mode().IsRegular() {
				t.Errorf("melusina-vendor-file-not-vendorable: %s is %s, not a regular file", vendored, info.Mode().Type())
				continue
			}
			content, err := os.ReadFile(filepath.FromSlash(vendored))
			if err != nil {
				t.Errorf("melusina-vendor-file-missing: %s: %v", vendored, err)
				continue
			}
			if got := gitBlobSHA1(content); got != blob.ID {
				t.Errorf("melusina-vendor-blob-diverged: %s is blob %s; %s is blob %s", vendored, got, source, blob.ID)
				continue
			}
			checked++
		}
		found := 0
		err := filepath.WalkDir(vendorDir, func(name string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			found++
			rel, err := filepath.Rel(vendorDir, name)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			vendored := melusinaVendorRoot + "/" + module.Module + "/" + rel
			if why := melusinaVendorNeverWritten(rel); why != "" {
				t.Errorf("melusina-vendor-file-not-vendorable: %s: %s; it was put there by hand", vendored, why)
				return nil
			}
			if !recorded[rel] {
				t.Errorf("melusina-vendor-file-unrecorded: %s is not in %s; go mod vendor from %s did not write it", vendored, melusinaVendorProvenancePath, provenance.SourceCommit)
			}
			return nil
		})
		if err != nil {
			t.Errorf("melusina-vendor-file-missing: walk %s: %v", vendorDir, err)
		}
		if found == 0 {
			t.Errorf("melusina-vendor-file-missing: %s holds no file", vendorDir)
		}
	}
	if t.Failed() {
		return
	}
	total := 0
	for _, module := range provenance.Modules {
		total += len(module.Files)
	}
	if checked != total {
		t.Fatalf("melusina-vendor-file-missing: compared %d vendored files with their commit blobs, provenance records %d", checked, total)
	}
	// Every object in git-objects/ is on this walk. A leftover object from an
	// older commit would be unverified bytes that look like evidence.
	files, err := os.ReadDir(melusinaVendorGitObjectsDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !used[file.Name()] || !file.Type().IsRegular() {
			t.Fatalf("melusina-vendor-git-object-unused: %s/%s is not on the walk from %s to a vendored file", melusinaVendorGitObjectsDir, file.Name(), provenance.SourceCommit)
		}
	}
}

// goModReplaces returns go.mod's single-line replace directives, module to
// target. The Store's go.mod writes each replace on its own line.
func goModReplaces(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	replaces := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "replace (" || strings.HasPrefix(line, "replace (") {
			t.Fatalf("melusina-vendor-replace-diverged: go.mod uses a replace block; this test reads single-line replace directives only")
		}
		rest, ok := strings.CutPrefix(line, "replace ")
		if !ok {
			continue
		}
		from, to, ok := strings.Cut(rest, " => ")
		if !ok {
			t.Fatalf("melusina-vendor-replace-diverged: go.mod replace line %q has no =>", line)
		}
		replaces[strings.TrimSpace(from)] = strings.TrimSpace(to)
	}
	return replaces
}

// vendorModulesTxt returns, per module, the replacement vendor/modules.txt
// records and the packages it lists.
func vendorModulesTxt(t *testing.T) (map[string]string, map[string][]string) {
	t.Helper()
	file, err := os.Open(filepath.Join(melusinaVendorRoot, "modules.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	replaces := map[string]string{}
	packages := map[string][]string{}
	current := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "## "):
			continue
		case strings.HasPrefix(line, "# "):
			fields := strings.Fields(strings.TrimPrefix(line, "# "))
			current = fields[0]
			for i := range fields {
				if fields[i] == "=>" && i+1 < len(fields) {
					if previous, ok := replaces[current]; ok && previous != fields[i+1] {
						t.Fatalf("melusina-vendor-replace-diverged: vendor/modules.txt replaces %s with both %s and %s", current, previous, fields[i+1])
					}
					replaces[current] = fields[i+1]
				}
			}
		case line != "":
			packages[current] = append(packages[current], line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return replaces, packages
}

// melusinaVendorMetadata mirrors cmd/go/internal/modcmd/vendor.go
// metaPrefixes: go mod vendor also copies these files from a vendored
// package's parent directories within its module.
var melusinaVendorMetadata = []string{"AUTHORS", "CONTRIBUTORS", "COPYLEFT", "COPYING", "COPYRIGHT", "LEGAL", "LICENSE", "NOTICE", "PATENTS"}

// TestVendoredMelusinaModulesAreTheGoModReplacements binds the provenance to
// the build: go.mod and vendor/modules.txt must replace exactly the pinned
// modules with exactly the recorded paths, no other module may be replaced
// into the Melusina monorepo unpinned, and every recorded file must sit in a
// package modules.txt lists (or be one of the metadata files go mod vendor
// copies from a package's parents).
func TestVendoredMelusinaModulesAreTheGoModReplacements(t *testing.T) {
	provenance := loadMelusinaVendorProvenance(t)
	goMod := goModReplaces(t)
	modulesTxt, packages := vendorModulesTxt(t)
	pinned := map[string]bool{}
	for _, module := range provenance.Modules {
		pinned[module.Module] = true
		if got := goMod[module.Module]; got != module.Replace {
			t.Errorf("melusina-vendor-replace-diverged: go.mod replaces %s with %q; provenance records %q", module.Module, got, module.Replace)
		}
		if got := modulesTxt[module.Module]; got != module.Replace {
			t.Errorf("melusina-vendor-replace-diverged: vendor/modules.txt replaces %s with %q; provenance records %q", module.Module, got, module.Replace)
		}
		listed := map[string]bool{}
		for _, pkg := range packages[module.Module] {
			if pkg != module.Module && !strings.HasPrefix(pkg, module.Module+"/") {
				t.Errorf("melusina-vendor-replace-diverged: vendor/modules.txt lists package %s under module %s", pkg, module.Module)
				continue
			}
			dir := strings.TrimPrefix(strings.TrimPrefix(pkg, module.Module), "/")
			if dir == "" {
				dir = "."
			}
			listed[dir] = true
		}
		if len(listed) == 0 {
			t.Errorf("melusina-vendor-file-unrecorded: vendor/modules.txt lists no package of %s", module.Module)
		}
		hasGo := map[string]bool{}
		for _, file := range module.Files {
			dir := path.Dir(file.Path)
			if strings.HasSuffix(file.Path, ".go") {
				hasGo[dir] = true
			}
			if listed[dir] {
				continue
			}
			metadata := false
			for _, prefix := range melusinaVendorMetadata {
				if strings.HasPrefix(path.Base(file.Path), prefix) {
					metadata = true
				}
			}
			ancestor := false
			for pkgDir := range listed {
				if dir == "." || pkgDir == dir || strings.HasPrefix(pkgDir, dir+"/") {
					ancestor = true
				}
			}
			if !metadata || !ancestor {
				t.Errorf("melusina-vendor-file-unrecorded: %s/%s is outside every package vendor/modules.txt lists for %s", module.Module, file.Path, module.Module)
			}
		}
		dirs := make([]string, 0, len(listed))
		for dir := range listed {
			dirs = append(dirs, dir)
		}
		sort.Strings(dirs)
		for _, dir := range dirs {
			if !hasGo[dir] {
				t.Errorf("melusina-vendor-file-missing: vendor/modules.txt lists %s/%s, but no recorded .go file is in it", module.Module, dir)
			}
		}
	}
	for module, target := range goMod {
		if strings.HasPrefix(target, melusinaMonorepoReplacePath) && !pinned[module] {
			t.Errorf("melusina-vendor-module-unpinned: go.mod replaces %s with %s in the Melusina monorepo, and %s does not pin it", module, target, melusinaVendorProvenancePath)
		}
	}
	for module, target := range modulesTxt {
		if strings.HasPrefix(target, melusinaMonorepoReplacePath) && !pinned[module] {
			t.Errorf("melusina-vendor-module-unpinned: vendor/modules.txt replaces %s with %s in the Melusina monorepo, and %s does not pin it", module, target, melusinaVendorProvenancePath)
		}
	}
}
