package storerecovery

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const testStoreID = "recovery-test-store"

func testOperatorKey(t *testing.T, seed byte) (ed25519.PrivateKey, string) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	var public primitives.Pubkey
	copy(public[:], private.Public().(ed25519.PublicKey))
	return private, public.Base58()
}

func signerFor(private ed25519.PrivateKey) Signer {
	return func(message []byte) []byte { return ed25519.Sign(private, message) }
}

// stateRoots names the fixture roots below base, as a Store config would.
func stateRoots(base string) []Root {
	return []Root{
		{Name: "catalog-generations", Kind: RootDirectory, Path: filepath.Join(base, "var", "generations")},
		{Name: "private-stage", Kind: RootDirectory, Path: filepath.Join(base, "var", "private")},
		{Name: "estate-enrollment-state", Kind: RootFile, Path: filepath.Join(base, "var", "estate-enrollment.json")},
	}
}

// buildStateTree lays out a small Store-shaped state below base: a sealed
// read-only generation, the relative current link, owner-only private state,
// a file root, and nanosecond modification times set after every child.
func buildStateTree(t *testing.T, base string) []Root {
	t.Helper()
	roots := stateRoots(base)
	if err := os.MkdirAll(filepath.Join(base, "var"), 0o700); err != nil {
		t.Fatal(err)
	}
	generations, private, enrollment := roots[0].Path, roots[1].Path, roots[2].Path
	mustMkdir(t, generations, 0o755)
	generation := filepath.Join(generations, "generation-0123456789abcdef0123456789abcdef")
	mustMkdir(t, generation, 0o755)
	mustMkdir(t, filepath.Join(generation, "apps"), 0o755)
	mustWrite(t, filepath.Join(generation, "apps", "index.json"), []byte("{\"apps\":[]}\n"), 0o444)
	mustMkdir(t, filepath.Join(generation, "packages"), 0o755)
	mustWrite(t, filepath.Join(generation, "packages", "pkg-a"), bytes.Repeat([]byte("spk"), 4000), 0o444)
	if err := os.Symlink("generation-0123456789abcdef0123456789abcdef", filepath.Join(generations, "current")); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(generations, "nonce-ledger-v1.initialized"), []byte("{\"sentinel\":true}\n"), 0o600)
	mustMkdir(t, private, 0o700)
	mustMkdir(t, filepath.Join(private, "rollouts"), 0o700)
	mustWrite(t, filepath.Join(private, "rollouts", "app-a.json"), []byte("{\"appId\":\"app-a\"}\n"), 0o600)
	mustWrite(t, filepath.Join(private, "rollouts", "app-b.json"), []byte("{\"appId\":\"app-b\"}\n"), 0o600)
	mustMkdir(t, filepath.Join(private, "nonce-receipts-v1"), 0o700)
	mustWrite(t, filepath.Join(private, "nonce-receipts-v1", "empty"), nil, 0o600)
	mustWrite(t, enrollment, []byte("{\"schema\":\"enrollment\"}\n"), 0o600)

	// Seal and time the tree bottom-up, the way a Store leaves it.
	when := time.Unix(1_800_000_000, 123_456_789)
	var paths []string
	for _, root := range roots {
		if err := filepath.Walk(root.Path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			paths = append(paths, path)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(paths)))
	for index, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if info.IsDir() && strings.Contains(path, "generation-") {
			if err := os.Chmod(path, 0o555); err != nil {
				t.Fatal(err)
			}
		}
		stamp := when.Add(time.Duration(index) * time.Millisecond)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { makeWritable(base) })
	return roots
}

// copyTree reproduces a tree at another path with identical contents,
// permission bits, modification times and links.
func copyTree(t *testing.T, from, to []Root) {
	t.Helper()
	for index := range from {
		type pending struct {
			path string
			info os.FileInfo
		}
		var dirs []pending
		err := filepath.Walk(from[index].Path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(from[index].Path, path)
			target := filepath.Join(to[index].Path, rel)
			switch {
			case info.Mode()&os.ModeSymlink != 0:
				link, err := os.Readlink(path)
				if err != nil {
					return err
				}
				return os.Symlink(link, target)
			case info.IsDir():
				if err := os.MkdirAll(target, 0o700); err != nil {
					return err
				}
				dirs = append(dirs, pending{target, info})
				return nil
			default:
				body, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if err := os.WriteFile(target, body, 0o600); err != nil {
					return err
				}
				if err := os.Chmod(target, info.Mode().Perm()); err != nil {
					return err
				}
				return os.Chtimes(target, info.ModTime(), info.ModTime())
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		for i := len(dirs) - 1; i >= 0; i-- {
			if err := os.Chmod(dirs[i].path, dirs[i].info.Mode().Perm()); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(dirs[i].path, dirs[i].info.ModTime(), dirs[i].info.ModTime()); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func mustMkdir(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func makeWritable(base string) {
	_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
}

// treeSnapshot is every member of every root as one comparable line: name,
// relative path, type, permission bits, time, content digest and link target.
func treeSnapshot(t *testing.T, roots []Root) []string {
	t.Helper()
	var lines []string
	for _, root := range roots {
		if err := filepath.Walk(root.Path, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root.Path, path)
			line := fmt.Sprintf("%s|%s|%s", root.Name, rel, info.Mode().String())
			switch {
			case info.Mode()&os.ModeSymlink != 0:
				link, _ := os.Readlink(path)
				line += "|link:" + link
			case info.IsDir():
				line += fmt.Sprintf("|mtime:%d", info.ModTime().UnixNano())
			default:
				body, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				digest := sha256.Sum256(body)
				line += fmt.Sprintf("|mtime:%d|sha256:%x", info.ModTime().UnixNano(), digest)
			}
			lines = append(lines, line)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return lines
}

func exportTree(t *testing.T, roots []Root, private ed25519.PrivateKey, operatorKey string) ([]byte, StateSummary) {
	t.Helper()
	var out bytes.Buffer
	summary, err := ExportState(&out, roots, StateHeader{StoreID: testStoreID, OperatorKey: operatorKey, CurrentGeneration: "generation-0123456789abcdef0123456789abcdef"}, signerFor(private))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return out.Bytes(), summary
}

func requireRefusal(t *testing.T, err error, name string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want refusal %s", name)
	}
	if got := RefusalName(err); got != name {
		t.Fatalf("refusal = %q (%v); want %s", got, err, name)
	}
}

// Same state, two different host paths: byte-identical streams. The stream
// names roots, never host paths, and no time or random value enters it.
func TestStoreStateTarDeterministicTwoPaths(t *testing.T) {
	private, operatorKey := testOperatorKey(t, 7)
	first := buildStateTree(t, t.TempDir())
	secondBase := filepath.Join(t.TempDir(), "a", "much", "deeper", "host", "path")
	if err := os.MkdirAll(filepath.Join(secondBase, "var"), 0o700); err != nil {
		t.Fatal(err)
	}
	second := stateRoots(secondBase)
	copyTree(t, first, second)
	t.Cleanup(func() { makeWritable(secondBase) })

	firstBytes, firstSummary := exportTree(t, first, private, operatorKey)
	secondBytes, secondSummary := exportTree(t, second, private, operatorKey)
	againBytes, _ := exportTree(t, first, private, operatorKey)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("store-state-tar-v1 differs between two host paths: %s vs %s", firstSummary.StreamSHA256, secondSummary.StreamSHA256)
	}
	if !bytes.Equal(firstBytes, againBytes) {
		t.Fatal("store-state-tar-v1 differs between two exports of one state")
	}
	digest := sha256.Sum256(firstBytes)
	if firstSummary.StreamSHA256 != hex.EncodeToString(digest[:]) || firstSummary.StreamBytes != int64(len(firstBytes)) {
		t.Fatalf("summary does not describe the written stream: %+v", firstSummary)
	}
	for _, root := range first {
		if bytes.Contains(firstBytes, []byte(filepath.Dir(root.Path))) {
			t.Fatalf("stream carries the host path %s", filepath.Dir(root.Path))
		}
	}
	// Positive control for the comparison itself: a one-second time change
	// on one member must change the stream.
	index := filepath.Join(second[0].Path, "generation-0123456789abcdef0123456789abcdef", "apps", "index.json")
	info, err := os.Stat(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(index, info.ModTime().Add(time.Second), info.ModTime().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if changed, _ := exportTree(t, second, private, operatorKey); bytes.Equal(changed, firstBytes) {
		t.Fatal("a changed member time did not change the stream; the determinism check proves nothing")
	}
}

func TestStoreStateRoundTripRestoresEveryMember(t *testing.T) {
	private, operatorKey := testOperatorKey(t, 7)
	source := buildStateTree(t, t.TempDir())
	raw, exported := exportTree(t, source, private, operatorKey)

	verified, err := VerifyState(bytes.NewReader(raw), operatorKey, testStoreID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.StreamSHA256 != exported.StreamSHA256 || verified.ManifestSHA256 != exported.ManifestSHA256 || verified.StreamBytes != exported.StreamBytes {
		t.Fatalf("verify summary %+v differs from export summary %+v", verified, exported)
	}

	targetBase := t.TempDir()
	if err := os.Mkdir(filepath.Join(targetBase, "var"), 0o700); err != nil {
		t.Fatal(err)
	}
	targets := stateRoots(targetBase)
	t.Cleanup(func() { makeWritable(targetBase) })
	var staged map[string]string
	imported, err := ImportState(bytes.NewReader(raw), ImportOptions{
		OperatorKey: operatorKey, StoreID: testStoreID, Targets: targets,
		BeforeCommit: func(manifest StateManifestV1, paths map[string]string) error {
			staged = paths
			for _, target := range targets {
				if _, err := os.Lstat(target.Path); !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("target %s exists before commit", target.Name)
				}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if imported.StreamSHA256 != exported.StreamSHA256 || len(staged) != len(targets) {
		t.Fatalf("import summary %+v / staged %v", imported, staged)
	}
	want, got := treeSnapshot(t, source), treeSnapshot(t, targets)
	if strings.Join(want, "\n") != strings.Join(got, "\n") {
		t.Fatalf("restored tree differs:\nwant %s\n got %s", strings.Join(want, "\n"), strings.Join(got, "\n"))
	}
	for _, path := range staged {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staging path %s survived the commit", path)
		}
	}
	// A restored state exports to the same bytes it was restored from.
	again, _ := exportTree(t, targets, private, operatorKey)
	if !bytes.Equal(again, raw) {
		t.Fatal("the restored state does not export to the stream it was restored from")
	}
}

type tarEntry struct {
	header *tar.Header
	body   []byte
}

func readEntries(t *testing.T, raw []byte) []tarEntry {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(raw))
	var entries []tarEntry
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return entries
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, tarEntry{header: header, body: body})
	}
}

func writeEntries(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	tw := tar.NewWriter(&out)
	for _, entry := range entries {
		header := *entry.header
		header.Size = int64(len(entry.body))
		if header.Typeflag != tar.TypeReg {
			header.Size = 0
		}
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func entryIndex(t *testing.T, entries []tarEntry, name string) int {
	t.Helper()
	for index, entry := range entries {
		if entry.header.Name == name {
			return index
		}
	}
	t.Fatalf("no member %s", name)
	return -1
}

// Every tampering of a genuine stream is refused by name, and a refused
// import leaves the targets absent and no staging behind.
func TestStoreStateImportRefusesTamperedStream(t *testing.T) {
	private, operatorKey := testOperatorKey(t, 7)
	_, otherKey := testOperatorKey(t, 9)
	source := buildStateTree(t, t.TempDir())
	raw, _ := exportTree(t, source, private, operatorKey)
	const packageMember = "roots/catalog-generations/generation-0123456789abcdef0123456789abcdef/packages/pkg-a"

	rewrite := func(edit func([]tarEntry) []tarEntry) []byte {
		return writeEntries(t, edit(readEntries(t, raw)))
	}
	cases := []struct {
		name        string
		stream      []byte
		operatorKey string
		storeID     string
		refusal     string
	}{
		{name: "genuine-control", stream: raw},
		{name: "expected-another-operator", stream: raw, operatorKey: otherKey, refusal: RefusalStateOperatorMismatch},
		{name: "expected-another-store", stream: raw, storeID: "another-store", refusal: RefusalStateStoreMismatch},
		{name: "manifest-edited", refusal: RefusalStateManifestSignature, stream: rewrite(func(entries []tarEntry) []tarEntry {
			entries[0].body = bytes.Replace(entries[0].body, []byte(`"mode":292`), []byte(`"mode":420`), 1)
			return entries
		})},
		{name: "file-byte-flipped", refusal: RefusalStateMemberDigestMismatch, stream: rewrite(func(entries []tarEntry) []tarEntry {
			index := entryIndex(t, entries, packageMember)
			entries[index].body = append([]byte(nil), entries[index].body...)
			entries[index].body[100] ^= 1
			return entries
		})},
		{name: "member-appended", refusal: RefusalStateMemberUnexpected, stream: rewrite(func(entries []tarEntry) []tarEntry {
			extra := *entries[len(entries)-1].header
			extra.Name = "roots/private-stage/zz-planted"
			return append(entries, tarEntry{header: &extra, body: entries[len(entries)-1].body})
		})},
		{name: "last-member-dropped", refusal: RefusalStateMemberMissing, stream: rewrite(func(entries []tarEntry) []tarEntry {
			return entries[:len(entries)-1]
		})},
		{name: "members-reordered", refusal: RefusalStateMemberHeaderMismatch, stream: rewrite(func(entries []tarEntry) []tarEntry {
			entries[2], entries[3] = entries[3], entries[2]
			return entries
		})},
		{name: "mode-widened", refusal: RefusalStateMemberHeaderMismatch, stream: rewrite(func(entries []tarEntry) []tarEntry {
			index := entryIndex(t, entries, packageMember)
			header := *entries[index].header
			header.Mode = 0o666
			entries[index].header = &header
			return entries
		})},
		{name: "owner-set", refusal: RefusalStateMemberHeaderMismatch, stream: rewrite(func(entries []tarEntry) []tarEntry {
			index := entryIndex(t, entries, packageMember)
			header := *entries[index].header
			header.Uid = 1000
			entries[index].header = &header
			return entries
		})},
		{name: "extended-attribute", refusal: RefusalStateMemberHeaderMismatch, stream: rewrite(func(entries []tarEntry) []tarEntry {
			index := entryIndex(t, entries, packageMember)
			header := *entries[index].header
			header.PAXRecords = map[string]string{"SCHILY.xattr.user.planted": "1"}
			entries[index].header = &header
			return entries
		})},
		{name: "symlink-retargeted", refusal: RefusalStateMemberHeaderMismatch, stream: rewrite(func(entries []tarEntry) []tarEntry {
			index := entryIndex(t, entries, "roots/catalog-generations/current")
			header := *entries[index].header
			header.Linkname = "generation-ffffffffffffffffffffffffffffffff"
			entries[index].header = &header
			return entries
		})},
		{name: "trailing-data", refusal: RefusalStateStreamMalformed, stream: append(append([]byte(nil), raw...), 'x')},
		{name: "truncated", refusal: RefusalStateStreamMalformed, stream: raw[:len(raw)/2]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, storeID := operatorKey, testStoreID
			if tc.operatorKey != "" {
				key = tc.operatorKey
			}
			if tc.storeID != "" {
				storeID = tc.storeID
			}
			_, verifyErr := VerifyState(bytes.NewReader(tc.stream), key, storeID)
			targetBase := t.TempDir()
			if err := os.Mkdir(filepath.Join(targetBase, "var"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { makeWritable(targetBase) })
			targets := stateRoots(targetBase)
			_, importErr := ImportState(bytes.NewReader(tc.stream), ImportOptions{OperatorKey: key, StoreID: storeID, Targets: targets})
			if tc.refusal == "" {
				if verifyErr != nil || importErr != nil {
					t.Fatalf("positive control refused: verify %v, import %v", verifyErr, importErr)
				}
				return
			}
			requireRefusal(t, verifyErr, tc.refusal)
			requireRefusal(t, importErr, tc.refusal)
			entries, err := os.ReadDir(filepath.Join(targetBase, "var"))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("a refused import left %d entries behind (first %s)", len(entries), entries[0].Name())
			}
		})
	}
}

func TestStoreStateImportRefusesOccupiedTargets(t *testing.T) {
	private, operatorKey := testOperatorKey(t, 7)
	raw, _ := exportTree(t, buildStateTree(t, t.TempDir()), private, operatorKey)
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, targets []Root)
		refusal string
	}{
		{name: "empty-directory-accepted", prepare: func(t *testing.T, targets []Root) {
			mustMkdir(t, targets[1].Path, 0o700)
		}},
		{name: "directory-with-an-entry", refusal: RefusalStateTargetNotEmpty, prepare: func(t *testing.T, targets []Root) {
			mustMkdir(t, targets[1].Path, 0o700)
			mustWrite(t, filepath.Join(targets[1].Path, "live"), []byte("newer state"), 0o600)
		}},
		{name: "file-root-present", refusal: RefusalStateTargetNotEmpty, prepare: func(t *testing.T, targets []Root) {
			mustWrite(t, targets[2].Path, []byte("{}"), 0o600)
		}},
		{name: "directory-root-is-a-symlink", refusal: RefusalStateTargetNotEmpty, prepare: func(t *testing.T, targets []Root) {
			if err := os.Symlink(t.TempDir(), targets[0].Path); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			if err := os.Mkdir(filepath.Join(base, "var"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { makeWritable(base) })
			targets := stateRoots(base)
			tc.prepare(t, targets)
			before := treeSnapshot(t, []Root{{Name: "base", Path: base}})
			stream := &countingReader{r: bytes.NewReader(raw)}
			_, err := ImportState(stream, ImportOptions{OperatorKey: operatorKey, StoreID: testStoreID, Targets: targets})
			if tc.refusal == "" {
				if err != nil {
					t.Fatalf("positive control refused: %v", err)
				}
				return
			}
			requireRefusal(t, err, tc.refusal)
			// An occupied target is refused before the members are read, not
			// after the whole stream was extracted beside it.
			if stream.n >= int64(len(raw))/2 {
				t.Fatalf("the import read %d of %d stream bytes before refusing an occupied target", stream.n, len(raw))
			}
			if after := treeSnapshot(t, []Root{{Name: "base", Path: base}}); strings.Join(after, "\n") != strings.Join(before, "\n") {
				t.Fatalf("a refused import changed the target host:\nbefore %v\n after %v", before, after)
			}
		})
	}
}

func TestStoreStateImportBeforeCommitRefusalLeavesNothing(t *testing.T) {
	private, operatorKey := testOperatorKey(t, 7)
	raw, _ := exportTree(t, buildStateTree(t, t.TempDir()), private, operatorKey)
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "var"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { makeWritable(base) })
	refused := Refuse("caller-check-refused", "")
	_, err := ImportState(bytes.NewReader(raw), ImportOptions{
		OperatorKey: operatorKey, StoreID: testStoreID, Targets: stateRoots(base),
		BeforeCommit: func(StateManifestV1, map[string]string) error { return refused },
	})
	if !errors.Is(err, refused) {
		t.Fatalf("import = %v, want the caller's refusal", err)
	}
	entries, _ := os.ReadDir(filepath.Join(base, "var"))
	if len(entries) != 0 {
		t.Fatalf("a caller refusal left %s behind", entries[0].Name())
	}
}

func TestStoreStateImportRefusesAnotherRootSet(t *testing.T) {
	private, operatorKey := testOperatorKey(t, 7)
	raw, _ := exportTree(t, buildStateTree(t, t.TempDir()), private, operatorKey)
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "var"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, targets := range map[string][]Root{
		"root-missing": stateRoots(base)[:2],
		"kind-changed": {stateRoots(base)[0], stateRoots(base)[1], {Name: "estate-enrollment-state", Kind: RootDirectory, Path: stateRoots(base)[2].Path}},
	} {
		_, err := ImportState(bytes.NewReader(raw), ImportOptions{OperatorKey: operatorKey, StoreID: testStoreID, Targets: targets})
		if RefusalName(err) != RefusalStateRootSetMismatch {
			t.Fatalf("%s: import = %v, want %s", name, err, RefusalStateRootSetMismatch)
		}
	}
}

func TestStoreStateExportRefusesWhatItCannotRepresent(t *testing.T) {
	private, operatorKey := testOperatorKey(t, 7)
	_, otherKey := testOperatorKey(t, 9)
	cases := []struct {
		name    string
		mutate  func(t *testing.T, roots []Root) []Root
		key     string
		refusal string
	}{
		{name: "genuine-control", mutate: func(t *testing.T, roots []Root) []Root { return roots }},
		{name: "symlink-leaving-its-directory", refusal: RefusalStateMemberUnsupported, mutate: func(t *testing.T, roots []Root) []Root {
			if err := os.Symlink("../escape", filepath.Join(roots[1].Path, "rollouts", "link")); err != nil {
				t.Fatal(err)
			}
			return roots
		}},
		{name: "named-pipe", refusal: RefusalStateMemberUnsupported, mutate: func(t *testing.T, roots []Root) []Root {
			if err := syscall.Mkfifo(filepath.Join(roots[1].Path, "pipe"), 0o600); err != nil {
				t.Fatal(err)
			}
			return roots
		}},
		{name: "setuid-file", refusal: RefusalStateMemberUnsupported, mutate: func(t *testing.T, roots []Root) []Root {
			path := filepath.Join(roots[1].Path, "rollouts", "app-a.json")
			if err := os.Chmod(path, 0o600|os.ModeSetuid); err != nil {
				t.Fatal(err)
			}
			return roots
		}},
		{name: "control-character-name", refusal: RefusalStateMemberPathUnsafe, mutate: func(t *testing.T, roots []Root) []Root {
			mustWrite(t, filepath.Join(roots[1].Path, "bad\nname"), nil, 0o600)
			return roots
		}},
		{name: "overlapping-roots", refusal: RefusalStateRootsOverlap, mutate: func(t *testing.T, roots []Root) []Root {
			return append(roots, Root{Name: "rollouts", Kind: RootDirectory, Path: filepath.Join(roots[1].Path, "rollouts")})
		}},
		{name: "missing-root", refusal: RefusalStateRootMissing, mutate: func(t *testing.T, roots []Root) []Root {
			return append(roots, Root{Name: "zz-absent", Kind: RootDirectory, Path: filepath.Join(filepath.Dir(roots[0].Path), "absent")})
		}},
		{name: "relative-root", refusal: RefusalStateRootInvalid, mutate: func(t *testing.T, roots []Root) []Root {
			roots[0].Path = "var/generations"
			return roots
		}},
		{name: "signer-is-not-the-operator", key: otherKey, refusal: RefusalStateManifestSignature, mutate: func(t *testing.T, roots []Root) []Root { return roots }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			roots := tc.mutate(t, buildStateTree(t, t.TempDir()))
			key := operatorKey
			if tc.key != "" {
				key = tc.key
			}
			_, err := ExportState(io.Discard, roots, StateHeader{StoreID: testStoreID, OperatorKey: key}, signerFor(private))
			if tc.refusal == "" {
				if err != nil {
					t.Fatalf("positive control refused: %v", err)
				}
				return
			}
			requireRefusal(t, err, tc.refusal)
		})
	}
}

func TestStoreStateManifestDecodeIsStrict(t *testing.T) {
	private, operatorKey := testOperatorKey(t, 7)
	raw, _ := exportTree(t, buildStateTree(t, t.TempDir()), private, operatorKey)
	manifest := readEntries(t, raw)[0].body
	if _, err := DecodeStateManifest(manifest); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	for name, variant := range map[string][]byte{
		"indented":      bytes.Replace(manifest, []byte(`{"schema"`), []byte("{ \"schema\""), 1),
		"duplicate-key": bytes.Replace(manifest, []byte(`{"schema"`), []byte(`{"schema":"x","schema"`), 1),
		"unknown-field": bytes.Replace(manifest, []byte(`{"schema"`), []byte(`{"extra":1,"schema"`), 1),
		"no-newline":    bytes.TrimSuffix(manifest, []byte("\n")),
	} {
		if _, err := DecodeStateManifest(variant); RefusalName(err) != RefusalStateManifestMalformed {
			t.Fatalf("%s: decode = %v, want %s", name, err, RefusalStateManifestMalformed)
		}
	}
}

func TestStateNamespaceVectors(t *testing.T) {
	for _, vector := range []struct {
		storeID    string
		generation uint64
		want       string
	}{
		{"root-store", 1, "store-root-store-g1"},
		{"root-store", 12, "store-root-store-g12"},
		{strings.Repeat("a", 54), 1, "store-" + strings.Repeat("a", 54) + "-g1"},
	} {
		got, err := StateNamespace(vector.storeID, vector.generation)
		if err != nil || got != vector.want {
			t.Fatalf("StateNamespace(%q, %d) = %q, %v; want %q", vector.storeID, vector.generation, got, err, vector.want)
		}
	}
	for name, vector := range map[string]struct {
		storeID    string
		generation uint64
	}{
		"generation-zero":    {"root-store", 0},
		"too-long":           {strings.Repeat("a", 55), 1},
		"too-long-later":     {strings.Repeat("a", 54), 10},
		"uppercase-store":    {"Root-store", 1},
		"store-id-too-short": {"r", 1},
	} {
		if _, err := StateNamespace(vector.storeID, vector.generation); RefusalName(err) != RefusalStateNamespaceInvalid {
			t.Fatalf("%s: StateNamespace = %v, want %s", name, err, RefusalStateNamespaceInvalid)
		}
	}
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
