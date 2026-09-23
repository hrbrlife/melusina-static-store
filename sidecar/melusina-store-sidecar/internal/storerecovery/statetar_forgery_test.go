package storerecovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resignedStream rewrites a genuine stream through edit and signs the edited
// manifest again with the operator key. The forgery therefore carries a valid
// operator signature, and the manifest's shape is the only thing that can
// refuse it: this is the case of an operator key used to sign a hostile
// stream, which the import then restores as root.
func resignedStream(t *testing.T, raw []byte, private ed25519.PrivateKey, edit func(manifest *StateManifestV1, entries []tarEntry) []tarEntry) []byte {
	t.Helper()
	entries := readEntries(t, raw)
	var manifest StateManifestV1
	if err := json.Unmarshal(entries[0].body, &manifest); err != nil {
		t.Fatal(err)
	}
	entries = edit(&manifest, entries)
	message, err := stateSigningMessage(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	body, err := canonicalDocument(manifest)
	if err != nil {
		t.Fatal(err)
	}
	entries[0].body = body
	return writeEntries(t, entries)
}

// retarget points the manifest's and the stream's symlink at target.
func retarget(t *testing.T, manifest *StateManifestV1, entries []tarEntry, path, target string) []tarEntry {
	t.Helper()
	found := false
	for index := range manifest.Members {
		if manifest.Members[index].Path == path {
			manifest.Members[index].Target = target
			found = true
		}
	}
	if !found {
		t.Fatalf("no manifest member %s", path)
	}
	index := entryIndex(t, entries, path)
	header := *entries[index].header
	header.Linkname = target
	entries[index].header = &header
	return entries
}

// insertMembers adds members, with their stream entries, directly after the
// member named after. The inserted paths must sort there, so the canonical
// order check passes and the guard under test is what decides.
func insertMembers(t *testing.T, manifest *StateManifestV1, entries []tarEntry, after string, added ...StateMemberV1) []tarEntry {
	t.Helper()
	position := -1
	for index, member := range manifest.Members {
		if member.Path == after {
			position = index + 1
		}
	}
	if position < 0 {
		t.Fatalf("no manifest member %s", after)
	}
	var newEntries []tarEntry
	for index := range added {
		var body []byte
		if added[index].Type == memberTypeFile {
			body = []byte("planted by a signed forgery\n")
			digest := sha256.Sum256(body)
			added[index].Size, added[index].SHA256 = int64(len(body)), hex.EncodeToString(digest[:])
		}
		newEntries = append(newEntries, tarEntry{header: memberHeader(added[index]), body: body})
	}
	manifest.Members = append(manifest.Members[:position], append(append([]StateMemberV1(nil), added...), manifest.Members[position:]...)...)
	// The manifest is entry 0, so member i is entry i+1.
	entryPosition := position + 1
	if entries[entryPosition-1].header.Name != after {
		t.Fatalf("stream entry before the insertion is %s, want %s", entries[entryPosition-1].header.Name, after)
	}
	return append(entries[:entryPosition], append(newEntries, entries[entryPosition:]...)...)
}

// A stream the operator key signed is still refused when its manifest names
// a member the import must never create: a symlink leaving its directory, a
// path segment that is empty, "." or "..", a member below a file root, or a
// member whose parent directory the manifest does not declare. Each is
// refused as store-state-manifest-malformed with the subject of the one
// guard that owns it, by verify and by import, and a refused import leaves
// nothing behind. The re-signed genuine stream is the positive control: the
// forgery machinery itself produces streams that verify and import.
func TestStoreStateImportRefusesSignedForgeries(t *testing.T) {
	private, operatorKey := testOperatorKey(t, 7)
	source := buildStateTree(t, t.TempDir())
	raw, _ := exportTree(t, source, private, operatorKey)
	const currentLink = "roots/catalog-generations/current"
	const privateStage = "roots/private-stage"
	const when = int64(1_800_000_000_123_456_789)
	directory := func(path string) StateMemberV1 {
		return StateMemberV1{Path: path, Type: memberTypeDir, Mode: 0o700, MTime: when}
	}
	file := func(path string) StateMemberV1 {
		return StateMemberV1{Path: path, Type: memberTypeFile, Mode: 0o600, MTime: when}
	}
	symlinkSubject := "symlink " + currentLink

	cases := []struct {
		name    string
		edit    func(manifest *StateManifestV1, entries []tarEntry) []tarEntry
		subject string
	}{
		{name: "resigned-genuine-control", edit: func(_ *StateManifestV1, entries []tarEntry) []tarEntry { return entries }},
		{name: "symlink-target-absolute", subject: symlinkSubject, edit: func(m *StateManifestV1, e []tarEntry) []tarEntry {
			return retarget(t, m, e, currentLink, "/etc")
		}},
		{name: "symlink-target-leaves-the-root", subject: symlinkSubject, edit: func(m *StateManifestV1, e []tarEntry) []tarEntry {
			return retarget(t, m, e, currentLink, "../../../../etc")
		}},
		{name: "symlink-target-parent", subject: symlinkSubject, edit: func(m *StateManifestV1, e []tarEntry) []tarEntry {
			return retarget(t, m, e, currentLink, "..")
		}},
		{name: "symlink-target-below-a-sibling", subject: symlinkSubject, edit: func(m *StateManifestV1, e []tarEntry) []tarEntry {
			return retarget(t, m, e, currentLink, "generation-0123456789abcdef0123456789abcdef/apps")
		}},
		{name: "segment-dot-dot", subject: `member path "roots/private-stage/.."`, edit: func(m *StateManifestV1, e []tarEntry) []tarEntry {
			return insertMembers(t, m, e, privateStage, directory(privateStage+"/.."), file(privateStage+"/../escaped"))
		}},
		{name: "segment-dot", subject: `member path "roots/private-stage/."`, edit: func(m *StateManifestV1, e []tarEntry) []tarEntry {
			return insertMembers(t, m, e, privateStage, directory(privateStage+"/."))
		}},
		{name: "segment-empty", subject: `member path "roots/private-stage/"`, edit: func(m *StateManifestV1, e []tarEntry) []tarEntry {
			return insertMembers(t, m, e, privateStage, directory(privateStage+"/"))
		}},
		{name: "member-below-a-file-root", subject: "member below a file root: roots/estate-enrollment-state/planted", edit: func(m *StateManifestV1, e []tarEntry) []tarEntry {
			return insertMembers(t, m, e, "roots/estate-enrollment-state", file("roots/estate-enrollment-state/planted"))
		}},
		{name: "member-without-a-directory-parent", subject: "member without a directory parent: roots/private-stage/absent/planted", edit: func(m *StateManifestV1, e []tarEntry) []tarEntry {
			return insertMembers(t, m, e, privateStage, file(privateStage+"/absent/planted"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stream := resignedStream(t, raw, private, tc.edit)
			_, verifyErr := VerifyState(bytes.NewReader(stream), operatorKey, testStoreID)
			targetBase := t.TempDir()
			if err := os.Mkdir(filepath.Join(targetBase, "var"), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { makeWritable(targetBase) })
			targets := stateRoots(targetBase)
			_, importErr := ImportState(bytes.NewReader(stream), ImportOptions{OperatorKey: operatorKey, StoreID: testStoreID, Targets: targets})
			if tc.subject == "" {
				if verifyErr != nil || importErr != nil {
					t.Fatalf("positive control refused: verify %v, import %v", verifyErr, importErr)
				}
				if want, got := treeSnapshot(t, source), treeSnapshot(t, targets); strings.Join(want, "\n") != strings.Join(got, "\n") {
					t.Fatal("the re-signed genuine stream did not restore the source tree")
				}
				return
			}
			for step, err := range map[string]error{"verify": verifyErr, "import": importErr} {
				requireRefusal(t, err, RefusalStateManifestMalformed)
				if want := RefusalStateManifestMalformed + ":" + tc.subject; err.Error() != want {
					t.Fatalf("%s refused as %q; want the guard's own subject %q", step, err.Error(), want)
				}
			}
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
