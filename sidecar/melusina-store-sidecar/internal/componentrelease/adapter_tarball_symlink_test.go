package componentrelease

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ulikunitz/xz"
)

type tarTestEntry struct {
	name     string
	body     []byte
	typeflag byte
	linkname string
}

func tarXZ(t *testing.T, entries ...tarTestEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	xw, err := xz.NewWriter(&out)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(xw)
	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0o755, Typeflag: typeflag, Linkname: e.linkname, Size: int64(len(e.body))}
		if typeflag == tar.TypeDir {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typeflag == tar.TypeReg && len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := xw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func shaBytes(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func staticGetter(b []byte) HTTPGetter {
	return func(context.Context, string) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil }
}

func tarInstall(t *testing.T) ComponentInstall {
	t.Helper()
	root := filepath.Join(t.TempDir(), "shell")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return ComponentInstall{
		ComponentID: "sandstorm-shell", ComponentClass: ClassShell,
		ApplyKind: ApplyTarballSymlinkSwap, InstallRoot: root,
		CurrentSymlink: filepath.Join(root, "latest"), StagingDir: filepath.Join(root, "stage"),
		ServiceUnit: "sandstorm.service", HealthCommand: []string{"/bin/true"}, RestartCommand: []string{"/bin/true"},
	}
}

func makePriorGeneration(t *testing.T, install ComponentInstall, hash string) string {
	t.Helper()
	dir := filepath.Join(install.InstallRoot, "release-prior")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sandstorm"), []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeTarballMetadata(dir, tarballReleaseMetadata{Schema: tarballMetadataSchema, ArtifactSHA: hash, ArtifactSize: 10, Version: "old"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, install.CurrentSymlink); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestTarballAdapterApplySwitchAndExactRollback(t *testing.T) {
	archive := tarXZ(t, tarTestEntry{name: "bin/sandstorm", body: []byte("new-shell")})
	newHash := shaBytes(archive)
	priorHash := strings.Repeat("a", 64)
	install := tarInstall(t)
	prior := makePriorGeneration(t, install, priorHash)
	a := NewTarballSymlinkAdapter(staticGetter(archive))
	desired := ComponentRelease{ComponentID: install.ComponentID, Version: "build-63", SHA256: newHash, SizeBytes: int64(len(archive)), BundleURL: "https://origin/shell.tar.xz", PreviousSHA256: priorHash}
	staged, err := a.Stage(context.Background(), desired, install, filepath.Join(install.InstallRoot, "staged"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(context.Background(), staged, desired, install); err != nil {
		t.Fatal(err)
	}
	rb, err := a.Apply(context.Background(), staged, desired, install)
	if err != nil {
		t.Fatal(err)
	}
	gotHash, err := InstalledArtifactSHA256(install)
	if err != nil || gotHash != newHash {
		t.Fatalf("installed archive hash = %q, %v; want %s", gotHash, err, newHash)
	}
	if err := rb(context.Background()); err != nil {
		t.Fatal(err)
	}
	target, err := TarballCurrentTargetForArtifact(install, priorHash)
	if err != nil || target != prior {
		t.Fatalf("rollback target = %q, %v; want %q", target, err, prior)
	}
}

func TestTarballAdapterRefusesMutatedArchiveAtApply(t *testing.T) {
	archive := tarXZ(t, tarTestEntry{name: "bin/sandstorm", body: []byte("new-shell")})
	install := tarInstall(t)
	priorHash := strings.Repeat("b", 64)
	makePriorGeneration(t, install, priorHash)
	a := NewTarballSymlinkAdapter(staticGetter(archive))
	desired := ComponentRelease{ComponentID: install.ComponentID, Version: "build-63", SHA256: shaBytes(archive), SizeBytes: int64(len(archive)), BundleURL: "https://origin/shell.tar.xz", PreviousSHA256: priorHash}
	staged, err := a.Stage(context.Background(), desired, install, filepath.Join(install.InstallRoot, "staged"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(context.Background(), staged, desired, install); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged.Path, bytes.Repeat([]byte{'x'}, len(archive)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(context.Background(), staged, desired, install); err == nil {
		t.Fatal("Apply accepted bytes mutated after Verify")
	}
	if target, err := TarballCurrentTargetForArtifact(install, priorHash); err != nil || target == "" {
		t.Fatalf("prior changed after refused apply: %q, %v", target, err)
	}
}

func TestTarballExtractorRejectsTraversalAndUnsafeLinks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry tarTestEntry
	}{
		{"traversal", tarTestEntry{name: "../outside", body: []byte("bad")}},
		{"absolute-symlink", tarTestEntry{name: "bin/link", typeflag: tar.TypeSymlink, linkname: "/etc/shadow"}},
		{"escaping-relative-symlink", tarTestEntry{name: "bin/link", typeflag: tar.TypeSymlink, linkname: "../../outside"}},
		{"hardlink", tarTestEntry{name: "bin/link", typeflag: tar.TypeLink}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := tarXZ(t, tc.entry)
			root := t.TempDir()
			path := filepath.Join(root, "archive.tar.xz")
			if err := os.WriteFile(path, archive, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := extractTarXZNoFollow(path, filepath.Join(root, "out")); err == nil {
				t.Fatalf("%s archive was accepted", tc.name)
			}
			if _, err := os.Stat(filepath.Join(root, "outside")); !os.IsNotExist(err) {
				t.Fatalf("extractor wrote outside target: %v", err)
			}
		})
	}
}

func TestTarballExtractorAcceptsContainedAndApprovedSystemLinks(t *testing.T) {
	archive := tarXZ(t,
		tarTestEntry{name: "sandstorm", body: []byte("shell")},
		tarTestEntry{name: "bin/spk", typeflag: tar.TypeSymlink, linkname: "../sandstorm"},
		tarTestEntry{name: "lib/libcurl.so.4", typeflag: tar.TypeSymlink, linkname: "/usr/lib/x86_64-linux-gnu/libcurl.so.4.8.0"},
	)
	root := t.TempDir()
	path := filepath.Join(root, "archive.tar.xz")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out")
	if err := extractTarXZNoFollow(path, out); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(out, "bin", "spk")); err != nil || target != "../sandstorm" {
		t.Fatalf("relative link = %q, %v", target, err)
	}
	if target, err := os.Readlink(filepath.Join(out, "lib", "libcurl.so.4")); err != nil || target != "/usr/lib/x86_64-linux-gnu/libcurl.so.4.8.0" {
		t.Fatalf("system link = %q, %v", target, err)
	}
}

func TestTarballExtractorRefusesWriteUnderPriorSymlink(t *testing.T) {
	archive := tarXZ(t,
		tarTestEntry{name: "link", typeflag: tar.TypeSymlink, linkname: "/usr/lib/"},
		tarTestEntry{name: "link/escaped", body: []byte("must-not-write")},
	)
	root := t.TempDir()
	path := filepath.Join(root, "archive.tar.xz")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractTarXZNoFollow(path, filepath.Join(root, "out")); err == nil {
		t.Fatal("extractor followed prior symlink as parent")
	}
}

func TestTarballAdapterWiring(t *testing.T) {
	a := NewTarballSymlinkAdapter(nil)
	if a.Kind() != ApplyTarballSymlinkSwap {
		t.Fatalf("Kind = %q", a.Kind())
	}
	adapters = map[string]Adapter{}
	if err := RegisterAdapter(a); err != nil {
		t.Fatal(err)
	}
	if got, ok := AdapterFor(ApplyTarballSymlinkSwap); !ok || got.Kind() != ApplyTarballSymlinkSwap {
		t.Fatal("tarball adapter not registered")
	}
	adapters = map[string]Adapter{}
}

func TestTarballMetadataRejectsDuplicateArtifactHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, tarballMetadataName)
	first := strings.Repeat("a", 64)
	second := strings.Repeat("b", 64)
	raw := `{"schema":"` + tarballMetadataSchema + `","artifactSha256":"` + first + `","artifactSha256":"` + second + `","artifactSizeBytes":1,"version":"build-1"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTarballMetadata(dir); err == nil {
		t.Fatal("duplicate artifactSha256 was accepted")
	}
}
