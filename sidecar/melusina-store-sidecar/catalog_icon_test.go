package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"capnproto.org/go/capnp/v3"
	"github.com/ulikunitz/xz"
	"zenhack.net/go/sandstorm/capnp/spk"
)

// iconPackage builds a real .spk carrying one market SVG, so these tests drive
// the production extractor rather than a stub.
func iconPackage(t *testing.T, svg string) []byte {
	t.Helper()

	manifestMsg, manifestSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("new manifest message: %v", err)
	}
	manifest, err := spk.NewRootManifest(manifestSeg)
	if err != nil {
		t.Fatalf("new manifest: %v", err)
	}
	metadata, err := manifest.NewMetadata()
	if err != nil {
		t.Fatalf("new metadata: %v", err)
	}
	icon, err := metadata.Icons().NewMarket()
	if err != nil {
		t.Fatalf("new market icon: %v", err)
	}
	if err := icon.SetSvg(svg); err != nil {
		t.Fatalf("set svg: %v", err)
	}
	manifestBytes, err := manifestMsg.Marshal()
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	archiveMsg, archiveSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("new archive message: %v", err)
	}
	archive, err := spk.NewRootArchive(archiveSeg)
	if err != nil {
		t.Fatalf("new archive: %v", err)
	}
	files, err := archive.NewFiles(1)
	if err != nil {
		t.Fatalf("new files: %v", err)
	}
	entry := files.At(0)
	if err := entry.SetName("sandstorm-manifest"); err != nil {
		t.Fatalf("set name: %v", err)
	}
	if err := entry.SetRegular(manifestBytes); err != nil {
		t.Fatalf("set regular: %v", err)
	}

	sigMsg, sigSeg, err := capnp.NewMessage(capnp.SingleSegment(nil))
	if err != nil {
		t.Fatalf("new signature message: %v", err)
	}
	if _, err := spk.NewRootSignature(sigSeg); err != nil {
		t.Fatalf("new signature: %v", err)
	}

	var out bytes.Buffer
	out.Write(spk.MagicNumber)
	compressed, err := xz.NewWriter(&out)
	if err != nil {
		t.Fatalf("new xz writer: %v", err)
	}
	encoder := capnp.NewEncoder(compressed)
	if err := encoder.Encode(sigMsg); err != nil {
		t.Fatalf("encode signature: %v", err)
	}
	if err := encoder.Encode(archiveMsg); err != nil {
		t.Fatalf("encode archive: %v", err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatalf("close xz: %v", err)
	}
	return out.Bytes()
}

// iconPublishInputs returns the (spk, metadata, release) triple for one app,
// with packageId derived exactly as projectCatalogIndex requires.
func iconPublishInputs(t *testing.T, appID, svg string) ([]byte, []byte, []byte) {
	t.Helper()
	pkg := iconPackage(t, svg)
	sum := sha256.Sum256(pkg)
	packageID := hex.EncodeToString(sum[:])[:32]
	metadata, err := json.Marshal(map[string]any{
		"appId":     appID,
		"packageId": packageID,
		"name":      appID,
		"version":   "1",
	})
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	release, err := json.Marshal(map[string]any{"appHash": "h", "version": "1"})
	if err != nil {
		t.Fatalf("marshal release: %v", err)
	}
	return pkg, metadata, release
}

func indexRows(t *testing.T, body []byte) map[string]map[string]any {
	t.Helper()
	var index struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(body, &index); err != nil {
		t.Fatalf("decode index: %v", err)
	}
	rows := map[string]map[string]any{}
	for _, row := range index.Apps {
		id, _ := row["appId"].(string)
		rows[id] = row
	}
	return rows
}

// A publish must record the app's own icon and carry its bytes, so the served
// row names an image the same catalog can actually return.
func TestProjectCatalogIndexRecordsPublishedIcon(t *testing.T) {
	root := t.TempDir()
	pkg, metadata, release := iconPublishInputs(t, "app-one", "<svg>one</svg>")

	projection, err := projectCatalogIndex(AppCatalogSnapshot{Root: root}, pkg, release, metadata)
	if err != nil {
		t.Fatalf("projectCatalogIndex: %v", err)
	}
	imageID, _ := indexRows(t, projection.indexBytes)["app-one"]["imageId"].(string)
	if imageID == "" {
		t.Fatal("published row carries no imageId")
	}
	if got := string(projection.icons[imageID]); got != "<svg>one</svg>" {
		t.Fatalf("icon bytes = %q, want the package's market icon", got)
	}
	// The id must be content-addressed, so identical icons converge and a changed
	// icon necessarily changes the signed index.
	sum := sha256.Sum256([]byte("<svg>one</svg>"))
	if want := hex.EncodeToString(sum[:])[:32] + ".svg"; imageID != want {
		t.Fatalf("imageId = %q, want content-addressed %q", imageID, want)
	}
}

// An app that ships no icon must still publish cleanly — the SPA draws its
// letter tile — rather than failing the publish.
func TestProjectCatalogIndexAcceptsIconlessPackage(t *testing.T) {
	root := t.TempDir()
	pkg := []byte("not a package at all")
	sum := sha256.Sum256(pkg)
	packageID := hex.EncodeToString(sum[:])[:32]
	metadata, err := json.Marshal(map[string]any{"appId": "plain", "packageId": packageID, "name": "plain"})
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	release, err := json.Marshal(map[string]any{"appHash": "h"})
	if err != nil {
		t.Fatalf("marshal release: %v", err)
	}

	projection, err := projectCatalogIndex(AppCatalogSnapshot{Root: root}, pkg, release, metadata)
	if err != nil {
		t.Fatalf("projectCatalogIndex rejected an icon-less package: %v", err)
	}
	if _, ok := indexRows(t, projection.indexBytes)["plain"]["imageId"]; ok {
		t.Fatal("icon-less row should carry no imageId")
	}
	if len(projection.icons) != 0 {
		t.Fatalf("icons = %d, want none", len(projection.icons))
	}
}

// Rows published before icons were projected must recover theirs from the
// packages already in the catalog, so existing apps gain icons without a
// republish or any re-sign of their metadata.
func TestProjectCatalogIndexBackfillsExistingRows(t *testing.T) {
	root := t.TempDir()
	assembler := NewCatalogAssembler("", root)

	oldPkg, oldMetadata, oldRelease := iconPublishInputs(t, "old-app", "<svg>old</svg>")
	if err := assembler.AssemblePublishedApp(oldPkg, oldRelease, oldMetadata); err != nil {
		t.Fatalf("assemble first app: %v", err)
	}
	// Simulate the pre-icon catalog: strip imageId from the stored row exactly as
	// a generation composed by the previous binary would have it.
	indexPath := filepath.Join(root, "apps", "index.json")
	body, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	var index struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(body, &index); err != nil {
		t.Fatalf("decode index: %v", err)
	}
	for _, row := range index.Apps {
		delete(row, "imageId")
	}
	stripped, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatalf("encode index: %v", err)
	}
	if err := os.WriteFile(indexPath, append(stripped, '\n'), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}

	newPkg, newMetadata, newRelease := iconPublishInputs(t, "new-app", "<svg>new</svg>")
	projection, err := projectCatalogIndex(AppCatalogSnapshot{Root: root}, newPkg, newRelease, newMetadata)
	if err != nil {
		t.Fatalf("projectCatalogIndex: %v", err)
	}

	rows := indexRows(t, projection.indexBytes)
	oldImageID, _ := rows["old-app"]["imageId"].(string)
	if oldImageID == "" {
		t.Fatal("pre-icon row was not backfilled")
	}
	if got := string(projection.icons[oldImageID]); got != "<svg>old</svg>" {
		t.Fatalf("backfilled icon = %q, want the old app's own icon", got)
	}
	if newImageID, _ := rows["new-app"]["imageId"].(string); newImageID == "" {
		t.Fatal("published row carries no imageId")
	}

	// Converged: once the backfilled index is persisted, a row that already
	// carries its icon is left alone, so a steady-state publish re-reads no
	// package but its own.
	if err := assembler.assemblePublishedAppProjection(newPkg, newRelease, newMetadata, projection); err != nil {
		t.Fatalf("assemble backfilled projection: %v", err)
	}
	settled, err := projectCatalogIndex(AppCatalogSnapshot{Root: root}, newPkg, newRelease, newMetadata)
	if err != nil {
		t.Fatalf("second projection: %v", err)
	}
	if len(settled.icons) != 1 {
		t.Fatalf("settled icons = %d, want only the published app's", len(settled.icons))
	}
}

// The row's imageId is only trustworthy if the image is actually a member of the
// same catalog, written before the index that names it.
func TestAssemblePublishedAppWritesIconMember(t *testing.T) {
	root := t.TempDir()
	pkg, metadata, release := iconPublishInputs(t, "app-one", "<svg>one</svg>")

	if err := NewCatalogAssembler("", root).AssemblePublishedApp(pkg, release, metadata); err != nil {
		t.Fatalf("AssemblePublishedApp: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(root, "apps", "index.json"))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	imageID, _ := indexRows(t, body)["app-one"]["imageId"].(string)
	if imageID == "" {
		t.Fatal("assembled row carries no imageId")
	}
	stored, err := os.ReadFile(filepath.Join(root, "images", imageID))
	if err != nil {
		t.Fatalf("catalog names an image it does not serve: %v", err)
	}
	if string(stored) != "<svg>one</svg>" {
		t.Fatalf("stored icon = %q", stored)
	}
}

// A republish whose icon changed must replace it, never keep serving the old one.
func TestAssemblePublishedAppReplacesChangedIcon(t *testing.T) {
	root := t.TempDir()
	assembler := NewCatalogAssembler("", root)

	firstPkg, firstMetadata, firstRelease := iconPublishInputs(t, "app-one", "<svg>before</svg>")
	if err := assembler.AssemblePublishedApp(firstPkg, firstRelease, firstMetadata); err != nil {
		t.Fatalf("first publish: %v", err)
	}
	secondPkg, secondMetadata, secondRelease := iconPublishInputs(t, "app-one", "<svg>after</svg>")
	if err := assembler.AssemblePublishedApp(secondPkg, secondRelease, secondMetadata); err != nil {
		t.Fatalf("second publish: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(root, "apps", "index.json"))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	imageID, _ := indexRows(t, body)["app-one"]["imageId"].(string)
	stored, err := os.ReadFile(filepath.Join(root, "images", imageID))
	if err != nil {
		t.Fatalf("read stored icon: %v", err)
	}
	if string(stored) != "<svg>after</svg>" {
		t.Fatalf("stored icon = %q, want the republished icon", stored)
	}
}

// images is served from the immutable generation, so it has to be one of the
// namespaces a request may resolve — otherwise rows would name images that fall
// through to the mutable flat tree.
func TestImagesIsACatalogNamespace(t *testing.T) {
	if !isAppCatalogRequestPath("/images/abc.svg") {
		t.Fatal("/images/ does not resolve from the app catalog snapshot")
	}
	if _, err := appCatalogPathParts("images/abc.svg"); err != nil {
		t.Fatalf("images path rejected by the catalog path guard: %v", err)
	}
}

// A generation composed before the images namespace existed — every generation
// currently on disk — must still resolve. Requiring the directory here would
// make the new binary refuse to serve the live catalog.
func TestResolveGenerationAcceptsPreImagesGeneration(t *testing.T) {
	root := t.TempDir()
	generation := filepath.Join(root, "generation-preimages")
	for _, namespace := range []string{"apps", "packages", "signatures", "attest"} {
		if err := os.MkdirAll(filepath.Join(generation, namespace), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", namespace, err)
		}
	}
	if err := validateCatalogTree(generation); err != nil {
		t.Fatalf("a generation without images/ was rejected: %v", err)
	}
}

// Laxness must stop at absence: a present images namespace is still held to the
// same no-symlink, real-directory rule as every other namespace.
func TestValidateCatalogTreeRejectsSymlinkedImages(t *testing.T) {
	root := t.TempDir()
	generation := filepath.Join(root, "generation-symlinked")
	for _, namespace := range []string{"apps", "packages", "signatures", "attest"} {
		if err := os.MkdirAll(filepath.Join(generation, namespace), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", namespace, err)
		}
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(generation, "images")); err != nil {
		t.Fatalf("symlink images: %v", err)
	}
	if err := validateCatalogTree(generation); err == nil {
		t.Fatal("a symlinked images namespace was accepted")
	}
}
