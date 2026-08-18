package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

func TestGovernedUIClosesOverStaleDistDir(t *testing.T) {
	ui, err := newGovernedUIStatic()
	if err != nil {
		t.Fatalf("load governed UI: %v", err)
	}

	flat := t.TempDir()
	if err := os.MkdirAll(filepath.Join(flat, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(flat, "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(flat, "index.html"), []byte("STALE ROOT WITH BAKED CATALOG"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(flat, "assets", "index-DDlYX80K.js"), []byte("STALE packageId 6f4ad"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(flat, "images", "catalog-icon.png"), []byte("catalog image"), 0o644); err != nil {
		t.Fatal(err)
	}

	current := t.TempDir()
	if err := os.MkdirAll(filepath.Join(current, "apps"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(current, "apps", "index.json"), []byte(`{"apps":["CURRENT"]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	h := requestScopedStatic{flat: http.FileServer(http.Dir(flat)), ui: ui}
	serve := func(request *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, request)
		return rec
	}

	root := serve(httptest.NewRequest(http.MethodGet, "/", nil))
	if root.Code != http.StatusOK {
		t.Fatalf("root status = %d, want 200", root.Code)
	}
	if strings.Contains(root.Body.String(), "STALE ROOT") || strings.Contains(root.Body.String(), "packageId 6f4ad") {
		t.Fatalf("root fell back to stale DistDir: %q", root.Body.String())
	}
	if got := root.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("root cache control = %q, want no-store", got)
	}

	staleAsset := serve(httptest.NewRequest(http.MethodGet, "/assets/index-DDlYX80K.js", nil))
	if staleAsset.Code != http.StatusNotFound {
		t.Fatalf("stale asset status = %d, want 404; body=%q", staleAsset.Code, staleAsset.Body.String())
	}

	assetMatch := regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`).FindStringSubmatch(root.Body.String())
	if len(assetMatch) != 2 {
		t.Fatalf("embedded index did not name a current asset: %q", root.Body.String())
	}
	currentAsset := serve(httptest.NewRequest(http.MethodGet, assetMatch[1], nil))
	if currentAsset.Code != http.StatusOK || currentAsset.Body.Len() == 0 {
		t.Fatalf("current embedded asset = HTTP %d, bytes=%d", currentAsset.Code, currentAsset.Body.Len())
	}

	request := httptest.NewRequest(http.MethodGet, "/apps/index.json", nil)
	request = request.WithContext(context.WithValue(request.Context(), appCatalogSnapshotContextKey{}, AppCatalogSnapshot{ID: "current", Root: current}))
	catalog := serve(request)
	if catalog.Code != http.StatusOK || catalog.Body.String() != `{"apps":["CURRENT"]}` {
		t.Fatalf("catalog response = HTTP %d %q, want immutable current snapshot", catalog.Code, catalog.Body.String())
	}

	image := serve(httptest.NewRequest(http.MethodGet, "/images/catalog-icon.png", nil))
	if image.Code != http.StatusOK || image.Body.String() != "catalog image" {
		t.Fatalf("catalog image did not retain DistDir ownership: HTTP %d %q", image.Code, image.Body.String())
	}

	installer := serve(httptest.NewRequest(http.MethodGet, "/update/install.sh", nil))
	if installer.Code != http.StatusOK || strings.Contains(installer.Body.String(), "hrbrlife.github.io/melusina-static-store") {
		t.Fatalf("embedded installer = HTTP %d and still names retired Pages=%t", installer.Code, strings.Contains(installer.Body.String(), "hrbrlife.github.io/melusina-static-store"))
	}
}

func TestRouterServesRuntimeContractSchemaFromDistDir(t *testing.T) {
	dist := t.TempDir()
	want := []byte(`{"schema":"melusina-app-runtime-contract-v1"}`)
	if err := os.MkdirAll(filepath.Join(dist, "schemas"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dist, "schemas", "melusina-app-runtime-contract-v1.schema.json"), want, 0o644); err != nil {
		t.Fatal(err)
	}

	router := newRouter(Config{DistDir: dist}, nil, nil, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/schemas/melusina-app-runtime-contract-v1.schema.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("schema status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != string(want) {
		t.Fatalf("schema body = %q, want %q", rec.Body.String(), want)
	}
}

func TestUIManifestFailsClosedOnHashMutation(t *testing.T) {
	files := fstest.MapFS{
		"UI-MANIFEST.json": &fstest.MapFile{Data: []byte(`{"schema":"melusina-store-sidecar-ui-v1","files":[{"path":"index.html","sha256":"0000000000000000000000000000000000000000000000000000000000000000","bytes":5}]}`)},
		"index.html":       &fstest.MapFile{Data: []byte("hello")},
	}
	if _, err := newUIStatic(files); err == nil || !strings.Contains(err.Error(), "check=ui_manifest") {
		t.Fatalf("hash-mutated UI manifest was accepted: %v", err)
	}
}

func TestGovernedUIServesLockedAppIcon(t *testing.T) {
	ui, err := newGovernedUIStatic()
	if err != nil {
		t.Fatalf("load governed UI: %v", err)
	}
	h := requestScopedStatic{ui: ui}

	// The AiLagoon path is one entry in the generated signed-SPK projection.
	// newUIStatic has already hash-checked every manifest entry; this test proves
	// the sidecar's owned /icons route serves that projection rather than falling
	// through to mutable DistDir images.
	icon := httptest.NewRecorder()
	h.ServeHTTP(icon, httptest.NewRequest(http.MethodGet,
		"/icons/apps/v4ywsgcuc6wgqvjre99k9j4js21rxt0hamxd5nsnn8q5vgw93gjh.png", nil))
	if icon.Code != http.StatusOK || icon.Body.Len() == 0 {
		t.Fatalf("locked icon = HTTP %d, bytes=%d", icon.Code, icon.Body.Len())
	}
	if got := icon.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Fatalf("locked icon cache control = %q, want public 1h", got)
	}

	unknown := httptest.NewRecorder()
	h.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet,
		"/icons/apps/not-a-locked-icon.png", nil))
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("undeclared icon = HTTP %d, want 404", unknown.Code)
	}
}
