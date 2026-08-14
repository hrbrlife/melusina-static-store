package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestGenerationHTTPPinsIndexAndPointerRequestsAcrossSwitch(t *testing.T) {
	root := t.TempDir()
	flat := filepath.Join(root, "dist")
	generationRoot := filepath.Join(root, "generations")
	cleanupImmutableCatalog(t, generationRoot)
	writeHTTPGenerationFixture(t, flat, "old-index", "old-pointer")

	store := AppCatalogGenerationStore{Root: generationRoot}
	old, err := store.BootstrapFromFlat(flat, nil)
	if err != nil {
		t.Fatal(err)
	}
	newSnapshot, err := store.BuildAndSwitch(func(candidateRoot string) error {
		if err := os.WriteFile(filepath.Join(candidateRoot, "apps", "index.json"), []byte("new-index"), 0o644); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(candidateRoot, "apps", "pointers", "app.json"), []byte("new-pointer"), 0o644)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	static := requestScopedStatic{flat: http.FileServer(http.Dir(flat))}
	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "/apps/index.json", want: "old-index"},
		{path: "/apps/pointers/app.json", want: "old-pointer"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			if err := store.SwitchCurrent(old); err != nil {
				t.Fatal(err)
			}
			var once sync.Once
			barrier := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				once.Do(func() {
					if err := store.SwitchCurrent(newSnapshot); err != nil {
						t.Fatal(err)
					}
				})
				static.ServeHTTP(w, r)
			})
			h := newGenerationHTTP(store, barrier)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if w.Code != http.StatusOK || w.Body.String() != tc.want {
				t.Fatalf("request crossed generation switch: status=%d body=%q want=%q", w.Code, w.Body.String(), tc.want)
			}
		})
	}
}

func TestGenerationHTTPPackageGETPinsLookupMetadataAndOpenFD(t *testing.T) {
	cfg, m, fixture, _, base := serveSetup(t)
	pinReleaseActive(m, fixture)
	generationRoot := t.TempDir()
	cleanupImmutableCatalog(t, generationRoot)
	store := AppCatalogGenerationStore{Root: generationRoot}
	old, err := store.BootstrapFromFlat(cfg.DistDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	newSnapshot, err := store.BuildAndSwitch(func(candidateRoot string) error {
		if err := os.Remove(filepath.Join(candidateRoot, "packages", base)); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(candidateRoot, "apps", "index.json"), []byte("{\"apps\":[]}"), 0o644)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SwitchCurrent(old); err != nil {
		t.Fatal(err)
	}

	static := requestScopedStatic{flat: http.FileServer(http.Dir(cfg.DistDir))}
	gate := newServeGate(cfg, m, static)
	lookupDone := make(chan struct{})
	continueOpen := make(chan struct{})
	gate.beforePackageOpen = func() {
		close(lookupDone)
		<-continueOpen
	}
	h := newGenerationHTTP(store, gate)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/packages/"+base, nil))
	}()
	<-lookupDone
	if err := store.SwitchCurrent(newSnapshot); err != nil {
		t.Fatal(err)
	}
	close(continueOpen)
	<-done

	if w.Code != http.StatusOK {
		t.Fatalf("package request failed after switch: status=%d body=%q", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), fixture.spk) {
		t.Fatal("package request mixed catalog lookup with the new generation")
	}
	current, err := store.ResolveCurrent()
	if err != nil {
		t.Fatal(err)
	}
	if current.ID != newSnapshot.ID {
		t.Fatalf("test did not switch current: got %s want %s", current.ID, newSnapshot.ID)
	}
}

func TestGenerationHTTPLeavesFlatNamespacesOutsideCatalog(t *testing.T) {
	root := t.TempDir()
	flat := filepath.Join(root, "dist")
	generationRoot := filepath.Join(root, "generations")
	cleanupImmutableCatalog(t, generationRoot)
	writeHTTPGenerationFixture(t, flat, "index", "pointer")
	if err := os.WriteFile(filepath.Join(flat, "flat.txt"), []byte("flat"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := AppCatalogGenerationStore{Root: generationRoot}
	if _, err := store.BootstrapFromFlat(flat, nil); err != nil {
		t.Fatal(err)
	}
	h := newGenerationHTTP(store, requestScopedStatic{flat: http.FileServer(http.Dir(flat))})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/flat.txt", nil))
	if w.Code != http.StatusOK || w.Body.String() != "flat" {
		t.Fatalf("flat namespace changed: status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestRouterUsesGenerationsOnlyForWriteCapableRuntime(t *testing.T) {
	root := t.TempDir()
	flat := filepath.Join(root, "dist")
	generationRoot := filepath.Join(root, "generations")
	cleanupImmutableCatalog(t, generationRoot)
	writeHTTPGenerationFixture(t, flat, "generation-index", "pointer")
	store := AppCatalogGenerationStore{Root: generationRoot}
	if _, err := store.BootstrapFromFlat(flat, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(flat, "apps", "index.json"), []byte("legacy-flat-index"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{DistDir: flat, CatalogGenerationRoot: generationRoot}

	writeRouter := newRouterWithCatalogRuntime(cfg, nil, nil, nil, catalogRuntime{
		appNonces:          &publishNonceLedger{},
		catalogGenerations: store,
	})
	w := httptest.NewRecorder()
	writeRouter.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/apps/index.json", nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "no on-chain reader") {
		t.Fatalf("write runtime served an unverified generation: status=%d body=%q", w.Code, w.Body.String())
	}

	readRouter := newRouterWithCatalogRuntime(cfg, nil, nil, nil, catalogRuntime{catalogGenerations: store})
	w = httptest.NewRecorder()
	readRouter.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/apps/index.json", nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "no on-chain reader") {
		t.Fatalf("read-only runtime served an unverified flat catalog: status=%d body=%q", w.Code, w.Body.String())
	}
}

func writeHTTPGenerationFixture(t *testing.T, root, index, pointer string) {
	t.Helper()
	for _, namespace := range appCatalogNamespaces {
		if err := os.MkdirAll(filepath.Join(root, namespace), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "apps", "pointers"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "apps", "index.json"), []byte(index), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "apps", "pointers", "app.json"), []byte(pointer), 0o644); err != nil {
		t.Fatal(err)
	}
}
