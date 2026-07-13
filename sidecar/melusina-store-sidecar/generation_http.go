package main

import (
	"context"
	"net/http"
	"path"
	"strings"
)

type appCatalogSnapshotContextKey struct{}

// generationHTTP resolves the active app-catalog generation once, before any
// handler reads an app-catalog path. The immutable snapshot is carried in the
// request context; downstream static and package-gate reads must use it rather
// than resolving the mutable current link again.
type generationHTTP struct {
	store AppCatalogGenerationStore
	next  http.Handler
}

func newGenerationHTTP(store AppCatalogGenerationStore, next http.Handler) http.Handler {
	return &generationHTTP{store: store, next: next}
}

func (h *generationHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isAppCatalogRequestPath(r.URL.Path) {
		h.next.ServeHTTP(w, r)
		return
	}
	snapshot, err := h.store.ResolveCurrent()
	if err != nil {
		http.Error(w, "app catalog unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx := context.WithValue(r.Context(), appCatalogSnapshotContextKey{}, snapshot)
	h.next.ServeHTTP(w, r.WithContext(ctx))
}

func appCatalogSnapshotFromRequest(r *http.Request) (AppCatalogSnapshot, bool) {
	snapshot, ok := r.Context().Value(appCatalogSnapshotContextKey{}).(AppCatalogSnapshot)
	return snapshot, ok && snapshot.ID != "" && snapshot.Root != ""
}

func isAppCatalogRequestPath(urlPath string) bool {
	clean := path.Clean(urlPath)
	if clean == "." || !strings.HasPrefix(clean, "/") {
		return false
	}
	part := strings.TrimPrefix(clean, "/")
	if slash := strings.IndexByte(part, '/'); slash >= 0 {
		part = part[:slash]
	}
	for _, namespace := range appCatalogNamespaces {
		if part == namespace {
			return true
		}
	}
	return false
}

// requestScopedStatic serves app-catalog paths from the already-resolved
// immutable root. Non-catalog paths retain the legacy flat DistDir surface.
type requestScopedStatic struct {
	flat http.Handler
}

func (h requestScopedStatic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if snapshot, ok := appCatalogSnapshotFromRequest(r); ok {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		relativePath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		f, err := snapshot.Open(relativePath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil {
			http.Error(w, "app catalog stat failed", http.StatusInternalServerError)
			return
		}
		http.ServeContent(w, r, info.Name(), info.ModTime(), f)
		return
	}
	h.flat.ServeHTTP(w, r)
}
