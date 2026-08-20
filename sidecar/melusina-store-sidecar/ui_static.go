package main

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"sort"
	"strings"
)

const (
	uiManifestName   = "UI-MANIFEST.json"
	uiManifestSchema = "melusina-store-sidecar-ui-v1"
)

// governedUI contains the generated Bazaar shell. It is compiled into the
// governed sidecar ELF, so a release cannot switch the server binary while
// leaving a different root UI in a mutable DistDir.
//
//go:embed ui
var governedUI embed.FS

type uiManifest struct {
	Schema string           `json:"schema"`
	Files  []uiManifestFile `json:"files"`
}

type uiManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// uiStatic is a closed allowlist. A request for a shell-owned path never falls
// back to DistDir: that would resurrect a stale bundle after a sidecar upgrade.
type uiStatic struct {
	fs    fs.FS
	files map[string]uiManifestFile
}

func newGovernedUIStatic() (*uiStatic, error) {
	root, err := fs.Sub(governedUI, "ui")
	if err != nil {
		return nil, fmt.Errorf("check=ui_manifest: embedded ui root: %w", err)
	}
	return newUIStatic(root)
}

func newUIStatic(root fs.FS) (*uiStatic, error) {
	raw, err := fs.ReadFile(root, uiManifestName)
	if err != nil {
		return nil, fmt.Errorf("check=ui_manifest: read %s: %w", uiManifestName, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var manifest uiManifest
	if err := dec.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("check=ui_manifest: decode: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("check=ui_manifest: trailing JSON")
	}
	if manifest.Schema != uiManifestSchema {
		return nil, fmt.Errorf("check=ui_manifest: schema %q is not %q", manifest.Schema, uiManifestSchema)
	}
	if len(manifest.Files) == 0 {
		return nil, fmt.Errorf("check=ui_manifest: empty file list")
	}

	declared := make(map[string]uiManifestFile, len(manifest.Files))
	for _, entry := range manifest.Files {
		if !fs.ValidPath(entry.Path) || entry.Path == uiManifestName || strings.HasPrefix(entry.Path, ".") {
			return nil, fmt.Errorf("check=ui_manifest: unsafe path %q", entry.Path)
		}
		if entry.Bytes < 0 || len(entry.SHA256) != 64 {
			return nil, fmt.Errorf("check=ui_manifest: invalid entry %q", entry.Path)
		}
		if _, err := hex.DecodeString(entry.SHA256); err != nil {
			return nil, fmt.Errorf("check=ui_manifest: invalid sha256 for %q", entry.Path)
		}
		if _, exists := declared[entry.Path]; exists {
			return nil, fmt.Errorf("check=ui_manifest: duplicate path %q", entry.Path)
		}
		declared[entry.Path] = entry
	}

	actual := map[string]struct{}{}
	err = fs.WalkDir(root, ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." || name == uiManifestName {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			return fmt.Errorf("non-regular file %q", name)
		}
		entry, ok := declared[name]
		if !ok {
			return fmt.Errorf("undeclared file %q", name)
		}
		body, err := fs.ReadFile(root, name)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(body)
		if int64(len(body)) != entry.Bytes || hex.EncodeToString(digest[:]) != entry.SHA256 {
			return fmt.Errorf("hash or size mismatch for %q", name)
		}
		actual[name] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("check=ui_manifest: %w", err)
	}
	if len(actual) != len(declared) {
		missing := make([]string, 0, len(declared)-len(actual))
		for name := range declared {
			if _, ok := actual[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("check=ui_manifest: declared file missing from embedded UI: %s", strings.Join(missing, ", "))
	}
	return &uiStatic{fs: root, files: declared}, nil
}

func isUIPath(urlPath string) bool {
	if urlPath == "" || !strings.HasPrefix(urlPath, "/") || path.Clean(urlPath) != urlPath {
		return false
	}
	switch urlPath {
	case "/", "/index.html", "/manifest.json", "/sw.js", "/installation-policy.json", "/update/install.sh":
		return true
	}
	return strings.HasPrefix(urlPath, "/assets/") || strings.HasPrefix(urlPath, "/icons/")
}

func (h *uiStatic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isUIPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	if _, ok := h.files[name]; !ok {
		http.NotFound(w, r)
		return
	}
	body, err := fs.ReadFile(h.fs, name)
	if err != nil {
		http.Error(w, "embedded UI unavailable", http.StatusServiceUnavailable)
		return
	}
	if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if name == "index.html" || name == "sw.js" || name == "manifest.json" || name == "installation-policy.json" || name == "update/install.sh" {
		w.Header().Set("Cache-Control", "no-store")
	} else if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

type unavailableUIStatic struct{ err error }

func (h unavailableUIStatic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "governed UI unavailable: "+h.err.Error(), http.StatusServiceUnavailable)
}
