package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// The bundled Store units run under ProtectSystem=strict and name, per unit,
// the paths the process may write (ReadWritePaths) or sees read-only
// (ReadOnlyPaths). systemd builds that mount namespace before the Store runs,
// and a listed path that does not exist fails the start with 226/NAMESPACE
// ("Failed to set up mount namespacing: ...: No such file or directory"),
// unless the entry starts with '-'. The Store unit once listed three roots of
// the retiring layout, /var/lib/melusina-store-{private,catalog,migrations},
// which the renderer never names, so a Store installed by the deployment
// contract could not start. These tests hold every such entry to the layout
// the renderer actually produces. The rule is deliberately stricter than one
// systemd version: systemd 252 was seen to drop, before it checks the path, an
// entry whose closest listed parent has the same mode (a missing ReadOnlyPaths
// entry under the read-only root of ProtectSystem=strict, or a missing
// ReadWritePaths entry under the writable state root), while a missing entry
// whose parent has another mode failed with 226/NAMESPACE. That dropping is an
// optimisation, not a promise, so every unprefixed entry must exist.

const (
	bundledStoreServerUnit   = "melusina-store-sidecar.service"
	bundledListingSignerUnit = "melusina-store-listing-signer.service"
	bundledPairingSignerUnit = "melusina-store-provider-pairing-signer.service"
)

// Directives whose entries systemd must find at start unless '-'-prefixed.
var storeUnitNamespaceDirectives = map[string]bool{
	"ReadWritePaths":    true,
	"ReadOnlyPaths":     true,
	"InaccessiblePaths": true,
	"ExecPaths":         true,
	"NoExecPaths":       true,
}

type storeUnitNamespaceEntry struct {
	Directive string
	Path      string
	Optional  bool // leading '-': systemd ignores the entry when the path is missing
}

type storeUnitNamespaceSpec struct {
	Entries        []storeUnitNamespaceEntry
	RuntimeDirs    []string // /run/<RuntimeDirectory>: systemd creates it before the namespace
	ConditionPaths []string // ConditionPathExists targets: the unit does not run without them
	ProtectSystem  string
}

// parseStoreUnitNamespace reads only what the check needs and refuses the
// unit syntax it does not model, so an unusual line cannot hide an entry.
func parseStoreUnitNamespace(raw []byte) (storeUnitNamespaceSpec, error) {
	var spec storeUnitNamespaceSpec
	section := ""
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasSuffix(line, `\`) {
			return spec, errors.New("continuation-line")
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return spec, fmt.Errorf("line-without-assignment:%s", line)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch {
		case section == "[Unit]" && key == "ConditionPathExists":
			// A negated or triggering ('|') condition does not guarantee the path.
			if value != "" && !strings.HasPrefix(value, "!") && !strings.HasPrefix(value, "|") {
				spec.ConditionPaths = append(spec.ConditionPaths, value)
			}
		case section == "[Service]" && key == "ProtectSystem":
			spec.ProtectSystem = value
		case section == "[Service]" && key == "RuntimeDirectory":
			for _, name := range strings.Fields(value) {
				if filepath.IsAbs(name) || filepath.Clean(name) != name || strings.HasPrefix(name, "..") {
					return spec, fmt.Errorf("runtime-directory-not-relative-clean:%s", name)
				}
				spec.RuntimeDirs = append(spec.RuntimeDirs, "/run/"+name)
			}
		case section == "[Service]" && storeUnitNamespaceDirectives[key]:
			if value == "" {
				// An empty assignment resets the directive's list.
				kept := spec.Entries[:0]
				for _, entry := range spec.Entries {
					if entry.Directive != key {
						kept = append(kept, entry)
					}
				}
				spec.Entries = kept
				continue
			}
			for _, field := range strings.Fields(value) {
				if strings.ContainsAny(field, `"'`) {
					return spec, fmt.Errorf("quoted-entry:%s", field)
				}
				entry := storeUnitNamespaceEntry{Directive: key}
				path := field
				for strings.HasPrefix(path, "-") || strings.HasPrefix(path, "+") {
					if path[0] == '+' {
						return spec, fmt.Errorf("root-relative:%s", field)
					}
					entry.Optional = true
					path = path[1:]
				}
				if !filepath.IsAbs(path) || filepath.Clean(path) != path {
					return spec, fmt.Errorf("path-not-absolute-clean:%s", field)
				}
				entry.Path = path
				spec.Entries = append(spec.Entries, entry)
			}
		}
	}
	return spec, nil
}

// renderedStoreUnitLayout is the part of the rendered layout the units depend
// on: the paths that exist before a bundled unit's first start, and the
// paths the Store itself writes.
type renderedStoreUnitLayout struct {
	stateRoot      string
	presentAtStart map[string]string // path -> why it exists before the first start
	storeWrites    map[string]string // rendered config field -> path the Store writes
}

func renderedStoreUnitLayoutFromConfig(cfg Config) (renderedStoreUnitLayout, error) {
	stateRoot := filepath.Dir(cfg.DistDir)
	layout := renderedStoreUnitLayout{
		stateRoot: stateRoot,
		storeWrites: map[string]string{
			"dist_dir":                     cfg.DistDir,
			"private_stage_dir":            cfg.PrivateStageDir,
			"catalog_generation_root":      cfg.CatalogGenerationRoot,
			"catalog_migration_state_dir":  cfg.CatalogMigrationStateDir,
			"catalog_repo_root":            cfg.CatalogRepoRoot,
			"estate_enrollment_state_path": cfg.EstateEnrollmentStatePath,
			// Created by the Store itself at start-up, so it is not in
			// presentAtStart: the unit must not name it without a '-'.
			"served_snapshot_dir": cfg.ServedSnapshotDir,
		},
		// DEPLOYMENT-CONTRACT.md "Deployer-owned inputs": install-bootstrap
		// creates /etc/melusina/store/{,tls,shards}; items 5 and 6 require
		// private_stage_dir, catalog_migration_state_dir and catalog_repo_root
		// before genesis; genesis-dist-init creates dist_dir and refuses to run
		// without its parent (genesis-dist-parent-unsafe). catalog_generation_root
		// is deliberately absent: item 5 lets it be "empty, or absent" at first
		// start, so a unit entry naming it needs a leading '-'.
		presentAtStart: map[string]string{
			stateRoot:                                  "dist_dir parent, required by genesis-dist-init",
			cfg.DistDir:                                "dist_dir, created by genesis-dist-init",
			cfg.PrivateStageDir:                        "private_stage_dir, contract item 5",
			cfg.CatalogMigrationStateDir:               "catalog_migration_state_dir, contract item 5",
			cfg.CatalogRepoRoot:                        "catalog_repo_root, contract item 6",
			filepath.Dir(cfg.TLS.CertPath):             "tls directory, install-bootstrap",
			filepath.Dir(cfg.TLS.KeyPath):              "tls directory, install-bootstrap",
			cfg.BootIdentity.ShardsDir:                 "shards directory, install-bootstrap",
			filepath.Dir(cfg.BootIdentity.TLSCertPath): "boot-identity certificate directory, install-bootstrap",
		},
	}
	fields := make([]string, 0, len(layout.storeWrites))
	for field := range layout.storeWrites {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		path := layout.storeWrites[field]
		if !strings.HasPrefix(path, stateRoot+"/") {
			return layout, fmt.Errorf("rendered-store-state-outside-state-root:%s:%s", field, path)
		}
	}
	return layout, nil
}

// coveringStoreUnitEntry returns the most specific entry that governs path; systemd
// applies the longest matching namespace path.
func coveringStoreUnitEntry(spec storeUnitNamespaceSpec, path string) (storeUnitNamespaceEntry, bool) {
	var best storeUnitNamespaceEntry
	found := false
	for _, entry := range spec.Entries {
		if entry.Path == path || strings.HasPrefix(path, strings.TrimSuffix(entry.Path, "/")+"/") {
			if !found || len(entry.Path) > len(best.Path) {
				best, found = entry, true
			}
		}
	}
	return best, found
}

// checkBundledStoreUnit returns every refusal for one unit, each named.
func checkBundledStoreUnit(unit string, raw []byte, layout renderedStoreUnitLayout) []string {
	spec, err := parseStoreUnitNamespace(raw)
	if err != nil {
		return []string{fmt.Sprintf("store-unit-namespace-parse:%s:%v", unit, err)}
	}
	var refusals []string

	present := map[string]bool{}
	for path := range layout.presentAtStart {
		present[path] = true
	}
	for _, dir := range spec.RuntimeDirs {
		present[dir] = true
	}
	for _, path := range spec.ConditionPaths {
		present[path] = true
		present[filepath.Dir(path)] = true
	}
	required := 0
	for _, entry := range spec.Entries {
		if entry.Optional {
			continue
		}
		required++
		if !present[entry.Path] {
			refusals = append(refusals, fmt.Sprintf("store-unit-namespace-path-may-be-missing:%s:%s:%s", unit, entry.Directive, entry.Path))
		}
	}

	storeUnit := unit == bundledStoreServerUnit || unit == bundledListingSignerUnit || unit == bundledPairingSignerUnit
	if !storeUnit {
		return refusals
	}
	// Positive control: a parse that finds nothing proves nothing.
	if required == 0 {
		refusals = append(refusals, fmt.Sprintf("store-unit-namespace-none-parsed:%s", unit))
	}
	// Everything below assumes the rest of the file system is read-only.
	if spec.ProtectSystem != "strict" {
		refusals = append(refusals, fmt.Sprintf("store-unit-not-protect-system-strict:%s", unit))
	}
	fields := make([]string, 0, len(layout.storeWrites))
	for field := range layout.storeWrites {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	for _, field := range fields {
		path := layout.storeWrites[field]
		entry, ok := coveringStoreUnitEntry(spec, path)
		writable := ok && entry.Directive == "ReadWritePaths"
		switch {
		case unit == bundledStoreServerUnit && !writable:
			refusals = append(refusals, fmt.Sprintf("store-unit-rendered-path-not-writable:%s:%s:%s", unit, field, path))
		case unit != bundledStoreServerUnit && writable:
			refusals = append(refusals, fmt.Sprintf("store-signer-unit-can-write-store-state:%s:%s:%s", unit, field, path))
		}
	}
	return refusals
}

func renderedStoreUnitLayoutForTest(t *testing.T) (Config, renderedStoreUnitLayout) {
	t.Helper()
	_, profilePath, inputPath, outputPath, input := newStoreConfigRenderFixture(t)
	writeStoreConfigRenderInput(t, inputPath, input)
	if _, err := renderEstateStoreConfig(estateStoreConfigRenderOptions{
		profilePath: profilePath,
		inputPath:   inputPath,
		outputPath:  outputPath,
	}); err != nil {
		t.Fatalf("render Store config: %v", err)
	}
	cfg, err := LoadConfig(outputPath)
	if err != nil {
		t.Fatalf("load rendered Store config: %v", err)
	}
	layout, err := renderedStoreUnitLayoutFromConfig(cfg)
	if err != nil {
		t.Fatalf("rendered layout: %v", err)
	}
	return cfg, layout
}

func readBundledStoreUnits(t *testing.T) map[string][]byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Join(filepath.Dir(thisFile), "..", "..", "deploy", "store-generation")
	paths, err := filepath.Glob(filepath.Join(dir, "*.service"))
	if err != nil {
		t.Fatal(err)
	}
	units := map[string][]byte{}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		units[filepath.Base(path)] = raw
	}
	for _, name := range []string{bundledStoreServerUnit, bundledListingSignerUnit, bundledPairingSignerUnit} {
		if _, ok := units[name]; !ok {
			t.Fatalf("bundled-store-unit-missing:%s in %s", name, dir)
		}
	}
	return units
}

func TestBundledStoreUnitNamespacePathsExistAtFirstStart(t *testing.T) {
	_, layout := renderedStoreUnitLayoutForTest(t)
	units := readBundledStoreUnits(t)
	names := make([]string, 0, len(units))
	for name := range units {
		names = append(names, name)
	}
	sort.Strings(names)
	var refusals []string
	for _, name := range names {
		refusals = append(refusals, checkBundledStoreUnit(name, units[name], layout)...)
	}
	if len(refusals) != 0 {
		t.Fatalf("bundled units would not start on the rendered layout:\n%s", strings.Join(refusals, "\n"))
	}
}

// appendToStoreUnitServiceSection adds lines at the end of the unit's
// [Service] section, after the unit's own settings, where a later assignment
// extends or (when empty) resets a list exactly as systemd reads it.
func appendToStoreUnitServiceSection(t *testing.T, unit, lines string) string {
	t.Helper()
	if strings.Count(unit, "\n[Service]\n") != 1 {
		t.Fatal("unit has no single [Service] section")
	}
	start := strings.Index(unit, "\n[Service]\n") + len("\n[Service]\n")
	end := len(unit)
	if next := strings.Index(unit[start:], "\n["); next >= 0 {
		end = start + next + 1
	}
	return unit[:end] + lines + unit[end:]
}

func TestBundledStoreUnitNamespaceCheckRefusesByName(t *testing.T) {
	cfg, layout := renderedStoreUnitLayoutForTest(t)
	units := readBundledStoreUnits(t)
	cases := []struct {
		name string
		unit string
		add  string
		want string // "" means the mutated unit must pass
	}{
		{"retiring private root, unprefixed", bundledStoreServerUnit,
			"ReadWritePaths=/var/lib/melusina-store-private\n",
			"store-unit-namespace-path-may-be-missing:melusina-store-sidecar.service:ReadWritePaths:/var/lib/melusina-store-private"},
		{"retiring private root, '-'-prefixed", bundledStoreServerUnit,
			"ReadWritePaths=-/var/lib/melusina-store-private\n", ""},
		{"retiring private root read-only in the listing signer", bundledListingSignerUnit,
			"ReadOnlyPaths=/var/lib/melusina-store-private\n",
			"store-unit-namespace-path-may-be-missing:melusina-store-listing-signer.service:ReadOnlyPaths:/var/lib/melusina-store-private"},
		{"generation root may be absent at first start", bundledStoreServerUnit,
			"ReadWritePaths=" + cfg.CatalogGenerationRoot + "\n",
			"store-unit-namespace-path-may-be-missing:melusina-store-sidecar.service:ReadWritePaths:" + cfg.CatalogGenerationRoot},
		{"generation root, '-'-prefixed", bundledStoreServerUnit,
			"ReadWritePaths=-" + cfg.CatalogGenerationRoot + "\n", ""},
		{"state root narrowed to dist", bundledStoreServerUnit,
			"ReadWritePaths=\nReadWritePaths=" + cfg.DistDir + "\n",
			"store-unit-rendered-path-not-writable:melusina-store-sidecar.service:private_stage_dir:" + cfg.PrivateStageDir},
		{"dist made read-only under the state root", bundledStoreServerUnit,
			"ReadOnlyPaths=" + cfg.DistDir + "\n",
			"store-unit-rendered-path-not-writable:melusina-store-sidecar.service:dist_dir:" + cfg.DistDir},
		{"served snapshots made read-only under the state root", bundledStoreServerUnit,
			"ReadOnlyPaths=" + cfg.ServedSnapshotDir + "\n",
			"store-unit-namespace-path-may-be-missing:melusina-store-sidecar.service:ReadOnlyPaths:" + cfg.ServedSnapshotDir},
		{"served snapshots made read-only, '-'-prefixed", bundledStoreServerUnit,
			"ReadOnlyPaths=-" + cfg.ServedSnapshotDir + "\n",
			"store-unit-rendered-path-not-writable:melusina-store-sidecar.service:served_snapshot_dir:" + cfg.ServedSnapshotDir},
		{"list reset by an empty assignment", bundledStoreServerUnit,
			"ReadWritePaths=\n",
			"store-unit-rendered-path-not-writable:melusina-store-sidecar.service:catalog_migration_state_dir:" + cfg.CatalogMigrationStateDir},
		{"listing signer can write Store state", bundledListingSignerUnit,
			"ReadWritePaths=" + layout.stateRoot + "\n",
			"store-signer-unit-can-write-store-state:melusina-store-listing-signer.service:private_stage_dir:" + cfg.PrivateStageDir},
		{"pairing signer can write Store state", bundledPairingSignerUnit,
			"ReadWritePaths=" + layout.stateRoot + "\n",
			"store-signer-unit-can-write-store-state:melusina-store-provider-pairing-signer.service:dist_dir:" + cfg.DistDir},
		{"file system not strict", bundledStoreServerUnit,
			"ProtectSystem=full\n",
			"store-unit-not-protect-system-strict:melusina-store-sidecar.service"},
		{"continuation line", bundledStoreServerUnit,
			"ReadWritePaths=" + layout.stateRoot + " \\\n  /var/lib/melusina-store-private\n",
			"store-unit-namespace-parse:melusina-store-sidecar.service:continuation-line"},
		{"root-relative entry", bundledStoreServerUnit,
			"ReadWritePaths=+" + layout.stateRoot + "\n",
			"store-unit-namespace-parse:melusina-store-sidecar.service:root-relative"},
		{"quoted entry", bundledStoreServerUnit,
			"ReadWritePaths=\"" + layout.stateRoot + "\"\n",
			"store-unit-namespace-parse:melusina-store-sidecar.service:quoted-entry"},
		{"no namespace entries at all", bundledPairingSignerUnit,
			"ReadOnlyPaths=\nReadWritePaths=\n",
			"store-unit-namespace-none-parsed:melusina-store-provider-pairing-signer.service"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refusals := checkBundledStoreUnit(tc.unit, []byte(appendToStoreUnitServiceSection(t, string(units[tc.unit]), tc.add)), layout)
			if tc.want == "" {
				if len(refusals) != 0 {
					t.Fatalf("mutated unit refused: %q", refusals)
				}
				return
			}
			for _, refusal := range refusals {
				if refusal == tc.want || strings.HasPrefix(refusal, tc.want+":") {
					return
				}
			}
			t.Fatalf("refusals %q, want %q", refusals, tc.want)
		})
	}

	// The layout is derived from the renderer, so a renderer that moved a
	// root out of the state root is refused by name, not silently unwritable.
	moved := cfg
	moved.PrivateStageDir = "/var/lib/melusina-store-private"
	if _, err := renderedStoreUnitLayoutFromConfig(moved); err == nil || err.Error() != "rendered-store-state-outside-state-root:private_stage_dir:/var/lib/melusina-store-private" {
		t.Fatalf("moved private_stage_dir: got %v", err)
	}
	// The served snapshots too: a renderer that put them on /run, a tmpfs
	// outside the state root, is refused by name.
	moved = cfg
	moved.ServedSnapshotDir = "/run/melusina-store/served-snapshots"
	if _, err := renderedStoreUnitLayoutFromConfig(moved); err == nil || err.Error() != "rendered-store-state-outside-state-root:served_snapshot_dir:/run/melusina-store/served-snapshots" {
		t.Fatalf("moved served_snapshot_dir: got %v", err)
	}
}
