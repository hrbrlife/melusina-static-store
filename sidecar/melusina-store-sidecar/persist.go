package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// This file closes C3: POST /publish persists the gate-verified bytes itself.
// The refusing gate (envelope → accept_publishers → on-chain VerifyPublish →
// timestamp-forward) runs FIRST; only bytes that passed every check are written
// into the catalog working tree that build-store.sh aggregates. Nothing lands
// any other way — hand-staging / scp into the serve tree is retired, not
// merely discouraged.

// slotHint carries the OPTIONAL explicit catalog-slot coordinates a publish may
// name (the packages/<developer>/<repo>/<slug> working-tree path the assembler
// scans). Required only for the FIRST publish of a new app; a re-publish
// resolves its existing slot by the Sandstorm appId in metadata.json.
type slotHint struct {
	Developer string
	Repo      string
	Slug      string
}

func (h slotHint) empty() bool { return h.Developer == "" && h.Repo == "" && h.Slug == "" }

func (h slotHint) validate() error {
	if h.empty() {
		return nil
	}
	if !isSafePathSegment(h.Developer) || !isSafePathSegment(h.Repo) || !isSafePathSegment(h.Slug) {
		return errors.New("developer/repo/slug must each be a single safe path segment")
	}
	return nil
}

var (
	// errSlotHintRequired: first publish of a new appId with no slot named (400).
	errSlotHintRequired = errors.New("slot unresolved")
	// errSlotAmbiguous: the tree already carries this appId in >1 slot (409) — a
	// blind write could fork the app across slots; the tree must be repaired first.
	errSlotAmbiguous = errors.New("slot ambiguous")
	// errSlotHintConflict: the named slot disagrees with where the appId already
	// lives (409) — refuse rather than silently duplicate the app.
	errSlotHintConflict = errors.New("slot conflict")
)

func slotErrorStatus(err error) int {
	switch {
	case errors.Is(err, errSlotAmbiguous), errors.Is(err, errSlotHintConflict):
		return 409
	default:
		return 400
	}
}

// resolveAppSlot locates the catalog working-tree slot for appID under
// catalogRoot/packages. Exactly one existing slot → that dir (a hint, if
// present, must agree). No existing slot → the hint names where to create it.
// More than one → refuse.
func resolveAppSlot(catalogRoot, appID string, hint slotHint) (string, error) {
	if strings.TrimSpace(appID) == "" {
		return "", errors.New("metadata.json carries no appId — cannot locate the catalog slot")
	}
	if err := hint.validate(); err != nil {
		return "", err
	}
	metas, err := filepath.Glob(filepath.Join(catalogRoot, "packages", "*", "*", "*", "metadata.json"))
	if err != nil {
		return "", fmt.Errorf("scan packages tree: %w", err)
	}
	var matches []string
	for _, mf := range metas {
		b, rerr := os.ReadFile(mf)
		if rerr != nil {
			continue
		}
		if metadataAppID(b) == appID {
			matches = append(matches, filepath.Dir(mf))
		}
	}
	switch {
	case len(matches) > 1:
		return "", fmt.Errorf("%w: appId %s appears in %d slots (%s) — repair the tree before publishing", errSlotAmbiguous, appID, len(matches), strings.Join(matches, ", "))
	case len(matches) == 1:
		dir := matches[0]
		if !hint.empty() {
			want := filepath.Join(catalogRoot, "packages", hint.Developer, hint.Repo, hint.Slug)
			if filepath.Clean(want) != filepath.Clean(dir) {
				return "", fmt.Errorf("%w: appId %s already lives at %s but the publish named %s", errSlotHintConflict, appID, dir, want)
			}
		}
		return dir, nil
	default:
		if hint.empty() {
			return "", fmt.Errorf("%w: first publish for appId %s — pass developer/repo/slug so the store knows its catalog slot", errSlotHintRequired, appID)
		}
		return filepath.Join(catalogRoot, "packages", hint.Developer, hint.Repo, hint.Slug), nil
	}
}

// persistPublishedApp writes the gate-verified {app.spk, RELEASE.json,
// metadata.json, RUNTIME-CONTRACT.json} into the slot, each file atomically
// (temp+rename, the same pattern as the installer artifact path).  The runtime
// contract has already passed its RELEASE.json + SPK binding check; persisting
// it beside the exact app bytes lets the assembler expose the same immutable
// declaration under /attest/<appId>/ for later UI acceptance.
func persistPublishedApp(slotDir string, spk, release, metadata, runtimeContract []byte) error {
	if err := os.MkdirAll(slotDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", slotDir, err)
	}
	for _, f := range []struct {
		name string
		data []byte
	}{
		{"app.spk", spk},
		{"RELEASE.json", release},
		{"metadata.json", metadata},
		{"RUNTIME-CONTRACT.json", runtimeContract},
	} {
		if err := atomicWriteInto(slotDir, f.name, f.data); err != nil {
			return err
		}
	}
	return nil
}

// atomicWriteInto writes data to dir/name via a same-dir temp file + rename so
// a reader never observes a torn file.
func atomicWriteInto(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	dst := filepath.Join(dir, name)
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename %s: %w", dst, err)
	}
	cleanup = false
	return nil
}
