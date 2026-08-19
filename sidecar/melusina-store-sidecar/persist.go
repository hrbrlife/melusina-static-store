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
// into the operator-owned catalog workspace. The serving generation is assembled
// from those verified bytes later in the same governed promotion transaction;
// it does not rely on build-store.sh or a Store source checkout. Nothing lands
// any other way — hand-staging / scp into the serve tree is retired, not merely
// discouraged.

// slotHint carries the OPTIONAL explicit catalog-slot coordinates a publish may
// name (the packages/<developer>/<repo>/<slug> path in that workspace). Required
// only for the FIRST publish of a new app; a re-publish resolves its existing
// slot by the Sandstorm appId in metadata.json.
type slotHint struct {
	Developer string `json:"developer,omitempty"`
	Repo      string `json:"repo,omitempty"`
	Slug      string `json:"slug,omitempty"`
}

func (h slotHint) empty() bool { return h.Developer == "" && h.Repo == "" && h.Slug == "" }

func (h slotHint) validate() error {
	if h.empty() {
		return nil
	}
	if !isSafePathSegment(h.Developer) || !isSafePathSegment(h.Repo) || !isSafePathSegment(h.Slug) {
		return errors.New("developer/repo/slug must each be a single safe path segment")
	}
	for _, part := range []string{h.Developer, h.Repo, h.Slug} {
		if len(part) > 255 {
			return errors.New("developer/repo/slug exceeds filesystem component limit")
		}
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

type publishedAppPersistencePlan struct{ slotDir string }

// planPublishedAppPersistence refuses every deterministic path/type conflict
// before the signed envelope is claimed. The service writer lock keeps this
// frozen plan exclusive from other publishes until it is consumed.
func planPublishedAppPersistence(catalogRoot, slotDir string) (publishedAppPersistencePlan, error) {
	var zero publishedAppPersistencePlan
	root, err := filepath.Abs(catalogRoot)
	if err != nil {
		return zero, err
	}
	slot, err := filepath.Abs(slotDir)
	if err != nil {
		return zero, err
	}
	packages := filepath.Join(root, "packages")
	rel, err := filepath.Rel(packages, slot)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return zero, errors.New("resolved slot escapes catalog packages root")
	}
	parts := strings.Split(rel, string(os.PathSeparator))
	if len(parts) != 3 {
		return zero, errors.New("resolved slot is not developer/repo/slug")
	}
	for _, part := range parts {
		if !isSafePathSegment(part) || len(part) > 255 {
			return zero, errors.New("resolved slot contains unsafe filesystem component")
		}
	}

	for _, dir := range []string{root, packages, filepath.Join(packages, parts[0]), filepath.Join(packages, parts[0], parts[1]), slot} {
		info, statErr := os.Lstat(dir)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return zero, fmt.Errorf("lstat source path: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return zero, fmt.Errorf("source path is not a real directory: %s", dir)
		}
	}
	if info, statErr := os.Lstat(slot); statErr == nil && info.IsDir() {
		for _, name := range []string{"app.spk", "RELEASE.json", "metadata.json"} {
			targetInfo, targetErr := os.Lstat(filepath.Join(slot, name))
			if errors.Is(targetErr, os.ErrNotExist) {
				continue
			}
			if targetErr != nil {
				return zero, fmt.Errorf("lstat source target: %w", targetErr)
			}
			if targetInfo.Mode()&os.ModeSymlink != 0 || !targetInfo.Mode().IsRegular() {
				return zero, fmt.Errorf("source target is not a regular file: %s", name)
			}
		}
	}
	return publishedAppPersistencePlan{slotDir: slot}, nil
}

// persistPublishedAppPlanned consumes only the slot frozen by the preclaim
// plan, then writes each verified file by same-directory atomic replacement.
func persistPublishedAppPlanned(plan publishedAppPersistencePlan, spk, release, metadata []byte) error {
	return persistPublishedAppPlannedWithRuntimeContract(plan, spk, release, metadata, nil)
}

func persistPublishedAppPlannedWithRuntimeContract(plan publishedAppPersistencePlan, spk, release, metadata, runtimeContract []byte) error {
	slotDir := plan.slotDir
	if err := os.MkdirAll(slotDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", slotDir, err)
	}
	files := []struct {
		name string
		data []byte
	}{
		{"app.spk", spk},
		{"RELEASE.json", release},
		{"metadata.json", metadata},
	}
	if len(runtimeContract) != 0 {
		files = append(files, struct {
			name string
			data []byte
		}{"RUNTIME-CONTRACT.json", runtimeContract})
	}
	for _, f := range files {
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
