package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type appCatalogRecoveryCandidate struct {
	snapshot AppCatalogSnapshot
	modified int64
}

// RecoverCurrent verifies current against the exact durable rollout set and
// the boot-identity operator key. If current is missing or invalid, it scans
// direct immutable generations newest-first (generation ID breaks timestamp
// ties), switches to the first fully verified generation using the normal
// relative-current protocol, and only then removes safe interrupted-write
// artifacts. No valid generation means startup fails without cleanup.
func (s AppCatalogGenerationStore) RecoverCurrent(rolloutAppIDs []string, operatorKey ed25519.PublicKey) (AppCatalogSnapshot, error) {
	if len(operatorKey) != ed25519.PublicKeySize {
		return AppCatalogSnapshot{}, errors.New("app catalog recovery requires an ed25519 operator public key")
	}
	if err := s.validateRoot(); err != nil {
		return AppCatalogSnapshot{}, err
	}
	validate := func(snapshot AppCatalogSnapshot) error {
		return ValidateAppCatalogSnapshot(snapshot, rolloutAppIDs, func(pointer AppCatalogPointer) error {
			return verifyAppCatalogPointer(operatorKey, pointer)
		})
	}

	current, currentErr := s.ResolveCurrent()
	if currentErr == nil {
		if err := validate(current); err == nil {
			if err := s.cleanupRecoveryOrphans(); err != nil {
				return AppCatalogSnapshot{}, fmt.Errorf("clean app catalog recovery orphans: %w", err)
			}
			return current, nil
		} else {
			currentErr = fmt.Errorf("validate current app catalog generation: %w", err)
		}
	}

	candidates, err := s.recoveryCandidates()
	if err != nil {
		return AppCatalogSnapshot{}, err
	}
	var rejected []string
	for _, candidate := range candidates {
		if current.ID != "" && candidate.snapshot.ID == current.ID {
			continue
		}
		if err := validate(candidate.snapshot); err != nil {
			rejected = append(rejected, candidate.snapshot.ID)
			continue
		}
		if err := s.SwitchCurrent(candidate.snapshot); err != nil {
			return AppCatalogSnapshot{}, fmt.Errorf("recover app catalog current to %s: %w", candidate.snapshot.ID, err)
		}
		if err := s.cleanupRecoveryOrphans(); err != nil {
			return AppCatalogSnapshot{}, fmt.Errorf("clean app catalog recovery orphans: %w", err)
		}
		return candidate.snapshot, nil
	}
	if currentErr == nil {
		currentErr = errors.New("current app catalog generation is unavailable")
	}
	return AppCatalogSnapshot{}, fmt.Errorf("no fully verified app catalog generation (current: %v; rejected: %s)", currentErr, strings.Join(rejected, ","))
}

func (s AppCatalogGenerationStore) recoveryCandidates() ([]appCatalogRecoveryCandidate, error) {
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return nil, fmt.Errorf("read app catalog generation root: %w", err)
	}
	candidates := make([]appCatalogRecoveryCandidate, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, appCatalogGenerationPrefix) {
			continue
		}
		if !validGenerationID(name) {
			return nil, fmt.Errorf("unsafe app catalog generation member %q", name)
		}
		path := filepath.Join(s.Root, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("lstat app catalog recovery candidate %s: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("app catalog recovery candidate %s is not a real directory", name)
		}
		snapshot, err := s.resolveGeneration(name)
		if err != nil {
			// A partial or corrupt real generation is a rejected candidate, not
			// an excuse to skip validation of older immutable generations.
			candidates = append(candidates, appCatalogRecoveryCandidate{
				snapshot: AppCatalogSnapshot{ID: name, Root: path},
				modified: info.ModTime().UnixNano(),
			})
			continue
		}
		candidates = append(candidates, appCatalogRecoveryCandidate{snapshot: snapshot, modified: info.ModTime().UnixNano()})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].modified != candidates[j].modified {
			return candidates[i].modified > candidates[j].modified
		}
		return candidates[i].snapshot.ID > candidates[j].snapshot.ID
	})
	return candidates, nil
}

func (s AppCatalogGenerationStore) cleanupRecoveryOrphans() error {
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(s.Root, name)
		switch {
		case strings.HasPrefix(name, "."+appCatalogGenerationPrefix) && strings.HasSuffix(name, ".tmp"):
			id := strings.TrimSuffix(strings.TrimPrefix(name, "."), ".tmp")
			if !validGenerationID(id) {
				return fmt.Errorf("unsafe interrupted generation name %q", name)
			}
			if err := validateRemovableCatalogTree(path); err != nil {
				return fmt.Errorf("unsafe interrupted generation %s: %w", name, err)
			}
			if err := os.RemoveAll(path); err != nil {
				return err
			}
			removed = true
		case strings.HasPrefix(name, ".current-"):
			suffix := strings.TrimPrefix(name, ".current-")
			id := appCatalogGenerationPrefix + suffix
			if !validGenerationID(id) {
				return fmt.Errorf("unsafe interrupted current name %q", name)
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink == 0 {
				return fmt.Errorf("interrupted current %s is not a symlink", name)
			}
			target, err := os.Readlink(path)
			if err != nil || target != id {
				return fmt.Errorf("interrupted current %s has unsafe target", name)
			}
			if err := os.Remove(path); err != nil {
				return err
			}
			removed = true
		}
	}
	if removed {
		return syncDir(s.Root)
	}
	return nil
}

func validateRemovableCatalogTree(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("temporary generation is not a real directory")
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("temporary generation contains symlink %s", path)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("temporary generation contains non-regular member %s", path)
		}
		return nil
	})
}

// exactRolloutAppIDs derives the mandatory pointer set from the complete,
// durable rollout directory. Unexpected members fail closed rather than being
// silently omitted from cold-start generation verification.
func exactRolloutAppIDs(cfg Config) ([]string, error) {
	root := rolloutStateDir(cfg)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read exact rollout set: %w", err)
	}
	appIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("lstat rollout member %s: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || filepath.Ext(name) != ".json" {
			return nil, fmt.Errorf("invalid rollout state member %s", name)
		}
		appID := strings.TrimSuffix(name, ".json")
		if !isSafePathSegment(appID) {
			return nil, fmt.Errorf("invalid rollout appId %q", appID)
		}
		if _, err := loadAppRollout(cfg, appID); err != nil {
			return nil, fmt.Errorf("validate rollout %s: %w", appID, err)
		}
		appIDs = append(appIDs, appID)
	}
	sort.Strings(appIDs)
	return appIDs, nil
}
