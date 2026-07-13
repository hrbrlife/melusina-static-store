package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func selectVerifiedRetentionPredecessor(store AppCatalogGenerationStore, currentID string, rolloutAppIDs []string, operatorKey ed25519.PublicKey, servingDomainHash, stagedRoot string, expectedUID, expectedGID uint32) (string, error) {
	candidates, err := store.recoveryCandidates()
	if err != nil {
		return "", err
	}
	for _, candidate := range candidates {
		if candidate.snapshot.ID == currentID {
			continue
		}
		if err := validateSealedCatalogTree(candidate.snapshot.Root, expectedUID, expectedGID); err != nil {
			continue
		}
		selections := make(map[string]appRolloutState, len(rolloutAppIDs))
		err := ValidateAppCatalogSnapshot(candidate.snapshot, rolloutAppIDs, func(pointer AppCatalogPointer) error {
			if err := verifyAppCatalogPointer(operatorKey, pointer); err != nil {
				return err
			}
			if pointer.ServingDomainHash != servingDomainHash {
				return errors.New("retention predecessor serving domain mismatch")
			}
			selections[pointer.AppID] = appRolloutState{
				Schema: appRolloutSchema, AppID: pointer.AppID,
				CurrentStageID: pointer.StageID, CurrentAppHash: pointer.AppHash,
				CurrentVersion: pointer.Version,
			}
			return nil
		})
		if err != nil {
			continue
		}
		if err := validateSnapshotBytesAgainstStaged(candidate.snapshot, selections, stagedRoot); err != nil {
			continue
		}
		return candidate.snapshot.ID, nil
	}
	return "", nil
}

const (
	appStageUnreferencedRetention = 7 * 24 * time.Hour
)

type appRetentionPlan struct {
	stageDirs      []string
	stageTempDirs  []string
	generationDirs []string
	rolloutUpdates []appRolloutState
}

// collectAppRetentionPlan performs the complete validation pass before any
// removal. Validation failures therefore leave every candidate untouched.
func collectAppRetentionPlan(cfg Config, store AppCatalogGenerationStore, rollouts map[string]appRolloutState, currentID, predecessorID string, now time.Time, expectedUID, expectedGID uint32) (appRetentionPlan, error) {
	var plan appRetentionPlan
	selected, err := store.ResolveCurrent()
	if err != nil {
		return plan, fmt.Errorf("resolve retention current: %w", err)
	}
	if selected.ID != currentID {
		return plan, fmt.Errorf("retention current mismatch: selected %s, requested %s", selected.ID, currentID)
	}
	if predecessorID != "" && !validGenerationID(predecessorID) {
		return plan, errors.New("invalid retention predecessor generation ID")
	}
	protectedStages := make(map[string]bool)
	for _, rollout := range rollouts {
		protectedStages[rollout.CurrentStageID] = true
		if rollout.PreviousStageID != "" && rollout.PreviousValidUntil >= now.UTC().Unix() {
			protectedStages[rollout.PreviousStageID] = true
		} else if rollout.PreviousStageID != "" {
			rollout.PreviousStageID = ""
			rollout.PreviousAppHash = ""
			rollout.PreviousVersion = ""
			rollout.PreviousValidUntil = 0
			plan.rolloutUpdates = append(plan.rolloutUpdates, rollout)
		}
	}

	entries, err := os.ReadDir(cfg.PrivateStageDir)
	if err != nil {
		return plan, fmt.Errorf("read private-stage retention root: %w", err)
	}
	cutoff := now.UTC().Add(-appStageUnreferencedRetention).Unix()
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(cfg.PrivateStageDir, name)
		switch {
		case name == publishNonceLedgerDirName || name == "rollouts":
			continue
		case validStageID(name):
			if err := validateCommittedStageTree(path, expectedUID, expectedGID); err != nil {
				return plan, fmt.Errorf("validate retained stage %s: %w", name, err)
			}
			manifest, _, _, _, err := loadStagedApp(cfg.PrivateStageDir, name)
			if err != nil {
				return plan, fmt.Errorf("validate retained stage %s content: %w", name, err)
			}
			if !protectedStages[name] && manifest.StoredAt < cutoff {
				plan.stageDirs = append(plan.stageDirs, path)
			}
		case validCandidateTempName(name):
			if err := validatePrivateStageTree(path, expectedUID, expectedGID); err != nil {
				return plan, fmt.Errorf("validate interrupted stage %s: %w", name, err)
			}
			plan.stageTempDirs = append(plan.stageTempDirs, path)
		default:
			return plan, fmt.Errorf("unsafe private-stage retention member %q", name)
		}
	}

	generationEntries, err := os.ReadDir(store.Root)
	if err != nil {
		return plan, fmt.Errorf("read generation retention root: %w", err)
	}
	for _, entry := range generationEntries {
		name := entry.Name()
		path := filepath.Join(store.Root, name)
		switch {
		case name == appCatalogCurrentLink || name == catalogNonceSentinelName:
			continue
		case validGenerationID(name):
			if err := validateSealedCatalogTree(path, expectedUID, expectedGID); err != nil {
				return plan, fmt.Errorf("validate generation retention member %s: %w", name, err)
			}
			if name != currentID && name != predecessorID {
				plan.generationDirs = append(plan.generationDirs, path)
			}
		default:
			return plan, fmt.Errorf("unsafe generation retention member %q", name)
		}
	}
	sort.Strings(plan.stageDirs)
	sort.Strings(plan.stageTempDirs)
	sort.Strings(plan.generationDirs)
	return plan, nil
}

func applyAppRetentionPlan(cfg Config, store AppCatalogGenerationStore, plan appRetentionPlan) error {
	sort.Slice(plan.rolloutUpdates, func(i, j int) bool { return plan.rolloutUpdates[i].AppID < plan.rolloutUpdates[j].AppID })
	for _, rollout := range plan.rolloutUpdates {
		if err := writeAppRollout(cfg, rollout); err != nil {
			return fmt.Errorf("clear expired rollout predecessor %s: %w", rollout.AppID, err)
		}
	}
	stageRemoved := false
	for _, path := range append(plan.stageTempDirs, plan.stageDirs...) {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove private-stage retention member: %w", err)
		}
		stageRemoved = true
	}
	if stageRemoved {
		if err := syncDir(cfg.PrivateStageDir); err != nil {
			return fmt.Errorf("fsync private-stage retention root: %w", err)
		}
	}
	generationRemoved := false
	for _, path := range plan.generationDirs {
		if err := makeCatalogTreeRemovable(path); err != nil {
			return err
		}
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove catalog generation: %w", err)
		}
		generationRemoved = true
	}
	if generationRemoved {
		if err := syncDir(store.Root); err != nil {
			return fmt.Errorf("fsync generation retention root: %w", err)
		}
	}
	return nil
}

func runAppRetentionGC(cfg Config, store AppCatalogGenerationStore, rollouts map[string]appRolloutState, currentID, predecessorID string, now time.Time, expectedUID, expectedGID uint32) error {
	if store.Barrier != nil {
		store.Barrier.Lock()
		defer store.Barrier.Unlock()
	}
	plan, err := collectAppRetentionPlan(cfg, store, rollouts, currentID, predecessorID, now, expectedUID, expectedGID)
	if err != nil {
		return err
	}
	return applyAppRetentionPlan(cfg, store, plan)
}

func validStageID(name string) bool {
	if len(name) != 64 || strings.ToLower(name) != name {
		return false
	}
	for _, c := range name {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validCandidateTempName(name string) bool {
	const prefix = ".candidate-"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, prefix)
	if len(suffix) < 1 || len(suffix) > 10 {
		return false
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func validatePrivateStageTree(root string, expectedUID, expectedGID uint32) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("private stage contains symlink %s", path)
		}
		if fileUID(info) != expectedUID || fileGID(info) != expectedGID {
			return fmt.Errorf("private stage member %s owner is not %d:%d", path, expectedUID, expectedGID)
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0o700 {
				return fmt.Errorf("private stage directory %s mode is not 0700", path)
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return fmt.Errorf("private stage file %s is not mode-0600 regular", path)
		}
		return nil
	})
}

func validateCommittedStageTree(root string, expectedUID, expectedGID uint32) error {
	if err := validatePrivateStageTree(root, expectedUID, expectedGID); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	want := map[string]bool{"app.spk": true, "metadata.json": true, "RELEASE.json": true, "stage.json": true}
	if len(entries) != len(want) {
		return errors.New("committed private stage must contain exactly four files")
	}
	for _, entry := range entries {
		if !want[entry.Name()] || entry.IsDir() {
			return fmt.Errorf("unexpected committed private-stage member %q", entry.Name())
		}
	}
	return nil
}

func makeCatalogTreeRemovable(root string) error {
	var dirs []string
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refuse to remove catalog tree containing a symlink")
		}
		if info.IsDir() {
			dirs = append(dirs, path)
		}
		return nil
	}); err != nil {
		return err
	}
	for _, dir := range dirs {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("make catalog generation removable: %w", err)
		}
	}
	return nil
}
