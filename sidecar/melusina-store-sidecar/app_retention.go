package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

func selectVerifiedRetentionPredecessor(store AppCatalogGenerationStore, currentID string, rolloutAppIDs []string, operatorKey ed25519.PublicKey, servingDomainHash, stagedRoot string, authority configuredSquadsAuthority, expectedUID, expectedGID uint32) (string, error) {
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
		if err := validateSnapshotBytesAgainstStaged(candidate.snapshot, selections, stagedRoot, authority); err != nil {
			continue
		}
		return candidate.snapshot.ID, nil
	}
	return "", nil
}

const (
	appStageUnreferencedRetention = 7 * 24 * time.Hour
	maxRetentionRootEntries       = 256
	maxPrivateStageTreeMembers    = 16
	maxCatalogGenerationMembers   = 512
	maxRetentionDeletes           = 128
	maxRetentionTreeDepth         = 64
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

	entries, err := readDirBounded(cfg.PrivateStageDir, maxRetentionRootEntries)
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
		case name == controlReceiptDirName:
			if _, err := openOrInitializeControlReceiptLedger(cfg.PrivateStageDir); err != nil {
				return plan, fmt.Errorf("validate control receipt ledger: %w", err)
			}
			continue
		case name == hostApplyIssuanceDirName:
			// Host-apply issuance evidence is append-only, short-lived authority
			// plus durable audit evidence. It is not an app candidate and must
			// never be swept by app-stage retention, but a corrupt ledger still
			// fails the whole retention plan closed.
			if _, err := openOrInitializeHostApplyIssuanceLedger(cfg.PrivateStageDir); err != nil {
				return plan, fmt.Errorf("validate host apply issuance ledger: %w", err)
			}
			continue
		case name == hostApplyPlanDirName, name == hostApplyProofDirName, name == hostApplyPlanIssuanceDir, name == controllerUpgradeReceiptDir:
			// The typed plan/proof/reference ledger is equally append-only and
			// is validated as one coherent store. The controller receipt reference
			// namespace must never be mistaken for an expendable app stage.
			if _, err := openOrInitializeHostApplyPlanStore(cfg.PrivateStageDir); err != nil {
				return plan, fmt.Errorf("validate host apply plan store: %w", err)
			}
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

	generationEntries, err := readDirBounded(store.Root, maxRetentionRootEntries)
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
	remaining := maxRetentionDeletes
	plan.stageTempDirs = takeRetentionBatch(plan.stageTempDirs, &remaining)
	plan.stageDirs = takeRetentionBatch(plan.stageDirs, &remaining)
	plan.generationDirs = takeRetentionBatch(plan.generationDirs, &remaining)
	return plan, nil
}

func takeRetentionBatch(paths []string, remaining *int) []string {
	if *remaining <= 0 {
		return nil
	}
	if len(paths) > *remaining {
		paths = paths[:*remaining]
	}
	*remaining -= len(paths)
	return paths
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
	// A claimed-but-missing runtime contract is quarantined, not deleted. Keep
	// its private stage and pre-reconciliation generations intact until a normal
	// Store publish replaces every affected rollout with bound contract bytes.
	classified, err := classifyRolloutStatesAt(cfg, now)
	if err != nil {
		return fmt.Errorf("classify rollout state before retention: %w", err)
	}
	if len(classified.quarantined) != 0 {
		return nil
	}
	rollouts = classified.serving
	const maxBatches = (2*maxRetentionRootEntries)/maxRetentionDeletes + 1
	for batch := 0; batch < maxBatches; batch++ {
		plan, err := collectAppRetentionPlan(cfg, store, rollouts, currentID, predecessorID, now, expectedUID, expectedGID)
		if err != nil {
			return err
		}
		deleted := len(plan.stageDirs) + len(plan.stageTempDirs) + len(plan.generationDirs)
		if err := applyAppRetentionPlan(cfg, store, plan); err != nil {
			return err
		}
		if deleted < maxRetentionDeletes {
			return nil
		}
		rollouts, err = exactRolloutStatesAt(cfg, now)
		if err != nil {
			return fmt.Errorf("reload rollout state between retention batches: %w", err)
		}
	}
	return errors.New("retention batching did not converge within bounded root capacity")
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
	return walkTreeBounded(root, maxPrivateStageTreeMembers, func(path string, info os.FileInfo) error {
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
	entries, err := readDirBounded(root, 5)
	if err != nil {
		return err
	}
	want := map[string]bool{"app.spk": true, "metadata.json": true, "RELEASE.json": true, "stage.json": true}
	for _, entry := range entries {
		if (!want[entry.Name()] && entry.Name() != "RUNTIME-CONTRACT.json") || entry.IsDir() {
			return fmt.Errorf("unexpected committed private-stage member %q", entry.Name())
		}
	}
	if len(entries) == len(want) {
		return nil
	}
	if len(entries) != len(want)+1 {
		return errors.New("committed private stage must contain exactly four files, or five with a bound runtime contract")
	}
	manifestBytes, err := os.ReadFile(filepath.Join(root, "stage.json"))
	if err != nil {
		return fmt.Errorf("read stage manifest for runtime contract: %w", err)
	}
	var manifest stagedAppManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("decode stage manifest for runtime contract: %w", err)
	}
	if manifest.RuntimeContractSHA256 == "" || manifest.RuntimeContractSize <= 0 {
		return errors.New("runtime contract file is not bound by staged manifest")
	}
	return nil
}

func makeCatalogTreeRemovable(root string) error {
	var dirs []string
	if err := walkTreeBounded(root, maxCatalogGenerationMembers, func(path string, info os.FileInfo) error {
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

func readDirBounded(root string, max int) ([]os.DirEntry, error) {
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), root)
	defer f.Close()
	entries, err := f.ReadDir(max + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > max {
		return nil, fmt.Errorf("directory %s exceeds %d entries", root, max)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func walkTreeBounded(root string, max int, visit func(string, os.FileInfo) error) error {
	count := 0
	var walk func(string, int) error
	walk = func(path string, depth int) error {
		if depth > maxRetentionTreeDepth {
			return fmt.Errorf("retention tree exceeds depth %d", maxRetentionTreeDepth)
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		count++
		if count > max {
			return fmt.Errorf("retention tree %s exceeds %d members", root, max)
		}
		if err := visit(path, info); err != nil {
			return err
		}
		if !info.IsDir() {
			return nil
		}
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		dir := os.NewFile(uintptr(fd), path)
		defer dir.Close()
		for {
			entries, readErr := dir.ReadDir(1)
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return readErr
			}
			if len(entries) == 0 {
				break
			}
			if err := walk(filepath.Join(path, entries[0].Name()), depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, 0)
}

func ensureDirectoryEntryCapacity(root string, reserve int) error {
	entries, err := readDirBounded(root, maxRetentionRootEntries)
	if err != nil {
		return err
	}
	if reserve < 0 || len(entries)+reserve > maxRetentionRootEntries {
		return fmt.Errorf("directory %s has no capacity for %d reserved members", root, reserve)
	}
	return nil
}
