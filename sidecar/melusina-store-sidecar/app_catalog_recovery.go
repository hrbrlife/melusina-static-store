package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
func (s AppCatalogGenerationStore) RecoverCurrent(rollouts map[string]appRolloutState, operatorKey ed25519.PublicKey, servingDomainHash, stagedRoot string, expectedUID, expectedGID uint32) (AppCatalogSnapshot, error) {
	if len(operatorKey) != ed25519.PublicKeySize {
		return AppCatalogSnapshot{}, errors.New("app catalog recovery requires an ed25519 operator public key")
	}
	if err := s.validateRoot(); err != nil {
		return AppCatalogSnapshot{}, err
	}
	rolloutAppIDs := make([]string, 0, len(rollouts))
	for appID := range rollouts {
		rolloutAppIDs = append(rolloutAppIDs, appID)
	}
	sort.Strings(rolloutAppIDs)
	validateContent := func(snapshot AppCatalogSnapshot) error {
		if err := ValidateAppCatalogSnapshot(snapshot, rolloutAppIDs, func(pointer AppCatalogPointer) error {
			if err := verifyAppCatalogPointer(operatorKey, pointer); err != nil {
				return err
			}
			rollout, ok := rollouts[pointer.AppID]
			if !ok {
				return errors.New("catalog pointer has no durable rollout")
			}
			if pointer.StageID != rollout.CurrentStageID ||
				pointer.AppHash != rollout.CurrentAppHash ||
				pointer.Version != rollout.CurrentVersion ||
				pointer.ServingDomainHash != servingDomainHash {
				return errors.New("catalog pointer does not match durable rollout selection")
			}
			return nil
		}); err != nil {
			return err
		}
		if strings.TrimSpace(stagedRoot) == "" {
			return errors.New("app catalog recovery requires the durable private-stage root")
		}
		return validateSnapshotBytesAgainstStaged(snapshot, rollouts, stagedRoot)
	}
	validateCommitted := func(snapshot AppCatalogSnapshot) error {
		if err := validateSealedCatalogTree(snapshot.Root, expectedUID, expectedGID); err != nil {
			return err
		}
		return validateContent(snapshot)
	}

	current, currentErr := s.ResolveCurrent()
	if currentErr == nil {
		if err := validateCommitted(current); err == nil {
			if err := s.cleanupRecoveryOrphans(); err != nil {
				return AppCatalogSnapshot{}, fmt.Errorf("clean app catalog recovery orphans: %w", err)
			}
			return current, nil
		} else {
			currentErr = fmt.Errorf("validate current app catalog generation: %w", err)
			// A generation whose ownership/modes or canonical SPK, metadata, or
			// release bytes are wrong is not a migration candidate: repairing it
			// would silently sanitize tampering. The only automatic rewrite is the
			// narrow v2-upgrade case where every other selected byte is exact and
			// the release-bound runtime contract alone is absent or differs.
			sealedErr := validateSealedCatalogTree(current.Root, expectedUID, expectedGID)
			repairable, eligibilityErr := recoveryRuntimeContractRepairEligible(current, rollouts, stagedRoot)
			if sealedErr == nil && eligibilityErr == nil && repairable {
				if repaired, repairErr := s.rehydrateRecoveryCurrent(current, rollouts, operatorKey, servingDomainHash, stagedRoot, validateContent); repairErr == nil {
					if err := validateCommitted(repaired); err == nil {
						if err := s.SwitchCurrent(repaired); err != nil {
							return AppCatalogSnapshot{}, fmt.Errorf("select rehydrated app catalog generation: %w", err)
						}
						if err := s.cleanupRecoveryOrphans(); err != nil {
							return AppCatalogSnapshot{}, fmt.Errorf("clean app catalog recovery orphans: %w", err)
						}
						return repaired, nil
					} else {
						currentErr = fmt.Errorf("validate rehydrated app catalog generation: %w", err)
					}
				}
			}
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
		if err := validateCommitted(candidate.snapshot); err != nil {
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

// recoveryRuntimeContractRepairEligible distinguishes the one safe migration
// repair from arbitrary sealed-generation corruption. It requires exact staged
// SPK/metadata and immutable release intent for every selection, requires all
// legacy v1 selections to remain contract-free, and returns true only when at
// least one v2 contract is missing or differs from its exact staged bytes.
func recoveryRuntimeContractRepairEligible(snapshot AppCatalogSnapshot, rollouts map[string]appRolloutState, stagedRoot string) (bool, error) {
	if strings.TrimSpace(stagedRoot) == "" {
		return false, errors.New("private-stage root is required")
	}
	needsRepair := false
	for appID, rollout := range rollouts {
		manifest, stagedSPK, stagedMetadata, stagedRelease, stagedContract, err := loadStagedAppWithRuntime(stagedRoot, rollout.CurrentStageID)
		if err != nil {
			return false, err
		}
		pointerBytes, err := readSnapshotFileBounded(snapshot, filepath.ToSlash(filepath.Join("apps", "pointers", appID+".json")), maxAppCatalogJSONBytes)
		if err != nil {
			return false, nil
		}
		var pointer AppCatalogPointer
		if err := json.Unmarshal(pointerBytes, &pointer); err != nil {
			return false, nil
		}
		for path, want := range map[string][]byte{
			filepath.ToSlash(filepath.Join("packages", pointer.PackageID)):        stagedSPK,
			filepath.ToSlash(filepath.Join("signatures", appID, "metadata.json")): stagedMetadata,
		} {
			got, err := readSnapshotFileExact(snapshot, path, int64(len(want)))
			if err != nil || !bytes.Equal(got, want) {
				return false, nil
			}
		}
		servedRelease, err := readSnapshotFileBounded(snapshot, filepath.ToSlash(filepath.Join("attest", appID, "RELEASE.json")), maxAppCatalogJSONBytes)
		if err != nil || validateFinalizedReleaseAgainstStage(stagedRelease, servedRelease) != nil {
			return false, nil
		}
		contractPath := filepath.ToSlash(filepath.Join("attest", appID, "RUNTIME-CONTRACT.json"))
		if manifest.Schema == appStageSchemaV1 {
			if requireSnapshotFileAbsent(snapshot, contractPath) != nil {
				return false, nil
			}
			continue
		}
		servedContract, err := readSnapshotFileExact(snapshot, contractPath, int64(len(stagedContract)))
		if err != nil || !bytes.Equal(servedContract, stagedContract) {
			needsRepair = true
		}
	}
	return needsRepair, nil
}

// rehydrateRecoveryCurrent creates a new candidate only after the frozen public
// pointer set has been authenticated against durable rollout state.  It never
// edits an existing generation. The caller supplies content validation because
// BuildCommittedFrom must validate its writable candidate before it can seal
// it; RecoverCurrent repeats the full sealed-tree validation after commit and
// before switching current.
func (s AppCatalogGenerationStore) rehydrateRecoveryCurrent(current AppCatalogSnapshot, rollouts map[string]appRolloutState, operatorKey ed25519.PublicKey, servingDomainHash, stagedRoot string, validateContent func(AppCatalogSnapshot) error) (AppCatalogSnapshot, error) {
	if current.ID == "" || current.Root == "" || strings.TrimSpace(stagedRoot) == "" {
		return AppCatalogSnapshot{}, errors.New("no recoverable current catalog generation or private stage root")
	}
	appIDs := make([]string, 0, len(rollouts))
	for appID := range rollouts {
		appIDs = append(appIDs, appID)
	}
	sort.Strings(appIDs)
	plan := appCatalogPointerPlan{pointers: make(map[string]AppCatalogPointer, len(appIDs)), rolloutAppIDs: appIDs}
	if err := ValidateAppCatalogSnapshot(current, appIDs, func(pointer AppCatalogPointer) error {
		if err := verifyAppCatalogPointer(operatorKey, pointer); err != nil {
			return err
		}
		rollout, ok := rollouts[pointer.AppID]
		if !ok || pointer.StageID != rollout.CurrentStageID || pointer.AppHash != rollout.CurrentAppHash || pointer.Version != rollout.CurrentVersion || pointer.ServingDomainHash != servingDomainHash {
			return errors.New("catalog pointer does not match durable rollout selection")
		}
		plan.pointers[pointer.AppID] = pointer
		return nil
	}); err != nil {
		return AppCatalogSnapshot{}, fmt.Errorf("authenticate frozen recovery pointers: %w", err)
	}
	if len(plan.pointers) != len(appIDs) {
		return AppCatalogSnapshot{}, errors.New("recovery pointer set is incomplete")
	}
	return s.BuildCommittedFrom(current.Root, func(candidateRoot string) error {
		return RehydrateAppCatalogPayloadsFromRollouts(Config{PrivateStageDir: stagedRoot}, candidateRoot, plan)
	}, validateContent)
}

func validateSnapshotBytesAgainstStaged(snapshot AppCatalogSnapshot, rollouts map[string]appRolloutState, stagedRoot string) error {
	for appID, rollout := range rollouts {
		manifest, stagedSPK, stagedMetadata, stagedRelease, stagedRuntimeContract, err := loadStagedAppWithRuntime(stagedRoot, rollout.CurrentStageID)
		if err != nil {
			return fmt.Errorf("load exact staged bytes for %s: %w", appID, err)
		}
		pointerBytes, err := readSnapshotFileBounded(snapshot, filepath.ToSlash(filepath.Join("apps", "pointers", appID+".json")), maxAppCatalogJSONBytes)
		if err != nil {
			return err
		}
		var pointer AppCatalogPointer
		if err := json.Unmarshal(pointerBytes, &pointer); err != nil {
			return err
		}
		for name, check := range map[string]struct {
			path string
			want []byte
		}{
			"SPK":      {path: filepath.ToSlash(filepath.Join("packages", pointer.PackageID)), want: stagedSPK},
			"metadata": {path: filepath.ToSlash(filepath.Join("signatures", appID, "metadata.json")), want: stagedMetadata},
		} {
			got, err := readSnapshotFileExact(snapshot, check.path, int64(len(check.want)))
			if err != nil {
				return fmt.Errorf("generation %s bytes differ from exact staged candidate for %s: %w", name, appID, err)
			}
			if !bytes.Equal(got, check.want) {
				return fmt.Errorf("generation %s bytes differ from exact staged candidate for %s", name, appID)
			}
		}
		if manifest.Schema == appStageSchemaV2 {
			contractPath := filepath.ToSlash(filepath.Join("attest", appID, "RUNTIME-CONTRACT.json"))
			servedContract, err := readSnapshotFileExact(snapshot, contractPath, int64(len(stagedRuntimeContract)))
			if err != nil {
				return fmt.Errorf("generation runtime-contract bytes differ from exact staged candidate for %s: %w", appID, err)
			}
			if !bytes.Equal(servedContract, stagedRuntimeContract) {
				return fmt.Errorf("generation runtime-contract bytes differ from exact staged candidate for %s", appID)
			}
		} else {
			contractPath := filepath.ToSlash(filepath.Join("attest", appID, "RUNTIME-CONTRACT.json"))
			if err := requireSnapshotFileAbsent(snapshot, contractPath); err != nil {
				return fmt.Errorf("legacy stage has an unbound runtime contract for %s: %w", appID, err)
			}
		}
		// A stage is intentionally created before the Squads ceremony: its
		// RELEASE.json is therefore provisional.  The catalog correctly serves
		// the ceremony-final representation, whose timestamp, ReleaseEntry PDA,
		// author signature, and quorum policy necessarily differ.  Do not require
		// byte identity across that authority transition.  Instead bind every
		// immutable release-intent field to the durable private stage.  The signed
		// catalog pointer has already bound this same appHash/releaseHash/version
		// selection to the sealed catalog generation above.
		servedRelease, err := readSnapshotFileBounded(snapshot, filepath.ToSlash(filepath.Join("attest", appID, "RELEASE.json")), maxAppCatalogJSONBytes)
		if err != nil {
			return fmt.Errorf("read finalized release for %s: %w", appID, err)
		}
		if err := validateFinalizedReleaseAgainstStage(stagedRelease, servedRelease); err != nil {
			return fmt.Errorf("generation release finalization differs from staged immutable intent for %s: %w", appID, err)
		}
	}
	return nil
}

// validateFinalizedReleaseAgainstStage permits only the fields that the chain
// ceremony is expected to finalize after a private candidate is staged.  It is
// deliberately not a generic "same parsed JSON" check: changing any release
// identity field would make the sealed catalog disagree with the exact staged
// candidate selected by the signed pointer.
func validateFinalizedReleaseAgainstStage(stagedBytes, finalizedBytes []byte) error {
	var staged, finalized ReleaseJSON
	if err := json.Unmarshal(stagedBytes, &staged); err != nil {
		return fmt.Errorf("decode staged release: %w", err)
	}
	if err := json.Unmarshal(finalizedBytes, &finalized); err != nil {
		return fmt.Errorf("decode finalized release: %w", err)
	}
	if staged.Schema != finalized.Schema {
		return errors.New("schema changed")
	}
	if staged.AppHash != finalized.AppHash {
		return errors.New("appHash changed")
	}
	if staged.ReleaseHash != finalized.ReleaseHash {
		return errors.New("releaseHash changed")
	}
	if staged.Version != finalized.Version {
		return errors.New("version changed")
	}
	if staged.RuntimeContractSchema != finalized.RuntimeContractSchema {
		return errors.New("runtimeContractSchema changed")
	}
	if staged.RuntimeContractSHA256 != finalized.RuntimeContractSHA256 {
		return errors.New("runtimeContractSha256 changed")
	}
	if staged.MasterNftMint != finalized.MasterNftMint {
		return errors.New("masterNftMint changed")
	}
	// The stage may precede creation of the Squads proposal that reveals the
	// custody vault. A blank staged value may therefore be filled by ceremony;
	// an already-declared value may never be replaced or erased.
	if staged.LicenseSquadsVault != "" && staged.LicenseSquadsVault != finalized.LicenseSquadsVault {
		return errors.New("licenseSquadsVault changed")
	}
	if staged.ReleaseNonce != finalized.ReleaseNonce {
		return errors.New("releaseNonce changed")
	}
	return nil
}

func (s AppCatalogGenerationStore) recoveryCandidates() ([]appCatalogRecoveryCandidate, error) {
	entries, err := readDirBounded(s.Root, maxRetentionRootEntries)
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
	entries, err := readDirBounded(s.Root, maxRetentionRootEntries)
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
	return walkTreeBounded(root, maxCatalogGenerationMembers, func(path string, info os.FileInfo) error {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("temporary generation contains symlink %s", path)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("temporary generation contains non-regular member %s", path)
		}
		return nil
	})
}

// exactRolloutStates derives the mandatory pointer selections from the complete,
// durable rollout directory. Unexpected members fail closed rather than being
// silently omitted from cold-start generation verification.
func exactRolloutStates(cfg Config) (map[string]appRolloutState, error) {
	return exactRolloutStatesAt(cfg, time.Now().UTC())
}

func exactRolloutStatesAt(cfg Config, now time.Time) (map[string]appRolloutState, error) {
	root := rolloutStateDir(cfg)
	entries, err := readDirBounded(root, maxRetentionRootEntries)
	if err != nil {
		return nil, fmt.Errorf("read exact rollout set: %w", err)
	}
	rollouts := make(map[string]appRolloutState, len(entries))
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
		rollout, err := loadAppRollout(cfg, appID)
		if err != nil {
			return nil, fmt.Errorf("validate rollout %s: %w", appID, err)
		}
		if err := validateRolloutStagedSelectionsAt(cfg, rollout, now); err != nil {
			return nil, fmt.Errorf("validate rollout %s staged selection: %w", appID, err)
		}
		rollouts[appID] = rollout
	}
	return rollouts, nil
}

func validateRolloutStagedSelections(cfg Config, rollout appRolloutState) error {
	return validateRolloutStagedSelectionsAt(cfg, rollout, time.Now().UTC())
}

func validateRolloutStagedSelectionsAt(cfg Config, rollout appRolloutState, now time.Time) error {
	current, _, _, _, err := loadStagedApp(cfg.PrivateStageDir, rollout.CurrentStageID)
	if err != nil {
		return fmt.Errorf("load current stage: %w", err)
	}
	if current.AppID != rollout.AppID || current.StageID != rollout.CurrentStageID ||
		current.AppHash != rollout.CurrentAppHash || current.Version != rollout.CurrentVersion {
		return errors.New("current staged candidate does not match rollout")
	}
	if rollout.PreviousStageID == "" {
		if rollout.PreviousAppHash != "" || rollout.PreviousVersion != "" || rollout.PreviousValidUntil != 0 {
			return errors.New("empty previous stage has non-empty previous selection")
		}
		return nil
	}
	if rollout.PreviousValidUntil < now.UTC().Unix() {
		return nil
	}
	previous, _, _, _, err := loadStagedApp(cfg.PrivateStageDir, rollout.PreviousStageID)
	if err != nil {
		return fmt.Errorf("load previous stage: %w", err)
	}
	if previous.AppID != rollout.AppID || previous.StageID != rollout.PreviousStageID ||
		previous.AppHash != rollout.PreviousAppHash || previous.Version != rollout.PreviousVersion {
		return errors.New("previous staged candidate does not match rollout")
	}
	return nil
}
