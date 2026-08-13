package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
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
	validate := func(snapshot AppCatalogSnapshot) error {
		if err := validateSealedCatalogTree(snapshot.Root, expectedUID, expectedGID); err != nil {
			return err
		}
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

// RebuildCurrentExcludingQuarantined creates one new immutable catalog
// generation containing only rollout selections whose staged bytes verify.
// It is deliberately narrower than a repair API: it does not alter rollout
// records, fabricate a missing RUNTIME-CONTRACT.json, or reclassify a claimed
// contract as legacy. The quarantined release remains private evidence and can
// return only through a normal, runtime-contract-bound Store publish.
func (s AppCatalogGenerationStore) RebuildCurrentExcludingQuarantined(rollouts, quarantined map[string]appRolloutState, operator *identity.Private, operatorKey ed25519.PublicKey, servingDomainHash, stagedRoot string, expectedUID, expectedGID uint32) (AppCatalogSnapshot, error) {
	if len(quarantined) == 0 {
		return AppCatalogSnapshot{}, errors.New("catalog reconciliation requires a quarantined rollout")
	}
	if operator == nil {
		return AppCatalogSnapshot{}, errors.New("app catalog reconciliation requires the active operator signer")
	}
	if len(operatorKey) != ed25519.PublicKeySize {
		return AppCatalogSnapshot{}, errors.New("app catalog reconciliation requires an ed25519 operator public key")
	}
	derivedOperatorKey, err := operator.Public().SignPublicKey()
	if err != nil || !bytes.Equal(derivedOperatorKey, operatorKey) {
		return AppCatalogSnapshot{}, errors.New("app catalog reconciliation signer does not match the boot operator key")
	}
	if strings.TrimSpace(stagedRoot) == "" {
		return AppCatalogSnapshot{}, errors.New("app catalog reconciliation requires the durable private-stage root")
	}
	rolloutAppIDs := make([]string, 0, len(rollouts))
	for appID := range rollouts {
		rolloutAppIDs = append(rolloutAppIDs, appID)
	}
	sort.Strings(rolloutAppIDs)
	validate := func(snapshot AppCatalogSnapshot) error {
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
		return validateSnapshotBytesAgainstStaged(snapshot, rollouts, stagedRoot)
	}
	return s.BuildAndSwitch(func(candidateRoot string) error {
		if err := removeQuarantinedCatalogEntries(candidateRoot, quarantined); err != nil {
			return err
		}
		return resignCandidateCatalogPointers(candidateRoot, rollouts, operator, servingDomainHash, stagedRoot, time.Now().UTC())
	}, validate)
}

// removeQuarantinedCatalogEntries edits only an unsealed, freshly copied
// candidate generation. Every entry removed from apps/index.json also loses
// its pointer, signature and release path; an unshared package is removed too.
func removeQuarantinedCatalogEntries(root string, quarantined map[string]appRolloutState) error {
	indexPath := filepath.Join(root, "apps", "index.json")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		return fmt.Errorf("read candidate app index: %w", err)
	}
	var index struct {
		Apps []map[string]any `json:"apps"`
	}
	if err := json.Unmarshal(raw, &index); err != nil {
		return fmt.Errorf("decode candidate app index: %w", err)
	}
	kept := make([]map[string]any, 0, len(index.Apps))
	removedPackages := make(map[string]struct{}, len(quarantined))
	retainedPackages := make(map[string]struct{}, len(index.Apps))
	for _, app := range index.Apps {
		appID, _ := app["appId"].(string)
		packageID, _ := app["packageId"].(string)
		if _, remove := quarantined[appID]; remove {
			if !isSafePathSegment(appID) || !validCatalogPackageID(packageID) {
				return fmt.Errorf("quarantined catalog row has invalid appId/packageId %q/%q", appID, packageID)
			}
			removedPackages[packageID] = struct{}{}
			continue
		}
		kept = append(kept, app)
		if validCatalogPackageID(packageID) {
			retainedPackages[packageID] = struct{}{}
		}
	}
	for appID := range quarantined {
		if err := removeCandidateCatalogFile(root, filepath.ToSlash(filepath.Join("apps", "pointers", appID+".json"))); err != nil {
			return fmt.Errorf("remove quarantined pointer %s: %w", appID, err)
		}
		for _, namespace := range []string{"signatures", "attest"} {
			if err := removeCandidateCatalogDirectory(root, filepath.ToSlash(filepath.Join(namespace, appID))); err != nil {
				return fmt.Errorf("remove quarantined %s for %s: %w", namespace, appID, err)
			}
		}
	}
	for packageID := range removedPackages {
		if _, retained := retainedPackages[packageID]; retained {
			continue
		}
		if err := removeCandidateCatalogFile(root, filepath.ToSlash(filepath.Join("packages", packageID))); err != nil {
			return fmt.Errorf("remove quarantined package %s: %w", packageID, err)
		}
	}
	index.Apps = kept
	body, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("encode quarantined catalog index: %w", err)
	}
	body = append(body, '\n')
	if len(body) > maxAppCatalogJSONBytes {
		return fmt.Errorf("%w: got %d bytes, cap %d", errCatalogIndexCapacity, len(body), maxAppCatalogJSONBytes)
	}
	return atomicWriteInto(filepath.Join(root, "apps"), "index.json", body)
}

func removeCandidateCatalogFile(root, relative string) error {
	path := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("candidate catalog target is not a regular file")
	}
	return os.Remove(path)
}

func removeCandidateCatalogDirectory(root, relative string) error {
	path := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("candidate catalog target is not a real directory")
	}
	if err := walkCatalogTree(path, nil); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

// resignCandidateCatalogPointers binds every surviving selection to the
// reconciled index digest. Removing a row necessarily changes that digest, so
// retaining old signatures would be a cryptographic mismatch, not recovery.
func resignCandidateCatalogPointers(root string, rollouts map[string]appRolloutState, operator *identity.Private, servingDomainHash, stagedRoot string, now time.Time) error {
	snapshot := AppCatalogSnapshot{Root: root}
	indexBytes, err := readSnapshotFileBounded(snapshot, "apps/index.json", maxAppCatalogJSONBytes)
	if err != nil {
		return err
	}
	var index catalogIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return fmt.Errorf("decode reconciled app index: %w", err)
	}
	packageByApp := make(map[string]string, len(index.Apps))
	for _, app := range index.Apps {
		if !isSafePathSegment(app.AppID) || !validCatalogPackageID(app.PackageID) {
			return errors.New("reconciled app index contains invalid appId/packageId")
		}
		if _, exists := packageByApp[app.AppID]; exists {
			return fmt.Errorf("reconciled app index duplicates appId %s", app.AppID)
		}
		packageByApp[app.AppID] = app.PackageID
	}
	catalogHash := sha256.Sum256(indexBytes)
	domainHash, err := hex.DecodeString(servingDomainHash)
	if err != nil || len(domainHash) != 32 {
		return errors.New("reconciled catalog has invalid serving domain hash")
	}
	var domain [32]byte
	copy(domain[:], domainHash)
	appIDs := make([]string, 0, len(rollouts))
	for appID := range rollouts {
		appIDs = append(appIDs, appID)
	}
	sort.Strings(appIDs)
	pointers := make(map[string]AppCatalogPointer, len(appIDs))
	bodies := make(map[string][]byte, len(appIDs))
	for _, appID := range appIDs {
		rollout := rollouts[appID]
		manifest, _, metadata, _, err := loadStagedApp(stagedRoot, rollout.CurrentStageID)
		if err != nil {
			return fmt.Errorf("load retained staged release for %s: %w", appID, err)
		}
		packageID := metadataPackageID(metadata)
		if packageID == "" || packageByApp[appID] != packageID {
			return fmt.Errorf("reconciled app index does not select rollout %s packageId %s", appID, packageID)
		}
		pointer, err := signAppCatalogPointer(operator, rollout, manifest, packageID, catalogHash, domain, now)
		if err != nil {
			return fmt.Errorf("sign reconciled pointer for %s: %w", appID, err)
		}
		body, err := json.MarshalIndent(pointer, "", "  ")
		if err != nil {
			return err
		}
		pointers[appID] = pointer
		bodies[appID] = append(body, '\n')
	}
	return WriteSignedAppCatalogPointersForGeneration(root, appCatalogPointerPlan{pointers: pointers, pointerBodies: bodies, rolloutAppIDs: appIDs})
}

func validateSnapshotBytesAgainstStaged(snapshot AppCatalogSnapshot, rollouts map[string]appRolloutState, stagedRoot string) error {
	for appID, rollout := range rollouts {
		_, stagedSPK, stagedMetadata, stagedRelease, err := loadStagedApp(stagedRoot, rollout.CurrentStageID)
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
	if staged.MasterNftMint != finalized.MasterNftMint {
		return errors.New("masterNftMint changed")
	}
	if staged.LicenseSquadsVault != finalized.LicenseSquadsVault {
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

// rolloutClassification separates selections that may safely be served from
// historical releases with precise, durable integrity failures. Quarantined
// releases stay on disk for ordinary Store-UI republish, but are excluded from
// the served catalog rather than making every unrelated valid package
// unavailable.
type rolloutClassification struct {
	serving     map[string]appRolloutState
	quarantined map[string]appRolloutState
}

// exactRolloutStates derives the mandatory *servable* pointer selections from
// the complete durable rollout directory. Unexpected members and every error
// other than a precise, durable quarantinable integrity condition still fail
// closed.
func exactRolloutStates(cfg Config) (map[string]appRolloutState, error) {
	return exactRolloutStatesAt(cfg, time.Now().UTC())
}

func exactRolloutStatesAt(cfg Config, now time.Time) (map[string]appRolloutState, error) {
	classified, err := classifyRolloutStatesAt(cfg, now)
	if err != nil {
		return nil, err
	}
	return classified.serving, nil
}

func classifyRolloutStatesAt(cfg Config, now time.Time) (rolloutClassification, error) {
	classified := rolloutClassification{
		serving:     make(map[string]appRolloutState),
		quarantined: make(map[string]appRolloutState),
	}
	root := rolloutStateDir(cfg)
	entries, err := readDirBounded(root, maxRetentionRootEntries)
	if err != nil {
		return rolloutClassification{}, fmt.Errorf("read exact rollout set: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if err != nil {
			return rolloutClassification{}, fmt.Errorf("lstat rollout member %s: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || filepath.Ext(name) != ".json" {
			return rolloutClassification{}, fmt.Errorf("invalid rollout state member %s", name)
		}
		appID := strings.TrimSuffix(name, ".json")
		if !isSafePathSegment(appID) {
			return rolloutClassification{}, fmt.Errorf("invalid rollout appId %q", appID)
		}
		rollout, err := loadAppRollout(cfg, appID)
		if err != nil {
			return rolloutClassification{}, fmt.Errorf("validate rollout %s: %w", appID, err)
		}
		if err := validateRolloutStagedSelectionsAt(cfg, rollout, now); err != nil {
			if quarantinableHistoricalStageError(err) {
				classified.quarantined[appID] = rollout
				continue
			}
			return rolloutClassification{}, fmt.Errorf("validate rollout %s staged selection: %w", appID, err)
		}
		classified.serving[appID] = rollout
	}
	return classified, nil
}

// quarantinableHistoricalStageError deliberately names only permanent,
// cryptographically-provable historical stage failures. Filesystem, network,
// parsing, and authorization errors remain fail-closed instead of being hidden
// as a quarantine.
func quarantinableHistoricalStageError(err error) bool {
	return errors.Is(err, runtimecontract.ErrEmpty) || errors.Is(err, ErrStagedReleaseAppHashMismatch)
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
