package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const appRolloutSchema = "melusina-app-rollout-v1"

var appRolloutReceiptDomain = []byte("melusina-app-rollout-receipt-v1\x00")

// appRolloutState is private store state. The public signed catalog selects the
// current release for new installs; this record retains only the immediately
// previous release for authenticated rollback/package serving during a bounded
// grace period.
type appRolloutState struct {
	Schema             string `json:"schema"`
	AppID              string `json:"appId"`
	CurrentStageID     string `json:"currentStageId"`
	CurrentAppHash     string `json:"currentAppHash"`
	CurrentVersion     string `json:"currentVersion"`
	PreviousStageID    string `json:"previousStageId,omitempty"`
	PreviousAppHash    string `json:"previousAppHash,omitempty"`
	PreviousVersion    string `json:"previousVersion,omitempty"`
	ActivatedAt        int64  `json:"activatedAt"`
	PreviousValidUntil int64  `json:"previousValidUntil,omitempty"`

	// capturedPrevious is populated only while preparing the first rollout for
	// an app that is already present in the public catalog. It deliberately is
	// not serialized: preparation is a read-only pre-claim operation, while
	// commitAppRollout durably retains these exact bytes after nonce claim.
	capturedPrevious            *capturedAppRelease
	capturedPreviousPersistence stagePersistencePlan
}

type capturedAppRelease struct {
	manifest        stagedAppManifest
	spk             []byte
	metadata        []byte
	release         []byte
	runtimeContract []byte
}

// AppRolloutReceipt is the operator-signed current/previous activation record
// returned with the normal provenance receipt. Unlike the provenance signature,
// this signature covers the rollback deadline and both release hashes.
type AppRolloutReceipt struct {
	Schema             string `json:"schema"`
	AppID              string `json:"appId"`
	CurrentStageID     string `json:"currentStageId"`
	CurrentAppHash     string `json:"currentAppHash"`
	CurrentVersion     string `json:"currentVersion"`
	PreviousStageID    string `json:"previousStageId,omitempty"`
	PreviousAppHash    string `json:"previousAppHash,omitempty"`
	PreviousVersion    string `json:"previousVersion,omitempty"`
	ActivatedAt        int64  `json:"activatedAt"`
	PreviousValidUntil int64  `json:"previousValidUntil,omitempty"`
	ServingDomainHash  string `json:"servingDomainHash"`
	OperatorSignature  string `json:"operatorSignature"`
}

func appRollbackWindow(cfg Config) time.Duration {
	switch {
	case cfg.AppRollbackWindowSeconds < 0:
		return 0
	case cfg.AppRollbackWindowSeconds == 0:
		return 24 * time.Hour
	default:
		return time.Duration(cfg.AppRollbackWindowSeconds) * time.Second
	}
}

func rolloutStateDir(cfg Config) string {
	return filepath.Join(cfg.PrivateStageDir, "rollouts")
}

func rolloutStatePath(cfg Config, appID string) (string, error) {
	if !isSafePathSegment(appID) {
		return "", errors.New("unsafe appId for rollout state")
	}
	return filepath.Join(rolloutStateDir(cfg), appID+".json"), nil
}

func loadAppRollout(cfg Config, appID string) (appRolloutState, error) {
	var state appRolloutState
	path, err := rolloutStatePath(cfg, appID)
	if err != nil {
		return state, err
	}
	dirFD, err := syscall.Open(filepath.Dir(path), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return state, err
	}
	defer syscall.Close(dirFD)
	fd, err := syscall.Openat(dirFD, filepath.Base(path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return state, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 0 || info.Size() > maxCatalogBootstrapJSON {
		return state, errors.New("rollout state type, mode, or size is invalid")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCatalogBootstrapJSON+1))
	if err != nil {
		return state, err
	}
	if int64(len(b)) != info.Size() || len(b) > maxCatalogBootstrapJSON {
		return state, errors.New("rollout state changed during bounded read")
	}
	if err := json.Unmarshal(b, &state); err != nil {
		return appRolloutState{}, fmt.Errorf("decode rollout state: %w", err)
	}
	if state.Schema != appRolloutSchema || state.AppID != appID {
		return appRolloutState{}, errors.New("rollout state schema/appId mismatch")
	}
	return state, nil
}

func writeAppRollout(cfg Config, state appRolloutState) error {
	path, err := rolloutStatePath(cfg, state.AppID)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := requireSecureDirectory(dir, 0o700); err != nil {
		return fmt.Errorf("rollout state is not initialized: %w", err)
	}
	if err := ensureDirectoryEntryCapacity(dir, 1); err != nil {
		return fmt.Errorf("rollout state capacity: %w", err)
	}
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rollout state: %w", err)
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(dir, ".rollout-")
	if err != nil {
		return fmt.Errorf("create rollout temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod rollout temp: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		return fmt.Errorf("write rollout temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("fsync rollout temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close rollout temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit rollout state: %w", err)
	}
	cleanup = false
	return syncDir(dir)
}

// prepareAppRollout computes the new/current and old/previous rollout plan. It
// is intentionally read-only so callers may run every rollout check before the
// durable nonce claim without consuming the request or mutating store state.
// If the public release must be retained, its exact bytes are carried only in
// the returned in-memory state until commitAppRollout is called post-claim.
func prepareAppRollout(cfg Config, current stagedAppManifest, now time.Time) (appRolloutState, error) {
	if prior, err := loadAppRollout(cfg, current.AppID); err == nil && prior.CurrentStageID == current.StageID {
		return prior, nil // idempotent promotion retry
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return appRolloutState{}, err
	}

	var previous stagedAppManifest
	var previousCapture *capturedAppRelease
	if prior, err := loadAppRollout(cfg, current.AppID); err == nil && prior.CurrentStageID != "" {
		published, publishedErr := rolloutStateIsCatalogCurrent(cfg, prior)
		if publishedErr != nil {
			return appRolloutState{}, publishedErr
		}
		if !published {
			return appRolloutState{}, fmt.Errorf(
				"pending rollout %s was not published as the signed catalog current; retry that exact candidate before promoting stage %s",
				prior.CurrentStageID, current.StageID)
		}
		loaded, _, _, _, loadErr := loadStagedApp(cfg.PrivateStageDir, prior.CurrentStageID)
		if loadErr != nil {
			return appRolloutState{}, fmt.Errorf("load current rollout candidate: %w", loadErr)
		}
		previous = loaded
	} else {
		captured, ok, captureErr := captureCurrentlyServedRelease(cfg, current.AppID, now)
		if captureErr != nil {
			return appRolloutState{}, captureErr
		}
		if ok {
			previous = captured.manifest
			previousCapture = &captured
		}
	}

	state := appRolloutState{
		Schema:         appRolloutSchema,
		AppID:          current.AppID,
		CurrentStageID: current.StageID,
		CurrentAppHash: current.AppHash,
		CurrentVersion: current.Version,
		ActivatedAt:    now.UTC().Unix(),
	}
	window := appRollbackWindow(cfg)
	if previous.StageID != "" && previous.StageID != current.StageID && window > 0 {
		state.PreviousStageID = previous.StageID
		state.PreviousAppHash = previous.AppHash
		state.PreviousVersion = previous.Version
		state.PreviousValidUntil = now.Add(window).UTC().Unix()
	}
	if previousCapture != nil && previousCapture.manifest.StageID == state.PreviousStageID {
		state.capturedPrevious = previousCapture
	}
	return state, nil
}

// commitAppRollout performs the durable half of a prepared rollout. It must be
// called only after the request's nonce has been durably claimed. Retaining the
// prior bytes before the rollout record makes a partial failure retryable: the
// retained candidate is immutable and still is not selected for serving until
// the rollout state is committed.
func commitAppRollout(cfg Config, state appRolloutState) error {
	if state.capturedPrevious != nil {
		captured := state.capturedPrevious
		if state.PreviousStageID == "" || captured.manifest.StageID != state.PreviousStageID {
			return errors.New("captured previous release does not match rollout state")
		}
		if err := persistStagedAppPlannedWithRuntimeContract(cfg.PrivateStageDir, captured.manifest, captured.spk, captured.metadata, captured.release, captured.runtimeContract, state.capturedPreviousPersistence); err != nil {
			return fmt.Errorf("retain current release: %w", err)
		}
	}
	return writeAppRollout(cfg, state)
}

// rolloutStateIsCatalogCurrent proves that a prior rollout record reached the
// public signed catalog before it can become the next rollout's rollback
// release. A failed assembly/pointer write leaves a retryable pending record;
// it must never displace the last version users could actually install.
func rolloutStateIsCatalogCurrent(cfg Config, state appRolloutState) (bool, error) {
	snapshot := AppCatalogSnapshot{Root: cfg.DistDir}
	pointerPath := filepath.ToSlash(filepath.Join("apps", "pointers", state.AppID+".json"))
	pointerBytes, err := readSnapshotFileBounded(snapshot, pointerPath, maxAppCatalogJSONBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read signed catalog pointer: %w", err)
	}
	var pointer AppCatalogPointer
	if err := json.Unmarshal(pointerBytes, &pointer); err != nil {
		return false, fmt.Errorf("decode signed catalog pointer: %w", err)
	}
	if pointer.AppID != state.AppID || pointer.StageID != state.CurrentStageID ||
		pointer.AppHash != state.CurrentAppHash || pointer.Version != state.CurrentVersion {
		return false, nil
	}
	indexBytes, err := readSnapshotFileBounded(snapshot, "apps/index.json", maxAppCatalogJSONBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read assembled app catalog: %w", err)
	}
	indexHash := sha256.Sum256(indexBytes)
	if pointer.CatalogSHA256 != hex.EncodeToString(indexHash[:]) {
		return false, nil
	}
	var index catalogIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return false, fmt.Errorf("decode assembled app catalog: %w", err)
	}
	for _, app := range index.Apps {
		if strings.TrimSpace(app.AppID) == state.AppID {
			return strings.TrimSpace(app.PackageID) == pointer.PackageID, nil
		}
	}
	return false, nil
}

func captureCurrentlyServedRelease(cfg Config, appID string, now time.Time) (capturedAppRelease, bool, error) {
	var zero capturedAppRelease
	snapshot := AppCatalogSnapshot{Root: cfg.DistDir}
	b, err := readSnapshotFileBounded(snapshot, "apps/index.json", maxAppCatalogJSONBytes)
	if errors.Is(err, os.ErrNotExist) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, fmt.Errorf("read current catalog index: %w", err)
	}
	var idx catalogIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		return zero, false, fmt.Errorf("decode current catalog index: %w", err)
	}
	var packageID string
	for _, app := range idx.Apps {
		if strings.TrimSpace(app.AppID) == appID {
			packageID = strings.TrimSpace(app.PackageID)
			break
		}
	}
	if packageID == "" {
		return zero, false, nil
	}
	spk, err := readSnapshotFileBounded(snapshot, filepath.ToSlash(filepath.Join("packages", packageID)), maxAppPublishBody)
	if err != nil {
		return zero, false, fmt.Errorf("read current package %s: %w", packageID, err)
	}
	metadata, err := readSnapshotFileBounded(snapshot, filepath.ToSlash(filepath.Join("signatures", appID, "metadata.json")), maxAppPublishBody)
	if err != nil {
		return zero, false, fmt.Errorf("read current metadata: %w", err)
	}
	release, err := readSnapshotFileBounded(snapshot, filepath.ToSlash(filepath.Join("attest", appID, "RELEASE.json")), maxAppPublishBody)
	if err != nil {
		return zero, false, fmt.Errorf("read current release: %w", err)
	}
	var rel ReleaseJSON
	if err := json.Unmarshal(release, &rel); err != nil {
		return zero, false, fmt.Errorf("decode current release: %w", err)
	}
	var runtimeContract []byte
	binding := runtimecontract.Binding{
		SPK: spk, Metadata: metadata, AppHash: rel.AppHash, Version: rel.Version,
		ReleaseContractSHA256: rel.RuntimeContractSHA256, ReleaseContractSchema: rel.RuntimeContractSchema,
	}
	if runtimecontract.RequiresContract(binding) {
		runtimeContract, err = readSnapshotFileBounded(snapshot, filepath.ToSlash(filepath.Join("attest", appID, "RUNTIME-CONTRACT.json")), maxAppPublishBody)
		if err != nil {
			return zero, false, fmt.Errorf("read current runtime contract: %w", err)
		}
		if _, err := runtimecontract.Validate(runtimeContract, binding); err != nil {
			return zero, false, fmt.Errorf("validate current runtime contract: %w", err)
		}
	}
	manifest, err := buildStagedAppManifestWithRuntimeContract(spk, metadata, release, runtimeContract, rel, slotHint{}, now)
	if err != nil {
		return zero, false, fmt.Errorf("capture current release: %w", err)
	}
	return capturedAppRelease{
		manifest:        manifest,
		spk:             append([]byte(nil), spk...),
		metadata:        append([]byte(nil), metadata...),
		release:         append([]byte(nil), release...),
		runtimeContract: append([]byte(nil), runtimeContract...),
	}, true, nil
}

func metadataPackageID(metadata []byte) string {
	var m struct {
		PackageID string `json:"packageId"`
	}
	if json.Unmarshal(metadata, &m) != nil {
		return ""
	}
	return strings.TrimSpace(m.PackageID)
}

func signAppRolloutReceipt(operator *identity.Private, state appRolloutState, domainHash [32]byte) (AppRolloutReceipt, error) {
	msg, err := appRolloutReceiptMessage(state, domainHash)
	if err != nil {
		return AppRolloutReceipt{}, err
	}
	return AppRolloutReceipt{
		Schema:             state.Schema,
		AppID:              state.AppID,
		CurrentStageID:     state.CurrentStageID,
		CurrentAppHash:     state.CurrentAppHash,
		CurrentVersion:     state.CurrentVersion,
		PreviousStageID:    state.PreviousStageID,
		PreviousAppHash:    state.PreviousAppHash,
		PreviousVersion:    state.PreviousVersion,
		ActivatedAt:        state.ActivatedAt,
		PreviousValidUntil: state.PreviousValidUntil,
		ServingDomainHash:  hex.EncodeToString(domainHash[:]),
		OperatorSignature:  primitives.EncodeBase58(operator.Sign(msg)),
	}, nil
}

func appRolloutReceiptMessage(state appRolloutState, domainHash [32]byte) ([]byte, error) {
	currentStage, err := hash32FromHex(state.CurrentStageID)
	if err != nil {
		return nil, fmt.Errorf("current stage id: %w", err)
	}
	currentHash, err := hash32FromHex(state.CurrentAppHash)
	if err != nil {
		return nil, fmt.Errorf("current app hash: %w", err)
	}
	var previousStage, previousHash [32]byte
	if state.PreviousStageID != "" {
		previousStage, err = hash32FromHex(state.PreviousStageID)
		if err != nil {
			return nil, fmt.Errorf("previous stage id: %w", err)
		}
	}
	if state.PreviousAppHash != "" {
		previousHash, err = hash32FromHex(state.PreviousAppHash)
		if err != nil {
			return nil, fmt.Errorf("previous app hash: %w", err)
		}
	}
	appIDHash := sha256.Sum256([]byte(state.AppID))
	currentVersionHash := sha256.Sum256([]byte(state.CurrentVersion))
	previousVersionHash := sha256.Sum256([]byte(state.PreviousVersion))
	msg := make([]byte, 0, len(appRolloutReceiptDomain)+32*8+16)
	msg = append(msg, appRolloutReceiptDomain...)
	msg = append(msg, appIDHash[:]...)
	msg = append(msg, currentVersionHash[:]...)
	msg = append(msg, currentStage[:]...)
	msg = append(msg, currentHash[:]...)
	msg = append(msg, previousVersionHash[:]...)
	msg = append(msg, previousStage[:]...)
	msg = append(msg, previousHash[:]...)
	msg = append(msg, domainHash[:]...)
	var times [16]byte
	binary.BigEndian.PutUint64(times[0:8], uint64(state.ActivatedAt))
	binary.BigEndian.PutUint64(times[8:16], uint64(state.PreviousValidUntil))
	msg = append(msg, times[:]...)
	return msg, nil
}

func verifyAppRolloutReceipt(pub ed25519.PublicKey, receipt AppRolloutReceipt) error {
	if receipt.Schema != appRolloutSchema {
		return errors.New("rollout receipt schema mismatch")
	}
	domainHash, err := hash32FromHex(receipt.ServingDomainHash)
	if err != nil {
		return err
	}
	state := appRolloutState{
		Schema:             receipt.Schema,
		AppID:              receipt.AppID,
		CurrentStageID:     receipt.CurrentStageID,
		CurrentAppHash:     receipt.CurrentAppHash,
		CurrentVersion:     receipt.CurrentVersion,
		PreviousStageID:    receipt.PreviousStageID,
		PreviousAppHash:    receipt.PreviousAppHash,
		PreviousVersion:    receipt.PreviousVersion,
		ActivatedAt:        receipt.ActivatedAt,
		PreviousValidUntil: receipt.PreviousValidUntil,
	}
	msg, err := appRolloutReceiptMessage(state, domainHash)
	if err != nil {
		return err
	}
	sig, err := primitives.DecodeBase58(receipt.OperatorSignature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("rollout receipt signature invalid")
	}
	return nil
}
