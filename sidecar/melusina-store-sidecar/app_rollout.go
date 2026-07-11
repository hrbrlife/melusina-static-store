package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
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
	b, err := os.ReadFile(path)
	if err != nil {
		return state, err
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir rollout state: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod rollout state: %w", err)
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

// prepareAppRollout captures the currently served release (if any) before its
// source slot is overwritten, then records new/current and old/previous. It is
// called before catalog assembly, so a failed assembly leaves the still-live old
// catalog plus a harmless, retryable rollout record.
func prepareAppRollout(cfg Config, current stagedAppManifest, now time.Time) (appRolloutState, error) {
	if prior, err := loadAppRollout(cfg, current.AppID); err == nil && prior.CurrentStageID == current.StageID {
		return prior, nil // idempotent promotion retry
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return appRolloutState{}, err
	}

	var previous stagedAppManifest
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
			previous = captured
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
	if err := writeAppRollout(cfg, state); err != nil {
		return appRolloutState{}, err
	}
	return state, nil
}

// rolloutStateIsCatalogCurrent proves that a prior rollout record reached the
// public signed catalog before it can become the next rollout's rollback
// release. A failed assembly/pointer write leaves a retryable pending record;
// it must never displace the last version users could actually install.
func rolloutStateIsCatalogCurrent(cfg Config, state appRolloutState) (bool, error) {
	pointerPath := filepath.Join(cfg.DistDir, "apps", "pointers", state.AppID+".json")
	pointerBytes, err := os.ReadFile(pointerPath)
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
	indexBytes, err := os.ReadFile(filepath.Join(cfg.DistDir, "apps", "index.json"))
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

func captureCurrentlyServedRelease(cfg Config, appID string, now time.Time) (stagedAppManifest, bool, error) {
	var zero stagedAppManifest
	b, err := os.ReadFile(filepath.Join(cfg.DistDir, "apps", "index.json"))
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
	spk, err := os.ReadFile(filepath.Join(cfg.DistDir, "packages", packageID))
	if err != nil {
		return zero, false, fmt.Errorf("read current package %s: %w", packageID, err)
	}
	metadata, err := os.ReadFile(filepath.Join(cfg.DistDir, "signatures", appID, "metadata.json"))
	if err != nil {
		return zero, false, fmt.Errorf("read current metadata: %w", err)
	}
	release, err := os.ReadFile(filepath.Join(cfg.DistDir, "attest", appID, "RELEASE.json"))
	if err != nil {
		return zero, false, fmt.Errorf("read current release: %w", err)
	}
	var rel ReleaseJSON
	if err := json.Unmarshal(release, &rel); err != nil {
		return zero, false, fmt.Errorf("decode current release: %w", err)
	}
	manifest, err := buildStagedAppManifest(spk, metadata, release, rel, slotHint{}, now)
	if err != nil {
		return zero, false, fmt.Errorf("capture current release: %w", err)
	}
	if err := persistStagedApp(cfg.PrivateStageDir, manifest, spk, metadata, release); err != nil {
		return zero, false, fmt.Errorf("retain current release: %w", err)
	}
	stored, _, _, _, err := loadStagedApp(cfg.PrivateStageDir, manifest.StageID)
	if err != nil {
		return zero, false, fmt.Errorf("reload retained release: %w", err)
	}
	return stored, true, nil
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
