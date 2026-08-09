package main

import (
	"bytes"
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
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
	"github.com/hrbrlife/melusina-store-sidecar/internal/stagefinalization"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	appStageSchemaV1      = "melusina-app-stage-v1"
	appStageSchemaV2      = "melusina-app-stage-v2"
	appStageSchema        = appStageSchemaV1 // legacy test and migration shorthand
	appStageReceiptSchema = "melusina-app-stage-receipt-v1"
	maxCatalogAppIDBytes  = 255 - len(".json")
)

var appStageReceiptDomain = []byte("melusina-app-stage-receipt-v1\x00")

// stagedAppManifest is the immutable descriptor stored beside private candidate
// bytes. StageID binds the exact SPK+metadata plus release intent. RELEASE.json
// itself is provisional before Squads and gains its PDA/signature/timestamp when
// finalized, so its exact body hash is recorded for stage integrity but is not
// part of StageID.
type stagedAppManifest struct {
	Schema                string   `json:"schema"`
	StageID               string   `json:"stageId"`
	AppID                 string   `json:"appId"`
	AppHash               string   `json:"appHash"`
	ReleaseHash           string   `json:"releaseHash"`
	Version               string   `json:"version"`
	SPKSHA256             string   `json:"spkSha256"`
	MetadataSHA256        string   `json:"metadataSha256"`
	ReleaseSHA256         string   `json:"releaseSha256"`
	RuntimeContractSHA256 string   `json:"runtimeContractSha256,omitempty"`
	SPKSize               int      `json:"spkSize"`
	MetadataSize          int      `json:"metadataSize"`
	ReleaseSize           int      `json:"releaseSize"`
	RuntimeContractSize   int      `json:"runtimeContractSize,omitempty"`
	StoredAt              int64    `json:"storedAt"`
	SlotHint              slotHint `json:"slotHint"`
}

// StageReceipt proves durable private persistence only. It is deliberately
// domain-separated from Receipt: a staged candidate is NOT served and has not
// yet passed the Active ReleaseEntry gate.
type StageReceipt struct {
	Schema            string `json:"schema"`
	StageID           string `json:"stageId"`
	AppID             string `json:"appId"`
	AppHash           string `json:"appHash"`
	ReleaseHash       string `json:"releaseHash"`
	ServingDomainHash string `json:"servingDomainHash"`
	StoredAt          int64  `json:"storedAt"`
	OperatorSignature string `json:"operatorSignature"`
}

func buildStagedAppManifest(spk, metadata, release []byte, rel ReleaseJSON, hint slotHint, storedAt time.Time, runtimeContracts ...[]byte) (stagedAppManifest, error) {
	var zero stagedAppManifest
	runtimeContract, err := oneRuntimeContract(runtimeContracts)
	if err != nil {
		return zero, err
	}
	appID := metadataAppID(metadata)
	if !isSafePathSegment(appID) {
		return zero, errors.New("metadata.json carries no safe appId")
	}
	if len(appID) > maxCatalogAppIDBytes {
		return zero, errors.New("metadata.json appId exceeds derived filename limit")
	}
	computedAppHash, err := apphash.Canonical(bytes.NewReader(spk), metadata)
	if err != nil {
		return zero, fmt.Errorf("compute app hash: %w", err)
	}
	if !strings.EqualFold(computedAppHash, strings.TrimSpace(rel.AppHash)) {
		return zero, fmt.Errorf("apphash(spk,metadata)=%s != release.appHash=%s", computedAppHash, rel.AppHash)
	}
	if _, err := hash32FromHex(strings.TrimSpace(rel.ReleaseHash)); err != nil {
		return zero, fmt.Errorf("releaseHash: %w", err)
	}
	if _, err := parseSemver(rel.Version); err != nil {
		return zero, fmt.Errorf("version: %w", err)
	}
	if err := hint.validate(); err != nil {
		return zero, err
	}
	if len(runtimeContract) != 0 {
		if _, err := runtimecontract.Validate(runtimeContract, runtimecontract.Binding{
			SPK:                   spk,
			Metadata:              metadata,
			AppHash:               strings.ToLower(strings.TrimSpace(rel.AppHash)),
			Version:               rel.Version,
			ReleaseContractSHA256: rel.RuntimeContractSHA256,
			ReleaseContractSchema: rel.RuntimeContractSchema,
		}); err != nil {
			return zero, fmt.Errorf("validate staged runtime contract: %w", err)
		}
	}

	spkHash := sha256.Sum256(spk)
	metadataHash := sha256.Sum256(metadata)
	releaseHash := sha256.Sum256(release)
	runtimeContractHash := sha256.Sum256(runtimeContract)
	releaseIntent, _ := hash32FromHex(strings.TrimSpace(rel.ReleaseHash))
	versionHash := sha256.Sum256([]byte(strings.TrimSpace(rel.Version)))
	masterMintHash := sha256.Sum256([]byte(strings.TrimSpace(rel.MasterNftMint)))
	stageSchema := appStageSchemaV1
	if len(runtimeContract) != 0 {
		stageSchema = appStageSchemaV2
	}
	stageHasher := sha256.New()
	_, _ = stageHasher.Write([]byte(stageSchema + "\x00"))
	_, _ = stageHasher.Write(spkHash[:])
	_, _ = stageHasher.Write(metadataHash[:])
	_, _ = stageHasher.Write(releaseIntent[:])
	_, _ = stageHasher.Write(versionHash[:])
	_, _ = stageHasher.Write(masterMintHash[:])
	if stageSchema == appStageSchemaV2 {
		_, _ = stageHasher.Write(runtimeContractHash[:])
	}
	for _, part := range []string{hint.Developer, hint.Repo, hint.Slug} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		_, _ = stageHasher.Write(size[:])
		_, _ = stageHasher.Write([]byte(part))
	}
	stageID := hex.EncodeToString(stageHasher.Sum(nil))

	return stagedAppManifest{
		Schema:         stageSchema,
		StageID:        stageID,
		AppID:          appID,
		AppHash:        strings.ToLower(computedAppHash),
		ReleaseHash:    strings.ToLower(strings.TrimSpace(rel.ReleaseHash)),
		Version:        strings.TrimSpace(rel.Version),
		SPKSHA256:      hex.EncodeToString(spkHash[:]),
		MetadataSHA256: hex.EncodeToString(metadataHash[:]),
		ReleaseSHA256:  hex.EncodeToString(releaseHash[:]),
		RuntimeContractSHA256: func() string {
			if stageSchema == appStageSchemaV2 {
				return hex.EncodeToString(runtimeContractHash[:])
			}
			return ""
		}(),
		SPKSize:             len(spk),
		MetadataSize:        len(metadata),
		ReleaseSize:         len(release),
		RuntimeContractSize: len(runtimeContract),
		StoredAt:            storedAt.UTC().Unix(),
		SlotHint:            hint,
	}, nil
}

func sameStagedReleaseIntent(staged, submitted stagedAppManifest) bool {
	return staged.Schema == submitted.Schema &&
		staged.StageID == submitted.StageID &&
		staged.AppID == submitted.AppID &&
		staged.AppHash == submitted.AppHash &&
		staged.ReleaseHash == submitted.ReleaseHash &&
		staged.Version == submitted.Version &&
		staged.SPKSHA256 == submitted.SPKSHA256 &&
		staged.MetadataSHA256 == submitted.MetadataSHA256 &&
		staged.RuntimeContractSHA256 == submitted.RuntimeContractSHA256 &&
		staged.SPKSize == submitted.SPKSize &&
		staged.MetadataSize == submitted.MetadataSize &&
		staged.RuntimeContractSize == submitted.RuntimeContractSize &&
		staged.SlotHint == submitted.SlotHint
}

func oneRuntimeContract(values [][]byte) ([]byte, error) {
	if len(values) > 1 {
		return nil, errors.New("at most one runtime contract may be supplied")
	}
	if len(values) == 0 {
		return nil, nil
	}
	return values[0], nil
}

type stagePersistencePlan struct {
	alreadyPresent    bool
	persistedManifest stagedAppManifest
}

func planStagePersistence(root string, manifest stagedAppManifest) (stagePersistencePlan, error) {
	var plan stagePersistencePlan
	if err := requireSecureDirectory(root, 0o700); err != nil {
		return plan, fmt.Errorf("private stage root is not initialized: %w", err)
	}
	target := filepath.Join(root, manifest.StageID)
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return plan, errors.New("existing staged candidate is not a real directory")
		}
		stored, _, _, _, err := loadStagedApp(root, manifest.StageID)
		if err != nil {
			return plan, err
		}
		if !sameStagedReleaseIntent(stored, manifest) {
			return plan, errors.New("existing staged candidate differs from submitted release intent")
		}
		plan.alreadyPresent = true
		plan.persistedManifest = stored
		return plan, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return plan, fmt.Errorf("stat staged candidate: %w", err)
	}
	if err := ensureDirectoryEntryCapacity(root, 1); err != nil {
		return plan, fmt.Errorf("private stage capacity: %w", err)
	}
	plan.persistedManifest = manifest
	return plan, nil
}

func persistStagedApp(root string, manifest stagedAppManifest, spk, metadata, release []byte, runtimeContracts ...[]byte) error {
	plan, err := planStagePersistence(root, manifest)
	if err != nil {
		return err
	}
	return persistStagedAppPlanned(root, manifest, spk, metadata, release, plan, runtimeContracts...)
}

func persistStagedAppPlanned(root string, manifest stagedAppManifest, spk, metadata, release []byte, plan stagePersistencePlan, runtimeContracts ...[]byte) error {
	runtimeContract, err := runtimeContractForManifest(manifest, runtimeContracts)
	if err != nil {
		return err
	}
	if plan.alreadyPresent {
		return nil
	}
	target := filepath.Join(root, manifest.StageID)

	tmp, err := os.MkdirTemp(root, ".candidate-")
	if err != nil {
		return fmt.Errorf("create candidate temp dir: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmp)
		}
	}()
	if err := os.Chmod(tmp, 0o700); err != nil {
		return fmt.Errorf("chmod candidate temp dir: %w", err)
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal staged manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	for _, file := range []struct {
		name string
		data []byte
	}{
		{"app.spk", spk},
		{"metadata.json", metadata},
		{"RELEASE.json", release},
		{"stage.json", manifestBytes},
	} {
		if err := writeSyncedFile(filepath.Join(tmp, file.name), file.data, 0o600); err != nil {
			return err
		}
	}
	if len(runtimeContract) != 0 {
		if err := writeSyncedFile(filepath.Join(tmp, "RUNTIME-CONTRACT.json"), runtimeContract, 0o600); err != nil {
			return err
		}
	}
	if err := syncDir(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		return fmt.Errorf("commit staged candidate: %w", err)
	}
	cleanup = false
	return syncDir(root)
}

func runtimeContractForManifest(manifest stagedAppManifest, values [][]byte) ([]byte, error) {
	runtimeContract, err := oneRuntimeContract(values)
	if err != nil {
		return nil, err
	}
	switch manifest.Schema {
	case appStageSchemaV1:
		if manifest.RuntimeContractSHA256 != "" || manifest.RuntimeContractSize != 0 || len(runtimeContract) != 0 {
			return nil, errors.New("legacy v1 stage cannot carry a runtime contract")
		}
		return nil, nil
	case appStageSchemaV2:
		if manifest.RuntimeContractSize <= 0 || len(runtimeContract) != manifest.RuntimeContractSize {
			return nil, errors.New("runtime contract size does not match v2 stage manifest")
		}
		digest := sha256.Sum256(runtimeContract)
		if manifest.RuntimeContractSHA256 != hex.EncodeToString(digest[:]) {
			return nil, errors.New("runtime contract hash does not match v2 stage manifest")
		}
		return runtimeContract, nil
	default:
		return nil, fmt.Errorf("unsupported staged app schema %q", manifest.Schema)
	}
}

func ensureStagePersistenceCapacity(root, stageID string) error {
	if !validStageID(stageID) {
		return errors.New("invalid stage ID for capacity reservation")
	}
	info, err := os.Lstat(filepath.Join(root, stageID))
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("existing staged candidate is not a real directory")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return ensureDirectoryEntryCapacity(root, 1)
}

func loadStagedApp(root, stageID string) (stagedAppManifest, []byte, []byte, []byte, error) {
	manifest, spk, metadata, release, _, err := loadStagedAppWithRuntime(root, stageID)
	return manifest, spk, metadata, release, err
}

func loadStagedAppWithRuntime(root, stageID string) (stagedAppManifest, []byte, []byte, []byte, []byte, error) {
	var zero stagedAppManifest
	if len(stageID) != 64 {
		return zero, nil, nil, nil, nil, errors.New("stageId must be 32-byte lowercase hex")
	}
	if _, err := hex.DecodeString(stageID); err != nil || strings.ToLower(stageID) != stageID {
		return zero, nil, nil, nil, nil, errors.New("stageId must be 32-byte lowercase hex")
	}
	if _, err := stagefinalization.Recover(filepath.Clean(root), stageID, nil); err != nil {
		return zero, nil, nil, nil, nil, fmt.Errorf("recover staged release finalization: %w", err)
	}
	stageFD, err := openStagedAppDir(root, stageID)
	if err != nil {
		return zero, nil, nil, nil, nil, err
	}
	defer syscall.Close(stageFD)
	manifestBytes, err := readStagedAppFile(stageFD, "stage.json", maxCatalogBootstrapJSON, false)
	if err != nil {
		return zero, nil, nil, nil, nil, fmt.Errorf("read staged manifest: %w", err)
	}
	var manifest stagedAppManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return zero, nil, nil, nil, nil, fmt.Errorf("decode staged manifest: %w", err)
	}
	if manifest.Schema != appStageSchemaV1 && manifest.Schema != appStageSchemaV2 {
		return zero, nil, nil, nil, nil, fmt.Errorf("unsupported staged app schema %q", manifest.Schema)
	}
	if manifest.SPKSize < 0 || manifest.MetadataSize < 0 || manifest.ReleaseSize < 0 || manifest.RuntimeContractSize < 0 ||
		int64(manifest.SPKSize)+int64(manifest.MetadataSize)+int64(manifest.ReleaseSize)+int64(manifest.RuntimeContractSize) > maxAppPublishBody {
		return zero, nil, nil, nil, nil, errors.New("staged candidate sizes exceed app publish bound")
	}
	if manifest.Schema == appStageSchemaV1 && (manifest.RuntimeContractSHA256 != "" || manifest.RuntimeContractSize != 0) {
		return zero, nil, nil, nil, nil, errors.New("legacy v1 stage carries runtime-contract fields")
	}
	if manifest.Schema == appStageSchemaV2 && (manifest.RuntimeContractSize <= 0 || len(manifest.RuntimeContractSHA256) != 64) {
		return zero, nil, nil, nil, nil, errors.New("v2 stage lacks a runtime contract binding")
	}
	if manifest.Schema == appStageSchemaV1 {
		fd, openErr := syscall.Openat(stageFD, "RUNTIME-CONTRACT.json", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if openErr == nil {
			_ = syscall.Close(fd)
			return zero, nil, nil, nil, nil, errors.New("legacy v1 stage contains an unbound runtime contract")
		}
		if !errors.Is(openErr, syscall.ENOENT) {
			return zero, nil, nil, nil, nil, fmt.Errorf("inspect legacy runtime contract: %w", openErr)
		}
	}
	spk, err := readStagedAppFile(stageFD, "app.spk", int64(manifest.SPKSize), true)
	if err != nil {
		return zero, nil, nil, nil, nil, fmt.Errorf("read staged SPK: %w", err)
	}
	metadata, err := readStagedAppFile(stageFD, "metadata.json", int64(manifest.MetadataSize), true)
	if err != nil {
		return zero, nil, nil, nil, nil, fmt.Errorf("read staged metadata: %w", err)
	}
	release, err := readStagedAppFile(stageFD, "RELEASE.json", int64(manifest.ReleaseSize), true)
	if err != nil {
		return zero, nil, nil, nil, nil, fmt.Errorf("read staged release: %w", err)
	}
	var runtimeContract []byte
	if manifest.Schema == appStageSchemaV2 {
		runtimeContract, err = readStagedAppFile(stageFD, "RUNTIME-CONTRACT.json", int64(manifest.RuntimeContractSize), true)
		if err != nil {
			return zero, nil, nil, nil, nil, fmt.Errorf("read staged runtime contract: %w", err)
		}
	}
	rebuilt, err := buildStagedAppManifest(spk, metadata, release, mustReleaseJSON(release), manifest.SlotHint, time.Unix(manifest.StoredAt, 0), runtimeContract)
	if err != nil {
		return zero, nil, nil, nil, nil, fmt.Errorf("verify staged candidate: %w", err)
	}
	if rebuilt != manifest || manifest.StageID != stageID {
		return zero, nil, nil, nil, nil, errors.New("staged candidate manifest/content mismatch")
	}
	return manifest, spk, metadata, release, runtimeContract, nil
}

func openStagedAppDir(root, stageID string) (int, error) {
	rootFD, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open private-stage root without following links: %w", err)
	}
	defer syscall.Close(rootFD)
	stageFD, err := syscall.Openat(rootFD, stageID, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open staged candidate without following links: %w", err)
	}
	return stageFD, nil
}

func readStagedAppFile(stageFD int, name string, sizeLimit int64, requireExact bool) ([]byte, error) {
	if sizeLimit < 0 || sizeLimit > maxAppPublishBody {
		return nil, errors.New("invalid staged file size")
	}
	fd, err := syscall.Openat(stageFD, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG || stat.Size > sizeLimit || (requireExact && stat.Size != sizeLimit) {
		return nil, fmt.Errorf("staged file type/size mismatch: got %d bytes, limit/want %d", stat.Size, sizeLimit)
	}
	body, err := io.ReadAll(io.LimitReader(f, sizeLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != stat.Size || (requireExact && int64(len(body)) != sizeLimit) {
		return nil, errors.New("staged file changed during bounded read")
	}
	return body, nil
}

func mustReleaseJSON(raw []byte) ReleaseJSON {
	var rel ReleaseJSON
	_ = json.Unmarshal(raw, &rel)
	return rel
}

func writeSyncedFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	ok = true
	return nil
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open dir for fsync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	return nil
}

func signStageReceipt(operator *identity.Private, manifest stagedAppManifest, servingDomainHash [32]byte) (StageReceipt, error) {
	stageID, err := hash32FromHex(manifest.StageID)
	if err != nil {
		return StageReceipt{}, err
	}
	appHash, err := hash32FromHex(manifest.AppHash)
	if err != nil {
		return StageReceipt{}, err
	}
	releaseHash, err := hash32FromHex(manifest.ReleaseHash)
	if err != nil {
		return StageReceipt{}, err
	}
	msg := stageReceiptMessage(stageID, appHash, releaseHash, servingDomainHash, manifest.StoredAt)
	sig := operator.Sign(msg)
	return StageReceipt{
		Schema:            appStageReceiptSchema,
		StageID:           manifest.StageID,
		AppID:             manifest.AppID,
		AppHash:           manifest.AppHash,
		ReleaseHash:       manifest.ReleaseHash,
		ServingDomainHash: hex.EncodeToString(servingDomainHash[:]),
		StoredAt:          manifest.StoredAt,
		OperatorSignature: primitives.EncodeBase58(sig),
	}, nil
}

func stageReceiptMessage(stageID, appHash, releaseHash, servingDomainHash [32]byte, storedAt int64) []byte {
	msg := make([]byte, 0, len(appStageReceiptDomain)+32*4+8)
	msg = append(msg, appStageReceiptDomain...)
	msg = append(msg, stageID[:]...)
	msg = append(msg, appHash[:]...)
	msg = append(msg, releaseHash[:]...)
	msg = append(msg, servingDomainHash[:]...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(storedAt))
	msg = append(msg, ts[:]...)
	return msg
}

func verifyStageReceipt(pub ed25519.PublicKey, receipt StageReceipt) error {
	if receipt.Schema != appStageReceiptSchema {
		return errors.New("stage receipt schema mismatch")
	}
	stageID, err := hash32FromHex(receipt.StageID)
	if err != nil {
		return err
	}
	appHash, err := hash32FromHex(receipt.AppHash)
	if err != nil {
		return err
	}
	releaseHash, err := hash32FromHex(receipt.ReleaseHash)
	if err != nil {
		return err
	}
	domainHash, err := hash32FromHex(receipt.ServingDomainHash)
	if err != nil {
		return err
	}
	sig, err := primitives.DecodeBase58(receipt.OperatorSignature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, stageReceiptMessage(stageID, appHash, releaseHash, domainHash, receipt.StoredAt), sig) {
		return errors.New("stage receipt signature invalid")
	}
	return nil
}
