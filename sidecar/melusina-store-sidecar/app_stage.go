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
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	appStageSchema        = "melusina-app-stage-v1"
	appStageReceiptSchema = "melusina-app-stage-receipt-v1"
)

var appStageReceiptDomain = []byte("melusina-app-stage-receipt-v1\x00")

// stagedAppManifest is the immutable descriptor stored beside private candidate
// bytes. StageID binds the exact SPK+metadata plus release intent. RELEASE.json
// itself is provisional before Squads and gains its PDA/signature/timestamp when
// finalized, so its exact body hash is recorded for stage integrity but is not
// part of StageID.
type stagedAppManifest struct {
	Schema         string   `json:"schema"`
	StageID        string   `json:"stageId"`
	AppID          string   `json:"appId"`
	AppHash        string   `json:"appHash"`
	ReleaseHash    string   `json:"releaseHash"`
	Version        string   `json:"version"`
	SPKSHA256      string   `json:"spkSha256"`
	MetadataSHA256 string   `json:"metadataSha256"`
	ReleaseSHA256  string   `json:"releaseSha256"`
	SPKSize        int      `json:"spkSize"`
	MetadataSize   int      `json:"metadataSize"`
	ReleaseSize    int      `json:"releaseSize"`
	StoredAt       int64    `json:"storedAt"`
	SlotHint       slotHint `json:"slotHint"`
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

func buildStagedAppManifest(spk, metadata, release []byte, rel ReleaseJSON, hint slotHint, storedAt time.Time) (stagedAppManifest, error) {
	var zero stagedAppManifest
	appID := metadataAppID(metadata)
	if !isSafePathSegment(appID) {
		return zero, errors.New("metadata.json carries no safe appId")
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

	spkHash := sha256.Sum256(spk)
	metadataHash := sha256.Sum256(metadata)
	releaseHash := sha256.Sum256(release)
	releaseIntent, _ := hash32FromHex(strings.TrimSpace(rel.ReleaseHash))
	versionHash := sha256.Sum256([]byte(strings.TrimSpace(rel.Version)))
	masterMintHash := sha256.Sum256([]byte(strings.TrimSpace(rel.MasterNftMint)))
	stageHasher := sha256.New()
	_, _ = stageHasher.Write([]byte(appStageSchema + "\x00"))
	_, _ = stageHasher.Write(spkHash[:])
	_, _ = stageHasher.Write(metadataHash[:])
	_, _ = stageHasher.Write(releaseIntent[:])
	_, _ = stageHasher.Write(versionHash[:])
	_, _ = stageHasher.Write(masterMintHash[:])
	for _, part := range []string{hint.Developer, hint.Repo, hint.Slug} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		_, _ = stageHasher.Write(size[:])
		_, _ = stageHasher.Write([]byte(part))
	}
	stageID := hex.EncodeToString(stageHasher.Sum(nil))

	return stagedAppManifest{
		Schema:         appStageSchema,
		StageID:        stageID,
		AppID:          appID,
		AppHash:        strings.ToLower(computedAppHash),
		ReleaseHash:    strings.ToLower(strings.TrimSpace(rel.ReleaseHash)),
		Version:        strings.TrimSpace(rel.Version),
		SPKSHA256:      hex.EncodeToString(spkHash[:]),
		MetadataSHA256: hex.EncodeToString(metadataHash[:]),
		ReleaseSHA256:  hex.EncodeToString(releaseHash[:]),
		SPKSize:        len(spk),
		MetadataSize:   len(metadata),
		ReleaseSize:    len(release),
		StoredAt:       storedAt.UTC().Unix(),
		SlotHint:       hint,
	}, nil
}

func sameStagedReleaseIntent(staged, submitted stagedAppManifest) bool {
	return staged.StageID == submitted.StageID &&
		staged.AppID == submitted.AppID &&
		staged.AppHash == submitted.AppHash &&
		staged.ReleaseHash == submitted.ReleaseHash &&
		staged.Version == submitted.Version &&
		staged.SPKSHA256 == submitted.SPKSHA256 &&
		staged.MetadataSHA256 == submitted.MetadataSHA256 &&
		staged.SPKSize == submitted.SPKSize &&
		staged.MetadataSize == submitted.MetadataSize &&
		staged.SlotHint == submitted.SlotHint
}

func persistStagedApp(root string, manifest stagedAppManifest, spk, metadata, release []byte) error {
	if err := requireSecureDirectory(root, 0o700); err != nil {
		return fmt.Errorf("private stage root is not initialized: %w", err)
	}
	target := filepath.Join(root, manifest.StageID)
	if _, err := os.Stat(target); err == nil {
		return verifyStagedApp(target, manifest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat staged candidate: %w", err)
	}

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
	if err := syncDir(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		if _, statErr := os.Stat(target); statErr == nil {
			return verifyStagedApp(target, manifest)
		}
		return fmt.Errorf("commit staged candidate: %w", err)
	}
	cleanup = false
	return syncDir(root)
}

func loadStagedApp(root, stageID string) (stagedAppManifest, []byte, []byte, []byte, error) {
	var zero stagedAppManifest
	if len(stageID) != 64 {
		return zero, nil, nil, nil, errors.New("stageId must be 32-byte lowercase hex")
	}
	if _, err := hex.DecodeString(stageID); err != nil || strings.ToLower(stageID) != stageID {
		return zero, nil, nil, nil, errors.New("stageId must be 32-byte lowercase hex")
	}
	stageFD, err := openStagedAppDir(root, stageID)
	if err != nil {
		return zero, nil, nil, nil, err
	}
	defer syscall.Close(stageFD)
	manifestBytes, err := readStagedAppFile(stageFD, "stage.json", maxCatalogBootstrapJSON, false)
	if err != nil {
		return zero, nil, nil, nil, fmt.Errorf("read staged manifest: %w", err)
	}
	var manifest stagedAppManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return zero, nil, nil, nil, fmt.Errorf("decode staged manifest: %w", err)
	}
	if manifest.SPKSize < 0 || manifest.MetadataSize < 0 || manifest.ReleaseSize < 0 ||
		int64(manifest.SPKSize)+int64(manifest.MetadataSize)+int64(manifest.ReleaseSize) > maxAppPublishBody {
		return zero, nil, nil, nil, errors.New("staged candidate sizes exceed app publish bound")
	}
	spk, err := readStagedAppFile(stageFD, "app.spk", int64(manifest.SPKSize), true)
	if err != nil {
		return zero, nil, nil, nil, fmt.Errorf("read staged SPK: %w", err)
	}
	metadata, err := readStagedAppFile(stageFD, "metadata.json", int64(manifest.MetadataSize), true)
	if err != nil {
		return zero, nil, nil, nil, fmt.Errorf("read staged metadata: %w", err)
	}
	release, err := readStagedAppFile(stageFD, "RELEASE.json", int64(manifest.ReleaseSize), true)
	if err != nil {
		return zero, nil, nil, nil, fmt.Errorf("read staged release: %w", err)
	}
	rebuilt, err := buildStagedAppManifest(spk, metadata, release, mustReleaseJSON(release), manifest.SlotHint, time.Unix(manifest.StoredAt, 0))
	if err != nil {
		return zero, nil, nil, nil, fmt.Errorf("verify staged candidate: %w", err)
	}
	if rebuilt != manifest || manifest.StageID != stageID {
		return zero, nil, nil, nil, errors.New("staged candidate manifest/content mismatch")
	}
	return manifest, spk, metadata, release, nil
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

func verifyStagedApp(dir string, want stagedAppManifest) error {
	root := filepath.Dir(dir)
	got, _, _, _, err := loadStagedApp(root, want.StageID)
	if err != nil {
		return err
	}
	// StageID binds the immutable package and release intent. StoredAt belongs to
	// the first durable write, while the provisional RELEASE body may gain its
	// PDA, author signature, quorum and timestamp after Squads. loadStagedApp()
	// already proved the stored files match their own manifest, so retries only
	// need to match the immutable intent.
	if !sameStagedReleaseIntent(got, want) {
		return errors.New("existing staged candidate differs from submitted release intent")
	}
	return nil
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
