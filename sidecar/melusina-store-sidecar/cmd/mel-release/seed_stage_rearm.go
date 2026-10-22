package main

// rearm-rejected-seed-stage is a product-owned reconciliation of a local
// Stage intent after a deterministically rejected Store preflight. It never
// resends Stage, changes Store state, or touches the chain. A separate normal
// stage-seed command remains necessary after this receipt is produced.

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

//go:embed seed_stage_absence_probe.py
var seedStageAbsenceProbePython string

const rejectedStageRearmSchema = "melusina.seed-stage-rejected-preflight-rearm.v1"

type rejectedStageAbsence struct {
	Schema        string `json:"schema"`
	AppID         string `json:"appId"`
	SidecarPID    int    `json:"sidecarPid"`
	Manifests     int    `json:"manifests"`
	TargetMatches int    `json:"targetMatches"`
}

type rejectedStageRearmReceipt struct {
	Schema         string               `json:"schema"`
	Outcome        string               `json:"outcome"`
	RefusalKind    string               `json:"refusalKind"`
	AppID          string               `json:"appId"`
	Version        string               `json:"version"`
	IntentSHA256   string               `json:"intentSha256"`
	RefusalSHA256  string               `json:"refusalSha256"`
	ScanSHA256     string               `json:"scanSha256"`
	StoreRead      rejectedStageAbsence `json:"storeRead"`
	ArchivedIntent string               `json:"archivedIntent"`
	RearmedAtUnix  int64                `json:"rearmedAtUnix"`
}

type rejectedStageProbeArgs struct {
	SSHKey, KnownHosts  string
	SSHPort, SidecarPID int
}

var rejectedStageProbe = probeRejectedStageAbsence

func readPinnedRearmFile(path, digest string) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 8192 ||
		!ok || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
		return nil, nil, errors.New("seed-stage-rearm-evidence-file-refused")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != digest {
		return nil, nil, errors.New("seed-stage-rearm-evidence-hash-mismatch")
	}
	return raw, info, nil
}

func requireAbsentRegularRearmPath(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("seed-stage-rearm-conflicting-state: %s", filepath.Base(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func runRejectedSeedStageRearm(c Config, catalog *Catalog, selector, version,
	intentDigest, refusalPath, refusalDigest, scanPath, scanDigest string,
	probeArgs rejectedStageProbeArgs) (string, error) {
	app, err := catalog.Select(selector)
	if err != nil {
		return "", err
	}
	if version == "" || !isLowerHex(intentDigest, 64) || !isLowerHex(refusalDigest, 64) || !isLowerHex(scanDigest, 64) {
		return "", errors.New("seed-stage-rearm-pins-required")
	}
	lock, err := acquireAppLock(appLockPath(c.lockDir(), app.AppID))
	if err != nil {
		return "", err
	}
	defer lock.Close()
	return reconcileRejectedSeedStage(c, app.AppID, version, intentDigest,
		refusalPath, refusalDigest, scanPath, scanDigest, probeArgs)
}

func reconcileRejectedSeedStage(c Config, appID, version, intentDigest,
	refusalPath, refusalDigest, scanPath, scanDigest string,
	probeArgs rejectedStageProbeArgs) (string, error) {
	intentPath := c.receiptPath(appID, "seed-stage-intent-"+safeSegment(version)+".json")
	stagePath := c.receiptPath(appID, "seed-stage-"+safeSegment(version)+".json")
	receiptPath := c.receiptPath(appID, "seed-stage-rearm-"+safeSegment(version)+".json")
	for _, path := range []string{stagePath, c.walPath(appID), c.candidatePath(appID), receiptPath} {
		if err := requireAbsentRegularRearmPath(path); err != nil {
			return "", err
		}
	}
	intentRaw, _, err := readPinnedRearmFile(intentPath, intentDigest)
	if err != nil {
		return "", err
	}
	var intent seedStageIntent
	if json.Unmarshal(intentRaw, &intent) != nil || intent.Schema != "melusina-governed-seed-stage-intent-v1" ||
		intent.AppID != appID || intent.Version != version || intent.AppHash == "" || intent.Proof == nil {
		return "", errors.New("seed-stage-rearm-intent-invalid")
	}
	refusal, refusalInfo, err := readPinnedRearmFile(refusalPath, refusalDigest)
	if err != nil {
		return "", err
	}
	refusalKind := ""
	if strings.Contains(string(refusal), "HTTP 401: check=scan_report: scan-report-expired") {
		refusalKind = "store-scan-preflight-401"
	} else if appID == "wfy0c4706yw6rp70t4a4pse8c2spm0d4hdasya6vkc4fdhhyw86h" && version == "0.6.3" &&
		strings.Contains(string(refusal), "mel-release-provider: command failed (go run): submit: check=runtime_contract: $schema must be \"urn:melusina:runtime-contract:v1\"") &&
		!strings.Contains(string(refusal), "Store HTTP") {
		// submit validates this contract before its first Store POST.
		// See cmd/submit/main.go:465-467 and :539-545.
		refusalKind = "local-mermail-runtime-contract-pre-post"
	}
	if refusalKind == "" || strings.Contains(string(refusal), "STAGE_SEED_OK") {
		return "", errors.New("seed-stage-rearm-not-preflight-refusal")
	}
	refusalSuffix := "-stage.log"
	if refusalKind == "local-mermail-runtime-contract-pre-post" {
		refusalSuffix = "-stage-a009.log"
	}
	if !strings.Contains(filepath.Base(refusalPath), appID) || !strings.HasSuffix(filepath.Base(refusalPath), refusalSuffix) ||
		scanPath != filepath.Join(c.appStateDir(appID), "provider", "scan-stage.json") {
		return "", errors.New("seed-stage-rearm-foreign-evidence-path")
	}
	scan, _, err := readPinnedRearmFile(scanPath, scanDigest)
	if err != nil {
		return "", err
	}
	var report struct {
		Method        string `json:"method"`
		Target        string `json:"target"`
		ScannedAtUnix int64  `json:"scannedAtUnix"`
		Signature     string `json:"signature"`
	}
	if json.Unmarshal(scan, &report) != nil || report.Method != "POST" || report.Target != "/publish/stage" ||
		report.ScannedAtUnix <= 0 || report.Signature == "" ||
		refusalInfo.ModTime().Unix() < report.ScannedAtUnix || refusalInfo.ModTime().Unix()-report.ScannedAtUnix > 30 {
		return "", errors.New("seed-stage-rearm-scan-refusal-mismatch")
	}
	// A fresh authenticated target read is mandatory; old saved screenshots or
	// a missing/ambiguous target response cannot rearm the local journal.
	read, err := rejectedStageProbe(appID, probeArgs)
	if err != nil || read.Schema != "melusina.store-stage-absence.v1" ||
		read.AppID != appID || read.SidecarPID != probeArgs.SidecarPID || read.Manifests < 2 || read.TargetMatches != 0 {
		return "", errors.New("seed-stage-rearm-store-absence-not-proven")
	}
	archiveRoot := filepath.Join(c.StateDir, "rejected-seed-stage-intents", appID)
	if err := os.MkdirAll(archiveRoot, 0o700); err != nil {
		return "", err
	}
	archiveInfo, err := os.Lstat(archiveRoot)
	if err != nil || !archiveInfo.IsDir() || archiveInfo.Mode()&os.ModeSymlink != 0 || archiveInfo.Mode().Perm() != 0o700 {
		return "", errors.New("seed-stage-rearm-archive-directory-refused")
	}
	archivePath := filepath.Join(archiveRoot, safeSegment(version)+"-"+intentDigest+".json")
	if err := requireAbsentRegularRearmPath(archivePath); err != nil {
		return "", err
	}
	if err := os.Rename(intentPath, archivePath); err != nil {
		return "", fmt.Errorf("seed-stage-rearm-archive: %w", err)
	}
	if err := fsyncDir(filepath.Dir(intentPath)); err != nil {
		return "", err
	}
	if err := fsyncDir(archiveRoot); err != nil {
		return "", err
	}
	receipt := rejectedStageRearmReceipt{Schema: rejectedStageRearmSchema,
		Outcome:     "rearmed-after-authenticated-preflight-refusal-no-store-stage",
		RefusalKind: refusalKind,
		AppID:       appID, Version: version, IntentSHA256: intentDigest,
		RefusalSHA256: refusalDigest, ScanSHA256: scanDigest, StoreRead: read,
		ArchivedIntent: archivePath, RearmedAtUnix: time.Now().UTC().Unix()}
	raw, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", err
	}
	if err := writeExclusive(receiptPath, append(raw, '\n')); err != nil {
		return "", err
	}
	return receiptPath, nil
}

func probeRejectedStageAbsence(appID string, args rejectedStageProbeArgs) (rejectedStageAbsence, error) {
	var zero rejectedStageAbsence
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/python3", "-c", seedStageAbsenceProbePython,
		"--app-id", appID, "--outer-ssh-key", args.SSHKey,
		"--outer-known-hosts", args.KnownHosts, "--outer-ssh-port", fmt.Sprint(args.SSHPort),
		"--sidecar-pid", fmt.Sprint(args.SidecarPID))
	output, err := cmd.Output()
	if err != nil {
		return zero, errors.New("seed-stage-rearm-authenticated-target-read-refused")
	}
	if json.Unmarshal(output, &zero) != nil {
		return rejectedStageAbsence{}, errors.New("seed-stage-rearm-authenticated-target-invalid")
	}
	return zero, nil
}
