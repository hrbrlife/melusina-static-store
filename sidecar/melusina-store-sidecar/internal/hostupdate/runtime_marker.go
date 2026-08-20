package hostupdate

// Runtime-marker handling is deliberately controller-owned, not adapter-owned:
// the controller knows the signed generation id and the WAL owns recovery. The
// root-owned install-local registry chooses the EnvironmentFile path; the remote
// generation names only the desired component/version/hash.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const (
	runtimeMarkerSchema   = "melusina-runtime-release-info-v1"
	maxRuntimeMarkerBytes = 64 << 10
)

// runtimeMarkerPlan captures the exact marker floor before mutation. PriorPath
// is persisted in the WAL before WriteRuntimeMarker can alter the live marker.
// It is intentionally internal: callers receive the serializable fields through
// WALEntry, not arbitrary marker bytes from a remote document.
type runtimeMarkerPlan struct {
	Path      string
	PriorPath string
	PriorSHA  string
	prior     []byte
	present   bool
}

func markerPathValid(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

// planRuntimeMarker reads the prior local marker through O_NOFOLLOW. It does not
// write anything: the caller first persists its planned backup path in the WAL,
// then PersistRuntimeMarkerFloor writes the backup before any live mutation.
func planRuntimeMarker(backupRoot string, generationID uint64, c componentrelease.ComponentRelease, install componentrelease.ComponentInstall) (runtimeMarkerPlan, error) {
	if install.RuntimeEnvFile == "" {
		return runtimeMarkerPlan{}, nil
	}
	if !markerPathValid(install.RuntimeEnvFile) {
		return runtimeMarkerPlan{}, fmt.Errorf("runtime marker path %q is not absolute and clean", install.RuntimeEnvFile)
	}
	if !markerPathValid(backupRoot) {
		return runtimeMarkerPlan{}, fmt.Errorf("runtime marker backup root %q is not absolute and clean", backupRoot)
	}
	if err := ensureSecureDir(filepath.Dir(install.RuntimeEnvFile)); err != nil {
		return runtimeMarkerPlan{}, fmt.Errorf("secure runtime marker parent: %w", err)
	}
	prior, present, err := readRuntimeMarker(install.RuntimeEnvFile)
	if err != nil {
		return runtimeMarkerPlan{}, fmt.Errorf("read prior runtime marker: %w", err)
	}
	p := runtimeMarkerPlan{Path: install.RuntimeEnvFile, prior: prior, present: present}
	if !present {
		return p, nil
	}
	sum := sha256.Sum256(prior)
	p.PriorSHA = hex.EncodeToString(sum[:])
	if len(c.SHA256) < 16 {
		return runtimeMarkerPlan{}, errors.New("desired artifact hash is too short for runtime marker backup name")
	}
	if err := ensureSecureDir(filepath.Join(backupRoot, c.ComponentID)); err != nil {
		return runtimeMarkerPlan{}, fmt.Errorf("secure runtime marker backup dir: %w", err)
	}
	p.PriorPath = filepath.Join(backupRoot, c.ComponentID, fmt.Sprintf("gen%d-before-%s.env", generationID, c.SHA256[:16]))
	return p, nil
}

// PersistRuntimeMarkerFloor writes the exact prior bytes to a fresh O_EXCL file.
// Re-reading the live marker and requiring the floor to match closes a local
// TOCTOU: an external edit between plan and mutation is refused, never silently
// overwritten by a controller that would no longer know what to restore. A
// retry may reuse an existing backup only if it is a regular, no-followed file
// whose bytes exactly equal the just-proved floor; a different retained file is
// a collision and fails closed.
func PersistRuntimeMarkerFloor(p runtimeMarkerPlan) error {
	if p.Path == "" || !p.present {
		return nil
	}
	current, present, err := readRuntimeMarker(p.Path)
	if err != nil {
		return fmt.Errorf("re-read prior runtime marker: %w", err)
	}
	if !present {
		return errors.New("prior runtime marker disappeared before WAL floor persistence")
	}
	sum := sha256.Sum256(current)
	if hex.EncodeToString(sum[:]) != p.PriorSHA || string(current) != string(p.prior) {
		return errors.New("prior runtime marker changed before WAL floor persistence")
	}
	if err := writeRuntimeMarkerExclusive(p.PriorPath, p.prior); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		retained, retainedPresent, readErr := readRuntimeMarker(p.PriorPath)
		if readErr != nil {
			return fmt.Errorf("read existing retained runtime marker: %w", readErr)
		}
		if !retainedPresent {
			return errors.New("retained runtime marker disappeared after exclusive collision")
		}
		if string(retained) != string(p.prior) {
			return errors.New("retained runtime marker collision does not match the verified prior floor")
		}
	}
	return nil
}

// WriteRuntimeMarker atomically installs the signed runtime tuple before the
// adapter restarts the unit. It re-checks the pre-WAL floor so a concurrent local
// edit cannot be overwritten, and it writes only constant controller keys — never
// a remote-selected environment variable or path.
func WriteRuntimeMarker(p runtimeMarkerPlan, generationID uint64, c componentrelease.ComponentRelease) error {
	if p.Path == "" {
		return nil
	}
	if err := assertRuntimeMarkerFloor(p); err != nil {
		return err
	}
	raw, err := renderRuntimeMarker(generationID, c)
	if err != nil {
		return err
	}
	return writeRuntimeMarkerAtomic(p.Path, raw)
}

// RestoreRuntimeMarkerFromWAL restores the exact pre-apply marker before the
// rollback restart. A marker that did not exist before a fresh install is removed.
// The registry path must still agree with the persisted WAL; a changed local
// registry is never allowed to redirect recovery to a different file.
func RestoreRuntimeMarkerFromWAL(entry WALEntry, install componentrelease.ComponentInstall) error {
	if entry.RuntimeMarkerPath == "" {
		return nil
	}
	if entry.RuntimeMarkerPath != install.RuntimeEnvFile {
		return fmt.Errorf("runtime marker WAL path %q != install-local registry path %q", entry.RuntimeMarkerPath, install.RuntimeEnvFile)
	}
	if !markerPathValid(entry.RuntimeMarkerPath) {
		return fmt.Errorf("runtime marker WAL path %q is not absolute and clean", entry.RuntimeMarkerPath)
	}
	if entry.RuntimeMarkerPriorPath == "" {
		return removeRuntimeMarker(entry.RuntimeMarkerPath)
	}
	prior, present, err := readRuntimeMarker(entry.RuntimeMarkerPriorPath)
	if err != nil {
		return fmt.Errorf("read retained runtime marker: %w", err)
	}
	if !present {
		return fmt.Errorf("retained runtime marker %s is missing", entry.RuntimeMarkerPriorPath)
	}
	sum := sha256.Sum256(prior)
	if hex.EncodeToString(sum[:]) != entry.RuntimeMarkerPriorSHA256 {
		return fmt.Errorf("retained runtime marker %s hash mismatch; refusing rollback", entry.RuntimeMarkerPriorPath)
	}
	return writeRuntimeMarkerAtomic(entry.RuntimeMarkerPath, prior)
}

func assertRuntimeMarkerFloor(p runtimeMarkerPlan) error {
	current, present, err := readRuntimeMarker(p.Path)
	if err != nil {
		return fmt.Errorf("re-check runtime marker floor: %w", err)
	}
	if present != p.present {
		return errors.New("runtime marker presence changed after WAL floor persistence")
	}
	if !present {
		return nil
	}
	sum := sha256.Sum256(current)
	if hex.EncodeToString(sum[:]) != p.PriorSHA || string(current) != string(p.prior) {
		return errors.New("runtime marker changed after WAL floor persistence")
	}
	return nil
}

func renderRuntimeMarker(generationID uint64, c componentrelease.ComponentRelease) ([]byte, error) {
	if generationID == 0 {
		return nil, errors.New("runtime marker generation id must be positive")
	}
	for field, value := range map[string]string{
		"component id":  c.ComponentID,
		"version":       c.Version,
		"artifact hash": c.SHA256,
	} {
		if !safeRuntimeEnvValue(value) {
			return nil, fmt.Errorf("runtime marker %s contains unsafe EnvironmentFile characters", field)
		}
	}
	return []byte(strings.Join([]string{
		"RRS_RUNTIME_SCHEMA=" + runtimeMarkerSchema,
		"RRS_COMPONENT_ID=" + c.ComponentID,
		"RRS_GENERATION_ID=" + strconv.FormatUint(generationID, 10),
		"RRS_SIDECAR_VERSION=" + c.Version,
		"RRS_ARTIFACT_SHA256=" + strings.ToLower(c.SHA256),
		"",
	}, "\n")), nil
}

func safeRuntimeEnvValue(v string) bool {
	if strings.TrimSpace(v) == "" || len(v) > 512 {
		return false
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '.', '-', '_', '+', ':', '@', '%', '/':
			continue
		}
		return false
	}
	return true
}

func readRuntimeMarker(path string) ([]byte, bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() {
		return nil, false, errors.New("runtime marker is not a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxRuntimeMarkerBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(raw) > maxRuntimeMarkerBytes {
		return nil, false, fmt.Errorf("runtime marker exceeds %d bytes", maxRuntimeMarkerBytes)
	}
	return raw, true, nil
}

func writeRuntimeMarkerExclusive(path string, raw []byte) error {
	if path == "" {
		return errors.New("empty retained runtime marker path")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

func writeRuntimeMarkerAtomic(path string, raw []byte) error {
	if !markerPathValid(path) {
		return fmt.Errorf("runtime marker path %q is not absolute and clean", path)
	}
	if err := ensureSecureDir(filepath.Dir(path)); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return fsyncDir(filepath.Dir(path))
}

func removeRuntimeMarker(path string) error {
	if !markerPathValid(path) {
		return fmt.Errorf("runtime marker path %q is not absolute and clean", path)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("runtime marker removal refused: target is not a regular file")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}
