// Package stagefinalization makes the one legal post-stage RELEASE.json update
// recoverable across process and machine crashes.
//
// A finalized ceremony may fill an initially blank licenseSquadsVault. That
// changes both RELEASE.json and the release hash/size recorded in stage.json,
// which cannot be committed atomically with two ordinary renames. A durable
// parent-level journal records both exact before/after pairs first. Recovery is
// idempotent and runs before a staged candidate is read or retained.
package stagefinalization

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const (
	Schema           = "melusina-stage-finalization-journal-v1"
	journalPrefix    = ".reconcile-stage-finalization-"
	journalSuffix    = ".json"
	journalTmpSuffix = ".json.tmp"
	maxJournalBytes  = 8 << 20
	defaultRootCap   = 256
)

// Hook is a test/fault-injection seam. Production callers pass nil.
type Hook func(step string) error

type journal struct {
	Schema        string `json:"schema"`
	StageID       string `json:"stageId"`
	BeforeRelease []byte `json:"beforeRelease"`
	BeforeStage   []byte `json:"beforeStage"`
	AfterRelease  []byte `json:"afterRelease"`
	AfterStage    []byte `json:"afterStage"`
}

// Prepare durably records a verified transition before either target changes.
func Prepare(root, stageID string, beforeRelease, beforeStage, afterRelease, afterStage []byte) error {
	if err := validateRootAndStage(root, stageID); err != nil {
		return err
	}
	if err := validateRootEntryAllowance(root, defaultRootCap); err != nil {
		return err
	}
	j := journal{
		Schema: Schema, StageID: stageID,
		BeforeRelease: append([]byte(nil), beforeRelease...),
		BeforeStage:   append([]byte(nil), beforeStage...),
		AfterRelease:  append([]byte(nil), afterRelease...),
		AfterStage:    append([]byte(nil), afterStage...),
	}
	if err := validateTransition(j); err != nil {
		return err
	}
	final := journalPath(root, stageID)
	if _, err := os.Lstat(final); err == nil {
		return errors.New("stage-finalization journal already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp := journalTempPath(root, stageID)
	if err := removeSafeRegularIfPresent(tmp); err != nil {
		return fmt.Errorf("remove stale journal temporary: %w", err)
	}
	body, err := json.Marshal(j)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if len(body) > maxJournalBytes {
		return errors.New("stage-finalization journal exceeds size bound")
	}
	if err := writeExclusiveSynced(tmp, body); err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmp)
		}
	}()
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	cleanup = false
	return syncDir(root)
}

// Recover completes a prepared transition, or reports that none exists.
func Recover(root, stageID string, hook Hook) (bool, error) {
	if err := validateRootAndStage(root, stageID); err != nil {
		return false, err
	}
	if err := removeSafeRegularIfPresent(journalTempPath(root, stageID)); err != nil {
		return false, fmt.Errorf("remove stale journal temporary: %w", err)
	}
	path := journalPath(root, stageID)
	body, err := readRegularBounded(path, maxJournalBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read stage-finalization journal: %w", err)
	}
	var j journal
	if err := decodeOne(body, &j); err != nil {
		return false, fmt.Errorf("decode stage-finalization journal: %w", err)
	}
	if j.Schema != Schema || j.StageID != stageID {
		return false, errors.New("stage-finalization journal identity mismatch")
	}
	if err := validateTransition(j); err != nil {
		return false, fmt.Errorf("validate stage-finalization journal: %w", err)
	}
	stageDir := filepath.Join(root, stageID)
	if err := applyTarget(stageDir, "RELEASE.json", ".RELEASE.json.reconcile.tmp", j.BeforeRelease, j.AfterRelease); err != nil {
		return false, err
	}
	if hook != nil {
		if err := hook("after-release"); err != nil {
			return false, err
		}
	}
	if err := applyTarget(stageDir, "stage.json", ".stage.json.reconcile.tmp", j.BeforeStage, j.AfterStage); err != nil {
		return false, err
	}
	if hook != nil {
		if err := hook("after-stage"); err != nil {
			return false, err
		}
	}
	if err := syncDir(stageDir); err != nil {
		return false, err
	}
	if hook != nil {
		if err := hook("after-stage-sync"); err != nil {
			return false, err
		}
	}
	if err := os.Remove(path); err != nil {
		return false, err
	}
	if err := syncDir(root); err != nil {
		return false, err
	}
	return true, nil
}

// RecoverAll repairs every bounded journal before retention validates exact
// stage-tree membership. Unknown root members remain the caller's concern.
func RecoverAll(root string, maxEntries int) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) > maxEntries*3 {
		return fmt.Errorf("private-stage root exceeds %d bounded stage/journal entries", maxEntries*3)
	}
	normal, journals, temporaries := 0, 0, 0
	for _, entry := range entries {
		if _, ok := ParseJournalName(entry.Name()); ok {
			journals++
		} else if _, ok := parseJournalTempName(entry.Name()); ok {
			temporaries++
		} else {
			normal++
		}
	}
	if normal > maxEntries {
		return fmt.Errorf("private-stage root exceeds %d entries", maxEntries)
	}
	if journals > maxEntries || temporaries > maxEntries {
		return fmt.Errorf("private-stage root exceeds bounded reconciliation-journal entries")
	}
	for _, entry := range entries {
		name := entry.Name()
		if stageID, ok := ParseJournalName(name); ok {
			if _, err := Recover(root, stageID, nil); err != nil {
				return fmt.Errorf("recover stage %s finalization: %w", stageID, err)
			}
			continue
		}
		if stageID, ok := parseJournalTempName(name); ok {
			if err := validateStageID(stageID); err != nil {
				return err
			}
			if err := removeSafeRegularIfPresent(filepath.Join(root, name)); err != nil {
				return err
			}
		}
	}
	return syncDir(root)
}

func validateRootEntryAllowance(root string, maxEntries int) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) >= maxEntries*3 {
		return errors.New("private-stage root has no bounded reconciliation-journal capacity")
	}
	normal, journals, temporaries := 0, 0, 0
	for _, entry := range entries {
		if _, ok := ParseJournalName(entry.Name()); ok {
			journals++
		} else if _, ok := parseJournalTempName(entry.Name()); ok {
			temporaries++
		} else {
			normal++
		}
	}
	if normal > maxEntries || journals >= maxEntries || temporaries > maxEntries {
		return errors.New("private-stage root has no bounded reconciliation-journal capacity")
	}
	return nil
}

// ParseJournalName recognizes only the exact bounded journal name.
func ParseJournalName(name string) (string, bool) {
	if !strings.HasPrefix(name, journalPrefix) || !strings.HasSuffix(name, journalSuffix) || strings.HasSuffix(name, journalTmpSuffix) {
		return "", false
	}
	stageID := strings.TrimSuffix(strings.TrimPrefix(name, journalPrefix), journalSuffix)
	return stageID, validateStageID(stageID) == nil
}

func parseJournalTempName(name string) (string, bool) {
	if !strings.HasPrefix(name, journalPrefix) || !strings.HasSuffix(name, journalTmpSuffix) {
		return "", false
	}
	stageID := strings.TrimSuffix(strings.TrimPrefix(name, journalPrefix), journalTmpSuffix)
	return stageID, validateStageID(stageID) == nil
}

func journalPath(root, stageID string) string {
	return filepath.Join(root, journalPrefix+stageID+journalSuffix)
}

func journalTempPath(root, stageID string) string {
	return filepath.Join(root, journalPrefix+stageID+journalTmpSuffix)
}

func validateRootAndStage(root, stageID string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("private-stage root must be absolute and clean")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("private-stage root must be a real directory")
	}
	if err := validateStageID(stageID); err != nil {
		return err
	}
	stageInfo, err := os.Lstat(filepath.Join(root, stageID))
	if err != nil {
		return err
	}
	if stageInfo.Mode()&os.ModeSymlink != 0 || !stageInfo.IsDir() {
		return errors.New("staged candidate must be a real directory")
	}
	return nil
}

func validateStageID(stageID string) error {
	if len(stageID) != 64 || strings.ToLower(stageID) != stageID {
		return errors.New("stageId must be 32-byte lowercase hex")
	}
	if _, err := hex.DecodeString(stageID); err != nil {
		return errors.New("stageId must be 32-byte lowercase hex")
	}
	return nil
}

func validateTransition(j journal) error {
	if len(j.BeforeRelease) == 0 || len(j.BeforeStage) == 0 || len(j.AfterRelease) == 0 || len(j.AfterStage) == 0 {
		return errors.New("journal carries an empty before/after artifact")
	}
	var beforeRelease, afterRelease map[string]json.RawMessage
	var beforeStage, afterStage map[string]json.RawMessage
	for _, item := range []struct {
		name string
		body []byte
		out  *map[string]json.RawMessage
	}{
		{"before release", j.BeforeRelease, &beforeRelease},
		{"after release", j.AfterRelease, &afterRelease},
		{"before stage", j.BeforeStage, &beforeStage},
		{"after stage", j.AfterStage, &afterStage},
	} {
		if err := decodeOne(item.body, item.out); err != nil || *item.out == nil {
			return fmt.Errorf("%s is not one JSON object", item.name)
		}
	}
	if err := equalExcept(beforeRelease, afterRelease, "licenseSquadsVault"); err != nil {
		return fmt.Errorf("release transition: %w", err)
	}
	var beforeVault, afterVault string
	if err := json.Unmarshal(beforeRelease["licenseSquadsVault"], &beforeVault); err != nil {
		return errors.New("before release has invalid licenseSquadsVault")
	}
	if err := json.Unmarshal(afterRelease["licenseSquadsVault"], &afterVault); err != nil || strings.TrimSpace(afterVault) == "" {
		return errors.New("after release has blank or invalid licenseSquadsVault")
	}
	if beforeVault != "" && beforeVault != afterVault {
		return errors.New("release transition replaces an already-declared vault")
	}
	if err := equalExcept(beforeStage, afterStage, "releaseSha256", "releaseSize"); err != nil {
		return fmt.Errorf("stage transition: %w", err)
	}
	if err := validateStageReleaseBinding(beforeStage, j.BeforeRelease); err != nil {
		return fmt.Errorf("before stage binding: %w", err)
	}
	if err := validateStageReleaseBinding(afterStage, j.AfterRelease); err != nil {
		return fmt.Errorf("after stage binding: %w", err)
	}
	return nil
}

func equalExcept(before, after map[string]json.RawMessage, exceptions ...string) error {
	if len(before) != len(after) {
		return errors.New("object field set changed")
	}
	allowed := make(map[string]bool, len(exceptions))
	for _, key := range exceptions {
		allowed[key] = true
	}
	for key, left := range before {
		right, ok := after[key]
		if !ok {
			return fmt.Errorf("field %q was removed", key)
		}
		if !allowed[key] {
			equal, err := equalJSONValue(left, right)
			if err != nil {
				return fmt.Errorf("field %q is invalid JSON: %w", key, err)
			}
			if !equal {
				return fmt.Errorf("field %q changed", key)
			}
		}
	}
	return nil
}

func equalJSONValue(left, right []byte) (bool, error) {
	decode := func(raw []byte) (any, error) {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			if err == nil {
				return nil, errors.New("trailing JSON value")
			}
			return nil, err
		}
		return value, nil
	}
	l, err := decode(left)
	if err != nil {
		return false, err
	}
	r, err := decode(right)
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(l, r), nil
}

func validateStageReleaseBinding(stage map[string]json.RawMessage, release []byte) error {
	var size int
	var digest string
	if err := json.Unmarshal(stage["releaseSize"], &size); err != nil || size != len(release) {
		return errors.New("releaseSize does not bind release bytes")
	}
	if err := json.Unmarshal(stage["releaseSha256"], &digest); err != nil {
		return errors.New("releaseSha256 is invalid")
	}
	want := sha256.Sum256(release)
	if digest != hex.EncodeToString(want[:]) {
		return errors.New("releaseSha256 does not bind release bytes")
	}
	return nil
}

func applyTarget(dir, name, tempName string, before, after []byte) error {
	path := filepath.Join(dir, name)
	current, err := readRegularBounded(path, maxJournalBytes)
	if err != nil {
		return fmt.Errorf("read reconciled %s: %w", name, err)
	}
	if bytes.Equal(current, after) {
		return removeSafeRegularIfPresent(filepath.Join(dir, tempName))
	}
	if !bytes.Equal(current, before) {
		return fmt.Errorf("%s matches neither journal before nor after bytes", name)
	}
	tmp := filepath.Join(dir, tempName)
	if err := removeSafeRegularIfPresent(tmp); err != nil {
		return err
	}
	if err := writeExclusiveSynced(tmp, after); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func writeExclusiveSynced(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func readRegularBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > limit {
		return nil, errors.New("artifact is not a bounded regular no-follow file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != info.Size() {
		return nil, errors.New("artifact changed during bounded read")
	}
	return body, nil
}

func removeSafeRegularIfPresent(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("refuse to remove non-regular reconciliation temporary")
	}
	return os.Remove(path)
}

func decodeOne(body []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
