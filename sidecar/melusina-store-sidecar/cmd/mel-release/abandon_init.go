package main

// The release WAL normally fails closed when an incomplete run is bound to a
// different version. That is essential once staging or a Squads proposal might
// exist. An INIT WAL is different: no externally mutable release step has run
// yet, so a failed local build can be archived and a new forward version may
// begin without hand-editing release state.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const abandonedInitSchema = "melusina-mel-release-abandoned-init-v1"

// abandonedInitReceipt is retained alongside every discarded preflight. It is
// deliberately not a terminal release receipt: it proves only that the old WAL
// never crossed the first mutable release boundary.
type abandonedInitReceipt struct {
	Schema          string `json:"schema"`
	Outcome         string `json:"outcome"`
	AppID           string `json:"appId"`
	Version         string `json:"version"`
	LedgerID        string `json:"ledgerId"`
	ReleaseNonce    string `json:"releaseNonce"`
	WALSHA256       string `json:"walSha256"`
	WALSize         int64  `json:"walSize"`
	AbandonedAtUnix int64  `json:"abandonedAtUnix"`
}

// runAbandonInit archives precisely one local INIT-only release attempt. It
// does not construct a provider, call the Store, sign, stage, propose, or make
// any on-chain mutation. The per-app lock makes it mutually exclusive with a
// live publish/approve run.
func runAbandonInit(c Config, catalog *Catalog, selector string) (string, error) {
	app, err := catalog.Select(selector)
	if err != nil {
		return "", err
	}
	lock, err := acquireAppLock(appLockPath(c.lockDir(), app.AppID))
	if err != nil {
		return "", err
	}
	defer lock.Close()
	return abandonInitState(c, app)
}

func abandonInitState(c Config, app App) (string, error) {
	appDir := c.appStateDir(app.AppID)
	info, err := os.Lstat(appDir)
	if errors.Is(err, os.ErrNotExist) {
		if archived, ok, findErr := findAbandonedInit(c, app.AppID); findErr != nil {
			return "", findErr
		} else if ok {
			return archived, nil
		}
		return "", fmt.Errorf("no local WAL for app %s", app.AppID)
	}
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("app state path %s is not a real directory", appDir)
	}

	walPath := c.walPath(app.AppID)
	rec, ok, err := readWAL(walPath)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("no local WAL for app %s", app.AppID)
	}
	if err := requireAbandonableInit(rec, app); err != nil {
		return "", err
	}
	if err := requireInitOnlyStateTree(appDir); err != nil {
		return "", err
	}

	walBytes, err := os.ReadFile(walPath)
	if err != nil {
		return "", err
	}
	archiveRoot := filepath.Join(c.StateDir, "abandoned-inits", app.AppID)
	archiveDir := filepath.Join(archiveRoot, safeSegment(rec.Version)+"-"+safeSegment(rec.LedgerID))
	if err := os.MkdirAll(archiveRoot, 0o700); err != nil {
		return "", err
	}
	if _, err := os.Lstat(archiveDir); err == nil {
		return "", fmt.Errorf("abandoned INIT archive already exists at %s", archiveDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	marker := abandonedInitReceipt{
		Schema:          abandonedInitSchema,
		Outcome:         "archived-no-external-release-effects",
		AppID:           rec.AppID,
		Version:         rec.Version,
		LedgerID:        rec.LedgerID,
		ReleaseNonce:    rec.ReleaseNonce,
		WALSHA256:       sha256Hex(walBytes),
		WALSize:         int64(len(walBytes)),
		AbandonedAtUnix: time.Now().UTC().Unix(),
	}
	if err := writeAbandonedInitMarker(filepath.Join(appDir, "abandoned-init.json"), marker); err != nil {
		return "", err
	}

	// A directory rename is a single-filesystem namespace operation. Keeping the
	// complete app state directory together prevents an old build or provider
	// candidate from being mistaken for a fresh forward release.
	if err := os.Rename(appDir, archiveDir); err != nil {
		return "", fmt.Errorf("archive INIT-only app state: %w", err)
	}
	if err := fsyncDir(filepath.Dir(appDir)); err != nil {
		return "", fmt.Errorf("sync app-state parent after archive: %w", err)
	}
	if err := fsyncDir(archiveRoot); err != nil {
		return "", fmt.Errorf("sync INIT archive after archive: %w", err)
	}
	return archiveDir, nil
}

func requireAbandonableInit(rec walReceipt, app App) error {
	if rec.Schema != walSchema || rec.State != stateInit {
		return fmt.Errorf("app %s WAL is %q; abandon-init accepts only %s", app.AppID, rec.State, stateInit)
	}
	if rec.AppID != app.AppID || rec.PublishSlug != app.PublishSlug || rec.CatalogName != app.CatalogName {
		return fmt.Errorf("app %s INIT WAL does not bind the current catalog identity", app.AppID)
	}
	if strings.TrimSpace(rec.Version) == "" || !isLowerHex(rec.ReleaseNonce, 32) || !isLowerHex(rec.LedgerID, 32) {
		return fmt.Errorf("app %s INIT WAL has an invalid version, nonce, or ledger ID", app.AppID)
	}
	if rec.NewAppHash != "" || rec.ReleaseHash != "" || rec.PackageID != "" || rec.MasterNftMint != "" ||
		rec.ArtifactSHA != "" || rec.ArtifactSize != 0 || rec.NewReleasePDA != "" || rec.StageID != "" ||
		rec.TransactionPDA != "" || rec.ServedAppHash != "" || rec.PreviousSHA256 != "" || rec.PreviousVersion != "" ||
		len(rec.StalePDAs) != 0 || len(rec.ActiveBefore) != 0 || len(rec.ActiveAfter) != 0 ||
		rec.BuildReceipt != (artifactRef{}) || rec.StageReceiptRef != (artifactRef{}) || rec.ReleaseJSON != (artifactRef{}) ||
		rec.ProposalReceipt != (artifactRef{}) || rec.RegisterReceipt != (artifactRef{}) || rec.PromoteReceipt != (artifactRef{}) ||
		len(rec.RevokeReceipts) != 0 || rec.GenerationID != 0 || rec.GenerationHash != "" || rec.CompletedAtUnix != 0 {
		return fmt.Errorf("app %s INIT WAL carries release effects; refusing to archive it", app.AppID)
	}
	return nil
}

// An INIT WAL can have only a local build and provider candidate. Any other
// top-level item implies historic or later-phase state, which must be handled by
// the normal resume/terminal path rather than discarded here.
func requireInitOnlyStateTree(appDir string) error {
	entries, err := os.ReadDir(appDir)
	if err != nil {
		return err
	}
	allowed := map[string]bool{
		"wal.json":            true,
		"build.json":          true,
		"provider":            true,
		"abandoned-init.json": true,
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("INIT app state contains non-preflight item %q; refusing to archive", entry.Name())
		}
	}
	return nil
}

func writeAbandonedInitMarker(path string, marker abandonedInitReceipt) error {
	raw, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := writeExclusive(path, raw); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	var existing abandonedInitReceipt
	stored, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := decodeStrictJSON(stored, &existing); err != nil {
		return fmt.Errorf("read existing abandoned INIT marker: %w", err)
	}
	if existing.Schema != marker.Schema || existing.Outcome != marker.Outcome || existing.AppID != marker.AppID ||
		existing.Version != marker.Version || existing.LedgerID != marker.LedgerID || existing.ReleaseNonce != marker.ReleaseNonce ||
		existing.WALSHA256 != marker.WALSHA256 || existing.WALSize != marker.WALSize || existing.AbandonedAtUnix <= 0 {
		return errors.New("existing abandoned INIT marker does not bind this WAL")
	}
	return nil
}

// findAbandonedInit makes a crash after the directory rename visibly
// idempotent: the caller receives the exact archive path rather than starting a
// second release while unsure whether the old local candidate survived.
func findAbandonedInit(c Config, appID string) (string, bool, error) {
	root := filepath.Join(c.StateDir, "abandoned-inits", appID)
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	var found string
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		path := filepath.Join(root, entry.Name(), "abandoned-init.json")
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", false, err
		}
		var marker abandonedInitReceipt
		if err := decodeStrictJSON(raw, &marker); err != nil {
			return "", false, fmt.Errorf("read abandoned INIT marker %s: %w", path, err)
		}
		if marker.Schema != abandonedInitSchema || marker.Outcome != "archived-no-external-release-effects" || marker.AppID != appID {
			return "", false, fmt.Errorf("invalid abandoned INIT marker %s", path)
		}
		if found != "" {
			return "", false, fmt.Errorf("multiple abandoned INIT archives exist for app %s", appID)
		}
		found = filepath.Join(root, entry.Name())
	}
	return found, found != "", nil
}
