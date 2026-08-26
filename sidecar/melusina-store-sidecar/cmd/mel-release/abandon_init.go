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
	if err := requireAbandonableInitStateTree(appDir, rec); err != nil {
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

// requireAbandonableInitStateTree accepts the ordinary INIT-only layout and one
// strictly validated historical variant. A completed WAL is rotated by moving
// {wal,candidate,terminal} into history/ before a new INIT is seeded. The old
// native receipts intentionally remain at their stable paths so the terminal
// can still point at them. A local build that then fails before the INIT->BUILT
// journal boundary can overwrite build.json, leaving precisely that rotated
// residue beside an INIT WAL. It is still safe to archive: the current WAL
// proves it has no stage/proposal/register/promotion effects, while the residue
// must prove it belongs to completed history rather than an untracked attempt.
func requireAbandonableInitStateTree(appDir string, rec walReceipt) error {
	if err := requireInitOnlyStateTree(appDir); err == nil {
		return nil
	} else if err := requireRotatedTerminalResidue(appDir, rec); err != nil {
		return fmt.Errorf("INIT state is neither preflight-only nor validated rotated history: %w", err)
	}
	return nil
}

// An ordinary INIT WAL can have only a local build and provider candidate. Any
// other top-level item is handled by requireRotatedTerminalResidue below.
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

type historicalTerminalResidue struct {
	wal       walReceipt
	candidate candidateReceipt
	terminal  terminalReceipt
}

// requireRotatedTerminalResidue accepts only the layout that rotateCompletedWAL
// leaves behind. It deliberately does not construct a provider or make a
// network call: this command remains local-only. The caller may archive the
// whole directory only after every retained receipt has been tied to a prior
// DONE WAL and the current build, if present, is demonstrably local to this INIT
// attempt.
func requireRotatedTerminalResidue(appDir string, init walReceipt) error {
	history, err := readHistoricalTerminalResidues(appDir, init.AppID)
	if err != nil {
		return err
	}
	selected, err := selectCurrentHistoricalResidue(appDir, history)
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(appDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("INIT state contains symlink %q", entry.Name())
		}
		path := filepath.Join(appDir, entry.Name())
		switch entry.Name() {
		case "wal.json", "abandoned-init.json":
			if !entry.Type().IsRegular() {
				return fmt.Errorf("INIT state item %q is not a regular file", entry.Name())
			}
		case "history":
			if !entry.IsDir() {
				return errors.New("rotated history is not a directory")
			}
		case "provider":
			if !entry.IsDir() {
				return errors.New("local provider candidate is not a directory")
			}
			if err := requireNoSymlinkTree(path); err != nil {
				return fmt.Errorf("provider candidate: %w", err)
			}
		case "build.json":
			if err := validateInitOrHistoricalBuild(path, init, history); err != nil {
				return err
			}
		case "final-release.json":
			if err := validateHistoricalFinalRelease(path, selected); err != nil {
				return fmt.Errorf("final release residue: %w", err)
			}
		case "release.json":
			if _, _, err := readFinalReleaseJSON(path, selected.wal.NewAppHash, selected.wal.Version, selected.wal.ReleaseNonce); err != nil {
				return fmt.Errorf("proposal release residue does not bind completed history: %w", err)
			}
		case "stage.json":
			if err := validateHistoricalStage(path, selected); err != nil {
				return err
			}
		case "propose.json":
			if err := validateHistoricalProposal(path, selected); err != nil {
				return err
			}
		case "register.json":
			if err := validateHistoricalRegister(path, selected); err != nil {
				return err
			}
		default:
			if strings.HasPrefix(entry.Name(), "promote-") && strings.HasSuffix(entry.Name(), ".json") {
				if err := validateHistoricalPromotion(path, history); err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(entry.Name(), "revoke-") && strings.HasSuffix(entry.Name(), ".json") {
				if err := validateHistoricalRevoke(path, history); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("INIT state contains non-preflight item %q", entry.Name())
		}
	}
	return nil
}

func requireNoSymlinkTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("contains symlink %s", path)
		}
		return nil
	})
}

func readHistoricalTerminalResidues(appDir, appID string) ([]historicalTerminalResidue, error) {
	root := filepath.Join(appDir, "history")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read rotated history: %w", err)
	}
	var out []historicalTerminalResidue
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("rotated history item %q is not a real directory", entry.Name())
		}
		dir := filepath.Join(root, entry.Name())
		if err := requireHistoricalDirectory(dir); err != nil {
			return nil, err
		}
		wal, ok, err := readWAL(filepath.Join(dir, "wal.json"))
		if err != nil {
			return nil, fmt.Errorf("read historical WAL %s: %w", dir, err)
		}
		if !ok {
			return nil, fmt.Errorf("historical release %s lacks wal.json", dir)
		}
		candidate, _, err := readCandidate(filepath.Join(dir, "candidate.json"))
		if err != nil {
			return nil, fmt.Errorf("read historical candidate %s: %w", dir, err)
		}
		terminal, _, err := readTerminalReceipt(filepath.Join(dir, "terminal.json"))
		if err != nil {
			return nil, fmt.Errorf("read historical terminal %s: %w", dir, err)
		}
		residue := historicalTerminalResidue{wal: wal, candidate: candidate, terminal: terminal}
		if err := validateHistoricalTerminal(residue, appID); err != nil {
			return nil, err
		}
		out = append(out, residue)
	}
	if len(out) == 0 {
		return nil, errors.New("rotated INIT state has no completed history")
	}
	return out, nil
}

func requireHistoricalDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"wal.json": true, "candidate.json": true, "terminal.json": true}
	for _, entry := range entries {
		if !allowed[entry.Name()] || !entry.Type().IsRegular() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("historical release %s contains invalid item %q", dir, entry.Name())
		}
	}
	for name := range allowed {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("historical release %s lacks %s", dir, name)
		}
	}
	return nil
}

func validateHistoricalTerminal(h historicalTerminalResidue, appID string) error {
	if h.wal.Schema != walSchema || h.wal.State != stateDone || h.wal.AppID != appID ||
		strings.TrimSpace(h.wal.Version) == "" || !isLowerHex(h.wal.ReleaseNonce, 32) || !isLowerHex(h.wal.LedgerID, 32) {
		return errors.New("historical WAL is not a completed release for this app")
	}
	c := h.candidate
	if c.Schema != candidateSchema || c.AppID != h.wal.AppID || c.Version != h.wal.Version ||
		c.ReleaseNonce != h.wal.ReleaseNonce || c.Component.ComponentID != h.wal.AppID ||
		c.Component.ComponentClass != "app" || c.Component.ContentSHA256 != h.wal.NewAppHash ||
		c.Component.SHA256 != h.wal.ArtifactSHA || c.Component.SizeBytes != h.wal.ArtifactSize ||
		c.Component.ArtifactName != h.wal.PackageID || c.Component.ReleaseHash != h.wal.ReleaseHash ||
		c.Component.StageID != h.wal.StageID || c.Component.Chain.ReleasePDA != h.wal.NewReleasePDA ||
		c.SquadsProposal.TransactionPDA != h.wal.TransactionPDA || !sameArtifactRef(c.StageReceipt, h.wal.StageReceiptRef) {
		return errors.New("historical candidate does not bind its completed WAL")
	}
	t := h.terminal
	if t.Schema != "melusina-mel-release-terminal-receipt-v1" || t.Outcome != "accepted" || t.CompletedAtUnix <= 0 ||
		t.AppID != h.wal.AppID || t.AppHash != h.wal.NewAppHash || t.Version != h.wal.Version ||
		t.ReleaseHash != h.wal.ReleaseHash || t.ReleaseEntryPDA != h.wal.NewReleasePDA ||
		t.StageID != h.wal.StageID || t.ServedAppHash != h.wal.NewAppHash {
		return errors.New("historical terminal does not bind its completed WAL")
	}
	for _, active := range t.ActiveAfter {
		if active.PDA == t.ReleaseEntryPDA && active.AppHash == t.AppHash && active.Version == t.Version {
			return nil
		}
	}
	return errors.New("historical terminal lacks its accepted Active release")
}

func selectCurrentHistoricalResidue(appDir string, history []historicalTerminalResidue) (historicalTerminalResidue, error) {
	path := filepath.Join(appDir, "final-release.json")
	var selected *historicalTerminalResidue
	for i := range history {
		h := &history[i]
		ref, ok := h.terminal.NativeReceipts["releaseJson"]
		if !ok || ref.Path != path {
			continue
		}
		_, got, err := readFinalReleaseJSON(path, h.wal.NewAppHash, h.wal.Version, h.wal.ReleaseNonce)
		if err != nil || !sameArtifactRef(ref, got) {
			continue
		}
		if selected != nil {
			return historicalTerminalResidue{}, errors.New("multiple completed histories bind the retained final release")
		}
		selected = h
	}
	if selected == nil {
		return historicalTerminalResidue{}, errors.New("retained final release does not bind one completed history")
	}
	return *selected, nil
}

func validateInitOrHistoricalBuild(path string, init walReceipt, history []historicalTerminalResidue) error {
	if build, _, err := readBuildReceipt(path, init.AppID, init.Version); err == nil {
		if err := verifyAppHash(build); err != nil {
			return fmt.Errorf("local INIT build does not reproduce its app hash: %w", err)
		}
		return nil
	}
	for _, h := range history {
		if ref, ok := h.terminal.NativeReceipts["build"]; ok && ref.Path == path && verifyArtifactRef(ref) == nil {
			return nil
		}
	}
	return errors.New("build residue binds neither this INIT nor completed history")
}

func validateHistoricalFinalRelease(path string, h historicalTerminalResidue) error {
	ref, ok := h.terminal.NativeReceipts["releaseJson"]
	if !ok || ref.Path != path || verifyArtifactRef(ref) != nil {
		return errors.New("final release receipt drifts from completed history")
	}
	_, got, err := readFinalReleaseJSON(path, h.wal.NewAppHash, h.wal.Version, h.wal.ReleaseNonce)
	if err != nil || !sameArtifactRef(ref, got) {
		return errors.New("final release receipt does not bind completed history")
	}
	return nil
}

func validateHistoricalStage(path string, h historicalTerminalResidue) error {
	ref, ok := h.terminal.NativeReceipts["stage"]
	if !ok || ref.Path != path || verifyArtifactRef(ref) != nil {
		return errors.New("stage residue drifts from completed history")
	}
	_, got, err := readStageReceipt(path, h.wal.AppID, h.wal.NewAppHash, h.wal.ReleaseHash)
	if err != nil || !sameArtifactRef(ref, got) {
		return errors.New("stage residue does not bind completed history")
	}
	return nil
}

func validateHistoricalProposal(path string, h historicalTerminalResidue) error {
	ref, ok := h.terminal.NativeReceipts["proposal"]
	if !ok || ref.Path != path || verifyArtifactRef(ref) != nil {
		return errors.New("proposal residue drifts from completed history")
	}
	_, got, err := readProposalReceipt(path, h.wal.NewReleasePDA)
	if err != nil || !sameArtifactRef(ref, got) {
		return errors.New("proposal residue does not bind completed history")
	}
	return nil
}

func validateHistoricalRegister(path string, h historicalTerminalResidue) error {
	ref, ok := h.terminal.NativeReceipts["register"]
	if !ok || ref.Path != path || verifyArtifactRef(ref) != nil {
		return errors.New("register residue drifts from completed history")
	}
	got, err := readRegisterReceipt(path, h.wal.NewReleasePDA, h.wal.ReleaseHash)
	if err != nil || !sameArtifactRef(ref, got) {
		return errors.New("register residue does not bind completed history")
	}
	return nil
}

func validateHistoricalPromotion(path string, history []historicalTerminalResidue) error {
	for _, h := range history {
		ref, ok := h.terminal.NativeReceipts["promote"]
		if !ok || ref.Path != path || verifyArtifactRef(ref) != nil {
			continue
		}
		got, err := readPromoteReceipt(path, h.wal.AppID, h.wal.NewAppHash, h.wal.ReleaseHash, h.wal.StageID, h.wal.Version)
		if err == nil && sameArtifactRef(ref, got) {
			return nil
		}
	}
	return errors.New("promotion residue does not bind completed history")
}

func validateHistoricalRevoke(path string, history []historicalTerminalResidue) error {
	for _, h := range history {
		for pda, ref := range h.terminal.RevokeReceipts {
			if ref.Path != path || verifyArtifactRef(ref) != nil {
				continue
			}
			got, err := readRevokeReceipt(path, pda, false)
			if err == nil && sameArtifactRef(ref, got) {
				return nil
			}
		}
	}
	return errors.New("revoke residue does not bind completed history")
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
