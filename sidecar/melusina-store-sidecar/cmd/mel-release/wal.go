package main

// The reordered no-gap supersede WAL. The frozen publish-supersede order is
//
//	INIT -> BUILT -> REGISTERED -> STAGED -> PROMOTED -> REVOKED -> VERIFIED -> DONE
//
// mel-release reorders and SPLITS it across the two-command authority boundary:
//
//	publish:  INIT -> BUILT -> STAGED -> PROPOSED          (‖ command boundary ‖)
//	approve:  PROPOSED -> REGISTERED -> PROMOTED -> GENERATED -> REVOKED -> VERIFIED -> DONE
//
// Moving STAGED before the on-chain registration is safe because staging signs a
// stage receipt WITHOUT requiring an Active ReleaseEntry (it is not catalog
// visible), and it preserves the no-0-Active invariant: nothing is ever promoted
// or revoked before the register lands, and on the approve side the sole
// Active->Revoked transition still happens strictly after the new release is both
// Active (REGISTERED) and served (PROMOTED). Each transition is journaled temp+
// fsync+rename+dir-fsync so a crash resumes forward from the recorded state.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const walSchema = "melusina-mel-release-wal-v1"

// WAL states (forward-only).
const (
	stateInit       = "INIT"
	stateBuilt      = "BUILT"
	stateStaged     = "STAGED"
	statePosed      = "PROPOSED"
	stateRegistered = "REGISTERED"
	statePromoted   = "PROMOTED"
	stateGenerated  = "GENERATED"
	stateRevoked    = "REVOKED"
	stateVerified   = "VERIFIED"
	stateDone       = "DONE"
)

// stateRank orders the WAL states so a resuming command can assert it is not
// running behind the persisted state.
func stateRank(s string) int {
	switch s {
	case stateInit:
		return 0
	case stateBuilt:
		return 1
	case stateStaged:
		return 2
	case statePosed:
		return 3
	case stateRegistered:
		return 4
	case statePromoted:
		return 5
	case stateGenerated:
		return 6
	case stateRevoked:
		return 7
	case stateVerified:
		return 8
	case stateDone:
		return 9
	default:
		return -1
	}
}

// walReceipt is the single durable source of truth for resuming a run.
type walReceipt struct {
	Schema       string `json:"schema"`
	State        string `json:"state"`
	AppID        string `json:"appId"`
	PublishSlug  string `json:"publishSlug"`
	CatalogName  string `json:"catalogName"`
	Version      string `json:"version"`
	NewAppHash   string `json:"newAppHash"`
	ReleaseNonce string `json:"releaseNonce"`
	ReleaseHash  string `json:"releaseHash,omitempty"`

	PackageID      string `json:"packageId,omitempty"`
	MasterNftMint  string `json:"masterNftMint,omitempty"`
	ArtifactSHA    string `json:"artifactSha256,omitempty"`
	ArtifactSize   int64  `json:"artifactSize,omitempty"`
	NewReleasePDA  string `json:"newReleasePda,omitempty"`
	StageID        string `json:"stageId,omitempty"`
	TransactionPDA string `json:"transactionPda,omitempty"`
	ServedAppHash  string `json:"servedAppHash,omitempty"`

	PreviousSHA256  string `json:"previousSha256,omitempty"`
	PreviousVersion string `json:"previousVersion,omitempty"`

	StalePDAs    []string     `json:"stalePdas"`
	ActiveBefore []releaseRef `json:"activeBefore,omitempty"`
	ActiveAfter  []releaseRef `json:"activeAfter,omitempty"`
	LedgerID     string       `json:"ledgerId"`

	BuildReceipt    artifactRef            `json:"buildReceipt,omitempty"`
	StageReceiptRef artifactRef            `json:"stageReceipt,omitempty"`
	ReleaseJSON     artifactRef            `json:"releaseJson,omitempty"`
	ProposalReceipt artifactRef            `json:"proposalReceipt,omitempty"`
	RegisterReceipt artifactRef            `json:"registerReceipt,omitempty"`
	PromoteReceipt  artifactRef            `json:"promoteReceipt,omitempty"`
	RevokeReceipts  map[string]artifactRef `json:"revokeReceipts,omitempty"`

	GenerationID   uint64 `json:"generationId,omitempty"`
	GenerationHash string `json:"generationHash,omitempty"`

	CompletedAtUnix int64 `json:"completedAtUnix,omitempty"`
}

func readWAL(path string) (walReceipt, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return walReceipt{}, false, nil
	}
	if err != nil {
		return walReceipt{}, false, err
	}
	if len(raw) > maxReceiptBytes {
		return walReceipt{}, false, fmt.Errorf("WAL exceeds %d-byte bound", maxReceiptBytes)
	}
	var rec walReceipt
	if err := decodeStrictJSON(raw, &rec); err != nil {
		return walReceipt{}, false, fmt.Errorf("decode WAL: %w", err)
	}
	return rec, true, nil
}

func encodeWAL(rec walReceipt) ([]byte, error) {
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > maxReceiptBytes {
		return nil, errors.New("WAL JSON exceeds bound")
	}
	return raw, nil
}

func seedWAL(path string, rec walReceipt) error {
	raw, err := encodeWAL(rec)
	if err != nil {
		return err
	}
	return writeExclusive(path, raw)
}

// advance journals the next state durably.
func advanceWAL(path string, rec *walReceipt, next string) error {
	rec.State = next
	raw, err := encodeWAL(*rec)
	if err != nil {
		return err
	}
	if err := writeDurable(path, raw); err != nil {
		return fmt.Errorf("journal state %s: %w", next, err)
	}
	return nil
}

// journalWAL rewrites the WAL at the current state (used to persist a sub-step
// artifact, e.g. one revoke receipt, before the state advances).
func journalWAL(path string, rec *walReceipt) error {
	raw, err := encodeWAL(*rec)
	if err != nil {
		return err
	}
	return writeDurable(path, raw)
}

// loadOrSeedWAL loads an existing WAL (validating it binds the same publish) or
// seeds a fresh INIT receipt keyed on the immutable appId.
//
// walPath/candidatePath are keyed on appId only (no version component), so a
// COMPLETED release for a prior version otherwise permanently blocks the next
// version bump for the same app. When the existing WAL is terminal (DONE) at a
// DIFFERENT version, its terminal receipts are archived under history/ and a
// fresh INIT is seeded — the tool's whole purpose is repeated per-app bumps. An
// INCOMPLETE WAL at a different version still fails closed (never mid-flight).
func loadOrSeedWAL(c Config, path string, seed walReceipt) (walReceipt, error) {
	existing, ok, err := readWAL(path)
	if err != nil {
		return walReceipt{}, err
	}
	if ok {
		if err := checkWALBinding(existing, seed); err != nil {
			if !rotatableCompleted(existing, seed) {
				return walReceipt{}, fmt.Errorf("existing WAL binds a different publish: %w", err)
			}
			if err := rotateCompletedWAL(c, existing, path); err != nil {
				return walReceipt{}, fmt.Errorf("rotate completed WAL for %s: %w", seed.AppID, err)
			}
			// fall through and seed a fresh INIT for the new version
		} else {
			return existing, nil
		}
	}
	if err := seedWAL(path, seed); err != nil {
		if errors.Is(err, os.ErrExist) {
			again, ok2, err2 := readWAL(path)
			if err2 != nil {
				return walReceipt{}, err2
			}
			if ok2 {
				if err := checkWALBinding(again, seed); err != nil {
					return walReceipt{}, fmt.Errorf("existing WAL binds a different publish: %w", err)
				}
				return again, nil
			}
		}
		return walReceipt{}, err
	}
	return seed, nil
}

// rotatableCompleted reports whether an existing WAL is a *completed* (DONE)
// release for the same app at a DIFFERENT version — the sole case where the next
// version bump archives the terminal state and seeds fresh rather than failing
// closed. Anything else (wrong schema, incomplete state, unknown state) is not
// rotatable and must fail closed.
func rotatableCompleted(existing, seed walReceipt) bool {
	return existing.Schema == walSchema &&
		existing.AppID == seed.AppID &&
		existing.State == stateDone &&
		existing.Version != seed.Version
}

// rotateCompletedWAL archives the terminal WAL + candidate + terminal receipt of
// a completed release into a per-version history directory so the fresh INIT can
// be seeded (and the stale candidate cannot be mistaken for the new one). The
// immutable evidence is preserved, not deleted.
func rotateCompletedWAL(c Config, existing walReceipt, walPath string) error {
	appDir := c.appStateDir(existing.AppID)
	suffix := existing.LedgerID
	if suffix == "" {
		suffix = fmt.Sprintf("done-%d", existing.CompletedAtUnix)
	}
	histDir := filepath.Join(appDir, "history", safeSegment(existing.Version)+"-"+safeSegment(suffix))
	if err := os.MkdirAll(histDir, 0o700); err != nil {
		return err
	}
	for _, name := range []string{"wal.json", "candidate.json", "terminal.json"} {
		src := filepath.Join(appDir, name)
		if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}
		if err := os.Rename(src, filepath.Join(histDir, name)); err != nil {
			return err
		}
	}
	return fsyncDir(appDir)
}

// safeSegment maps an arbitrary string to a single filesystem-safe path segment.
func safeSegment(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "seg"
	}
	return b.String()
}

func checkWALBinding(rec, seed walReceipt) error {
	if rec.Schema != walSchema {
		return fmt.Errorf("schema %q is not %q", rec.Schema, walSchema)
	}
	if rec.AppID != seed.AppID {
		return fmt.Errorf("appId %q != %q", rec.AppID, seed.AppID)
	}
	if rec.Version != seed.Version {
		return fmt.Errorf("version %q != %q", rec.Version, seed.Version)
	}
	if !isLowerHex(rec.ReleaseNonce, 32) {
		return errors.New("persisted releaseNonce is malformed")
	}
	if stateRank(rec.State) < 0 {
		return fmt.Errorf("unknown persisted state %q", rec.State)
	}
	return nil
}
