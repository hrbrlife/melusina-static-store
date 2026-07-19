// Package hostupdate is the greenfield out-of-shell host update controller: the
// external process that discovers a promoted desired generation, verifies it,
// and applies each component atomically with a durable write-ahead log,
// health-gated rollback, and terminal receipts. It runs OUTSIDE the shell it
// updates and replaces the legacy in-shell/Python melusina-update-checker.py.
//
// This file is the crash-safe WAL + recovery state machine — the foundation the
// adapters (Stage/Verify/Apply/Probe/Rollback) and the poll loop build on. It is
// pure and deterministic (time is passed in, no os/exec, no network) so recovery
// is fully unit-testable.
package hostupdate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const walSchema = "melusina-hostupdate-wal-v1"

// maxWALBytes bounds a single WAL entry (small typed JSON). An oversized WAL file
// — e.g. dropped by a compromised writable/symlinked dir — is refused, not parsed.
const maxWALBytes = 1 << 20

// WALState is the durable apply state of one component. The intent is written
// BEFORE any host mutation and completed only after the deep-stable window, so a
// crash at any point is recoverable to a coherent prior or target generation.
type WALState string

const (
	// StateStaged: the target bundle is downloaded + size/sha256-verified and the
	// intent is recorded; NO host mutation has happened. A crash here needs no
	// rollback — the running component is still the prior artifact.
	StateStaged WALState = "staged"
	// StateApplying: the atomic swap / restart is in progress. A crash here MUST
	// roll back — the component may be partially mutated.
	StateApplying WALState = "applying"
	// StateRestarted: the swap + single restart completed; the health probe has
	// not yet passed. A crash here rolls back unless recovery re-proves target+health.
	StateRestarted WALState = "restarted"
	// StateHealthyUnstable: the component is running the target build and passed
	// its health probe, but the deep-stable window has not yet elapsed. A crash
	// here completes iff still target+healthy+deep-stable, else rolls back.
	StateHealthyUnstable WALState = "healthy-unstable"
	// StateApplied: terminal success — deep-stable elapsed, guards removed. The
	// prior artifact may now be pruned (keep-old floor).
	StateApplied WALState = "applied"
	// StateRolledBack: terminal failure — the exact prior artifact was restored.
	StateRolledBack WALState = "rolled-back"
)

func (s WALState) terminal() bool { return s == StateApplied || s == StateRolledBack }

// WALEntry is the durable intent + progress for one component apply.
type WALEntry struct {
	Schema         string `json:"schema"`
	ComponentID    string `json:"componentId"`
	ComponentClass string `json:"componentClass,omitempty"` // persisted so the pre-Complete chain re-verify can reconstruct the ComponentRelease from disk
	GenerationID   uint64 `json:"generationId"`
	AutoApply      bool   `json:"autoApply"`
	ApplyKind      string `json:"applyKind"`
	FromHash       string `json:"fromHash,omitempty"` // prior artifact sha256 (rollback target); empty if brand-new
	FromVersion    string `json:"fromVersion,omitempty"`
	ToHash         string `json:"toHash"` // target artifact sha256 (served bytes)
	ToVersion      string `json:"toVersion"`
	// ContentHash is the on-chain CONTENT identity (app tree hash for release_v2),
	// distinct from ToHash when the served bytes differ from the chain-pinned hash
	// (apps). Persisted so the pre-Complete chain re-verify checks the SAME hash the
	// mutation-time gate did. Empty means it equals ToHash (whole-file artifacts).
	ContentHash string `json:"contentHash,omitempty"`
	// Chain is the on-chain authority reference, persisted so a later poll tick or a
	// fresh post-crash process can re-run the chain gate (pre-Complete) entirely from
	// the WAL — the running host never trusts the remote document to re-verify.
	Chain        componentrelease.ChainAuthority `json:"chain,omitempty"`
	StagedPath   string                          `json:"stagedPath"`          // verified staged artifact (pre-apply)
	PriorPath    string                          `json:"priorPath,omitempty"` // RETAINED prior artifact — kept until terminal (retention invariant)
	State        WALState                        `json:"state"`
	OpenedAtUnix int64                           `json:"openedAtUnix"`
	// AppliedAtUnix marks when the component first became target+healthy — the
	// start of the deep-stable window.
	AppliedAtUnix     int64  `json:"appliedAtUnix,omitempty"`
	DeepStableSeconds int64  `json:"deepStableSeconds"`
	TerminalAtUnix    int64  `json:"terminalAtUnix,omitempty"`
	LastError         string `json:"lastError,omitempty"`
	// Terminal-proof bindings (the accepted receipt is reconstructed from these):
	// RawGenerationSHA256 is the sha256 of the EXACT signed desired-generation bytes
	// this apply came from; DeadlineUnix is the promote-to-healthy deadline;
	// Trigger records what fired this apply (a manual/one-shot trigger can never
	// mint a timer-qualified receipt); RuntimeEvidence is the bound running-process
	// tuple (schema+componentId+generationId+version+pid+/proc/<pid>/exe hash).
	RawGenerationSHA256 string          `json:"rawGenerationSha256,omitempty"`
	DeadlineUnix        int64           `json:"deadlineUnix,omitempty"`
	Trigger             string          `json:"trigger,omitempty"`
	RuntimeEvidence     RuntimeEvidence `json:"runtimeEvidence,omitempty"`
	// RuntimeMarker* persists the exact install-local EnvironmentFile rollback
	// floor. It is written before the component restart so a fresh controller can
	// restore the old generation/version marker before restarting the old binary.
	RuntimeMarkerPath        string `json:"runtimeMarkerPath,omitempty"`
	RuntimeMarkerPriorPath   string `json:"runtimeMarkerPriorPath,omitempty"`
	RuntimeMarkerPriorSHA256 string `json:"runtimeMarkerPriorSha256,omitempty"`
}

func (e WALEntry) validate() error {
	if e.Schema != walSchema {
		return fmt.Errorf("wal schema mismatch: %q", e.Schema)
	}
	if !safeComponentToken(e.ComponentID) {
		return fmt.Errorf("unsafe componentId %q", e.ComponentID)
	}
	if !isLowerHex64(e.ToHash) {
		return errors.New("toHash must be 64 lowercase hex chars")
	}
	if e.FromHash != "" && !isLowerHex64(e.FromHash) {
		return errors.New("fromHash must be 64 lowercase hex chars")
	}
	if e.DeepStableSeconds < 0 {
		return errors.New("deepStableSeconds must be non-negative")
	}
	if e.RuntimeMarkerPath == "" {
		if e.RuntimeMarkerPriorPath != "" || e.RuntimeMarkerPriorSHA256 != "" {
			return errors.New("runtime marker prior fields require runtimeMarkerPath")
		}
	} else {
		if !filepath.IsAbs(e.RuntimeMarkerPath) || filepath.Clean(e.RuntimeMarkerPath) != e.RuntimeMarkerPath {
			return errors.New("runtimeMarkerPath must be an absolute clean path")
		}
		if e.RuntimeMarkerPriorPath == "" && e.RuntimeMarkerPriorSHA256 != "" {
			return errors.New("runtimeMarkerPriorSha256 requires runtimeMarkerPriorPath")
		}
		if e.RuntimeMarkerPriorPath != "" {
			if !filepath.IsAbs(e.RuntimeMarkerPriorPath) || filepath.Clean(e.RuntimeMarkerPriorPath) != e.RuntimeMarkerPriorPath {
				return errors.New("runtimeMarkerPriorPath must be an absolute clean path")
			}
			if !isLowerHex64(e.RuntimeMarkerPriorSHA256) {
				return errors.New("runtimeMarkerPriorSha256 must be 64 lowercase hex chars")
			}
		}
	}
	return nil
}

// validateTerminalReceiptBindings makes a terminal WAL receipt a proof artifact
// rather than a state-transition log. The raw signed-generation digest, bounded
// deadline, and actual trigger are required for every terminal result; a success
// additionally needs the runtime tuple that was bound to the running process at
// apply time. Rollback receipts intentionally may lack runtime evidence because
// an unhealthy or interrupted new process has no truthful target runtime tuple.
func (e WALEntry) validateTerminalReceiptBindings() error {
	if !isLowerHex64(e.RawGenerationSHA256) {
		return errors.New("terminal receipt rawGenerationSha256 must be 64 lowercase hex chars")
	}
	if e.OpenedAtUnix <= 0 || e.DeadlineUnix <= e.OpenedAtUnix {
		return errors.New("terminal receipt deadlineUnix must be after openedAtUnix")
	}
	if e.TerminalAtUnix <= 0 || e.TerminalAtUnix > e.DeadlineUnix {
		return errors.New("terminal receipt timestamp exceeds deadlineUnix")
	}
	switch PollTrigger(e.Trigger) {
	case PollTriggerTimer, PollTriggerBell, PollTriggerManual:
	default:
		return fmt.Errorf("terminal receipt has invalid trigger %q", e.Trigger)
	}
	if e.State != StateApplied {
		return nil
	}
	if e.RuntimeEvidence.Schema != componentrelease.RuntimeReleaseInfoSchema ||
		e.RuntimeEvidence.ComponentID != e.ComponentID ||
		e.RuntimeEvidence.GenerationID != e.GenerationID ||
		e.RuntimeEvidence.Version != e.ToVersion ||
		e.RuntimeEvidence.PID <= 0 ||
		!strings.EqualFold(e.RuntimeEvidence.ArtifactSHA256, e.ToHash) {
		return errors.New("terminal applied receipt lacks a bound runtime evidence tuple")
	}
	return nil
}

// RecoveryAction is what a crash-recovery pass must do for one WAL entry, given
// the observed running-build hash + health at controller startup.
type RecoveryAction string

const (
	// RecoverNone: the entry is terminal — nothing to do.
	RecoverNone RecoveryAction = "none"
	// RecoverDiscard: no host mutation happened (staged) — drop the WAL; the
	// prior artifact is still running, no rollback needed.
	RecoverDiscard RecoveryAction = "discard"
	// RecoverComplete: the target is running + healthy + deep-stable elapsed —
	// finish the apply (terminal applied receipt).
	RecoverComplete RecoveryAction = "complete"
	// RecoverWait: the target is running + healthy but the deep-stable window has
	// not elapsed — keep probing.
	RecoverWait RecoveryAction = "wait"
	// RecoverRollback: the component is not coherently at the target — restore the
	// exact prior artifact.
	RecoverRollback RecoveryAction = "rollback"
)

// RecoveryDecision decides what to do with a WAL entry at controller startup (or
// re-probe), given the observed running-build hash and whether the component is
// healthy right now, and the current unix time. Pure + deterministic.
func RecoveryDecision(e WALEntry, observedRunningHash string, healthy bool, nowUnix int64) RecoveryAction {
	if e.State.terminal() {
		return RecoverNone
	}
	atTarget := strings.EqualFold(strings.TrimSpace(observedRunningHash), e.ToHash)
	switch e.State {
	case StateStaged:
		// No mutation occurred — nothing to roll back.
		return RecoverDiscard
	case StateApplying:
		// A swap/restart was interrupted — the component may be partially mutated;
		// always restore the prior artifact.
		return RecoverRollback
	case StateRestarted, StateHealthyUnstable:
		if atTarget && healthy {
			applied := e.AppliedAtUnix
			if applied == 0 {
				applied = nowUnix
			}
			if nowUnix-applied >= e.DeepStableSeconds {
				return RecoverComplete
			}
			return RecoverWait
		}
		return RecoverRollback
	default:
		return RecoverRollback
	}
}

// ── durable per-component WAL store ───────────────────────────────────────────

// WALStore owns the on-disk WAL: one active file per component (its exclusive
// existence is the per-component lock) plus retained terminal receipts.
type WALStore struct {
	activeDir  string // <root>/active/<componentId>.wal
	receiptDir string // <root>/receipts/<componentId>-<generationId>-<state>.json
}

// NewWALStore initializes the WAL directories (0700) under root, refusing an
// insecure trust dir: a SYMLINK anywhere in the ancestor chain (a symlinked
// parent could redirect the WAL to an attacker directory) or a group/world-
// writable target directory.
func NewWALStore(root string) (*WALStore, error) {
	active := filepath.Join(root, "active")
	receipts := filepath.Join(root, "receipts")
	for _, d := range []string{root, active, receipts} {
		if err := ensureSecureDir(d); err != nil {
			return nil, err
		}
	}
	return &WALStore{activeDir: active, receiptDir: receipts}, nil
}

// ensureSecureDir creates dir (0700) if missing and verifies the WAL trust dir is
// safe. It refuses a SYMLINK anywhere in the ancestor chain and a group/world-
// writable target directory. Ancestor WRITABILITY is deliberately not constrained
// (e.g. /tmp is legitimately sticky-world-writable) — only symlinks in the chain
// and the target dir's OWN mode are enforced.
func ensureSecureDir(dir string) error {
	abs, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return fmt.Errorf("resolve %s: %w", dir, err)
	}
	cur := string(os.PathSeparator)
	for _, comp := range strings.Split(strings.TrimPrefix(abs, string(os.PathSeparator)), string(os.PathSeparator)) {
		if comp == "" {
			continue
		}
		cur = filepath.Join(cur, comp)
		fi, err := os.Lstat(cur)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if err := os.Mkdir(cur, 0o700); err != nil {
					return fmt.Errorf("mkdir %s: %w", cur, err)
				}
				continue
			}
			return fmt.Errorf("lstat %s: %w", cur, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("WAL path component %s is a symlink", cur)
		}
		if !fi.IsDir() {
			return fmt.Errorf("WAL path component %s is not a directory", cur)
		}
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return fmt.Errorf("lstat %s: %w", abs, err)
	}
	// Refuse a GROUP- or WORLD-writable trust dir — a non-owner-writable WAL root is
	// not a trust root. (The production WAL root is installed root-owned 0700/0755;
	// a standard-umask temp dir is 0755, which passes.)
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("WAL directory %s is group/world-writable (%#o)", abs, fi.Mode().Perm())
	}
	return nil
}

func (w *WALStore) activePath(componentID string) (string, error) {
	if !safeComponentToken(componentID) {
		return "", fmt.Errorf("unsafe componentId %q", componentID)
	}
	return filepath.Join(w.activeDir, componentID+".wal"), nil
}

// Open records the initial staged intent EXCLUSIVELY: the O_EXCL create is the
// per-component lock — a second in-flight apply for the same component fails
// here rather than racing. The entry is forced to StateStaged.
func (w *WALStore) Open(entry WALEntry) error {
	entry.Schema = walSchema
	entry.State = StateStaged
	if err := entry.validate(); err != nil {
		return err
	}
	path, err := w.activePath(entry.ComponentID)
	if err != nil {
		return err
	}
	raw, err := marshalWAL(entry)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("component %s already has an in-flight apply (WAL locked)", entry.ComponentID)
		}
		return fmt.Errorf("open wal %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return fmt.Errorf("write wal: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync wal: %w", err)
	}
	return fsyncDir(w.activeDir)
}

// Load reads the active WAL entry for a component, or (_, false, nil) if none.
func (w *WALStore) Load(componentID string) (WALEntry, bool, error) {
	var e WALEntry
	path, err := w.activePath(componentID)
	if err != nil {
		return e, false, err
	}
	// Open the WAL file itself no-follow (never read through a symlinked WAL) and
	// bound the read so an oversized file cannot be slurped whole before the size
	// check rejects it.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return e, false, nil
		}
		return e, false, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxWALBytes+1))
	if err != nil {
		return e, false, err
	}
	if err := unmarshalWAL(raw, &e); err != nil {
		return e, false, fmt.Errorf("decode wal %s: %w", path, err)
	}
	return e, true, nil
}

// LoadAll reads every active WAL entry — the recovery inventory at startup.
func (w *WALStore) LoadAll() ([]WALEntry, error) {
	ents, err := os.ReadDir(w.activeDir)
	if err != nil {
		return nil, err
	}
	var out []WALEntry
	for _, de := range ents {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".wal") {
			continue
		}
		id := strings.TrimSuffix(de.Name(), ".wal")
		e, ok, err := w.Load(id)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, e)
		}
	}
	return out, nil
}

// Advance transitions the active WAL to newState, applying mutate under the
// current entry, and durably rewrites it (temp + rename + fsync). It refuses a
// transition on a terminal entry.
func (w *WALStore) Advance(componentID string, newState WALState, mutate func(*WALEntry)) error {
	e, ok, err := w.Load(componentID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no active WAL for component %s", componentID)
	}
	if e.State.terminal() {
		return fmt.Errorf("component %s WAL is already terminal (%s)", componentID, e.State)
	}
	if !legalTransition(e.State, newState) {
		return fmt.Errorf("illegal WAL transition %s -> %s for component %s (no skip/regress)", e.State, newState, componentID)
	}
	e.State = newState
	if mutate != nil {
		mutate(&e)
	}
	if err := e.validate(); err != nil {
		return err
	}
	path, err := w.activePath(componentID)
	if err != nil {
		return err
	}
	raw, err := marshalWAL(e)
	if err != nil {
		return err
	}
	return writeDurable(path, raw)
}

// UpdateActive durably refreshes evidence on an in-flight WAL without advancing
// its state. It exists for later-tick proof refreshes: deep-stable completion must
// retain the runtime tuple that was re-bound immediately before the terminal
// receipt, not merely the tuple observed at the initial restart.
func (w *WALStore) UpdateActive(componentID string, mutate func(*WALEntry)) error {
	e, ok, err := w.Load(componentID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no active WAL for component %s", componentID)
	}
	if e.State.terminal() {
		return fmt.Errorf("component %s WAL is already terminal (%s)", componentID, e.State)
	}
	if mutate != nil {
		mutate(&e)
	}
	if err := e.validate(); err != nil {
		return err
	}
	path, err := w.activePath(componentID)
	if err != nil {
		return err
	}
	raw, err := marshalWAL(e)
	if err != nil {
		return err
	}
	return writeDurable(path, raw)
}

// finalize writes the terminal receipt and removes the active WAL. The terminal
// state (applied / rolled-back) is retained forever as the receipt.
func (w *WALStore) finalize(componentID string, terminal WALState, terminalAtUnix int64, lastErr string) (WALEntry, error) {
	var zero WALEntry
	e, ok, err := w.Load(componentID)
	if err != nil {
		return zero, err
	}
	if !ok {
		return zero, fmt.Errorf("no active WAL for component %s", componentID)
	}
	if !legalTransition(e.State, terminal) {
		return zero, fmt.Errorf("illegal WAL finalize %s -> %s for component %s", e.State, terminal, componentID)
	}
	e.State = terminal
	e.TerminalAtUnix = terminalAtUnix
	if lastErr != "" {
		e.LastError = lastErr
	}
	if err := e.validateTerminalReceiptBindings(); err != nil {
		return zero, err
	}
	raw, err := marshalWAL(e)
	if err != nil {
		return zero, err
	}
	receipt := filepath.Join(w.receiptDir, fmt.Sprintf("%s-gen%d-%s.json", e.ComponentID, e.GenerationID, terminal))
	// The accepted terminal receipt is APPEND-ONLY: O_EXCL refuses to overwrite an
	// existing receipt (a receipt is written exactly once per component+generation+
	// terminal-state). A failed receipt write returns BEFORE the active WAL is
	// removed, so the component stays recoverable rather than silently terminalized.
	if err := writeReceiptExclusive(receipt, raw); err != nil {
		return zero, fmt.Errorf("write terminal receipt: %w", err)
	}
	active, err := w.activePath(componentID)
	if err != nil {
		return zero, err
	}
	if err := os.Remove(active); err != nil && !errors.Is(err, os.ErrNotExist) {
		return zero, fmt.Errorf("remove active wal: %w", err)
	}
	if err := fsyncDir(w.activeDir); err != nil {
		return zero, err
	}
	return e, nil
}

// Complete marks the apply terminal-applied (deep-stable elapsed) and retains the
// receipt.
func (w *WALStore) Complete(componentID string, nowUnix int64) (WALEntry, error) {
	return w.finalize(componentID, StateApplied, nowUnix, "")
}

// Rollback marks the apply terminal-rolled-back (prior restored) and retains the
// receipt with the failure reason.
func (w *WALStore) Rollback(componentID string, nowUnix int64, reason string) (WALEntry, error) {
	return w.finalize(componentID, StateRolledBack, nowUnix, reason)
}

// discard removes the active WAL for a component that never mutated the host
// (staged). No terminal receipt is written — nothing happened to record — and the
// per-component lock is released.
func (w *WALStore) discard(componentID string) error {
	active, err := w.activePath(componentID)
	if err != nil {
		return err
	}
	if err := os.Remove(active); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("discard active wal: %w", err)
	}
	return fsyncDir(w.activeDir)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func marshalWAL(e WALEntry) ([]byte, error) {
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal wal: %w", err)
	}
	return append(raw, '\n'), nil
}

func unmarshalWAL(raw []byte, e *WALEntry) error {
	if len(raw) > maxWALBytes {
		return fmt.Errorf("wal exceeds %d bytes", maxWALBytes)
	}
	// Reject case-shadowed/exact duplicate keys (a decoy "State" shadowing "state")
	// and trailing data before decoding into the struct.
	if err := assertNoDuplicateJSONKeys(raw); err != nil {
		return fmt.Errorf("wal: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(e); err != nil {
		return err
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("wal has unexpected trailing data")
	}
	return e.validate()
}

// ParseTerminalReceipt strictly decodes one immutable terminal receipt. Receipt
// readers must not treat an arbitrary WAL-shaped JSON object as proof: it has to
// be a known terminal state and carry the same deadline/trigger/runtime bindings
// that finalize required when it was written.
func ParseTerminalReceipt(raw []byte) (WALEntry, error) {
	var e WALEntry
	if err := unmarshalWAL(raw, &e); err != nil {
		return WALEntry{}, fmt.Errorf("decode terminal receipt: %w", err)
	}
	if !e.State.terminal() {
		return WALEntry{}, fmt.Errorf("receipt state %q is not terminal", e.State)
	}
	if err := e.validateTerminalReceiptBindings(); err != nil {
		return WALEntry{}, fmt.Errorf("validate terminal receipt: %w", err)
	}
	return e, nil
}

// legalTransition encodes the WAL's forward-only apply graph: a state may only
// advance to its immediate successor or fail to rolled-back. No skip (staged ->
// applied) and no regress (applying -> staged) are permitted; terminal states
// have no outgoing edge.
func legalTransition(from, to WALState) bool {
	switch from {
	case StateStaged:
		return to == StateApplying || to == StateRolledBack
	case StateApplying:
		return to == StateRestarted || to == StateRolledBack
	case StateRestarted:
		return to == StateHealthyUnstable || to == StateRolledBack
	case StateHealthyUnstable:
		return to == StateApplied || to == StateRolledBack
	}
	return false
}

// writeDurable atomically writes data to path via a same-dir temp file + fsync +
// rename + dir fsync, so a reader (or a crash) never sees a torn WAL.
// writeReceiptExclusive writes an APPEND-ONLY receipt: O_CREATE|O_EXCL|O_NOFOLLOW
// refuses to overwrite (or follow a symlinked) existing receipt, then fsyncs the
// file and its parent dir so the accepted receipt is durable.
func writeReceiptExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write receipt: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("fsync receipt: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close receipt: %w", err)
	}
	return fsyncDir(filepath.Dir(path))
}

func writeDurable(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	cleanup = false
	return fsyncDir(dir)
}

func fsyncDir(path string) error {
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

func safeComponentToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return s[0] != '.' && !strings.Contains(s, "..")
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
