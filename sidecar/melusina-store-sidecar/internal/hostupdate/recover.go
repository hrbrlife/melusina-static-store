package hostupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// CommandRunner runs a host command (e.g. systemctl restart/stop). It is injected
// so the recovery/apply paths are unit-testable without a live systemd.
type CommandRunner interface {
	Run(ctx context.Context, argv []string) error
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return errors.New("empty command")
	}
	return exec.CommandContext(ctx, argv[0], argv[1:]...).Run()
}

// DefaultRunner executes commands via os/exec.
func DefaultRunner() CommandRunner { return execRunner{} }

func restartArgv(install componentrelease.ComponentInstall) []string {
	if len(install.RestartCommand) > 0 {
		return install.RestartCommand
	}
	return []string{"systemctl", "restart", install.ServiceUnit}
}

func stopArgv(install componentrelease.ComponentInstall) []string {
	return []string{"systemctl", "stop", install.ServiceUnit}
}

// RollbackFromWAL restores the EXACT prior artifact recorded in a PERSISTED WAL
// entry and restarts the component. It is the generic, fresh-process-executable
// rollback that replaces the in-memory closure returned by Adapter.Apply (which
// dies with a crashed controller): everything it needs — the retained prior path,
// the prior hash, the install root and unit — lives in the WAL entry + the
// install-local registry, so a brand-new controller process can execute the exact
// rollback after a crash-post-swap. Fail-closed: it refuses to restore a prior
// whose bytes do not hash to the recorded fromHash.
func RollbackFromWAL(ctx context.Context, entry WALEntry, install componentrelease.ComponentInstall, runner CommandRunner) error {
	if runner == nil {
		return errors.New("no command runner")
	}
	switch entry.ApplyKind {
	case componentrelease.ApplyBinaryReplace:
		return rollbackBinaryReplace(ctx, entry, install, runner)
	default:
		return fmt.Errorf("rollback for applyKind %q not implemented", entry.ApplyKind)
	}
}

func rollbackBinaryReplace(ctx context.Context, entry WALEntry, install componentrelease.ComponentInstall, runner CommandRunner) error {
	if !filepath.IsAbs(install.InstallRoot) {
		return fmt.Errorf("installRoot %q is not absolute", install.InstallRoot)
	}
	// Restore the exact old EnvironmentFile BEFORE restarting the old binary.
	// Otherwise a rollback can run old bytes under the new generation/version and
	// falsely pass an application-level self-report.
	if err := RestoreRuntimeMarkerFromWAL(entry, install); err != nil {
		return fmt.Errorf("restore runtime marker: %w", err)
	}
	// A constrained stalled-successor recovery never replaced artifact bytes:
	// its valid rollback is restoring the prior runtime marker and restarting the
	// already-proved target. Do not fabricate a binary rollback floor. Re-measure
	// through O_NOFOLLOW so a substituted executable cannot be restarted under an
	// old marker and silently accepted as recovery.
	if entry.ReapplyCurrent {
		got, err := sha256RegularFileNoFollow(install.InstallRoot)
		if err != nil {
			return fmt.Errorf("measure already-current target: %w", err)
		}
		if got != entry.ToHash {
			return fmt.Errorf("already-current target hashes %s != recorded toHash %s; refusing restart", got, entry.ToHash)
		}
		return runner.Run(ctx, restartArgv(install))
	}
	// Brand-new component (no prior artifact): the exact-old-state restore is to
	// UNINSTALL the just-swapped binary and stop the unit.
	if entry.FromHash == "" || entry.PriorPath == "" {
		if err := os.Remove(install.InstallRoot); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove new binary: %w", err)
		}
		return runner.Run(ctx, stopArgv(install))
	}
	// Never restore a wrong/tampered prior: the retained bytes MUST hash to the
	// recorded fromHash.
	got, err := sha256File(entry.PriorPath)
	if err != nil {
		return fmt.Errorf("hash retained prior %s: %w", entry.PriorPath, err)
	}
	if got != entry.FromHash {
		return fmt.Errorf("retained prior %s hashes %s != recorded fromHash %s; refusing to restore", entry.PriorPath, got, entry.FromHash)
	}
	if err := atomicReplaceFile(entry.PriorPath, install.InstallRoot, 0o755); err != nil {
		return fmt.Errorf("restore prior binary: %w", err)
	}
	return runner.Run(ctx, restartArgv(install))
}

// RecoveryOutcome records what the recovery pass did for one component.
type RecoveryOutcome struct {
	ComponentID string
	Action      RecoveryAction
	Err         error
}

// RecoverAll runs a crash-recovery pass over every active WAL entry INDEPENDENTLY.
// It is the per-component primitive; the controller startup path is
// RecoverGenerations, which groups entries by generation and recovers each ATOMICALLY
// (never completing one member while a sibling rolls back). Use RecoverAll only when
// every active entry is known to be a standalone single-component generation.
//
// For each entry it consults RecoveryDecision with the
// observed running hash + health, then executes:
//   - discard: no mutation happened (staged) — drop the WAL;
//   - complete: target + healthy + deep-stable elapsed — finalize applied;
//   - rollback: not coherently at target — restore the exact prior via
//     RollbackFromWAL, then finalize rolled-back;
//   - wait/none: leave for the poll loop / already terminal.
//
// Fail-closed: if a rollback restore itself fails, the WAL is LEFT ACTIVE (the
// intent is not lost) so the next pass retries; the outcome carries the error.
func RecoverAll(
	ctx context.Context,
	ws *WALStore,
	installFor func(componentID string) (componentrelease.ComponentInstall, bool),
	observe func(componentID string) (runningHash string, healthy bool),
	runner CommandRunner,
	nowUnix int64,
) ([]RecoveryOutcome, error) {
	entries, err := ws.LoadAll()
	if err != nil {
		return nil, err
	}
	var outcomes []RecoveryOutcome
	for _, e := range entries {
		running, healthy := observe(e.ComponentID)
		action := RecoveryDecision(e, running, healthy, nowUnix)
		oc := RecoveryOutcome{ComponentID: e.ComponentID, Action: action}
		switch action {
		case RecoverNone, RecoverWait:
			// leave as-is
		case RecoverDiscard:
			oc.Err = ws.discard(e.ComponentID)
		case RecoverComplete:
			// The graph forbids restarted -> applied directly; advance through
			// healthy-unstable first (it is proven target+healthy+deep-stable).
			if e.State == StateRestarted {
				if err := ws.Advance(e.ComponentID, StateHealthyUnstable, func(en *WALEntry) {
					if en.AppliedAtUnix == 0 {
						en.AppliedAtUnix = e.AppliedAtUnix
					}
				}); err != nil {
					oc.Err = err
					break
				}
			}
			_, oc.Err = ws.Complete(e.ComponentID, nowUnix)
		case RecoverRollback:
			install, ok := installFor(e.ComponentID)
			if !ok {
				oc.Err = fmt.Errorf("no registry install for component %s", e.ComponentID)
				break
			}
			if err := RollbackFromWAL(ctx, e, install, runner); err != nil {
				// Leave the WAL active so the next pass retries.
				oc.Err = err
				break
			}
			_, oc.Err = ws.Rollback(e.ComponentID, nowUnix, "crash recovery: not coherently at target")
		}
		outcomes = append(outcomes, oc)
	}
	return outcomes, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// sha256RegularFileNoFollow hashes a concrete regular-file inode without
// following a substituted symlink. Recovery uses it when no binary replacement
// occurred and therefore no retained prior artifact exists to restore.
func sha256RegularFileNoFollow(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// atomicReplaceFile copies src to dst via a same-dir temp file + fsync + rename so
// dst is never observed torn (crash-safe restore).
func atomicReplaceFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src %s: %w", src, err)
	}
	defer in.Close()
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".restore-*")
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
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("copy: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	cleanup = false
	return fsyncDir(dir)
}
