// Command melusina-update-controller is the out-of-shell host update controller.
//
// It runs OUTSIDE the shell/store/sidecars it updates and is invoked ONCE per
// systemd timer tick (OnUnitActiveSec=60): each invocation loads the root-owned
// config + the persisted ControllerState, builds the real PollDeps, runs exactly one
// PollOnce, and exits. Discovery is internally gated to the 5-minute cadence via the
// persisted LastDiscovery; a component's deep-stable Completion happens on a later
// tick that services the active WAL. A path-unit or admin trigger can invoke the
// bell/manual mode, which bypasses the discovery cadence but is recorded AS
// bell/manual (a one-shot trigger never mints a timer-qualified receipt).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/hostupdate"
)

// controllerStateUID is the uid the root-owned config + state files must be owned by.
// The controller runs as root (it mutates system units + binaries); its trust files
// are root-owned 0600.
const controllerStateUID = 0

func main() {
	configPath := flag.String("config", "/etc/melusina/update-controller/config.json", "path to the root-owned controller config (JSON)")
	trigger := flag.String("trigger", "timer", "poll trigger: timer (default, cadence-gated) | bell | manual")
	flag.Parse()

	pollTrigger, err := parseTrigger(*trigger)
	if err != nil {
		log.Fatalf("controller: %v", err)
	}

	cfg, err := LoadControllerConfig(*configPath)
	if err != nil {
		log.Fatalf("controller config: %v", err)
	}

	// Ensure the staging root exists (the WAL constructor creates state/active +
	// state/receipts itself; the adapter stages downloads under stagingRoot).
	if err := os.MkdirAll(cfg.stagingRoot(), 0o700); err != nil {
		log.Fatalf("controller staging root: %v", err)
	}

	// The binary-replace adapter is the one host-action recipe wired today; nil
	// selects the split no-redirect(stage)/loopback(probe) fetchers. Additional
	// adapters register here as they land. A duplicate registration is a fatal
	// wiring bug (RegisterAdapter refuses it).
	if err := componentrelease.RegisterAdapter(componentrelease.NewBinaryReplaceAdapter(nil)); err != nil {
		log.Fatalf("controller adapter wiring: %v", err)
	}

	// Single-instance controller lock: two overlapping timer invocations must never
	// run concurrently. A busy lock means the prior tick is still running — skip this
	// tick cleanly (exit 0), do not stack a second writer.
	lock, held, err := acquireControllerLock(filepath.Join(cfg.StateDir, "controller.lock"))
	if err != nil {
		log.Fatalf("controller lock: %v", err)
	}
	if !held {
		log.Printf("controller: a prior tick still holds the lock — skipping this %s tick", pollTrigger)
		return
	}
	defer lock.Close()

	deps, err := buildPollDeps(cfg, controllerStateUID)
	if err != nil {
		log.Fatalf("controller deps: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := hostupdate.PollOnce(ctx, pollTrigger, deps); err != nil {
		log.Fatalf("poll (%s): %v", pollTrigger, err)
	}
	log.Printf("controller: %s tick complete", pollTrigger)
}

func parseTrigger(s string) (hostupdate.PollTrigger, error) {
	switch s {
	case "timer":
		return hostupdate.PollTriggerTimer, nil
	case "bell":
		return hostupdate.PollTriggerBell, nil
	case "manual":
		return hostupdate.PollTriggerManual, nil
	default:
		return "", fmt.Errorf("unknown -trigger %q (want timer|bell|manual)", s)
	}
}

// acquireControllerLock opens/creates the controller singleton lock and takes a
// non-blocking exclusive flock. held=false (no error) means another invocation holds
// it and this tick should be skipped.
func acquireControllerLock(path string) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("open controller lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("flock controller lock: %w", err)
	}
	return f, true, nil
}
