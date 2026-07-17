package main

// CLI wiring for the no-gap supersede orchestrator. The orchestrator itself
// signs nothing and writes no chain state directly: it COORDINATES governed
// operator-supplied commands in the crash-safe order proven in supersede.go.
// The register/revoke commands are the off-box Squads ceremonies (HT13 — keys
// never touch the box); the stage/promote commands drive the existing gated
// /publish routes; the active/served commands are read-only.
//
// Each op command is executed via `sh -c` with the request bound in the
// environment, so an operator wraps the existing tools without this binary ever
// embedding credentials:
//
//	MEL_APP_ID        appId being superseded
//	MEL_NEW_APP_HASH  new release app_hash
//	MEL_NEW_VERSION   new release version
//	MEL_STAGE_ID      verified stage id (promote-cmd only)
//	MEL_PDA           the exact stale ReleaseEntry PDA to revoke (revoke-cmd only)
//
// --active-cmd MUST print the same JSON-lines shape list-active-releases emits:
// one {"pda":..,"version":..,"appHash":..} object per Active entry.
// --served-cmd MUST print the served app_hash for MEL_APP_ID (empty = none).

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("empty value")
	}
	*s = append(*s, v)
	return nil
}

type cliOptions struct {
	wal               string
	lockDir           string
	receiptDir        string
	releaseJSON       string
	appID             string
	newAppHash        string
	newVersion        string
	releaseNonce      string
	stalePDAs         stringList
	buildCmd          string
	activeCmd         string
	statusCmd         string
	registerCmd       string
	stageCmd          string
	promoteCmd        string
	revokeCmd         string
	servedCmd         string
	opTimeout         time.Duration
	adapterCgroupRoot string
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "publish-supersede: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out *os.File) error {
	opts, err := parseCLI(args)
	if err != nil {
		return err
	}
	ops := &commandOps{opts: opts}
	p := Params{
		WALPath:         opts.wal,
		LockPath:        appLockPath(opts.lockDir, opts.appID),
		ReceiptDir:      opts.receiptDir,
		ReleaseJSONPath: opts.releaseJSON,
		AppID:           opts.appID,
		NewAppHash:      opts.newAppHash,
		NewVersion:      opts.newVersion,
		ReleaseNonce:    opts.releaseNonce,
		StalePDAs:       opts.stalePDAs,
		Build:           ops,
		Chain:           ops,
		Store:           ops,
	}
	rec, err := RunSupersede(p)
	if err != nil {
		return err
	}
	terminal := newTerminalReceipt(rec)
	if err := writeTerminalReceiptDurable(terminalReceiptPath(p), terminal); err != nil {
		return fmt.Errorf("terminal receipt: %w", err)
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(terminal)
}

func parseCLI(args []string) (cliOptions, error) {
	var o cliOptions
	fs := flag.NewFlagSet("publish-supersede", flag.ContinueOnError)
	fs.StringVar(&o.wal, "wal", "", "absolute path to the durable write-ahead receipt (required)")
	fs.StringVar(&o.lockDir, "lock-dir", "", "absolute directory for per-app locks (required)")
	fs.StringVar(&o.receiptDir, "receipt-dir", "", "absolute directory for immutable native receipts (required)")
	fs.StringVar(&o.releaseJSON, "release-json", "", "absolute finalized RELEASE.json path written by register-cmd (required)")
	fs.StringVar(&o.appID, "app-id", "", "appId being superseded (required)")
	fs.StringVar(&o.newAppHash, "new-app-hash", "", "new release app_hash (required)")
	fs.StringVar(&o.newVersion, "new-version", "", "new release version, strictly greater (required)")
	fs.StringVar(&o.releaseNonce, "release-nonce", "", "32 lowercase hex nonce override; generated once and WAL-pinned when omitted")
	fs.Var(&o.stalePDAs, "stale-pda", "an exact prior Active ReleaseEntry PDA to retire (repeatable; omit for first publication)")
	fs.StringVar(&o.buildCmd, "build-cmd", "", "build exact candidate and write MEL_CANDIDATE_RECEIPT_OUT (required)")
	fs.StringVar(&o.activeCmd, "active-cmd", "", "read-only: prints JSON-lines of Active releases for MEL_APP_ID (required)")
	fs.StringVar(&o.statusCmd, "status-cmd", "", "read-only exact-PDA status JSON for MEL_PDA (required when stale-pda is present)")
	fs.StringVar(&o.registerCmd, "register-cmd", "", "governed off-box ceremony: register the new release Active (required)")
	fs.StringVar(&o.stageCmd, "stage-cmd", "", "stage the new bytes privately, print {\"stageId\":..} (required)")
	fs.StringVar(&o.promoteCmd, "promote-cmd", "", "durable /publish promote of the staged new bytes (required)")
	fs.StringVar(&o.revokeCmd, "revoke-cmd", "", "governed off-box ceremony: revoke the ReleaseEntry at MEL_PDA (required)")
	fs.StringVar(&o.servedCmd, "served-cmd", "", "read-only: prints the served app_hash for MEL_APP_ID (required)")
	fs.DurationVar(&o.opTimeout, "op-timeout", 8*time.Minute, "per-command timeout")
	fs.StringVar(&o.adapterCgroupRoot, "adapter-cgroup-root", "", "absolute delegated cgroup-v2 subtree for per-command containment (required)")
	if err := fs.Parse(args); err != nil {
		return cliOptions{}, err
	}
	if fs.NArg() != 0 {
		return cliOptions{}, fmt.Errorf("unexpected positional args: %v", fs.Args())
	}
	required := map[string]string{
		"--wal": o.wal, "--lock-dir": o.lockDir, "--receipt-dir": o.receiptDir,
		"--release-json": o.releaseJSON, "--app-id": o.appID, "--new-app-hash": o.newAppHash,
		"--new-version": o.newVersion, "--active-cmd": o.activeCmd,
		"--build-cmd":    o.buildCmd,
		"--register-cmd": o.registerCmd, "--stage-cmd": o.stageCmd,
		"--promote-cmd": o.promoteCmd, "--revoke-cmd": o.revokeCmd, "--served-cmd": o.servedCmd,
		"--adapter-cgroup-root": o.adapterCgroupRoot,
	}
	for name, val := range required {
		if strings.TrimSpace(val) == "" {
			return cliOptions{}, fmt.Errorf("%s is required", name)
		}
	}
	if len(o.stalePDAs) > 0 && strings.TrimSpace(o.statusCmd) == "" {
		return cliOptions{}, errors.New("--status-cmd is required when --stale-pda is present")
	}
	for name, path := range map[string]string{"--wal": o.wal, "--lock-dir": o.lockDir, "--receipt-dir": o.receiptDir, "--release-json": o.releaseJSON, "--adapter-cgroup-root": o.adapterCgroupRoot} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return cliOptions{}, fmt.Errorf("%s must be an absolute clean path", name)
		}
	}
	return o, nil
}

func appLockPath(dir, appID string) string {
	h := sha256.Sum256([]byte(appID))
	return filepath.Join(dir, fmt.Sprintf("%x.lock", h[:16]))
}

// commandOps satisfies both ChainOps and StoreOps by shelling to the operator's
// governed commands.
type commandOps struct{ opts cliOptions }

const maxAdapterOutputBytes = 4 << 20

type cappedWriter struct {
	b        strings.Builder
	limit    int
	overflow bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	n := len(p)
	remaining := w.limit - w.b.Len()
	if remaining > 0 {
		if remaining > len(p) {
			remaining = len(p)
		}
		_, _ = w.b.Write(p[:remaining])
	}
	if remaining < len(p) {
		w.overflow = true
	}
	return n, nil
}

func (w *cappedWriter) String() string { return w.b.String() }

func (c *commandOps) exec(cmdStr string, env map[string]string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.opts.opTimeout)
	defer cancel()
	scope, err := newOperationContainment(c.opts.adapterCgroupRoot)
	if err != nil {
		return "", fmt.Errorf("adapter containment: %w", err)
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	scope.Configure(cmd)
	cmd.Cancel = scope.Terminate
	cmd.WaitDelay = 500 * time.Millisecond
	cmd.Env = environmentWithOverrides(os.Environ(), env)
	var stdout, stderr cappedWriter
	stdout.limit, stderr.limit = maxAdapterOutputBytes, maxAdapterOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		_ = scope.Cleanup()
		return "", err
	}
	runErr := cmd.Wait()
	cleanupErr := scope.Cleanup()
	if ctx.Err() != nil {
		runErr = ctx.Err()
	}
	if cleanupErr != nil {
		return "", fmt.Errorf("adapter containment cleanup: %w", cleanupErr)
	}
	if runErr != nil {
		return "", fmt.Errorf("%w: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	if stdout.overflow || stderr.overflow {
		return "", fmt.Errorf("adapter output exceeds %d-byte bound", maxAdapterOutputBytes)
	}
	return stdout.String(), nil
}

func environmentWithOverrides(base []string, overrides map[string]string) []string {
	out := make([]string, 0, len(base)+len(overrides))
	for _, item := range base {
		key, _, _ := strings.Cut(item, "=")
		if _, replaced := overrides[key]; !replaced {
			out = append(out, item)
		}
	}
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, key+"="+overrides[key])
	}
	return out
}

func (c *commandOps) ActiveReleases(appID string) ([]releaseRef, error) {
	out, err := c.exec(c.opts.activeCmd, map[string]string{"MEL_APP_ID": appID})
	if err != nil {
		return nil, err
	}
	var refs []releaseRef
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r struct {
			PDA     string `json:"pda"`
			Version string `json:"version"`
			AppHash string `json:"appHash"`
		}
		if err := decodeOneJSON([]byte(line), &r, true); err != nil {
			return nil, fmt.Errorf("parse active-cmd line %q: %w", line, err)
		}
		if strings.TrimSpace(r.PDA) == "" || !isLowerHex(r.AppHash, 64) || strings.TrimSpace(r.Version) == "" {
			return nil, fmt.Errorf("active-cmd returned an incomplete release: %q", line)
		}
		refs = append(refs, releaseRef{PDA: r.PDA, AppHash: r.AppHash, Version: r.Version})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return refs, nil
}

func (c *commandOps) Build(candidateReceiptPath string) error {
	_, err := c.exec(c.opts.buildCmd, map[string]string{
		"MEL_APP_ID": c.opts.appID, "MEL_NEW_APP_HASH": c.opts.newAppHash,
		"MEL_NEW_VERSION": c.opts.newVersion, "MEL_CANDIDATE_RECEIPT_OUT": candidateReceiptPath,
	})
	return err
}

func (c *commandOps) RegisterRelease(appID, newAppHash, newVersion, nonce, releaseJSONPath, receiptPath string) error {
	_, err := c.exec(c.opts.registerCmd, map[string]string{
		"MEL_APP_ID": appID, "MEL_NEW_APP_HASH": newAppHash, "MEL_NEW_VERSION": newVersion,
		"MEL_RELEASE_NONCE": nonce, "MEL_RELEASE_JSON_OUT": releaseJSONPath,
		"MEL_REGISTER_RECEIPT_OUT": receiptPath,
	})
	return err
}

func (c *commandOps) ReleaseStatus(pda string) (releaseStatus, error) {
	out, err := c.exec(c.opts.statusCmd, map[string]string{"MEL_PDA": pda})
	if err != nil {
		return releaseStatus{}, err
	}
	var parsed releaseStatus
	if err := decodeOneJSON([]byte(strings.TrimSpace(out)), &parsed, true); err != nil {
		return releaseStatus{}, fmt.Errorf("parse status-cmd output: %w", err)
	}
	if parsed.PDA == "" || !isLowerHex(parsed.AppHash, 64) || parsed.Version == "" || parsed.Status == "" {
		return releaseStatus{}, errors.New("status-cmd returned an incomplete exact-PDA status")
	}
	return parsed, nil
}

func (c *commandOps) RevokeRelease(pda, receiptPath string) error {
	_, err := c.exec(c.opts.revokeCmd, map[string]string{
		"MEL_PDA": pda, "MEL_REVOKE_RECEIPT_OUT": receiptPath,
	})
	return err
}

func (c *commandOps) Stage(appID, newAppHash, releaseHash string, candidate candidateBinding, receiptPath string) error {
	_, err := c.exec(c.opts.stageCmd, map[string]string{
		"MEL_APP_ID": appID, "MEL_NEW_APP_HASH": newAppHash, "MEL_RELEASE_HASH": releaseHash,
		"MEL_CANDIDATE_SPK": candidate.SPK.Path, "MEL_CANDIDATE_SPK_SHA256": candidate.SPK.SHA256,
		"MEL_CANDIDATE_METADATA": candidate.Metadata.Path, "MEL_CANDIDATE_METADATA_SHA256": candidate.Metadata.SHA256,
		"MEL_CANDIDATE_APP_HASH": candidate.AppHash, "MEL_STAGE_RECEIPT_OUT": receiptPath,
	})
	return err
}

func (c *commandOps) Promote(appID, newAppHash, releaseHash, stageID, receiptPath string) error {
	_, err := c.exec(c.opts.promoteCmd, map[string]string{
		"MEL_APP_ID": appID, "MEL_NEW_APP_HASH": newAppHash, "MEL_RELEASE_HASH": releaseHash,
		"MEL_NEW_VERSION": c.opts.newVersion, "MEL_STAGE_ID": stageID, "MEL_PROMOTE_RECEIPT_OUT": receiptPath,
	})
	return err
}

func (c *commandOps) ServedAppHash(appID string) (string, error) {
	out, err := c.exec(c.opts.servedCmd, map[string]string{"MEL_APP_ID": appID})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}
