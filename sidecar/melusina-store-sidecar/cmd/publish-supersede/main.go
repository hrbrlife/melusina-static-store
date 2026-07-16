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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
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
	wal                string
	appID              string
	newAppHash         string
	newVersion         string
	stalePDAs          stringList
	programID          string
	clusterGenesisHash string
	operatorPubkey     string
	storeAuthority     string
	storeOrigin        string
	activeCmd          string
	registerCmd        string
	stageCmd           string
	promoteCmd         string
	revokeCmd          string
	servedCmd          string
	opTimeout          time.Duration
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
		WALPath:    opts.wal,
		AppID:      opts.appID,
		NewAppHash: opts.newAppHash,
		NewVersion: opts.newVersion,
		StalePDAs:  opts.stalePDAs,
		ProgramID:  opts.programID, ClusterGenesisHash: opts.clusterGenesisHash,
		OperatorPubkey: opts.operatorPubkey, StoreAuthority: opts.storeAuthority,
		StoreOrigin: opts.storeOrigin,
		Chain:       ops,
		Store:       ops,
	}
	rec, err := RunSupersede(p)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(rec)
}

func parseCLI(args []string) (cliOptions, error) {
	var o cliOptions
	fs := flag.NewFlagSet("publish-supersede", flag.ContinueOnError)
	fs.StringVar(&o.wal, "wal", "", "absolute path to the durable write-ahead receipt (required)")
	fs.StringVar(&o.appID, "app-id", "", "appId being superseded (required)")
	fs.StringVar(&o.newAppHash, "new-app-hash", "", "new release app_hash (required)")
	fs.StringVar(&o.newVersion, "new-version", "", "new release version, strictly greater (required)")
	fs.Var(&o.stalePDAs, "stale-pda", "an exact prior Active ReleaseEntry PDA to retire (repeatable; omit only for a proven zero-state first publish)")
	fs.StringVar(&o.programID, "program-id", "", "exact freshly-deployed license program id (required; legacy default refused)")
	fs.StringVar(&o.clusterGenesisHash, "cluster-genesis-hash", "", "exact getGenesisHash result for the target cluster (required)")
	fs.StringVar(&o.operatorPubkey, "operator-pubkey", "", "store receipt-signing operator pubkey (required)")
	fs.StringVar(&o.storeAuthority, "store-authority", "", "on-chain StoreOperatorAuthorization.store_authority (required; must equal operator)")
	fs.StringVar(&o.storeOrigin, "store-origin", "", "exact https store origin (required)")
	fs.StringVar(&o.activeCmd, "active-cmd", "", "read-only: prints JSON-lines of Active releases for MEL_APP_ID (required)")
	fs.StringVar(&o.registerCmd, "register-cmd", "", "governed off-box ceremony: register the new release Active (required)")
	fs.StringVar(&o.stageCmd, "stage-cmd", "", "stage the new bytes privately, print {\"stageId\":..} (required)")
	fs.StringVar(&o.promoteCmd, "promote-cmd", "", "durable /publish promote of the staged new bytes (required)")
	fs.StringVar(&o.revokeCmd, "revoke-cmd", "", "governed off-box ceremony: revoke the ReleaseEntry at MEL_PDA (required)")
	fs.StringVar(&o.servedCmd, "served-cmd", "", "read-only: prints the served app_hash for MEL_APP_ID (required)")
	fs.DurationVar(&o.opTimeout, "op-timeout", 8*time.Minute, "per-command timeout")
	if err := fs.Parse(args); err != nil {
		return cliOptions{}, err
	}
	if fs.NArg() != 0 {
		return cliOptions{}, fmt.Errorf("unexpected positional args: %v", fs.Args())
	}
	required := map[string]string{
		"--wal": o.wal, "--app-id": o.appID, "--new-app-hash": o.newAppHash,
		"--new-version": o.newVersion, "--active-cmd": o.activeCmd,
		"--program-id": o.programID, "--cluster-genesis-hash": o.clusterGenesisHash,
		"--operator-pubkey": o.operatorPubkey, "--store-authority": o.storeAuthority,
		"--store-origin": o.storeOrigin,
		"--register-cmd": o.registerCmd, "--stage-cmd": o.stageCmd,
		"--promote-cmd": o.promoteCmd, "--revoke-cmd": o.revokeCmd, "--served-cmd": o.servedCmd,
	}
	for name, val := range required {
		if strings.TrimSpace(val) == "" {
			return cliOptions{}, fmt.Errorf("%s is required", name)
		}
	}
	return o, nil
}

// commandOps satisfies both ChainOps and StoreOps by shelling to the operator's
// governed commands.
type commandOps struct{ opts cliOptions }

func (c *commandOps) exec(cmdStr string, env map[string]string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.opts.opTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	cmd.Env = os.Environ()
	bound := map[string]string{
		"MEL_PROGRAM_ID":           c.opts.programID,
		"MEL_CLUSTER_GENESIS_HASH": c.opts.clusterGenesisHash,
		"MEL_OPERATOR_PUBKEY":      c.opts.operatorPubkey,
		"MEL_STORE_AUTHORITY":      c.opts.storeAuthority,
		"MEL_STORE_ORIGIN":         c.opts.storeOrigin,
	}
	for k, v := range env {
		bound[k] = v
	}
	for k, v := range bound {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
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
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("parse active-cmd line %q: %w", line, err)
		}
		refs = append(refs, releaseRef{PDA: r.PDA, AppHash: r.AppHash, Version: r.Version})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return refs, nil
}

func (c *commandOps) RegisterRelease(appID, newAppHash, newVersion string) (releaseRef, error) {
	if _, err := c.exec(c.opts.registerCmd, map[string]string{
		"MEL_APP_ID": appID, "MEL_NEW_APP_HASH": newAppHash, "MEL_NEW_VERSION": newVersion,
	}); err != nil {
		return releaseRef{}, err
	}
	// Re-read to obtain the freshly-registered PDA (and confirm it is Active).
	active, err := c.ActiveReleases(appID)
	if err != nil {
		return releaseRef{}, err
	}
	for _, r := range active {
		if r.AppHash == newAppHash {
			return r, nil
		}
	}
	return releaseRef{}, fmt.Errorf("register-cmd completed but appHash %s is not Active", newAppHash)
}

func (c *commandOps) RevokeRelease(pda string) error {
	_, err := c.exec(c.opts.revokeCmd, map[string]string{"MEL_PDA": pda})
	return err
}

func (c *commandOps) Stage(appID, newAppHash string) (string, error) {
	out, err := c.exec(c.opts.stageCmd, map[string]string{"MEL_APP_ID": appID, "MEL_NEW_APP_HASH": newAppHash})
	if err != nil {
		return "", err
	}
	var parsed struct {
		StageID string `json:"stageId"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); err != nil {
		return "", fmt.Errorf("parse stage-cmd output: %w", err)
	}
	if parsed.StageID == "" {
		return "", errors.New("stage-cmd returned an empty stageId")
	}
	return parsed.StageID, nil
}

func (c *commandOps) Promote(appID, newAppHash, stageID string) error {
	_, err := c.exec(c.opts.promoteCmd, map[string]string{
		"MEL_APP_ID": appID, "MEL_NEW_APP_HASH": newAppHash, "MEL_STAGE_ID": stageID,
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
