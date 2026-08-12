package main

// The signer-provider seam (Invariant 4: no keys dir). mel-release itself holds
// NO chain signing key. Every governed mutation — the off-box Squads
// register/approve/revoke ceremonies (HT13, keys never on the box), the store
// stage/promote routes, and the read-only chain/served queries — is delegated to
// one configured command, MEL_RELEASE_SIGNER_PROVIDER, invoked as
//
//	sh -c "<provider> <op>"
//
// with the request bound in the environment and every native receipt written to
// a MEL_*_RECEIPT_OUT path this process then re-verifies. This is the exact
// abstraction proven in cmd/publish-supersede's commandOps, with register split
// into a `propose-register` (publish side, unexecuted) and an `approve-register`
// (approve side, executes the authorized proposal) so the authority boundary is
// a real command boundary, not a flag.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// releaseRef identifies one on-chain ReleaseEntry for an app.
type releaseRef struct {
	PDA     string `json:"pda"`
	AppHash string `json:"appHash"`
	Version string `json:"version"`
}

// releaseStatus is an exact-PDA status read (includes Revoked entries).
type releaseStatus struct {
	PDA     string `json:"pda"`
	AppHash string `json:"appHash"`
	Version string `json:"version"`
	Status  string `json:"status"`
}

// SignerProvider is the whole governed surface mel-release drives. Every mutating
// method MUST be idempotent (a repeat call for an already-applied change is a
// no-op success) so the WAL's forward recovery converges. No method ever returns
// or accepts key material.
type SignerProvider interface {
	// Build materializes the exact candidate package and writes a build receipt
	// (schema melusina-app-candidate-receipt-v1) to receiptOut, including the
	// served-SPK sha256/size, the on-chain app_hash claim, the packageId, the
	// master NFT mint, and absolute paths to the staged {app.spk, metadata.json}.
	Build(appID, version, receiptOut string) error

	// ActiveReleases lists every Active on-chain ReleaseEntry for appID.
	ActiveReleases(appID string) ([]releaseRef, error)
	// ReleaseStatus reads the exact declared PDA, including Revoked entries.
	ReleaseStatus(pda string) (releaseStatus, error)
	// ServedAppHash returns the appHash the store currently serves (or "").
	ServedAppHash(appID string) (string, error)

	// Stage privately stages the new bytes at the store and writes a store-signed
	// stage receipt (schema melusina-app-stage-receipt-v1). No Active ReleaseEntry
	// is required to stage — staging is not catalog-visible.
	Stage(app App, appHash, releaseHash, version, releaseNonce, receiptOut string) error

	// ProposeRegister creates the UNEXECUTED Squads register_release_entry proposal
	// and writes RELEASE.json (releaseJSONOut) + a proposal receipt (proposeOut,
	// schema melusina-register-proposal-receipt-v1) naming the transaction PDA.
	// Nothing becomes Active.
	ProposeRegister(appID, appHash, releaseHash, version, nonce, multisig, vault, releaseJSONOut, proposeOut string) error

	// ApproveRegister executes the authorized Squads approval of transactionPda,
	// landing register_release_entry -> ReleaseEntry Active, and writes a register
	// receipt (registerOut, schema melusina-register-release-receipt-v1).
	ApproveRegister(appID, appHash, releaseHash, version, nonce, transactionPda, registerOut, finalReleaseOut string) error

	// Promote durably promotes the staged bytes into the served catalog + signed
	// pointer and writes a promotion receipt (schema melusina-app-promotion-receipt-v1).
	Promote(app App, appHash, releaseHash, version, stageID, receiptOut string) error

	// RevokeRelease flips the ReleaseEntry at pda Active -> Revoked and writes a
	// revoke receipt (schema melusina-revoke-release-receipt-v1). Idempotent.
	RevokeRelease(pda, receiptOut string) error
}

// execProvider satisfies SignerProvider by shelling to the configured governed
// command with the request in the environment.
type execProvider struct {
	command string
	env     map[string]string
	timeout time.Duration
}

func newExecProvider(c Config) *execProvider {
	return &execProvider{
		command: c.SignerProvider,
		env: map[string]string{
			"MEL_RELEASE_RPC_URL":         c.RPCURL,
			"MEL_RELEASE_STATE_DIR":       c.StateDir,
			"MEL_RELEASE_STORE_URL":       c.StoreURL,
			"MEL_RELEASE_STORE_PUBKEY":    c.StorePubkey,
			"MEL_RELEASE_PUBLISHER_KEY":   c.PublisherKey,
			"MEL_RELEASE_SQUADS_MULTISIG": c.SquadsMultisig,
			"MEL_RELEASE_SQUADS_VAULT":    c.SquadsVault,
			"MEL_PROGRAM_ID":              c.ProgramID,
		},
		timeout: time.Duration(c.OpTimeoutSecs) * time.Second,
	}
}

func (e *execProvider) run(op string, env map[string]string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", e.command+" "+op)
	cmd.Env = os.Environ()
	for k, v := range e.env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("signer-provider %q failed: %w: %s", op, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func (e *execProvider) Build(appID, version, receiptOut string) error {
	_, err := e.run("build", map[string]string{
		"MEL_APP_ID": appID, "MEL_NEW_VERSION": version,
		"MEL_CANDIDATE_RECEIPT_OUT": receiptOut,
	})
	return err
}

func (e *execProvider) ActiveReleases(appID string) ([]releaseRef, error) {
	out, err := e.run("active-releases", map[string]string{"MEL_APP_ID": appID})
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
		var r releaseRef
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("parse active-releases line %q: %w", line, err)
		}
		if strings.TrimSpace(r.PDA) == "" || !isLowerHex(r.AppHash, 64) || strings.TrimSpace(r.Version) == "" {
			return nil, fmt.Errorf("active-releases returned an incomplete release: %q", line)
		}
		refs = append(refs, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return refs, nil
}

func (e *execProvider) ReleaseStatus(pda string) (releaseStatus, error) {
	out, err := e.run("release-status", map[string]string{"MEL_PDA": pda})
	if err != nil {
		return releaseStatus{}, err
	}
	var s releaseStatus
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &s); err != nil {
		return releaseStatus{}, fmt.Errorf("parse release-status output: %w", err)
	}
	if s.PDA == "" || !isLowerHex(s.AppHash, 64) || s.Version == "" || s.Status == "" {
		return releaseStatus{}, errors.New("release-status returned an incomplete exact-PDA status")
	}
	return s, nil
}

func (e *execProvider) ServedAppHash(appID string) (string, error) {
	out, err := e.run("served-app-hash", map[string]string{"MEL_APP_ID": appID})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func (e *execProvider) Stage(app App, appHash, releaseHash, version, releaseNonce, receiptOut string) error {
	if err := requireCompleteCatalogSlot(app); err != nil {
		return err
	}
	_, err := e.run("stage", map[string]string{
		"MEL_APP_ID": app.AppID, "MEL_NEW_APP_HASH": appHash, "MEL_RELEASE_HASH": releaseHash, "MEL_NEW_VERSION": version,
		"MEL_RELEASE_NONCE":             releaseNonce,
		"MEL_STAGE_RECEIPT_OUT":         receiptOut,
		"MEL_RELEASE_CATALOG_DEVELOPER": app.CatalogDeveloper,
		"MEL_RELEASE_CATALOG_REPO":      app.CatalogRepo,
		"MEL_RELEASE_CATALOG_SLUG":      app.CatalogSlug,
	})
	return err
}

func (e *execProvider) ProposeRegister(appID, appHash, releaseHash, version, nonce, multisig, vault, releaseJSONOut, proposeOut string) error {
	_, err := e.run("propose-register", map[string]string{
		"MEL_APP_ID": appID, "MEL_NEW_APP_HASH": appHash, "MEL_NEW_VERSION": version,
		"MEL_RELEASE_HASH": releaseHash, "MEL_RELEASE_NONCE": nonce,
		"MEL_SQUADS_MULTISIG": multisig, "MEL_SQUADS_VAULT": vault,
		"MEL_RELEASE_JSON_OUT": releaseJSONOut, "MEL_PROPOSE_RECEIPT_OUT": proposeOut,
	})
	return err
}

func (e *execProvider) ApproveRegister(appID, appHash, releaseHash, version, nonce, transactionPda, registerOut, finalReleaseOut string) error {
	_, err := e.run("approve-register", map[string]string{
		"MEL_APP_ID": appID, "MEL_NEW_APP_HASH": appHash, "MEL_RELEASE_HASH": releaseHash,
		"MEL_NEW_VERSION": version, "MEL_RELEASE_NONCE": nonce, "MEL_TRANSACTION_PDA": transactionPda,
		"MEL_REGISTER_RECEIPT_OUT": registerOut, "MEL_FINAL_RELEASE_JSON_OUT": finalReleaseOut,
	})
	return err
}

func (e *execProvider) Promote(app App, appHash, releaseHash, version, stageID, receiptOut string) error {
	if err := requireCompleteCatalogSlot(app); err != nil {
		return err
	}
	_, err := e.run("promote", map[string]string{
		"MEL_APP_ID": app.AppID, "MEL_NEW_APP_HASH": appHash, "MEL_RELEASE_HASH": releaseHash,
		"MEL_NEW_VERSION": version, "MEL_STAGE_ID": stageID, "MEL_PROMOTE_RECEIPT_OUT": receiptOut,
		"MEL_RELEASE_CATALOG_DEVELOPER": app.CatalogDeveloper,
		"MEL_RELEASE_CATALOG_REPO":      app.CatalogRepo,
		"MEL_RELEASE_CATALOG_SLUG":      app.CatalogSlug,
	})
	return err
}

// requireCompleteCatalogSlot rejects a half-specified catalog location before a
// provider command can accidentally point stage and promotion at different
// paths. A slot is optional for an already-known catalog entry, but a first
// publish must carry all three immutable path segments to the store.
func requireCompleteCatalogSlot(app App) error {
	fields := []string{app.CatalogDeveloper, app.CatalogRepo, app.CatalogSlug}
	empty := 0
	for _, field := range fields {
		if strings.TrimSpace(field) == "" {
			empty++
		}
	}
	if empty != 0 && empty != len(fields) {
		return fmt.Errorf("app %q catalog slot must set catalog_developer, catalog_repo, and catalog_slug together", app.AppID)
	}
	return nil
}

func (e *execProvider) RevokeRelease(pda, receiptOut string) error {
	_, err := e.run("revoke", map[string]string{
		"MEL_PDA": pda, "MEL_REVOKE_RECEIPT_OUT": receiptOut,
	})
	return err
}
