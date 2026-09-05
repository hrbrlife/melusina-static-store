package main

// The worker-facing preflight boundary verifies a candidate before the release
// rail is allowed to create private Store state or a Squads proposal. It is not
// a second publishing rail: it reuses the exact build and AppHash checks used
// by publish, journals source-to-package evidence only, and creates no release
// state.
//
// This gives Bazaar Control one useful machine result before a reviewer asks
// for signatures: either the frozen source-to-package facts reproduce, or the
// release is paused with the previously served catalog untouched.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	preflightSchema           = "melusina-release-preflight-receipt-v1"
	maxPreflightArtifactBytes = int64(2 << 30)
)

// preflightReceipt deliberately contains only source-to-package facts. A
// release nonce/hash, Store stage, publisher envelope, policy, grant, Squads
// proposal, listing, and catalog selector are post-review facts and must not
// enter this record.
type preflightReceipt struct {
	Schema       string `json:"schema"`
	AppID        string `json:"appId"`
	Version      string `json:"version"`
	SourceCommit string `json:"sourceCommit"`

	ArtifactSHA256 string `json:"artifactSha256"`
	ArtifactSize   int64  `json:"artifactSize"`
	MetadataSHA256 string `json:"metadataSha256"`
	// RuntimeContractSHA256 is empty only for a build profile that has no
	// materialized runtime contract. A worker comparing a Pearl request with a
	// non-empty runtime digest must reject such a preflight rather than assume
	// the package check covered it.
	RuntimeContractSHA256 string `json:"runtimeContractSha256,omitempty"`
	PackageID             string `json:"packageId"`
	AppHash               string `json:"appHash"`
	MasterNftMint         string `json:"masterNftMint"`

	PreviousSHA256  string      `json:"previousSha256,omitempty"`
	PreviousVersion string      `json:"previousVersion,omitempty"`
	BuildReceipt    artifactRef `json:"buildReceipt"`
}

func (c Config) preflightPath(appID, version, sourceCommit string) string {
	return c.receiptPath(appID, "preflight-"+safeSegment(version)+"-"+sourceCommit+".json")
}

func (c Config) preflightBuildPath(appID, version, sourceCommit string) string {
	return c.receiptPath(appID, "preflight-build-"+safeSegment(version)+"-"+sourceCommit+".json")
}

// runPreflight has no Store or chain mutation and never creates a release
// nonce. Its only writes are the provider's bounded source-to-package evidence
// and this exact receipt. It is deliberately separate from the legacy release
// WAL: a later post-review preparation needs its own release nonce and must
// independently compare this frozen result before staging anything.
func runPreflight(c Config, catalog *Catalog, selector, version string) (string, error) {
	app, err := catalog.Select(selector)
	if err != nil {
		return "", err
	}
	if err := app.RequireReleaseReady(); err != nil {
		return "", err
	}
	if version == "" {
		return "", errors.New("--version is required")
	}

	lock, err := acquireAppLock(appLockPath(c.lockDir(), app.AppID))
	if err != nil {
		return "", err
	}
	defer lock.Close()

	if err := refuseLegacyReleaseBoundary(c, app.AppID); err != nil {
		return "", err
	}
	path := c.preflightPath(app.AppID, version, app.SourceCommit)
	if existing, statErr := os.ReadFile(path); statErr == nil {
		if err := verifyExistingPreflight(existing, app, version); err != nil {
			return "", err
		}
		return path, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("read existing preflight receipt: %w", statErr)
	}

	b, ref, err := loadOrBuildPreflight(c, newPreflightExecProvider(c), app, version)
	if err != nil {
		return "", err
	}
	result, err := makePreflightReceipt(app, version, b, ref)
	if err != nil {
		return "", err
	}
	raw, err := encodePreflight(result)
	if err != nil {
		return "", err
	}
	if err := writeExclusive(path, raw); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", errors.New("preflight receipt appeared concurrently; retry safely")
		}
		return "", err
	}
	return path, nil
}

func refuseLegacyReleaseBoundary(c Config, appID string) error {
	rec, exists, err := readWAL(c.walPath(appID))
	if err != nil || !exists || rec.State == stateDone {
		return err
	}
	if stateRank(rec.State) >= stateRank(stateStaged) {
		return fmt.Errorf("app %s already crossed the private-stage boundary (%s); resume its recorded release instead of preflighting another", appID, rec.State)
	}
	return fmt.Errorf("app %s has a legacy release record at %s; preflight needs a fresh private state directory", appID, rec.State)
}

func loadOrBuildPreflight(c Config, prov SignerProvider, app App, version string) (buildReceipt, artifactRef, error) {
	path := c.preflightBuildPath(app.AppID, version, app.SourceCommit)
	if _, err := os.Lstat(path); err == nil {
		b, ref, err := readBuildReceipt(path, app.AppID, version)
		if err != nil {
			return buildReceipt{}, artifactRef{}, fmt.Errorf("preflight build receipt: %w", err)
		}
		if err := verifyAppHash(b); err != nil {
			return buildReceipt{}, artifactRef{}, fmt.Errorf("preflight canonical app hash: %w", err)
		}
		return b, ref, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return buildReceipt{}, artifactRef{}, fmt.Errorf("inspect preflight build receipt: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return buildReceipt{}, artifactRef{}, fmt.Errorf("create preflight evidence directory: %w", err)
	}
	if err := prov.Build(app.AppID, version, path); err != nil {
		return buildReceipt{}, artifactRef{}, fmt.Errorf("build: %w", err)
	}
	b, ref, err := readBuildReceipt(path, app.AppID, version)
	if err != nil {
		return buildReceipt{}, artifactRef{}, fmt.Errorf("preflight build receipt: %w", err)
	}
	if err := verifyAppHash(b); err != nil {
		return buildReceipt{}, artifactRef{}, fmt.Errorf("preflight canonical app hash: %w", err)
	}
	return b, ref, nil
}

func makePreflightReceipt(app App, version string, b buildReceipt, ref artifactRef) (preflightReceipt, error) {
	artifactSHA256, artifactSize, err := regularFileSHA256(b.SpkPath, maxPreflightArtifactBytes)
	if err != nil {
		return preflightReceipt{}, fmt.Errorf("preflight package: %w", err)
	}
	if artifactSHA256 != b.Artifact.SHA256 || artifactSize != b.Artifact.Size {
		return preflightReceipt{}, errors.New("preflight package differs from the build receipt")
	}
	metadataSHA256, metadataSize, err := regularFileSHA256(b.MetadataPath, maxNativeReceiptBytes)
	if err != nil {
		return preflightReceipt{}, fmt.Errorf("preflight metadata: %w", err)
	}
	if metadataSize < 1 {
		return preflightReceipt{}, errors.New("preflight metadata is empty")
	}
	runtimeContractSHA256 := ""
	if b.RuntimeContract.Path != "" {
		var runtimeContractSize int64
		runtimeContractSHA256, runtimeContractSize, err = regularFileSHA256(b.RuntimeContract.Path, maxNativeReceiptBytes)
		if err != nil {
			return preflightReceipt{}, fmt.Errorf("preflight runtime contract: %w", err)
		}
		if runtimeContractSize != b.RuntimeContract.Size || runtimeContractSHA256 != b.RuntimeContract.SHA256 {
			return preflightReceipt{}, errors.New("preflight runtime contract differs from the build receipt")
		}
	}
	return preflightReceipt{
		Schema: preflightSchema, AppID: app.AppID, Version: version,
		SourceCommit: app.SourceCommit, ArtifactSHA256: b.Artifact.SHA256,
		ArtifactSize: b.Artifact.Size, MetadataSHA256: metadataSHA256,
		RuntimeContractSHA256: runtimeContractSHA256,
		PackageID:             b.PackageID, AppHash: b.AppHash, MasterNftMint: b.MasterNftMint,
		PreviousSHA256: b.PreviousSHA256, PreviousVersion: b.PreviousVersion,
		BuildReceipt: ref,
	}, nil
}

func verifyExistingPreflight(raw []byte, app App, version string) error {
	var existing preflightReceipt
	if err := decodeStrictJSON(raw, &existing); err != nil {
		return fmt.Errorf("decode existing preflight receipt: %w", err)
	}
	if existing.AppID != app.AppID || existing.Version != version || existing.SourceCommit != app.SourceCommit {
		return errors.New("preflight receipt already exists with different source-to-package facts")
	}
	if err := verifyArtifactRef(existing.BuildReceipt); err != nil {
		return fmt.Errorf("preflight build receipt: %w", err)
	}
	b, ref, err := readBuildReceipt(existing.BuildReceipt.Path, app.AppID, version)
	if err != nil {
		return fmt.Errorf("preflight build receipt: %w", err)
	}
	if ref != existing.BuildReceipt {
		return errors.New("preflight build receipt drifted after evidence was written")
	}
	if err := verifyAppHash(b); err != nil {
		return fmt.Errorf("preflight canonical app hash: %w", err)
	}
	want, err := makePreflightReceipt(app, version, b, ref)
	if err != nil {
		return err
	}
	canonical, err := encodePreflight(want)
	if err != nil {
		return err
	}
	if string(raw) != string(canonical) {
		return errors.New("preflight receipt drifted after evidence was written")
	}
	return nil
}

func encodePreflight(value preflightReceipt) ([]byte, error) {
	if value.Schema != preflightSchema || value.AppID == "" || value.Version == "" ||
		!isLowerHex(value.SourceCommit, 40) || !isLowerHex(value.ArtifactSHA256, 64) ||
		value.ArtifactSize < 1 || !isLowerHex(value.MetadataSHA256, 64) ||
		value.PackageID == "" || !isLowerHex(value.AppHash, 64) || value.MasterNftMint == "" {
		return nil, errors.New("preflight receipt is incomplete")
	}
	if value.RuntimeContractSHA256 != "" && !isLowerHex(value.RuntimeContractSHA256, 64) {
		return nil, errors.New("preflight receipt has an invalid runtime-contract digest")
	}
	if err := verifyArtifactRef(value.BuildReceipt); err != nil {
		return nil, fmt.Errorf("preflight build receipt: %w", err)
	}
	return encodeCanonicalJSON(value)
}
