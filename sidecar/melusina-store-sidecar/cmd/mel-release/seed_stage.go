package main

// stage-seed is the product's private Store boundary for an already governed
// seed release. It proves the exact frozen app and V2 owner authority before
// invoking the canonical provider Stage. A durable intent prevents a blind
// second Store send if the first response is lost.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type seedStageIntent struct {
	Schema       string             `json:"schema"`
	AppID        string             `json:"appId"`
	Version      string             `json:"version"`
	AppHash      string             `json:"appHash"`
	ReleaseHash  string             `json:"releaseHash"`
	ReleaseNonce string             `json:"releaseNonce"`
	Build        artifactRef        `json:"build"`
	Proof        *seedAdoptionProof `json:"proof"`
}

// An intent with no signed stage receipt is ambiguous: the Store may have
// committed the stage while the client lost its response. Never send again.
func priorSeedStage(intentPath, stagePath string, intent seedStageIntent) (bool, error) {
	if _, err := os.Lstat(intentPath); err == nil {
		var prior seedStageIntent
		if _, err := readNativeJSON(intentPath, &prior); err != nil {
			return false, err
		}
		expected, _ := json.Marshal(intent)
		observed, _ := json.Marshal(prior)
		if string(expected) != string(observed) {
			return false, errors.New("seed-stage-existing-intent-differs")
		}
		if _, _, err := readStageReceipt(stagePath, intent.AppID, intent.AppHash, intent.ReleaseHash); err != nil {
			return false, fmt.Errorf("seed-stage-outcome-unknown-refuse-resend: %w", err)
		}
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return false, nil
}

func runSeedStage(c Config, catalog *Catalog, selector, version, buildPath,
	authorizationPath, rowsPath, reviewPath string) (string, error) {
	app, err := catalog.Select(selector)
	if err != nil {
		return "", err
	}
	if err := app.RequireReleaseReady(); err != nil {
		return "", err
	}
	if version == "" || c.AllowGlobalReleaseRevoke {
		return "", errors.New("seed-stage-version-required-and-global-revoke-forbidden")
	}
	lock, err := acquireAppLock(appLockPath(c.lockDir(), app.AppID))
	if err != nil {
		return "", err
	}
	defer lock.Close()
	if _, exists, err := readWAL(c.walPath(app.AppID)); err != nil {
		return "", err
	} else if exists {
		return "", errors.New("seed-stage-wal-already-exists")
	}
	var review seedReview
	reviewRef, err := readNativeJSON(reviewPath, &review)
	if err != nil {
		return "", err
	}
	if review.Schema != "melusina.firstdrop-cohort-review.v1" || review.EstateID != c.estate.EstateID || len(review.Apps) != 14 {
		return "", errors.New("seed-stage-review-estate-or-count-mismatch")
	}
	var selected *seedReviewApp
	for i := range review.Apps {
		if review.Apps[i].AppID == app.AppID {
			if selected != nil {
				return "", errors.New("seed-stage-review-app-duplicate")
			}
			selected = &review.Apps[i]
		}
	}
	if selected == nil || selected.Version != version || selected.SourceCommit != app.SourceCommit ||
		!isLowerHex(selected.ReleaseNonce, 32) {
		return "", errors.New("seed-stage-review-app-mismatch")
	}
	b, buildRef, err := readBuildReceipt(buildPath, app.AppID, version)
	if err != nil {
		return "", err
	}
	if err := requireEstateMasterMint(c, b); err != nil {
		return "", err
	}
	if err := verifyAppHash(b); err != nil {
		return "", err
	}
	if b.AppHash != selected.AppHash || b.Artifact.SHA256 != selected.SPKSHA256 ||
		b.SpkPath != selected.SPKPath || b.MetadataPath != selected.MetadataPath ||
		b.RuntimeContract.Path != selected.RuntimeContractPath ||
		b.RuntimeContract.SHA256 != selected.RuntimeContractSHA256 {
		return "", errors.New("seed-stage-build-review-mismatch")
	}
	if err := seedAuthorizationStillLive(authorizationPath); err != nil {
		return "", err
	}
	var authorization seedAuthorization
	authRef, err := readNativeJSON(authorizationPath, &authorization)
	if err != nil {
		return "", err
	}
	digest, err := seedDigest(authorization)
	if err != nil {
		return "", err
	}
	var rows seedRows
	rowsRef, err := readNativeJSON(rowsPath, &rows)
	if err != nil {
		return "", err
	}
	rec := walReceipt{AppID: app.AppID, Version: version, NewAppHash: b.AppHash,
		ReleaseHash: selected.ReleaseHash, ReleaseNonce: selected.ReleaseNonce,
		ArtifactSHA: b.Artifact.SHA256,
		SeedAdoption: &seedAdoptionProof{Schema: seedAdoptionSchema, Authorization: authRef,
			Rows: rowsRef, Review: reviewRef, AuthorizationDigest: digest,
			SourceCommit: app.SourceCommit, ReleaseNonce: selected.ReleaseNonce}}
	if err := verifySeedAdoptionProof(c, app, &rec); err != nil {
		return "", err
	}
	provider := newExecProvider(c)
	if err := verifySeedActiveRelease(c, provider, app, b, selected, rows); err != nil {
		return "", err
	}
	intent := seedStageIntent{Schema: "melusina-governed-seed-stage-intent-v1",
		AppID: app.AppID, Version: version, AppHash: b.AppHash,
		ReleaseHash: selected.ReleaseHash, ReleaseNonce: selected.ReleaseNonce,
		Build: buildRef, Proof: rec.SeedAdoption}
	intentPath := c.receiptPath(app.AppID, "seed-stage-intent-"+safeSegment(version)+".json")
	stagePath := c.receiptPath(app.AppID, "seed-stage-"+safeSegment(version)+".json")
	resumed, err := priorSeedStage(intentPath, stagePath, intent)
	if err != nil {
		return "", err
	}
	if resumed {
		return stagePath, nil
	}
	raw, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		return "", err
	}
	if err := writeExclusive(intentPath, append(raw, '\n')); err != nil {
		return "", err
	}
	if err := provider.Stage(app, b.AppHash, selected.ReleaseHash, version, selected.ReleaseNonce, stagePath); err != nil {
		return "", err
	}
	if _, _, err := readStageReceipt(stagePath, app.AppID, b.AppHash, selected.ReleaseHash); err != nil {
		return "", err
	}
	return stagePath, nil
}
