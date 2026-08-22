package main

// Pearl-controlled app publish route.
//
// This is intentionally a thin authority adapter over handleAppPublish. It
// does not introduce a second packaging, catalog, listing, nonce, or receipt
// path. The Pearl describes one release; the sidecar derives each security
// fact again from the submitted bytes, active chain accounts, and the selected
// local catalog before it calls the ordinary publish implementation.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	controlPublishPathPrefix     = "/control/v1/releases/"
	controlPreparePathSuffix     = "/prepare"
	controlPublishPathSuffix     = "/publish"
	controlCommandHeader         = "X-Bazaar-Control-Command"
	controlPearlSignatureHeader  = "X-Bazaar-Pearl-Signature"
	controlOfflineApprovalHeader = "X-Bazaar-Offline-Approval"
	maxControlHeaderEncodedBytes = 32 << 10
)

// controlExecution binds a verified Pearl command to its private durable
// receipt record. It is passed only to the shared stage/publish implementations
// after the typed route has selected the authority model.
type controlExecution struct {
	command  controlCommand
	receipts *controlReceiptLedger
}

// handleControlRelease is the only Pearl route family. Its two exact actions
// deliberately have different authority: prepare may persist an immutable
// private candidate; publish requires the separate human offline approval
// before it can select a catalog release.
func (s *publishService) handleControlRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, controlPreparePathSuffix):
		s.handleControlPrepare(w, r)
	case strings.HasSuffix(r.URL.Path, controlPublishPathSuffix):
		s.handleControlPublish(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleControlPublish accepts only the one typed Pearl action. It is not a
// generic RPC tunnel: the command route, app, publisher, candidate hashes,
// policy/grant epochs, current predecessor, and expiry must all agree.
func (s *publishService) handleControlPublish(w http.ResponseWriter, r *http.Request) {
	dossierID, route, err := controlPublishRoute(r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	command, pearlSignature, offlineApproval, err := parsePearlControlHeaders(r)
	if err != nil {
		http.Error(w, "check=control_command: "+err.Error(), http.StatusBadRequest)
		return
	}
	if command.DossierID != dossierID || command.Route != route {
		http.Error(w, "check=control_command: command does not name this release route", http.StatusForbidden)
		return
	}
	if s.respondStoredControlResult(w, command) {
		return
	}

	resolvePublisher := func(preflight appPublishPreflight, claimed identity.Public) (string, error) {
		return s.verifyControlPublishAuthorization(r, preflight, command, pearlSignature, offlineApproval, claimed, s.currentTime())
	}
	criticalCheck := func(preflight appPublishPreflight, now time.Time) error {
		_, err := s.verifyControlPublishAuthorization(r, preflight, command, pearlSignature, offlineApproval, preflight.sig.Payload.Source, now)
		return err
	}
	snapshotCheck := func(snapshot AppCatalogSnapshot, preflight appPublishPreflight) error {
		return verifyControlCommandPredecessor(snapshot, preflight, command)
	}
	s.handleAppPublish(w, r, route, resolvePublisher, criticalCheck, snapshotCheck, &controlExecution{command: command, receipts: s.controlReceipts})
}

// handleControlPrepare accepts the same exact-candidate command shape as the
// publish route, but only creates private staged bytes. It requires a
// policy-bound Pearl command and a publisher grant with PREPARE permission;
// it neither accepts an offline approval nor reaches catalog selection.
func (s *publishService) handleControlPrepare(w http.ResponseWriter, r *http.Request) {
	dossierID, route, err := controlPrepareRoute(r.URL.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	command, pearlSignature, err := parsePearlControlPrepareHeaders(r)
	if err != nil {
		http.Error(w, "check=control_command: "+err.Error(), http.StatusBadRequest)
		return
	}
	if command.DossierID != dossierID || command.Route != route {
		http.Error(w, "check=control_command: command does not name this release route", http.StatusForbidden)
		return
	}
	if s.respondStoredControlResult(w, command) {
		return
	}

	resolvePublisher := func(preflight appPublishPreflight, claimed identity.Public) (string, error) {
		return s.verifyControlPrepareAuthorization(r, preflight, command, pearlSignature, claimed, s.currentTime())
	}
	criticalCheck := func(preflight appPublishPreflight, now time.Time) error {
		_, err := s.verifyControlPrepareAuthorization(r, preflight, command, pearlSignature, preflight.sig.Payload.Source, now)
		return err
	}
	s.handleAppStage(w, r, route, resolvePublisher, criticalCheck, &controlExecution{command: command, receipts: s.controlReceipts})
}

// respondStoredControlResult turns a lost response into a harmless exact retry.
// A pending entry never retries blind: it becomes an explicit attention item,
// because the sidecar must not guess which post-claim mutation completed.
func (s *publishService) respondStoredControlResult(w http.ResponseWriter, command controlCommand) bool {
	if s.controlReceiptErr != nil || s.controlReceipts == nil {
		http.Error(w, "Bazaar Control receipt storage is unavailable.", http.StatusServiceUnavailable)
		return true
	}
	record, found, err := s.controlReceipts.Load(command)
	if err != nil {
		http.Error(w, "check=control_receipt: "+err.Error(), http.StatusConflict)
		return true
	}
	if !found {
		return false
	}
	switch record.State {
	case controlReceiptCompleted:
		w.Header().Set("Content-Type", "application/json")
		switch command.Action {
		case controlCommandActionPrepare:
			if record.Stage == nil {
				http.Error(w, "check=control_receipt: completed preparation has no receipt", http.StatusInternalServerError)
				return true
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(record.Stage)
		case controlCommandActionPublish:
			if record.Publish == nil {
				http.Error(w, "check=control_receipt: completed publication has no receipt", http.StatusInternalServerError)
				return true
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(record.Publish)
		default:
			http.Error(w, "check=control_receipt: unsupported completed action", http.StatusConflict)
		}
		return true
	case controlReceiptPending:
		_, _ = s.controlReceipts.MarkNeedsAttention(command, "reconcile_required", s.currentTime())
		http.Error(w, "Publishing paused: a prior attempt needs safe reconciliation in Bazaar Control.", http.StatusConflict)
		return true
	case controlReceiptAttention:
		http.Error(w, "Publishing paused: safe reconciliation is required in Bazaar Control.", http.StatusConflict)
		return true
	default:
		http.Error(w, "check=control_receipt: unsupported receipt state", http.StatusConflict)
		return true
	}
}

func controlPublishRoute(path string) (dossierID, route string, err error) {
	if !strings.HasPrefix(path, controlPublishPathPrefix) || !strings.HasSuffix(path, controlPublishPathSuffix) {
		return "", "", errors.New("not a control publish route")
	}
	dossierID = strings.TrimSuffix(strings.TrimPrefix(path, controlPublishPathPrefix), controlPublishPathSuffix)
	if !isSafePathSegment(dossierID) {
		return "", "", errors.New("unsafe dossier id")
	}
	return dossierID, controlPublishPathPrefix + dossierID + controlPublishPathSuffix, nil
}

func controlPrepareRoute(path string) (dossierID, route string, err error) {
	if !strings.HasPrefix(path, controlPublishPathPrefix) || !strings.HasSuffix(path, controlPreparePathSuffix) {
		return "", "", errors.New("not a control prepare route")
	}
	dossierID = strings.TrimSuffix(strings.TrimPrefix(path, controlPublishPathPrefix), controlPreparePathSuffix)
	if !isSafePathSegment(dossierID) {
		return "", "", errors.New("unsafe dossier id")
	}
	return dossierID, controlPublishPathPrefix + dossierID + controlPreparePathSuffix, nil
}

func parsePearlControlPrepareHeaders(r *http.Request) (controlCommand, pearlCommandSignature, error) {
	var command controlCommand
	var signature pearlCommandSignature
	if err := decodeControlHeader(r.Header.Get(controlCommandHeader), &command); err != nil {
		return command, signature, fmt.Errorf("command header: %w", err)
	}
	if err := decodeControlHeader(r.Header.Get(controlPearlSignatureHeader), &signature); err != nil {
		return command, signature, fmt.Errorf("Pearl signature header: %w", err)
	}
	return command, signature, nil
}

func parsePearlControlHeaders(r *http.Request) (controlCommand, pearlCommandSignature, offlineControlApproval, error) {
	var command controlCommand
	var signature pearlCommandSignature
	var approval offlineControlApproval
	if err := decodeControlHeader(r.Header.Get(controlCommandHeader), &command); err != nil {
		return command, signature, approval, fmt.Errorf("command header: %w", err)
	}
	if err := decodeControlHeader(r.Header.Get(controlPearlSignatureHeader), &signature); err != nil {
		return command, signature, approval, fmt.Errorf("Pearl signature header: %w", err)
	}
	if err := decodeControlHeader(r.Header.Get(controlOfflineApprovalHeader), &approval); err != nil {
		return command, signature, approval, fmt.Errorf("offline approval header: %w", err)
	}
	return command, signature, approval, nil
}

func decodeControlHeader(encoded string, target any) error {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" || len(encoded) > maxControlHeaderEncodedBytes {
		return errors.New("missing or oversized header")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maxControlHeaderEncodedBytes {
		return errors.New("header is not bounded base64url JSON")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("header JSON is malformed")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("header JSON has trailing data")
	}
	return nil
}

func (s *publishService) verifyControlPublishAuthorization(r *http.Request, preflight appPublishPreflight, command controlCommand, signature pearlCommandSignature, approval offlineControlApproval, claimed identity.Public, now time.Time) (string, error) {
	appID := metadataAppID(preflight.metadata)
	chainAppID, err := controlSandstormAppID(appID)
	if err != nil {
		return "", fmt.Errorf("app identity: %w", err)
	}
	stage, err := buildStagedAppManifestWithRuntimeContract(preflight.spk, preflight.metadata, preflight.releaseBytes, preflight.runtimeContract, preflight.release, preflight.hint, now)
	if err != nil {
		return "", fmt.Errorf("stage: %w", err)
	}
	if err := commandMatchesCandidate(command, preflight, stage); err != nil {
		return "", err
	}

	_, _, _, releaseMeta, err := verifyReleaseEntryHash(r.Context(), s.cr, s.cfg, stage.AppHash, preflight.release)
	if err != nil {
		return "", err
	}
	if releaseMeta.AppID != chainAppID {
		return "", errors.New("ReleaseEntry app identity does not match metadata appId")
	}
	publisherKey, err := primitives.PubkeyFromBase58(strings.TrimSpace(claimed.SignPubkeyB58))
	if err != nil {
		return "", errors.New("publisher envelope contains no valid ed25519 public key")
	}
	policy, err := fetchActiveStoreControlPolicy(r.Context(), s.cfg, s.cr)
	if err != nil {
		return "", fmt.Errorf("store policy: %w", err)
	}
	grant, err := fetchStorePublisherGrant(r.Context(), s.cfg, s.cr, policy, chainAppID, publisherKey)
	if err != nil {
		return "", fmt.Errorf("publisher grant: %w", err)
	}
	facts := controlCommandFacts{
		PolicyPDA: policy.PDA, AppID: chainAppID, PublisherSquadsVault: releaseMeta.PublisherSquadsVault,
		PublisherEd25519PublicKey: publisherKey,
	}
	if err := verifyPearlControlCommand(command, signature, policy, grant, facts, now); err != nil {
		return "", err
	}
	if err := verifyOfflineControlApproval(command, approval, policy, now); err != nil {
		return "", err
	}
	return publisherKey.Base58(), nil
}

func (s *publishService) verifyControlPrepareAuthorization(r *http.Request, preflight appPublishPreflight, command controlCommand, signature pearlCommandSignature, claimed identity.Public, now time.Time) (string, error) {
	appID := metadataAppID(preflight.metadata)
	chainAppID, err := controlSandstormAppID(appID)
	if err != nil {
		return "", fmt.Errorf("app identity: %w", err)
	}
	stage, err := buildStagedAppManifestWithRuntimeContract(preflight.spk, preflight.metadata, preflight.releaseBytes, preflight.runtimeContract, preflight.release, preflight.hint, now)
	if err != nil {
		return "", fmt.Errorf("stage: %w", err)
	}
	if err := commandMatchesCandidate(command, preflight, stage); err != nil {
		return "", err
	}
	publisherKey, err := primitives.PubkeyFromBase58(strings.TrimSpace(claimed.SignPubkeyB58))
	if err != nil {
		return "", errors.New("publisher envelope contains no valid ed25519 public key")
	}
	publisherVault, err := primitives.PubkeyFromBase58(strings.TrimSpace(preflight.release.LicenseSquadsVault))
	if err != nil {
		return "", errors.New("release claims no valid publisher Squads vault")
	}
	policy, err := fetchActiveStoreControlPolicy(r.Context(), s.cfg, s.cr)
	if err != nil {
		return "", fmt.Errorf("store policy: %w", err)
	}
	grant, err := fetchStorePublisherGrant(r.Context(), s.cfg, s.cr, policy, chainAppID, publisherKey)
	if err != nil {
		return "", fmt.Errorf("publisher grant: %w", err)
	}
	facts := controlCommandFacts{
		PolicyPDA: policy.PDA, AppID: chainAppID, PublisherSquadsVault: publisherVault,
		PublisherEd25519PublicKey: publisherKey,
	}
	if err := verifyPearlControlCommand(command, signature, policy, grant, facts, now); err != nil {
		return "", err
	}
	return publisherKey.Base58(), nil
}

func commandMatchesCandidate(command controlCommand, preflight appPublishPreflight, stage stagedAppManifest) error {
	if command.AppID != stage.AppID || command.Version != stage.Version || command.ArtifactSHA256 != stage.SPKSHA256 || command.AppHash != stage.AppHash || command.ReleaseHash != stage.ReleaseHash || command.StageID != stage.StageID {
		return errors.New("control command does not bind the submitted release candidate")
	}
	// PayloadHash is the publisher envelope's canonical, signed content address.
	// Its later envelope verification proves this exact binding is not merely a
	// caller-provided string.
	if command.PublisherIntentHash != strings.ToLower(strings.TrimSpace(preflight.sig.PayloadHash)) {
		return errors.New("control command does not bind this publisher intent")
	}
	return nil
}

func controlSandstormAppID(value string) ([32]byte, error) {
	var zero [32]byte
	if len(value) != 52 || strings.ToLower(value) != value {
		return zero, errors.New("Sandstorm appId must be exactly 52 lower-case characters")
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') {
			return zero, errors.New("Sandstorm appId contains an invalid character")
		}
	}
	return sha256.Sum256([]byte(value)), nil
}

func verifyControlCommandPredecessor(snapshot AppCatalogSnapshot, preflight appPublishPreflight, command controlCommand) error {
	appID := metadataAppID(preflight.metadata)
	if !isSafePathSegment(appID) {
		return errors.New("submitted metadata has no safe appId")
	}
	priorBytes, err := readSnapshotFileBounded(snapshot, "attest/"+appID+"/RELEASE.json", maxAppPublishBody)
	if errors.Is(err, os.ErrNotExist) {
		if command.ExpectedPriorAppHash != "" {
			return errors.New("control command expects a prior release but this app has none")
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read current release: %w", err)
	}
	prior, ok := parseReleaseClaim(priorBytes)
	if !ok {
		return errors.New("current published release is malformed")
	}
	if command.ExpectedPriorAppHash != strings.ToLower(strings.TrimSpace(prior.AppHash)) {
		return errors.New("control command predecessor no longer matches the selected catalog")
	}
	return nil
}
