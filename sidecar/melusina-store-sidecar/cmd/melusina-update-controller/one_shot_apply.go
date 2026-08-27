package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/hostupdate"
)

const maxOneShotReceiptBytes = 128 << 10

// oneShotReceiptURLPrefix is derived from the controller's pinned bundle origin;
// the command-line flag is a selector under this origin, never an arbitrary URL.
func oneShotReceiptURLPrefix(cfg ControllerConfig) string {
	return strings.TrimRight(cfg.BundleOrigin, "/") + "/update/one-shot/"
}

func isLowerHex64Value(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// validateOneShotReceiptURL permits exactly one immutable receipt object under
// the pinned Store origin.  Query strings, fragments, redirects, alternate
// hosts, nested paths, and encoded path tricks are all refused before any HTTP
// request is made.
func validateOneShotReceiptURL(cfg ControllerConfig, receiptURL string) (string, error) {
	prefix := oneShotReceiptURLPrefix(cfg)
	if !strings.HasPrefix(receiptURL, prefix) {
		return "", fmt.Errorf("one-shot receipt URL %q is not under pinned prefix %q", receiptURL, prefix)
	}
	name := strings.TrimPrefix(receiptURL, prefix)
	if len(name) != 69 || !strings.HasSuffix(name, ".json") {
		return "", errors.New("one-shot receipt URL must name exactly <64-lower-hex>.json")
	}
	id := strings.TrimSuffix(name, ".json")
	if !isLowerHex64Value(id) || receiptURL != prefix+id+".json" {
		return "", errors.New("one-shot receipt URL is not canonical")
	}
	return id, nil
}

func fetchOneShotReceipt(ctx context.Context, cfg ControllerConfig, receiptURL string) (componentrelease.OneShotApplyAuthorization, []byte, error) {
	var zero componentrelease.OneShotApplyAuthorization
	if _, err := validateOneShotReceiptURL(cfg, receiptURL); err != nil {
		return zero, nil, err
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect refused: one-shot receipt URL is origin-pinned")
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, receiptURL, nil)
	if err != nil {
		return zero, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return zero, nil, fmt.Errorf("fetch one-shot receipt: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, nil, fmt.Errorf("fetch one-shot receipt: HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxOneShotReceiptBytes+1))
	if err != nil {
		return zero, nil, err
	}
	if len(raw) > maxOneShotReceiptBytes {
		return zero, nil, errors.New("one-shot receipt exceeds bounded read limit")
	}
	if err := assertNoDuplicateTopLevelKeys(raw); err != nil {
		return zero, nil, fmt.Errorf("one-shot receipt: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var authorization componentrelease.OneShotApplyAuthorization
	if err := dec.Decode(&authorization); err != nil {
		return zero, nil, fmt.Errorf("decode one-shot receipt: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return zero, nil, errors.New("one-shot receipt has trailing data")
	}
	return authorization, raw, nil
}

// verifiedOneShotBinding checks a fetched receipt against the exact generation
// bytes this controller just verified, its root-owned Fineract scope, and the
// pinned Store signing key.  It does not use a receipt field to choose a local
// registry member or host action.
func verifiedOneShotBinding(cfg ControllerConfig, operator ed25519.PublicKey, registry componentrelease.ComponentRegistry, vg hostupdate.VerifiedGeneration, receiptURL string, authorization componentrelease.OneShotApplyAuthorization, raw []byte, nowUnix int64) (hostupdate.OneShotAuthorizationBinding, error) {
	var zero hostupdate.OneShotAuthorizationBinding
	if cfg.OneShotApply == nil {
		return zero, errors.New("one-shot receipt supplied but controller has no oneShotApply scope policy")
	}
	urlID, err := validateOneShotReceiptURL(cfg, receiptURL)
	if err != nil {
		return zero, err
	}
	if authorization.AuthorizationID != urlID {
		return zero, errors.New("one-shot receipt authorizationId does not match its immutable URL")
	}
	if len(registry.Components) != 1 {
		return zero, fmt.Errorf("one-shot receipt requires singleton local registry, got %d entries", len(registry.Components))
	}
	install, ok := registry.Components[cfg.OneShotApply.ComponentID]
	if !ok || install.ComponentID != cfg.OneShotApply.ComponentID || install.ComponentClass != componentrelease.ClassSidecar {
		return zero, errors.New("one-shot receipt local registry does not contain its configured Fineract sidecar")
	}
	var component componentrelease.ComponentRelease
	for _, candidate := range vg.Doc.Components {
		if candidate.ComponentID != cfg.OneShotApply.ComponentID {
			continue
		}
		if component.ComponentID != "" {
			return zero, errors.New("verified generation names the one-shot component more than once")
		}
		component = candidate
	}
	if component.ComponentID == "" {
		return zero, fmt.Errorf("verified generation does not contain one-shot component %q", cfg.OneShotApply.ComponentID)
	}
	expected := componentrelease.OneShotApplyExpectation{
		ExpectedStoreID:      cfg.ExpectedStoreID,
		TargetControllerID:   cfg.OneShotApply.ControllerID,
		TargetLicenseNftMint: cfg.LicenseNftMint,
		ComponentID:          cfg.OneShotApply.ComponentID,
		GenerationID:         vg.Doc.GenerationID,
		GenerationHash:       vg.Doc.GenerationHash,
		RawGenerationSHA256:  vg.RawSHA256,
		Component:            component,
		NowUnix:              nowUnix,
	}
	if err := componentrelease.VerifyOneShotApplyAuthorization(operator, expected, authorization); err != nil {
		return zero, fmt.Errorf("verify one-shot receipt: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hostupdate.OneShotAuthorizationBinding{
		AuthorizationID:     authorization.AuthorizationID,
		ReceiptSHA256:       hex.EncodeToString(sum[:]),
		TargetControllerID:  authorization.TargetControllerID,
		ComponentID:         authorization.ComponentID,
		GovernanceReceiptID: authorization.GovernanceReceiptID,
		ExpiresAtUnix:       authorization.ExpiresAtUnix,
	}, nil
}
