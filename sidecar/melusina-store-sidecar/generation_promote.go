package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// ── canonical publisher: store-side generation promote (task B) ───────────────
//
// The promote step of the canonical self-service publisher. A vertical, after
// deterministically building its artifact, sealing the on-chain release, and
// staging+publishing the bytes through the store's existing v2 /publish path,
// submits a GenerationPromoteRequest. The store re-verifies each component
// against the chain (the HTTP handler, next), then this engine composes the next
// desired generation, enforces compare-and-swap against the current generation,
// operator-signs it, and atomically persists it under the single-writer lock so
// the producer immediately serves it.
//
// The operator SIGNING KEY stays in the store (boot identity); the publisher is
// authorized by the v2 envelope, never by holding the operator key. This file is
// the deterministic engine (compose -> CAS -> sign -> atomic persist); it is
// proven end-to-end against the producer without a wallet or RPC.

const generationPromoteSchema = "melusina-generation-promote-v1"

// GenerationPromoteRequest is the publisher's promote body (carried inside a v2
// KindPublishRequest envelope). Components are the artifact facts the publisher
// asserts for THIS publish; the store re-verifies each against the chain before
// promoting — they are claims, not trust.
type GenerationPromoteRequest struct {
	Schema                    string                              `json:"schema"`
	Channel                   string                              `json:"channel"`
	ExpectedCurrentGeneration uint64                              `json:"expectedCurrentGeneration"`
	Components                []componentrelease.ComponentRelease `json:"components"`
}

// planGenerationPromote validates the request against the store's current
// generation: it composes the next generation and enforces the compare-and-swap
// predicate. It is pure — the caller performs the envelope verify, the
// per-component on-chain re-verify, the operator signature, and the atomic
// persist. Returns the UNSIGNED next generation.
func planGenerationPromote(current *componentrelease.DesiredGeneration, req GenerationPromoteRequest, policy GenerationPolicy, signedAtUnix int64) (componentrelease.DesiredGeneration, error) {
	next, err := composeNextGeneration(current, policy, signedAtUnix, req.Components)
	if err != nil {
		return componentrelease.DesiredGeneration{}, err
	}
	if v := generationCAS(current, next, req.ExpectedCurrentGeneration); v != "" {
		return componentrelease.DesiredGeneration{}, errors.New(v)
	}
	return next, nil
}

// loadCurrentGenerationOrNil returns the persisted current generation, or nil if
// none has been published yet (genesis). A malformed/absent-but-present file is a
// real error, not treated as genesis.
func (s *publishService) loadCurrentGenerationOrNil() (*componentrelease.DesiredGeneration, error) {
	doc, _, err := loadCurrentGeneration(s.cfg.DistDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &doc, nil
}

// promoteGeneration composes the next generation from req, enforces CAS against
// the on-disk current generation INSIDE the single-writer lock (so two concurrent
// promotes cannot both advance onto the same base), operator-signs it, and
// atomically persists it. Returns the signed generation bytes the producer will
// serve. Fail-closed: no operator, no configured origin, schema mismatch, CAS
// violation, or a validation failure all return an error and leave the current
// generation untouched.
func (s *publishService) promoteGeneration(req GenerationPromoteRequest, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.promoteGenerationLocked(req, now)
}

// promoteGenerationLocked is the promote body; the caller MUST hold s.mu. The
// HTTP handler holds the lock across the per-class on-chain re-verify AND this
// promote so a concurrent publish cannot slip between the verify and the CAS.
func (s *publishService) promoteGenerationLocked(req GenerationPromoteRequest, now time.Time) ([]byte, error) {
	if req.Schema != generationPromoteSchema {
		return nil, fmt.Errorf("generation promote schema mismatch: %q", req.Schema)
	}
	if s.operator == nil {
		return nil, errors.New("no operator identity to sign the generation")
	}
	origin := strings.TrimRight(strings.TrimSpace(s.cfg.PublicBaseURL), "/")
	if origin == "" {
		return nil, errors.New("no public_base_url to pin the bundle origin")
	}
	current, err := s.loadCurrentGenerationOrNil()
	if err != nil {
		return nil, fmt.Errorf("load current generation: %w", err)
	}
	policy := GenerationPolicy{StoreID: s.cfg.StoreID, BundleOrigin: origin, Channel: req.Channel}
	next, err := planGenerationPromote(current, req, policy, now.UTC().Unix())
	if err != nil {
		return nil, err
	}
	signed, err := componentrelease.Sign(s.operator, next)
	if err != nil {
		return nil, fmt.Errorf("sign generation: %w", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return nil, fmt.Errorf("marshal generation: %w", err)
	}
	if err := persistDesiredGeneration(s.cfg.DistDir, raw); err != nil {
		return nil, fmt.Errorf("persist generation: %w", err)
	}
	return raw, nil
}
