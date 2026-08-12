package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// reconcileDesiredGenerationAfterAppCatalogQuarantine advances the signed
// desired generation only when catalog recovery has excluded the exact app
// rollouts whose claimed runtime-contract bytes are absent. A generation that
// still advertises one of those apps cannot pass its own served-surface check,
// so preserving it would keep every unrelated component unavailable. The
// existing generation is verified before it is transformed; non-app members
// are never removed, and a retained dependency on a quarantined app refuses
// rather than silently changing the dependency graph.
func reconcileDesiredGenerationAfterAppCatalogQuarantine(cfg Config, operator *identity.Private, operatorKey []byte, quarantined map[string]appRolloutState, now time.Time) (bool, componentrelease.DesiredGeneration, error) {
	var zero componentrelease.DesiredGeneration
	if len(quarantined) == 0 {
		return false, zero, nil
	}
	if operator == nil {
		return false, zero, errors.New("desired-generation reconciliation requires the active operator signer")
	}
	if len(operatorKey) != 32 {
		return false, zero, errors.New("desired-generation reconciliation requires the active operator public key")
	}
	current, _, err := loadCurrentGeneration(cfg.DistDir)
	if err != nil {
		return false, zero, fmt.Errorf("load signed desired generation: %w", err)
	}
	if err := componentrelease.Verify(operatorKey, cfg.StoreID, current); err != nil {
		return false, zero, fmt.Errorf("verify signed desired generation before reconciliation: %w", err)
	}
	if !sameOrigin(current.BundleOrigin, cfg.PublicBaseURL) {
		return false, zero, errors.New("desired generation bundle origin does not match the configured Store origin")
	}

	removed := make(map[string]struct{}, len(quarantined))
	kept := make([]componentrelease.ComponentRelease, 0, len(current.Components))
	for _, component := range current.Components {
		if component.ComponentClass == componentrelease.ClassApp {
			if _, quarantine := quarantined[component.ComponentID]; quarantine {
				removed[component.ComponentID] = struct{}{}
				continue
			}
		}
		kept = append(kept, component)
	}
	if len(removed) == 0 {
		return false, current, nil
	}
	for _, component := range kept {
		for _, dependency := range component.Requires {
			if _, removedDependency := removed[dependency.ComponentID]; removedDependency {
				return false, zero, fmt.Errorf("desired generation component %s requires quarantined app %s", component.ComponentID, dependency.ComponentID)
			}
		}
	}
	if current.GenerationID == math.MaxUint64 {
		return false, zero, errors.New("desired generation id exhausted during catalog reconciliation")
	}
	next := current
	next.GenerationID++
	next.PreviousGeneration = current.GenerationID
	next.SignedAtUnix = now.UTC().Unix()
	next.Components = kept
	next.GenerationHash = ""
	next.OperatorPubkey = ""
	next.OperatorSignature = ""
	signed, err := componentrelease.Sign(operator, next)
	if err != nil {
		return false, zero, fmt.Errorf("sign reconciled desired generation: %w", err)
	}
	if err := componentrelease.Verify(operatorKey, cfg.StoreID, signed); err != nil {
		return false, zero, fmt.Errorf("verify reconciled desired generation: %w", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return false, zero, fmt.Errorf("marshal reconciled desired generation: %w", err)
	}
	if err := persistDesiredGeneration(cfg.DistDir, raw); err != nil {
		return false, zero, fmt.Errorf("persist reconciled desired generation: %w", err)
	}
	return true, signed, nil
}
