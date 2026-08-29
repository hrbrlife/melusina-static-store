package main

// The controller replacement is deliberately modelled as a second, exact
// action on the proven Fineract plan/proof substrate. It shares the tenant
// scope, Store-policy and Squads-custody observations with a Fineract-v2
// sidecar apply, but selects a separately attested data artifact. That keeps a
// Store-wide controller binary from becoming an implicit tenant authority.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/squadsproof"
)

type controllerUpgradeCurrentFacts struct {
	Host       hostApplyCurrentFacts
	Controller componentrelease.ComponentRelease
}

func fetchControllerUpgradeCurrentFacts(ctx context.Context, s *publishService) (controllerUpgradeCurrentFacts, error) {
	var zero controllerUpgradeCurrentFacts
	host, err := fetchHostApplyCurrentFacts(ctx, s)
	if err != nil {
		return zero, err
	}
	controller, err := verifyControllerUpgradeCurrentComponent(host.Document, host.RawGeneration)
	if err != nil {
		return zero, err
	}
	if err := s.verifyComponentReleaseOnChain(ctx, controller); err != nil {
		return zero, fmt.Errorf("controller component chain: %w", err)
	}
	return controllerUpgradeCurrentFacts{Host: host, Controller: controller}, nil
}

// verifyControllerUpgradeCurrentComponent admits exactly one data-class
// InstallerRelease artifact. Its target tenant is never taken from this
// component: tenant scope derives solely from the current fineract-v2 sidecar
// component in fetchHostApplyCurrentFacts.
func verifyControllerUpgradeCurrentComponent(doc componentrelease.DesiredGeneration, raw []byte) (componentrelease.ComponentRelease, error) {
	component, ok := doc.Component(controllerUpgradeComponentID)
	if !ok || component.ComponentClass != componentrelease.ClassData ||
		component.Chain.Kind != componentrelease.AuthorityInstallerRelease {
		return componentrelease.ComponentRelease{}, errors.New("current generation does not contain the governed Fineract controller artifact")
	}
	if len(raw) == 0 || !isLowerHex(component.PreviousSHA256, 64) {
		return componentrelease.ComponentRelease{}, errors.New("current generation has no exact controller artifact or incumbent rollback hash")
	}
	return component, nil
}

func controllerUpgradePlanFromFacts(dossierID string, facts controllerUpgradeCurrentFacts, nowTime time.Time) (hostApplyPlan, error) {
	nowTime = nowTime.UTC().Truncate(time.Second)
	rawHash := sha256.Sum256(facts.Host.RawGeneration)
	controller := facts.Controller
	plan := hostApplyPlan{
		Schema:    hostApplyPlanSchema,
		DossierID: dossierID,
		StoreID:   facts.Host.Document.StoreID,

		StorePolicy:                facts.Host.Policy.PDA,
		PolicyEpoch:                facts.Host.Policy.PolicyEpoch,
		StoreOperatorAuthorization: facts.Host.OperatorAuthz,
		StoreOperatorPubkey:        facts.Host.OperatorPubkey,

		Action:               controllerUpgradeAction,
		TargetControllerID:   hostApplyFineractControllerID,
		TargetLicenseNftMint: facts.Host.TargetLicense.Base58(),
		ComponentID:          controllerUpgradeComponentID,
		SidecarID:            hostApplyFineractSidecarID,

		GenerationID:           facts.Host.Document.GenerationID,
		GenerationHash:         facts.Host.Document.GenerationHash,
		RawGenerationSHA256:    hex.EncodeToString(rawHash[:]),
		ComponentDigest:        componentrelease.ComponentReleaseDigestHex(controller),
		ComponentSHA256:        controller.SHA256,
		ComponentVersion:       controller.Version,
		ExpectedPreviousSHA256: controller.PreviousSHA256,

		CandidateArtifactName:  controller.ArtifactName,
		CandidateSizeBytes:     controller.SizeBytes,
		InstallerReleasePDA:    controller.Chain.ReleasePDA,
		InstallerReleaseSHA256: controller.SHA256,

		SquadsProgramID:             squadsproof.DefaultProgramIDBase58,
		SquadsMultisig:              facts.Host.Custody.Multisig.Base58(),
		SquadsVault:                 facts.Host.Custody.Vault.Base58(),
		SquadsThreshold:             facts.Host.Multisig.Threshold,
		SquadsStableConfigSHA256:    hostApplySquadsStableConfigSHA256(facts.Host.Multisig),
		SquadsTransactionIndexFloor: facts.Host.Multisig.TransactionIndex,
		SquadsMembers:               hostApplyMembersFromMultisig(facts.Host.Multisig),
		CreatedAt:                   nowTime,
		ExpiresAt:                   nowTime.Add(maxHostApplyPlanTTL),
	}
	if err := plan.Validate(nowTime); err != nil {
		return hostApplyPlan{}, err
	}
	return plan, nil
}

func verifyControllerUpgradePlanAgainstFacts(plan hostApplyPlan, facts controllerUpgradeCurrentFacts, nowTime time.Time) error {
	if plan.Action != controllerUpgradeAction {
		return errors.New("controller upgrade plan has the wrong governed action")
	}
	if err := plan.Validate(nowTime); err != nil {
		return err
	}
	rawHash := sha256.Sum256(facts.Host.RawGeneration)
	controller := facts.Controller
	for label, values := range map[string][2]string{
		"store id":                     {plan.StoreID, facts.Host.Document.StoreID},
		"store policy":                 {plan.StorePolicy, facts.Host.Policy.PDA},
		"store operator authorization": {plan.StoreOperatorAuthorization, facts.Host.OperatorAuthz},
		"store operator pubkey":        {plan.StoreOperatorPubkey, facts.Host.OperatorPubkey},
		"target license":               {plan.TargetLicenseNftMint, facts.Host.TargetLicense.Base58()},
		"generation hash":              {plan.GenerationHash, facts.Host.Document.GenerationHash},
		"raw generation sha256":        {plan.RawGenerationSHA256, hex.EncodeToString(rawHash[:])},
		"component digest":             {plan.ComponentDigest, componentrelease.ComponentReleaseDigestHex(controller)},
		"component sha256":             {plan.ComponentSHA256, controller.SHA256},
		"component version":            {plan.ComponentVersion, controller.Version},
		"previous sha256":              {plan.ExpectedPreviousSHA256, controller.PreviousSHA256},
		"candidate artifact":           {plan.CandidateArtifactName, controller.ArtifactName},
		"installer release PDA":        {plan.InstallerReleasePDA, controller.Chain.ReleasePDA},
		"installer release sha256":     {plan.InstallerReleaseSHA256, controller.SHA256},
		"Squads multisig":              {plan.SquadsMultisig, facts.Host.Custody.Multisig.Base58()},
		"Squads vault":                 {plan.SquadsVault, facts.Host.Custody.Vault.Base58()},
		"Squads config":                {plan.SquadsStableConfigSHA256, hostApplySquadsStableConfigSHA256(facts.Host.Multisig)},
	} {
		if values[0] != values[1] {
			return fmt.Errorf("controller upgrade plan %s no longer matches current facts", label)
		}
	}
	if plan.CandidateSizeBytes != controller.SizeBytes || plan.PolicyEpoch != facts.Host.Policy.PolicyEpoch ||
		plan.GenerationID != facts.Host.Document.GenerationID || plan.SquadsThreshold != facts.Host.Multisig.Threshold ||
		facts.Host.Multisig.TransactionIndex < plan.SquadsTransactionIndexFloor {
		return errors.New("controller upgrade plan no longer matches current policy, generation, artifact, or Squads floor")
	}
	if len(plan.SquadsMembers) != len(facts.Host.Multisig.Members) {
		return errors.New("controller upgrade plan Squads roster no longer matches current facts")
	}
	for i, member := range facts.Host.Multisig.Members {
		if plan.SquadsMembers[i].Pubkey != member.Key.Base58() || plan.SquadsMembers[i].Permissions != member.Permissions {
			return errors.New("controller upgrade plan Squads roster no longer matches current facts")
		}
	}
	return nil
}
