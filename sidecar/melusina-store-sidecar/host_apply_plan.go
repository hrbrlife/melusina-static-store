package main

// Immutable server-created facts for the Fineract host-apply ceremony.  A
// caller never supplies a component selector, approval hash, or human signature
// here: Store reads its live policy/operator/generation/cascade and the target
// license's current Squads custody itself, then freezes exactly those facts into
// a short-lived plan that the browser can review and execute through Squads.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/squadsproof"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	hostApplyPlanSchema        = "bazaar-control-host-apply-plan-v1"
	hostApplySquadsProofSchema = "bazaar-control-host-apply-squads-proof-v1"
	hostApplyPlanMemoPrefix    = "MELUSINA_HOST_APPLY_PLAN_V1:"

	maxHostApplyPlanTTL = 30 * time.Minute
	hostApplyPlanSkew   = 2 * time.Minute
)

// hostApplySquadsMember is persisted in plan order, not a map: the exact
// configuration snapshot is reviewable and has a stable digest. Permission bits
// are Squads v4 bits; unknown bits are refused at the Squads parser boundary.
type hostApplySquadsMember struct {
	Pubkey      string `json:"pubkey"`
	Permissions uint8  `json:"permissions"`
}

// hostApplyPlan binds every mutable fact observed by Store before the browser
// creates its governance proposal. SquadsTransactionIndexFloor establishes
// temporal order without trusting a client timestamp: accepted execution must
// use an index strictly greater than the plan-time monotonic index.
type hostApplyPlan struct {
	Schema    string `json:"schema"`
	DossierID string `json:"dossierId"`
	StoreID   string `json:"storeId"`

	StorePolicy                string `json:"storePolicy"`
	PolicyEpoch                uint64 `json:"policyEpoch"`
	StoreOperatorAuthorization string `json:"storeOperatorAuthorization"`
	StoreOperatorPubkey        string `json:"storeOperatorPubkey"`

	TargetControllerID   string `json:"targetControllerId"`
	TargetLicenseNftMint string `json:"targetLicenseNftMint"`
	ComponentID          string `json:"componentId"`
	SidecarID            string `json:"sidecarId"`

	GenerationID           uint64 `json:"generationId"`
	GenerationHash         string `json:"generationHash"`
	RawGenerationSHA256    string `json:"rawGenerationSha256"`
	ComponentDigest        string `json:"componentDigest"`
	ComponentSHA256        string `json:"componentSha256"`
	ComponentVersion       string `json:"componentVersion"`
	ExpectedPreviousSHA256 string `json:"expectedPreviousSha256"`

	SquadsProgramID             string                  `json:"squadsProgramId"`
	SquadsMultisig              string                  `json:"squadsMultisig"`
	SquadsVault                 string                  `json:"squadsVault"`
	SquadsThreshold             uint16                  `json:"squadsThreshold"`
	SquadsStableConfigSHA256    string                  `json:"squadsStableConfigSha256"`
	SquadsTransactionIndexFloor uint64                  `json:"squadsTransactionIndexFloor"`
	SquadsMembers               []hostApplySquadsMember `json:"squadsMembers"`

	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// hostApplySquadsProof is a Store-observed finalized chain fact. It carries no
// caller-provided proposal digest or approval count; all values are derived from
// the exact finalized execution transcript and owner-bound Squads accounts.
type hostApplySquadsProof struct {
	Schema              string    `json:"schema"`
	PlanDigest          string    `json:"planDigest"`
	ExecutionSignature  string    `json:"executionSignature"`
	TransactionIndex    uint64    `json:"transactionIndex"`
	Slot                uint64    `json:"slot"`
	ProposalPDA         string    `json:"proposalPda"`
	VaultTransactionPDA string    `json:"vaultTransactionPda"`
	ExecutedBy          string    `json:"executedBy"`
	ApprovedBy          []string  `json:"approvedBy"`
	Threshold           uint16    `json:"threshold"`
	MemoSHA256          string    `json:"memoSha256"`
	VerifiedAt          time.Time `json:"verifiedAt"`
}

func (p hostApplyPlan) Digest() string {
	parts := []string{
		p.Schema, p.DossierID, p.StoreID, p.StorePolicy, fmt.Sprint(p.PolicyEpoch),
		p.StoreOperatorAuthorization, p.StoreOperatorPubkey,
		p.TargetControllerID, p.TargetLicenseNftMint, p.ComponentID, p.SidecarID,
		fmt.Sprint(p.GenerationID), p.GenerationHash, p.RawGenerationSHA256,
		p.ComponentDigest, p.ComponentSHA256, p.ComponentVersion, p.ExpectedPreviousSHA256,
		p.SquadsProgramID, p.SquadsMultisig, p.SquadsVault, fmt.Sprint(p.SquadsThreshold),
		p.SquadsStableConfigSHA256, fmt.Sprint(p.SquadsTransactionIndexFloor),
		p.CreatedAt.UTC().Format(time.RFC3339Nano), p.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	for _, member := range p.SquadsMembers {
		parts = append(parts, member.Pubkey, fmt.Sprint(member.Permissions))
	}
	return hostApplyDigest(parts)
}

func (p hostApplyPlan) Memo() string { return hostApplyPlanMemoPrefix + p.Digest() }

func (p hostApplySquadsProof) Digest() string {
	parts := []string{
		p.Schema, p.PlanDigest, p.ExecutionSignature, fmt.Sprint(p.TransactionIndex),
		fmt.Sprint(p.Slot), p.ProposalPDA, p.VaultTransactionPDA, p.ExecutedBy,
		fmt.Sprint(p.Threshold), p.MemoSHA256, p.VerifiedAt.UTC().Format(time.RFC3339Nano),
	}
	parts = append(parts, p.ApprovedBy...)
	return hostApplyDigest(parts)
}

func isCanonicalBase58(s string, wantLen int) bool {
	raw, err := primitives.DecodeBase58(s)
	return err == nil && len(raw) == wantLen && primitives.EncodeBase58(raw) == s
}

func (p hostApplyPlan) Validate(now time.Time) error {
	if p.Schema != hostApplyPlanSchema || !isLowerHex(p.DossierID, 24) {
		return errors.New("host apply plan has an unknown schema or invalid dossier")
	}
	for label, value := range map[string]string{
		"store id": p.StoreID, "store policy": p.StorePolicy,
		"store operator authorization": p.StoreOperatorAuthorization,
		"target license":               p.TargetLicenseNftMint, "component version": p.ComponentVersion,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("host apply plan %s is required", label)
		}
	}
	if !safeHostApplyToken(p.StoreID) || !safeHostApplyToken(p.TargetControllerID) ||
		!safeHostApplyToken(p.ComponentID) || p.TargetControllerID != hostApplyFineractControllerID ||
		p.ComponentID != hostApplyFineractComponentID || p.SidecarID != hostApplyFineractSidecarID {
		return errors.New("host apply plan is not scoped to the governed Fineract controller/component")
	}
	if p.PolicyEpoch == 0 || p.GenerationID == 0 {
		return errors.New("host apply plan has an invalid policy epoch or generation id")
	}
	for label, value := range map[string]string{
		"generation hash": p.GenerationHash, "raw generation sha256": p.RawGenerationSHA256,
		"component digest": p.ComponentDigest, "component sha256": p.ComponentSHA256,
		"expected previous sha256":    p.ExpectedPreviousSHA256,
		"Squads stable config sha256": p.SquadsStableConfigSHA256,
	} {
		if !isLowerHex(value, 64) {
			return fmt.Errorf("host apply plan %s is not canonical", label)
		}
	}
	if !isCanonicalBase58(p.StorePolicy, 32) || !isCanonicalBase58(p.StoreOperatorAuthorization, 32) ||
		!isCanonicalBase58(p.StoreOperatorPubkey, 32) || !isCanonicalBase58(p.TargetLicenseNftMint, 32) ||
		!isCanonicalBase58(p.SquadsProgramID, 32) || !isCanonicalBase58(p.SquadsMultisig, 32) || !isCanonicalBase58(p.SquadsVault, 32) {
		return errors.New("host apply plan has an invalid canonical public key")
	}
	if p.SquadsProgramID != squadsproof.DefaultProgramIDBase58 || p.SquadsThreshold < 2 ||
		len(p.SquadsMembers) < int(p.SquadsThreshold) || len(p.SquadsMembers) > 65535 {
		return errors.New("host apply plan has an invalid Squads quorum")
	}
	seen := make(map[string]struct{}, len(p.SquadsMembers))
	votes := 0
	for i, member := range p.SquadsMembers {
		if !isCanonicalBase58(member.Pubkey, 32) {
			return fmt.Errorf("host apply plan Squads member %d has invalid public key", i)
		}
		if member.Permissions&^(squadsproof.PermissionInitiate|squadsproof.PermissionVote|squadsproof.PermissionExecute) != 0 {
			return fmt.Errorf("host apply plan Squads member %d has unknown permissions", i)
		}
		if _, duplicate := seen[member.Pubkey]; duplicate {
			return fmt.Errorf("host apply plan Squads member %d is duplicated", i)
		}
		seen[member.Pubkey] = struct{}{}
		if member.Permissions&squadsproof.PermissionVote != 0 {
			votes++
		}
	}
	if votes < int(p.SquadsThreshold) {
		return errors.New("host apply plan threshold exceeds frozen voting members")
	}
	now = now.UTC()
	if p.CreatedAt.IsZero() || p.ExpiresAt.IsZero() || p.CreatedAt.After(now.Add(hostApplyPlanSkew)) ||
		!p.ExpiresAt.After(p.CreatedAt) || p.ExpiresAt.Sub(p.CreatedAt) > maxHostApplyPlanTTL ||
		!p.ExpiresAt.After(now) {
		return errors.New("host apply plan has an invalid or expired time window")
	}
	return nil
}

func (p hostApplySquadsProof) Validate(plan hostApplyPlan, now time.Time) error {
	if p.Schema != hostApplySquadsProofSchema || p.PlanDigest != plan.Digest() ||
		!isLowerHex(p.MemoSHA256, 64) || p.TransactionIndex <= plan.SquadsTransactionIndexFloor ||
		p.Slot == 0 || p.Threshold != plan.SquadsThreshold || p.VerifiedAt.IsZero() ||
		p.VerifiedAt.After(now.UTC().Add(hostApplyPlanSkew)) {
		return errors.New("host apply Squads proof has invalid immutable bindings")
	}
	if !isCanonicalBase58(p.ExecutionSignature, 64) || !isCanonicalBase58(p.ProposalPDA, 32) ||
		!isCanonicalBase58(p.VaultTransactionPDA, 32) || !isCanonicalBase58(p.ExecutedBy, 32) ||
		len(p.ApprovedBy) < int(p.Threshold) {
		return errors.New("host apply Squads proof has invalid canonical references")
	}
	seen := make(map[string]struct{}, len(p.ApprovedBy))
	for i, approver := range p.ApprovedBy {
		if !isCanonicalBase58(approver, 32) {
			return fmt.Errorf("host apply Squads proof approver %d is invalid", i)
		}
		if _, duplicate := seen[approver]; duplicate {
			return fmt.Errorf("host apply Squads proof approver %d is duplicated", i)
		}
		seen[approver] = struct{}{}
	}
	return nil
}

type hostApplyLicenseCustody struct {
	License  primitives.Pubkey
	Vault    primitives.Pubkey
	Multisig primitives.Pubkey
}

func readHostApplyLicenseCustody(data []byte, owner string, expectedProgram, expectedLicense primitives.Pubkey) (hostApplyLicenseCustody, error) {
	var zero hostApplyLicenseCustody
	if len(data) < 8 || !strings.EqualFold(owner, expectedProgram.Base58()) || !bytesEqual(data[:8], accountDiscriminator("LicenseEntry")) {
		return zero, errors.New("host apply LicenseEntry owner or discriminator is invalid")
	}
	c := &borshCursor{b: data, off: 8}
	readPubkey := func() primitives.Pubkey {
		var key primitives.Pubkey
		if c.need(32) {
			copy(key[:], c.b[c.off:c.off+32])
			c.off += 32
		}
		return key
	}
	readOptionPubkey := func() *primitives.Pubkey {
		switch c.u8() {
		case 0:
			return nil
		case 1:
			key := readPubkey()
			return &key
		default:
			c.fail("host apply LicenseEntry custody option tag is invalid")
			return nil
		}
	}
	license := readPubkey()
	_ = readPubkey() // reseller
	_ = readPubkey() // master
	c.skipU64()
	c.skipString()
	c.skipString()
	c.skip(32)
	c.skip(3)
	_ = readPubkey() // owner
	custodyMode := c.u8()
	vault := readOptionPubkey()
	multisig := readOptionPubkey()
	status := c.u8()
	if c.err != nil || license != expectedLicense || custodyMode != 1 || status != 0 || vault == nil || multisig == nil || *vault == (primitives.Pubkey{}) || *multisig == (primitives.Pubkey{}) {
		return zero, errors.New("host apply LicenseEntry is not an active Squads-custodied target license")
	}
	if derived, _, err := squadsproof.DeriveVaultPDA(*multisig, 0, squadsproof.DefaultProgramID); err != nil || derived != *vault {
		return zero, errors.New("host apply LicenseEntry Squads vault does not match its multisig")
	}
	return hostApplyLicenseCustody{License: license, Vault: *vault, Multisig: *multisig}, nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var diff byte
	for i := range left {
		diff |= left[i] ^ right[i]
	}
	return diff == 0
}

type hostApplyCurrentFacts struct {
	Policy         storeControlPolicyMeta
	OperatorPubkey string
	OperatorAuthz  string
	// TargetLicense is deliberately distinct from the Store's own configured
	// license. The Store's operator authorization and policy remain rooted in
	// cfg.LicenseNFTMint; the controlled Fineract component names the tenant
	// license whose sidecar cascade, Squads custody, plan and receipt must bind.
	// Collapsing those planes makes a multi-tenant Store unable to authorize a
	// tenant-owned receiver even when every tenant-side fact is valid.
	TargetLicense primitives.Pubkey
	Document      componentrelease.DesiredGeneration
	RawGeneration []byte
	Component     componentrelease.ComponentRelease
	Custody       hostApplyLicenseCustody
	Multisig      squadsproof.Multisig
}

func hostApplySquadsStableConfigSHA256(multisig squadsproof.Multisig) string {
	parts := []string{
		multisig.Address.Base58(), multisig.CreateKey.Base58(), multisig.ConfigAuthority.Base58(),
		fmt.Sprint(multisig.Threshold), fmt.Sprint(multisig.TimeLock),
	}
	if multisig.RentCollector == nil {
		parts = append(parts, "")
	} else {
		parts = append(parts, multisig.RentCollector.Base58())
	}
	for _, member := range multisig.Members {
		parts = append(parts, member.Key.Base58(), fmt.Sprint(member.Permissions))
	}
	return hostApplyDigest(parts)
}

func hostApplyMembersFromMultisig(multisig squadsproof.Multisig) []hostApplySquadsMember {
	members := make([]hostApplySquadsMember, len(multisig.Members))
	for i, member := range multisig.Members {
		members[i] = hostApplySquadsMember{Pubkey: member.Key.Base58(), Permissions: member.Permissions}
	}
	return members
}

func fetchHostApplyCurrentFacts(ctx context.Context, s *publishService) (hostApplyCurrentFacts, error) {
	var zero hostApplyCurrentFacts
	if s == nil || s.operator == nil || s.cr == nil {
		return zero, errors.New("host apply dependencies are unavailable")
	}
	proofReader, ok := s.cr.(hostApplySquadsProofReader)
	if !ok {
		return zero, errors.New("chain reader lacks finalized Squads proof support")
	}
	policy, err := fetchActiveStoreControlPolicy(ctx, s.cfg, s.cr)
	if err != nil {
		return zero, fmt.Errorf("policy: %w", err)
	}
	operatorRaw, err := signPubkey32(s.operator.Public())
	if err != nil {
		return zero, fmt.Errorf("store operator: %w", err)
	}
	_, storeLicense, err := VerifyStoreOperator(ctx, s.cr, s.cfg, operatorRaw, false)
	if err != nil {
		return zero, fmt.Errorf("store operator: %w", err)
	}
	program, err := primitives.PubkeyFromBase58(strings.TrimSpace(s.cfg.ProgramID))
	if err != nil {
		return zero, fmt.Errorf("program id: %w", err)
	}
	authz, _, err := pda.StoreOperatorAuthorization(storeLicense, primitives.StoreDomainHash(s.cfg.Domain), program)
	if err != nil {
		return zero, fmt.Errorf("derive store operator authorization: %w", err)
	}
	doc, rawGeneration, err := s.loadVerifiedDesiredGeneration()
	if err != nil {
		return zero, fmt.Errorf("generation: %w", err)
	}
	if doc.StoreID != s.cfg.StoreID {
		return zero, errors.New("generation store id does not match the serving Store")
	}
	component, targetLicense, err := verifyHostApplyCurrentComponent(doc, rawGeneration)
	if err != nil {
		return zero, err
	}
	if err := s.verifyComponentReleaseOnChain(ctx, component); err != nil {
		return zero, fmt.Errorf("component chain: %w", err)
	}
	licensePDA, _, err := primitives.DeriveLicense(targetLicense, program)
	if err != nil {
		return zero, fmt.Errorf("derive LicenseEntry: %w", err)
	}
	licenseCohort, err := proofReader.fetchFinalizedHostApplyAccounts(ctx, []string{licensePDA.Base58()}, 0)
	if err != nil {
		return zero, fmt.Errorf("fetch finalized LicenseEntry: %w", err)
	}
	if len(licenseCohort.Accounts) != 1 {
		return zero, errors.New("fetch finalized LicenseEntry: expected one account")
	}
	custody, err := readHostApplyLicenseCustody(licenseCohort.Accounts[0].Data, licenseCohort.Accounts[0].Owner, program, targetLicense)
	if err != nil {
		return zero, err
	}
	multisigCohort, err := proofReader.fetchFinalizedHostApplyAccounts(ctx, []string{custody.Multisig.Base58()}, licenseCohort.ContextSlot)
	if err != nil {
		return zero, fmt.Errorf("fetch finalized Squads multisig: %w", err)
	}
	if len(multisigCohort.Accounts) != 1 {
		return zero, errors.New("fetch finalized Squads multisig: expected one account")
	}
	multisigOwner, err := squadsproof.DecodePubkey(multisigCohort.Accounts[0].Owner)
	if err != nil {
		return zero, fmt.Errorf("decode finalized Squads multisig owner: %w", err)
	}
	multisig, err := squadsproof.ParseMultisig(squadsproof.Account{
		Address: custody.Multisig, Owner: multisigOwner, Data: multisigCohort.Accounts[0].Data,
	}, squadsproof.DefaultProgramID)
	if err != nil {
		return zero, fmt.Errorf("parse finalized Squads multisig: %w", err)
	}
	operatorPub, err := operatorSignPublicKey(s.operator)
	if err != nil {
		return zero, fmt.Errorf("store operator signing key: %w", err)
	}
	return hostApplyCurrentFacts{
		Policy: policy, OperatorPubkey: primitives.EncodeBase58(operatorPub), OperatorAuthz: authz.Base58(),
		TargetLicense: targetLicense, Document: doc, RawGeneration: rawGeneration, Component: component,
		Custody: custody, Multisig: multisig,
	}, nil
}

// verifyHostApplyCurrentComponent is the no-caller-input counterpart of the
// old authorization binding. The selected component is always the exact
// `fineract-v2` sidecar in Store's currently verified desired generation. Its
// tenant target is derived from that already signed component; neither a
// browser nor the Store's root license can substitute a target here.
func verifyHostApplyCurrentComponent(doc componentrelease.DesiredGeneration, raw []byte) (componentrelease.ComponentRelease, primitives.Pubkey, error) {
	component, ok := doc.Component(hostApplyFineractComponentID)
	if !ok || component.ComponentClass != componentrelease.ClassSidecar ||
		component.Chain.Kind != componentrelease.AuthoritySidecarIdentity ||
		component.Chain.SidecarID != hostApplyFineractSidecarID {
		return componentrelease.ComponentRelease{}, primitives.Pubkey{}, errors.New("current generation does not contain the governed fineract-v2 sidecar component")
	}
	if len(raw) == 0 {
		return componentrelease.ComponentRelease{}, primitives.Pubkey{}, errors.New("current generation has no exact raw bytes")
	}
	targetLicense, err := primitives.PubkeyFromBase58(strings.TrimSpace(component.Chain.LicenseNftMint))
	if err != nil {
		return componentrelease.ComponentRelease{}, primitives.Pubkey{}, errors.New("current generation has an invalid governed fineract-v2 tenant license")
	}
	return component, targetLicense, nil
}

func hostApplyPlanFromFacts(dossierID string, facts hostApplyCurrentFacts, now time.Time) (hostApplyPlan, error) {
	now = now.UTC().Truncate(time.Second)
	rawHash := sha256.Sum256(facts.RawGeneration)
	plan := hostApplyPlan{
		Schema: hostApplyPlanSchema, DossierID: dossierID, StoreID: facts.Document.StoreID,
		StorePolicy: facts.Policy.PDA, PolicyEpoch: facts.Policy.PolicyEpoch,
		StoreOperatorAuthorization: facts.OperatorAuthz, StoreOperatorPubkey: facts.OperatorPubkey,
		TargetControllerID: hostApplyFineractControllerID, TargetLicenseNftMint: facts.TargetLicense.Base58(),
		ComponentID: hostApplyFineractComponentID, SidecarID: hostApplyFineractSidecarID,
		GenerationID: facts.Document.GenerationID, GenerationHash: facts.Document.GenerationHash,
		RawGenerationSHA256: hex.EncodeToString(rawHash[:]), ComponentDigest: componentrelease.ComponentReleaseDigestHex(facts.Component),
		ComponentSHA256: facts.Component.SHA256, ComponentVersion: facts.Component.Version,
		ExpectedPreviousSHA256: facts.Component.PreviousSHA256,
		SquadsProgramID:        squadsproof.DefaultProgramIDBase58, SquadsMultisig: facts.Custody.Multisig.Base58(),
		SquadsVault: facts.Custody.Vault.Base58(), SquadsThreshold: facts.Multisig.Threshold,
		SquadsStableConfigSHA256:    hostApplySquadsStableConfigSHA256(facts.Multisig),
		SquadsTransactionIndexFloor: facts.Multisig.TransactionIndex, SquadsMembers: hostApplyMembersFromMultisig(facts.Multisig),
		CreatedAt: now, ExpiresAt: now.Add(maxHostApplyPlanTTL),
	}
	if err := plan.Validate(now); err != nil {
		return hostApplyPlan{}, err
	}
	return plan, nil
}

func verifyHostApplyPlanAgainstFacts(plan hostApplyPlan, facts hostApplyCurrentFacts, now time.Time) error {
	if err := plan.Validate(now); err != nil {
		return err
	}
	rawHash := sha256.Sum256(facts.RawGeneration)
	for label, values := range map[string][2]string{
		"store id": {plan.StoreID, facts.Document.StoreID}, "store policy": {plan.StorePolicy, facts.Policy.PDA},
		"store operator authorization": {plan.StoreOperatorAuthorization, facts.OperatorAuthz},
		"store operator pubkey":        {plan.StoreOperatorPubkey, facts.OperatorPubkey},
		"target license":               {plan.TargetLicenseNftMint, facts.TargetLicense.Base58()},
		"generation hash":              {plan.GenerationHash, facts.Document.GenerationHash},
		"raw generation sha256":        {plan.RawGenerationSHA256, hex.EncodeToString(rawHash[:])},
		"component digest":             {plan.ComponentDigest, componentrelease.ComponentReleaseDigestHex(facts.Component)},
		"component sha256":             {plan.ComponentSHA256, facts.Component.SHA256},
		"component version":            {plan.ComponentVersion, facts.Component.Version},
		"previous sha256":              {plan.ExpectedPreviousSHA256, facts.Component.PreviousSHA256},
		"Squads multisig":              {plan.SquadsMultisig, facts.Custody.Multisig.Base58()},
		"Squads vault":                 {plan.SquadsVault, facts.Custody.Vault.Base58()},
		"Squads config":                {plan.SquadsStableConfigSHA256, hostApplySquadsStableConfigSHA256(facts.Multisig)},
	} {
		if values[0] != values[1] {
			return fmt.Errorf("host apply plan %s no longer matches current facts", label)
		}
	}
	if plan.PolicyEpoch != facts.Policy.PolicyEpoch || plan.GenerationID != facts.Document.GenerationID ||
		plan.SquadsThreshold != facts.Multisig.Threshold || facts.Multisig.TransactionIndex < plan.SquadsTransactionIndexFloor {
		return errors.New("host apply plan no longer matches current policy, generation, or Squads floor")
	}
	if len(plan.SquadsMembers) != len(facts.Multisig.Members) {
		return errors.New("host apply plan Squads roster no longer matches current facts")
	}
	for i, member := range facts.Multisig.Members {
		if plan.SquadsMembers[i].Pubkey != member.Key.Base58() || plan.SquadsMembers[i].Permissions != member.Permissions {
			return errors.New("host apply plan Squads roster no longer matches current facts")
		}
	}
	return nil
}
