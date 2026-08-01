package main

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// solanaChainGate is the controller's real on-chain authority gate: for each
// component it DERIVES every PDA LOCALLY from the ROOT-OWNED-config-pinned program +
// master/license mints and the known Anchor seeds, REFUSES any component whose
// document-claimed PDA does not equal the seed-derived PDA, and only then confirms
// the on-chain account is owned by the pinned program, Active, and pins the exact
// content hash. A compromised or malicious operator therefore cannot point the
// controller at a wrong-but-Active PDA — the seeds (not the document) decide which
// account is authoritative. Account decode uses the shared, verified
// melusina-identity-gate/verify readers (no hand-rolled Borsh, base58, or curve math).
type solanaChainGate struct {
	rpc               *verify.RPCClient
	program           primitives.Pubkey
	masterMint        primitives.Pubkey
	licenseMintPubkey primitives.Pubkey
	programB58        string
	masterB58         string
	licenseB58        string
}

func newSolanaChainGate(cfg ControllerConfig) (*solanaChainGate, error) {
	program, err := primitives.PubkeyFromBase58(cfg.ProgramID)
	if err != nil {
		return nil, fmt.Errorf("programId is not a valid pubkey: %w", err)
	}
	master, err := primitives.PubkeyFromBase58(cfg.MasterNftMint)
	if err != nil {
		return nil, fmt.Errorf("masterNftMint is not a valid pubkey: %w", err)
	}
	license, err := primitives.PubkeyFromBase58(cfg.LicenseNftMint)
	if err != nil {
		return nil, fmt.Errorf("licenseNftMint is not a valid pubkey: %w", err)
	}
	return &solanaChainGate{
		rpc:               verify.NewRPCClient(cfg.SolanaRPCURL),
		program:           program,
		masterMint:        master,
		licenseMintPubkey: license,
		programB58:        cfg.ProgramID,
		masterB58:         cfg.MasterNftMint,
		licenseB58:        cfg.LicenseNftMint,
	}, nil
}

// contentIdentity is the hash the chain pins: ContentSHA256 when present (apps pin a
// tree hash distinct from the served bytes), otherwise the served-artifact SHA256.
func contentIdentity(c componentrelease.ComponentRelease) string {
	if strings.TrimSpace(c.ContentSHA256) != "" {
		return strings.ToLower(c.ContentSHA256)
	}
	return strings.ToLower(c.SHA256)
}

func hex32(b [32]byte) string { return hex.EncodeToString(b[:]) }

func hashBytes(hexStr string) ([32]byte, error) {
	var h [32]byte
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 32 {
		return h, fmt.Errorf("artifact hash %q is not 32-byte hex", hexStr)
	}
	copy(h[:], b)
	return h, nil
}

func isZero32(b [32]byte) bool { return b == [32]byte{} }

// assertDerivedPDA refuses a document-claimed PDA that does not equal the locally
// seed-derived PDA. The 32-byte comparison is constant-time. This is the integrity
// core: nothing downstream (owner/discriminator/Active/hash) is trusted until the
// account address itself is proven to be the seed-derived one, not doc-supplied.
func assertDerivedPDA(record, docPDA string, derived primitives.Pubkey) error {
	docKey, err := primitives.PubkeyFromBase58(docPDA)
	if err != nil {
		return fmt.Errorf("%s: document PDA %q is not a valid pubkey: %w", record, docPDA, err)
	}
	if subtle.ConstantTimeCompare(docKey[:], derived[:]) != 1 {
		return fmt.Errorf("%s PDA mismatch: doc claims %s, seed-derives %s", record, docPDA, derived.Base58())
	}
	return nil
}

// gate is the ApplyDeps.ChainGate callback.
func (g *solanaChainGate) gate(ctx context.Context, c componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) error {
	if c.Chain.Program != g.programB58 {
		return fmt.Errorf("chain gate %s: program %q != pinned %q", c.ComponentID, c.Chain.Program, g.programB58)
	}
	want, err := hashBytes(contentIdentity(c))
	if err != nil {
		return fmt.Errorf("chain gate %s: %w", c.ComponentID, err)
	}
	switch c.Chain.Kind {
	case componentrelease.AuthorityInstallerRelease:
		return g.gateInstallerRelease(ctx, c, want)
	case componentrelease.AuthorityReleaseV2:
		return g.gateReleaseV2(ctx, c, want)
	case componentrelease.AuthoritySidecarIdentity:
		return g.gateSidecarCascade(ctx, c, want)
	default:
		return fmt.Errorf("chain gate %s: unknown chain kind %q", c.ComponentID, c.Chain.Kind)
	}
}

func (g *solanaChainGate) gateInstallerRelease(ctx context.Context, c componentrelease.ComponentRelease, want [32]byte) error {
	if c.Chain.MasterNftMint != g.masterB58 {
		return fmt.Errorf("chain gate %s: masterNftMint pin mismatch", c.ComponentID)
	}
	derived, _, err := primitives.DeriveInstallerRelease(g.masterMint, want, g.program)
	if err != nil {
		return fmt.Errorf("chain gate %s: derive InstallerReleaseEntry PDA: %w", c.ComponentID, err)
	}
	if err := assertDerivedPDA("InstallerReleaseEntry", c.Chain.ReleasePDA, derived); err != nil {
		return fmt.Errorf("chain gate %s: %w", c.ComponentID, err)
	}
	hash, status, err := g.rpc.FetchInstallerReleaseEntry(ctx, derived.Base58())
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch InstallerReleaseEntry: %w", c.ComponentID, err)
	}
	if err := status.RequireActive(); err != nil {
		return fmt.Errorf("chain gate %s: installer release not Active: %w", c.ComponentID, err)
	}
	if hex32(hash) != hex32(want) {
		return fmt.Errorf("chain gate %s: installer_hash %s != artifact %s", c.ComponentID, hex32(hash), hex32(want))
	}
	return nil
}

func (g *solanaChainGate) gateReleaseV2(ctx context.Context, c componentrelease.ComponentRelease, want [32]byte) error {
	if c.Chain.MasterNftMint != g.masterB58 {
		return fmt.Errorf("chain gate %s: masterNftMint pin mismatch", c.ComponentID)
	}
	derived, _, err := primitives.DeriveReleaseV2(g.masterMint, want, g.program)
	if err != nil {
		return fmt.Errorf("chain gate %s: derive ReleaseEntry PDA: %w", c.ComponentID, err)
	}
	if err := assertDerivedPDA("ReleaseEntry", c.Chain.ReleasePDA, derived); err != nil {
		return fmt.Errorf("chain gate %s: %w", c.ComponentID, err)
	}
	appHash, status, err := g.rpc.FetchReleaseEntry(ctx, derived.Base58())
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch ReleaseEntry: %w", c.ComponentID, err)
	}
	if err := status.RequireActive(); err != nil {
		return fmt.Errorf("chain gate %s: release not Active: %w", c.ComponentID, err)
	}
	if hex32(appHash) != hex32(want) {
		return fmt.Errorf("chain gate %s: app_hash %s != content %s", c.ComponentID, hex32(appHash), hex32(want))
	}
	return nil
}

// gateSidecarCascade DERIVES all three document-claimed sidecar PDAs from the pinned
// license/master mints + seeds and refuses any doc != derived BEFORE any fetch, then
// confirms the identity + global + local approvals are Active and hash-pinned, and
// finally the LicenseEntry is Active with the pinned master (and, when the license is
// resold, both the reseller entity and its reseller-sidecar approval are Active).
func (g *solanaChainGate) gateSidecarCascade(ctx context.Context, c componentrelease.ComponentRelease, want [32]byte) error {
	if c.Chain.LicenseNftMint != g.licenseB58 {
		return fmt.Errorf("chain gate %s: licenseNftMint pin mismatch", c.ComponentID)
	}
	if c.Chain.MasterNftMint != g.masterB58 {
		return fmt.Errorf("chain gate %s: masterNftMint (global-approval seed) pin mismatch", c.ComponentID)
	}
	sidecarID := c.Chain.SidecarID
	keyVersion := c.Chain.KeyVersion

	// Phase 1 — derive every doc-supplied PDA from the pinned mints + seeds and REFUSE
	// any mismatch before touching the chain.
	idPDA, _, err := primitives.DeriveSidecarIdentity(g.licenseMintPubkey, sidecarID, keyVersion, g.program)
	if err != nil {
		return fmt.Errorf("chain gate %s: derive SidecarIdentityEntry PDA: %w", c.ComponentID, err)
	}
	if err := assertDerivedPDA("SidecarIdentityEntry", c.Chain.IdentityPDA, idPDA); err != nil {
		return fmt.Errorf("chain gate %s: %w", c.ComponentID, err)
	}
	globalPDA, _, err := primitives.DeriveGlobalSidecar(g.masterMint, sidecarID, g.program)
	if err != nil {
		return fmt.Errorf("chain gate %s: derive GlobalSidecarApproval PDA: %w", c.ComponentID, err)
	}
	if err := assertDerivedPDA("GlobalSidecarApproval", c.Chain.GlobalApprovalPDA, globalPDA); err != nil {
		return fmt.Errorf("chain gate %s: %w", c.ComponentID, err)
	}
	localPDA, _, err := primitives.DeriveLocalSidecar(g.licenseMintPubkey, sidecarID, g.program)
	if err != nil {
		return fmt.Errorf("chain gate %s: derive LocalSidecarApproval PDA: %w", c.ComponentID, err)
	}
	if err := assertDerivedPDA("LocalSidecarApproval", c.Chain.LocalApprovalPDA, localPDA); err != nil {
		return fmt.Errorf("chain gate %s: %w", c.ComponentID, err)
	}

	// Phase 2 — fetch the SEED-DERIVED PDAs and enforce Active + hash pin.
	id, err := g.rpc.FetchSidecarIdentity(ctx, idPDA.Base58())
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch SidecarIdentityEntry: %w", c.ComponentID, err)
	}
	if err := id.Status.RequireActive(); err != nil {
		return fmt.Errorf("chain gate %s: sidecar identity not Active: %w", c.ComponentID, err)
	}
	if hex32(id.BinaryHash) != hex32(want) {
		return fmt.Errorf("chain gate %s: identity binary_hash %s != artifact %s", c.ComponentID, hex32(id.BinaryHash), hex32(want))
	}

	gStatus, err := g.rpc.FetchGlobalSidecarStatus(ctx, globalPDA.Base58())
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch GlobalSidecarApproval status: %w", c.ComponentID, err)
	}
	if err := gStatus.RequireActive(); err != nil {
		return fmt.Errorf("chain gate %s: global sidecar approval not Active: %w", c.ComponentID, err)
	}
	gHash, err := g.rpc.FetchGlobalSidecarBinaryHash(ctx, globalPDA.Base58())
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch GlobalSidecarApproval binary_hash: %w", c.ComponentID, err)
	}
	if hex32(gHash) != hex32(want) {
		return fmt.Errorf("chain gate %s: global approval binary_hash %s != artifact %s", c.ComponentID, hex32(gHash), hex32(want))
	}

	lStatus, err := g.rpc.FetchLocalSidecarStatus(ctx, localPDA.Base58())
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch LocalSidecarApproval status: %w", c.ComponentID, err)
	}
	if err := lStatus.RequireActive(); err != nil {
		return fmt.Errorf("chain gate %s: local sidecar approval not Active: %w", c.ComponentID, err)
	}
	lHash, present, err := g.rpc.FetchLocalSidecarBinaryHash(ctx, localPDA.Base58())
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch LocalSidecarApproval binary_hash: %w", c.ComponentID, err)
	}
	if present && hex32(lHash) != hex32(want) {
		return fmt.Errorf("chain gate %s: local approval binary_hash %s != artifact %s", c.ComponentID, hex32(lHash), hex32(want))
	}

	// Phase 3 — LicenseEntry Active + pinned master, and the reseller entity +
	// sidecar approval when the license is resold. The reseller mint is read from
	// the CHAIN LicenseEntry, never the document.
	return g.gateLicenseAndReseller(ctx, c, sidecarID)
}

func (g *solanaChainGate) gateLicenseAndReseller(ctx context.Context, c componentrelease.ComponentRelease, sidecarID string) error {
	licPDA, _, err := primitives.DeriveLicense(g.licenseMintPubkey, g.program)
	if err != nil {
		return fmt.Errorf("chain gate %s: derive LicenseEntry PDA: %w", c.ComponentID, err)
	}
	lic, err := g.rpc.FetchLicenseEntrySummary(ctx, licPDA.Base58())
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch LicenseEntry: %w", c.ComponentID, err)
	}
	if err := lic.Status.RequireActive(); err != nil {
		return fmt.Errorf("chain gate %s: LicenseEntry not Active: %w", c.ComponentID, err)
	}
	if subtle.ConstantTimeCompare(lic.MasterNftMint[:], g.masterMint[:]) != 1 {
		return fmt.Errorf("chain gate %s: LicenseEntry master %s != pinned master %s", c.ComponentID, hex32(lic.MasterNftMint), g.masterMint.Base58())
	}
	if isZero32(lic.ResellerNFTMint) {
		return nil // direct (non-resold) license — no reseller cascade
	}
	resellerMint := primitives.Pubkey(lic.ResellerNFTMint)
	resellerPDA, _, err := primitives.DeriveReseller(resellerMint, g.program)
	if err != nil {
		return fmt.Errorf("chain gate %s: derive ResellerEntry PDA: %w", c.ComponentID, err)
	}
	resellerStatus, err := g.rpc.FetchResellerEntryStatus(ctx, resellerPDA.Base58())
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch ResellerEntry: %w", c.ComponentID, err)
	}
	if err := resellerStatus.RequireActive(); err != nil {
		return fmt.Errorf("chain gate %s: reseller entry not Active: %w", c.ComponentID, err)
	}
	raPDA, _, err := primitives.DeriveResellerSidecar(resellerMint, sidecarID, g.program)
	if err != nil {
		return fmt.Errorf("chain gate %s: derive ResellerSidecarApproval PDA: %w", c.ComponentID, err)
	}
	raStatus, err := g.rpc.FetchResellerSidecarStatus(ctx, raPDA.Base58())
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch ResellerSidecarApproval: %w", c.ComponentID, err)
	}
	if err := raStatus.RequireActive(); err != nil {
		return fmt.Errorf("chain gate %s: reseller sidecar approval not Active: %w", c.ComponentID, err)
	}
	return nil
}
