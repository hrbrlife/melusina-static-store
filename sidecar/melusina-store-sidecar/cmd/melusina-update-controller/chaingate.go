package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

// solanaChainGate is the controller's real on-chain authority gate: for each
// component it confirms the operator-signed ChainAuthority PDAs are Active on-chain
// and pin the exact content hash BEFORE any host mutation. It decodes accounts via
// the shared, verified melusina-identity-gate/verify readers (the same account
// layouts the store's publish gate uses) rather than re-implementing Borsh, and pins
// the program id + master/license mints from the ROOT-OWNED config (never the doc).
//
// The PDA addresses themselves are carried in the operator-SIGNED generation and were
// bound by componentrelease.Verify, so they are signature-backed; this gate confirms
// the on-chain records those addresses name are Active and hash-pinned. (Deriving the
// PDAs from seeds as an independent cross-check is a future hardening — noted in
// docs/CONTROLLER_INSTALL_SURFACE.md.)
type solanaChainGate struct {
	rpc            *verify.RPCClient
	programID      string
	masterNftMint  string
	licenseNftMint string
}

func newSolanaChainGate(cfg ControllerConfig) *solanaChainGate {
	return &solanaChainGate{
		rpc:            verify.NewRPCClient(cfg.SolanaRPCURL),
		programID:      cfg.ProgramID,
		masterNftMint:  cfg.MasterNftMint,
		licenseNftMint: cfg.LicenseNftMint,
	}
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

// gate is the ApplyDeps.ChainGate callback.
func (g *solanaChainGate) gate(ctx context.Context, c componentrelease.ComponentRelease, _ componentrelease.ComponentInstall) error {
	if c.Chain.Program != g.programID {
		return fmt.Errorf("chain gate %s: program %q != pinned %q", c.ComponentID, c.Chain.Program, g.programID)
	}
	want := contentIdentity(c)
	switch c.Chain.Kind {
	case componentrelease.AuthorityInstallerRelease:
		if c.Chain.MasterNftMint != g.masterNftMint {
			return fmt.Errorf("chain gate %s: masterNftMint pin mismatch", c.ComponentID)
		}
		hash, status, err := g.rpc.FetchInstallerReleaseEntry(ctx, c.Chain.ReleasePDA)
		if err != nil {
			return fmt.Errorf("chain gate %s: fetch InstallerReleaseEntry: %w", c.ComponentID, err)
		}
		if err := status.RequireActive(); err != nil {
			return fmt.Errorf("chain gate %s: installer release not Active: %w", c.ComponentID, err)
		}
		if hex32(hash) != want {
			return fmt.Errorf("chain gate %s: installer_hash %s != artifact %s", c.ComponentID, hex32(hash), want)
		}
	case componentrelease.AuthorityReleaseV2:
		if c.Chain.MasterNftMint != g.masterNftMint {
			return fmt.Errorf("chain gate %s: masterNftMint pin mismatch", c.ComponentID)
		}
		appHash, status, err := g.rpc.FetchReleaseEntry(ctx, c.Chain.ReleasePDA)
		if err != nil {
			return fmt.Errorf("chain gate %s: fetch ReleaseEntry: %w", c.ComponentID, err)
		}
		if err := status.RequireActive(); err != nil {
			return fmt.Errorf("chain gate %s: release not Active: %w", c.ComponentID, err)
		}
		if hex32(appHash) != want {
			return fmt.Errorf("chain gate %s: app_hash %s != content %s", c.ComponentID, hex32(appHash), want)
		}
	case componentrelease.AuthoritySidecarIdentity:
		if c.Chain.LicenseNftMint != g.licenseNftMint {
			return fmt.Errorf("chain gate %s: licenseNftMint pin mismatch", c.ComponentID)
		}
		if c.Chain.MasterNftMint != g.masterNftMint {
			return fmt.Errorf("chain gate %s: masterNftMint (global-approval seed) pin mismatch", c.ComponentID)
		}
		return g.gateSidecarCascade(ctx, c, want)
	default:
		return fmt.Errorf("chain gate %s: unknown chain kind %q", c.ComponentID, c.Chain.Kind)
	}
	return nil
}

// gateSidecarCascade confirms the three-PDA sidecar identity cascade: the identity
// entry is Active and pins the artifact, and BOTH the global and local approvals are
// Active (and pin the artifact where a binary hash is recorded). A revoked approval
// anywhere in the cascade fail-closes the apply.
func (g *solanaChainGate) gateSidecarCascade(ctx context.Context, c componentrelease.ComponentRelease, want string) error {
	id, err := g.rpc.FetchSidecarIdentity(ctx, c.Chain.IdentityPDA)
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch SidecarIdentityEntry: %w", c.ComponentID, err)
	}
	if err := id.Status.RequireActive(); err != nil {
		return fmt.Errorf("chain gate %s: sidecar identity not Active: %w", c.ComponentID, err)
	}
	if hex32(id.BinaryHash) != want {
		return fmt.Errorf("chain gate %s: identity binary_hash %s != artifact %s", c.ComponentID, hex32(id.BinaryHash), want)
	}

	gStatus, err := g.rpc.FetchGlobalSidecarStatus(ctx, c.Chain.GlobalApprovalPDA)
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch GlobalSidecarApproval status: %w", c.ComponentID, err)
	}
	if err := gStatus.RequireActive(); err != nil {
		return fmt.Errorf("chain gate %s: global sidecar approval not Active: %w", c.ComponentID, err)
	}
	gHash, err := g.rpc.FetchGlobalSidecarBinaryHash(ctx, c.Chain.GlobalApprovalPDA)
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch GlobalSidecarApproval binary_hash: %w", c.ComponentID, err)
	}
	if hex32(gHash) != want {
		return fmt.Errorf("chain gate %s: global approval binary_hash %s != artifact %s", c.ComponentID, hex32(gHash), want)
	}

	lStatus, err := g.rpc.FetchLocalSidecarStatus(ctx, c.Chain.LocalApprovalPDA)
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch LocalSidecarApproval status: %w", c.ComponentID, err)
	}
	if err := lStatus.RequireActive(); err != nil {
		return fmt.Errorf("chain gate %s: local sidecar approval not Active: %w", c.ComponentID, err)
	}
	lHash, present, err := g.rpc.FetchLocalSidecarBinaryHash(ctx, c.Chain.LocalApprovalPDA)
	if err != nil {
		return fmt.Errorf("chain gate %s: fetch LocalSidecarApproval binary_hash: %w", c.ComponentID, err)
	}
	if present && hex32(lHash) != want {
		return fmt.Errorf("chain gate %s: local approval binary_hash %s != artifact %s", c.ComponentID, hex32(lHash), want)
	}
	return nil
}
