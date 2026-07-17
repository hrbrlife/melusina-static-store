package main

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func randPubkeyB58(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return primitives.EncodeBase58(b[:])
}

func mustPubkey(t *testing.T, b58 string) primitives.Pubkey {
	t.Helper()
	k, err := primitives.PubkeyFromBase58(b58)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A chain gate pointed at an unroutable RPC. Any code path that reaches a fetch
// errors on the network; a "PDA mismatch" error therefore PROVES the refusal happened
// in the local derive-and-assert phase, before any account was fetched.
func newOfflineGate(t *testing.T) (*solanaChainGate, ControllerConfig) {
	t.Helper()
	cfg := ControllerConfig{
		ProgramID:      randPubkeyB58(t),
		MasterNftMint:  randPubkeyB58(t),
		LicenseNftMint: randPubkeyB58(t),
		SolanaRPCURL:   "http://127.0.0.1:1/unroutable",
	}
	g, err := newSolanaChainGate(cfg)
	if err != nil {
		t.Fatalf("construct chain gate: %v", err)
	}
	return g, cfg
}

// A doc-supplied sidecar PDA (identity / global / local) that != the seed-derived PDA
// must be REFUSED with "PDA mismatch" before any chain fetch.
func TestChainGateRefusesDocSuppliedSidecarPDAMismatch(t *testing.T) {
	g, cfg := newOfflineGate(t)
	program := mustPubkey(t, cfg.ProgramID)
	master := mustPubkey(t, cfg.MasterNftMint)
	license := mustPubkey(t, cfg.LicenseNftMint)
	const sidecarID = "melusina-store-sidecar"
	const keyVersion = uint32(2)
	want := strings.Repeat("ab", 32)

	idPDA, _, err := primitives.DeriveSidecarIdentity(license, sidecarID, keyVersion, program)
	if err != nil {
		t.Fatal(err)
	}
	globalPDA, _, err := primitives.DeriveGlobalSidecar(master, sidecarID, program)
	if err != nil {
		t.Fatal(err)
	}
	localPDA, _, err := primitives.DeriveLocalSidecar(license, sidecarID, program)
	if err != nil {
		t.Fatal(err)
	}

	base := componentrelease.ComponentRelease{
		ComponentID:    "melusina-store-sidecar",
		ComponentClass: componentrelease.ClassSidecar,
		SHA256:         want,
		Chain: componentrelease.ChainAuthority{
			Kind:              componentrelease.AuthoritySidecarIdentity,
			Program:           cfg.ProgramID,
			MasterNftMint:     cfg.MasterNftMint,
			LicenseNftMint:    cfg.LicenseNftMint,
			SidecarID:         sidecarID,
			KeyVersion:        keyVersion,
			IdentityPDA:       idPDA.Base58(),
			GlobalApprovalPDA: globalPDA.Base58(),
			LocalApprovalPDA:  localPDA.Base58(),
		},
	}

	// Sanity: with the correct seed-derived PDAs, phase 1 passes and the gate proceeds
	// to a fetch that fails on the network — so the error is NOT a PDA mismatch. This
	// proves the derivation matches the deployed program's seeds.
	if err := g.gate(context.Background(), base, componentrelease.ComponentInstall{}); err == nil {
		t.Fatal("offline gate unexpectedly succeeded")
	} else if strings.Contains(err.Error(), "PDA mismatch") {
		t.Fatalf("correct doc PDAs wrongly flagged as mismatch: %v", err)
	}

	wrong := randPubkeyB58(t)
	for _, tc := range []struct {
		name   string
		mutate func(*componentrelease.ChainAuthority)
		record string
	}{
		{"identity", func(a *componentrelease.ChainAuthority) { a.IdentityPDA = wrong }, "SidecarIdentityEntry"},
		{"global", func(a *componentrelease.ChainAuthority) { a.GlobalApprovalPDA = wrong }, "GlobalSidecarApproval"},
		{"local", func(a *componentrelease.ChainAuthority) { a.LocalApprovalPDA = wrong }, "LocalSidecarApproval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			c.Chain = base.Chain
			tc.mutate(&c.Chain)
			err := g.gate(context.Background(), c, componentrelease.ComponentInstall{})
			if err == nil || !strings.Contains(err.Error(), "PDA mismatch") {
				t.Fatalf("doc-supplied %s PDA mismatch not refused pre-fetch: %v", tc.name, err)
			}
			if !strings.Contains(err.Error(), tc.record) {
				t.Fatalf("mismatch error did not name %s: %v", tc.record, err)
			}
		})
	}
}

// A doc-supplied installer_release ReleasePDA that != the seed-derived PDA must be
// REFUSED with "PDA mismatch" before any chain fetch; the correct one passes phase 1.
func TestChainGateRefusesDocSuppliedReleasePDAMismatch(t *testing.T) {
	g, cfg := newOfflineGate(t)
	program := mustPubkey(t, cfg.ProgramID)
	master := mustPubkey(t, cfg.MasterNftMint)
	want := strings.Repeat("cd", 32)
	wantBytes, err := hashBytes(want)
	if err != nil {
		t.Fatal(err)
	}
	relPDA, _, err := primitives.DeriveInstallerRelease(master, wantBytes, program)
	if err != nil {
		t.Fatal(err)
	}
	c := componentrelease.ComponentRelease{
		ComponentID:    "sandstorm-shell",
		ComponentClass: componentrelease.ClassShell,
		SHA256:         want,
		Chain: componentrelease.ChainAuthority{
			Kind:          componentrelease.AuthorityInstallerRelease,
			Program:       cfg.ProgramID,
			MasterNftMint: cfg.MasterNftMint,
			ReleasePDA:    randPubkeyB58(t), // wrong
		},
	}
	if err := g.gate(context.Background(), c, componentrelease.ComponentInstall{}); err == nil ||
		!strings.Contains(err.Error(), "PDA mismatch") || !strings.Contains(err.Error(), "InstallerReleaseEntry") {
		t.Fatalf("doc-supplied installer ReleasePDA mismatch not refused: %v", err)
	}
	// Correct derived PDA passes phase 1 (then fails on the offline fetch).
	c.Chain.ReleasePDA = relPDA.Base58()
	if err := g.gate(context.Background(), c, componentrelease.ComponentInstall{}); err == nil ||
		strings.Contains(err.Error(), "PDA mismatch") {
		t.Fatalf("correct installer ReleasePDA wrongly flagged: %v", err)
	}
}
