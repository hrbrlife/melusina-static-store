package main

import (
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func chainwatchV5ParentFixture(t *testing.T, raw []byte) (keylessFixture, stagedSidecarClassRequest) {
	t.Helper()
	f, request := parentPrepareFixture(t)
	name := "synthetic-chainwatch-v5.tar"
	writeReleaseArtifact(t, f.svc.cfg.DistDir, componentrelease.ClassSidecar, name, raw)
	chain := f.component.Chain
	chain.Kind, chain.SidecarID, chain.KeyVersion = componentrelease.AuthoritySidecarIdentity, "chainwatch-v2", 1
	global, _, err := primitives.DeriveGlobalSidecar(seedCascadeMaster(), chain.SidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	local, _, err := primitives.DeriveLocalSidecar(f.license, chain.SidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	identity, _, err := primitives.DeriveSidecarIdentity(f.license, chain.SidecarID, 1, programID)
	if err != nil {
		t.Fatal(err)
	}
	chain.GlobalApprovalPDA, chain.LocalApprovalPDA, chain.IdentityPDA = global.Base58(), local.Base58(), identity.Base58()
	seedValidCascade(t, f.m, f.license, chain.SidecarID, sha256.Sum256(raw))
	delete(f.m.rawAccounts, local.Base58())
	delete(f.m.rawAccounts, identity.Base58())
	request.Rows[0] = stagedSidecarClassRow{ID: "chainwatch", Class: componentrelease.AuthoritySidecarIdentity,
		KeyCustody: "sidecar-held-identity", ArtifactName: name, SHA256: chainwatchV5TestDigest(raw), SizeBytes: int64(len(raw)), Chain: &chain}
	return f, request
}

func TestChainwatchV5ParentProducerRefusesChangedAuthorityAndArchive(t *testing.T) {
	cases := []struct {
		name     string
		artifact func([]chainwatchV5TestEntry) []chainwatchV5TestEntry
		change   func(keylessFixture, *stagedSidecarClassRequest)
	}{
		{name: "wrong key version", change: func(_ keylessFixture, r *stagedSidecarClassRequest) { r.Rows[0].Chain.KeyVersion = 2 }},
		{name: "cascade instead of identity", change: func(_ keylessFixture, r *stagedSidecarClassRequest) {
			r.Rows[0].Class = componentrelease.AuthoritySidecarCascade
			r.Rows[0].KeyCustody = "none"
			r.Rows[0].Chain.Kind = componentrelease.AuthoritySidecarCascade
		}},
		{name: "foreign component alias", change: func(_ keylessFixture, r *stagedSidecarClassRequest) { r.Rows[0].ID = "unrelated" }},
		{name: "missing global", change: func(f keylessFixture, r *stagedSidecarClassRequest) {
			delete(f.m.rawAccounts, r.Rows[0].Chain.GlobalApprovalPDA)
		}},
		{name: "global approves different bytes", change: func(f keylessFixture, r *stagedSidecarClassRequest) {
			seedValidCascade(t, f.m, f.license, "chainwatch-v2", sha256.Sum256([]byte("different")))
		}},
		{name: "declared child differs", artifact: func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry { v[1].body[0] ^= 1; return v }},
		{name: "capabilities absent", artifact: func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry { return v[:2] }},
		{name: "legacy contract relabeled", artifact: func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry {
			v[0].body = []byte(`{"schema":"melusina-sidecar-runtime-v1","sidecarId":"chainwatch","authoritySidecarId":"chainwatch-v2","components":[]}`)
			v[0].header.Size = int64(len(v[0].body))
			return v
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries, _ := chainwatchV5TestFixture(t)
			if tc.artifact != nil {
				entries = tc.artifact(entries)
			}
			f, r := chainwatchV5ParentFixture(t, chainwatchV5TestBundle(t, entries))
			if tc.change != nil {
				tc.change(f, &r)
			}
			if _, err := f.svc.classesFromParentStagedRequest(context.Background(), r, strings.Repeat("a", 64), time.Now().UTC()); err == nil {
				t.Fatal("foreign authority or malformed approved archive accepted")
			}
		})
	}
}

func TestChainwatchV5ParentProducerReleasedArchive(t *testing.T) {
	path := os.Getenv("CHAINWATCH_V5_REVIEWED_ARCHIVE")
	if path == "" {
		t.Skip("reviewed release archive not supplied")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	expected := os.Getenv("CHAINWATCH_V5_REVIEWED_SHA256")
	if !validChainwatchV5SHA256(expected) || chainwatchV5TestDigest(raw) != expected {
		t.Fatal("independently reviewed complete archive differs")
	}
	f, r := chainwatchV5ParentFixture(t, raw)
	table, err := f.svc.classesFromParentStagedRequest(context.Background(), r, strings.Repeat("a", 64), time.Now().UTC())
	if err != nil || len(table.Rows) != 1 {
		t.Fatalf("exact reviewed release parent refused: %v", err)
	}
	// Parent classification is deliberately insufficient for generation serving:
	// the tenant's Local and Identity accounts have not been created.
	c := f.component
	c.ComponentID = r.Rows[0].ID
	c.Chain = *r.Rows[0].Chain
	c.SHA256 = r.Rows[0].SHA256
	c.SizeBytes = r.Rows[0].SizeBytes
	c.ArtifactName = r.Rows[0].ArtifactName
	if err = f.svc.verifyComponentReleaseOnChain(context.Background(), c); err == nil {
		t.Fatal("parent proof incorrectly authorized generation serving before tenant Local/Identity")
	}
}
