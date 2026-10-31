package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type chainwatchV5TestEntry struct {
	header tar.Header
	body   []byte
}

func chainwatchV5TestDigest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func chainwatchV5TestBundle(t *testing.T, entries []chainwatchV5TestEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	w := tar.NewWriter(&out)
	for _, entry := range entries {
		if err := w.WriteHeader(&entry.header); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func chainwatchV5TestFixture(t *testing.T) ([]chainwatchV5TestEntry, chainwatchV5ArtifactPins) {
	t.Helper()
	bin := []byte("synthetic-reviewed-v5-executable")
	pins := chainwatchV5ArtifactPins{ExecutableSHA256: chainwatchV5TestDigest(bin), ExecutableSize: int64(len(bin))}
	contract, err := chainwatchV5ExpectedContract(pins)
	if err != nil {
		t.Fatal(err)
	}
	entry := func(name string, mode int64, body []byte) chainwatchV5TestEntry {
		return chainwatchV5TestEntry{header: tar.Header{Name: name, Mode: mode, Size: int64(len(body)), Typeflag: tar.TypeReg}, body: append([]byte(nil), body...)}
	}
	return []chainwatchV5TestEntry{
		entry("runtime.json", 0o644, contract),
		entry("bin/chainwatch", 0o755, bin),
		entry("share/chainwatch-runtime-capabilities-v5.json", 0o644, chainwatchV5Capabilities),
	}, pins
}

func chainwatchV5TestPinArchive(pins chainwatchV5ArtifactPins, raw []byte) chainwatchV5ArtifactPins {
	pins.ArchiveSHA256, pins.ArchiveSize = chainwatchV5TestDigest(raw), int64(len(raw))
	return pins
}

func TestChainwatchV5ArchiveAcceptsExactIndependentPins(t *testing.T) {
	entries, pins := chainwatchV5TestFixture(t)
	raw := chainwatchV5TestBundle(t, entries)
	pins = chainwatchV5TestPinArchive(pins, raw)
	if err := verifyChainwatchV5Archive(bytes.NewReader(raw), pins); err != nil {
		t.Fatal(err)
	}
}

func TestChainwatchV5ArchiveRejectsPinnedButRelabeledExecutable(t *testing.T) {
	entries, pins := chainwatchV5TestFixture(t)
	// Even an archive whose whole digest is independently approved cannot
	// substitute a different child for the independently approved executable.
	bad := []byte(strings.Repeat("x", len(entries[1].body)))
	entries[1].body = bad
	raw := chainwatchV5TestBundle(t, entries)
	pins = chainwatchV5TestPinArchive(pins, raw)
	if err := verifyChainwatchV5Archive(bytes.NewReader(raw), pins); err == nil || !strings.Contains(err.Error(), "executable-mismatch") {
		t.Fatalf("relabeled binary accepted or wrong refusal: %v", err)
	}
}

func TestChainwatchV5ArchiveRejectsMutationsEvenWithNewArchivePin(t *testing.T) {
	cases := map[string]func([]chainwatchV5TestEntry) []chainwatchV5TestEntry{
		"altered contract": func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry {
			v[0].body[0] ^= 1
			return v
		},
		"altered capabilities": func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry {
			v[2].body[0] ^= 1
			return v
		},
		"missing capability": func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry { return v[:2] },
		"undeclared payload": func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry {
			return append(v, chainwatchV5TestEntry{header: tar.Header{Name: "bin/other", Mode: 0o755, Size: 1, Typeflag: tar.TypeReg}, body: []byte("x")})
		},
		"duplicate executable":    func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry { return append(v, v[1]) },
		"foreign owner":           func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry { v[1].header.Uid = 1; return v },
		"privileged bit":          func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry { v[1].header.Mode |= 0o4000; return v },
		"non executable":          func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry { v[1].header.Mode = 0o644; return v },
		"executable capabilities": func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry { v[2].header.Mode = 0o755; return v },
		"symlink": func(v []chainwatchV5TestEntry) []chainwatchV5TestEntry {
			v[1] = chainwatchV5TestEntry{header: tar.Header{Name: "bin/chainwatch", Mode: 0o755, Typeflag: tar.TypeSymlink, Linkname: "/bin/chainwatch"}}
			return v
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			entries, pins := chainwatchV5TestFixture(t)
			raw := chainwatchV5TestBundle(t, mutate(entries))
			pins = chainwatchV5TestPinArchive(pins, raw)
			if err := verifyChainwatchV5Archive(bytes.NewReader(raw), pins); err == nil {
				t.Fatalf("accepted %s even with a new archive pin", name)
			}
		})
	}
}

func TestChainwatchV5ArchiveRejectsBadPinAndTrailingData(t *testing.T) {
	entries, pins := chainwatchV5TestFixture(t)
	raw := chainwatchV5TestBundle(t, entries)
	pins = chainwatchV5TestPinArchive(pins, raw)
	for _, bad := range []chainwatchV5ArtifactPins{
		{ArchiveSHA256: strings.Repeat("0", 64), ArchiveSize: pins.ArchiveSize, ExecutableSHA256: pins.ExecutableSHA256, ExecutableSize: pins.ExecutableSize},
		{ArchiveSHA256: strings.Repeat("b", 64), ArchiveSize: pins.ArchiveSize, ExecutableSHA256: pins.ExecutableSHA256, ExecutableSize: pins.ExecutableSize},
		{ArchiveSHA256: pins.ArchiveSHA256, ArchiveSize: pins.ArchiveSize + 1, ExecutableSHA256: pins.ExecutableSHA256, ExecutableSize: pins.ExecutableSize},
		{ArchiveSHA256: pins.ArchiveSHA256, ArchiveSize: (256 << 20) + 1, ExecutableSHA256: pins.ExecutableSHA256, ExecutableSize: pins.ExecutableSize},
		{ArchiveSHA256: pins.ArchiveSHA256, ArchiveSize: pins.ArchiveSize, ExecutableSHA256: strings.Repeat("b", 64), ExecutableSize: pins.ExecutableSize},
		{ArchiveSHA256: pins.ArchiveSHA256, ArchiveSize: pins.ArchiveSize, ExecutableSHA256: pins.ExecutableSHA256, ExecutableSize: pins.ExecutableSize + 1},
	} {
		if err := verifyChainwatchV5Archive(bytes.NewReader(raw), bad); err == nil {
			t.Fatal("bad independent pin accepted")
		}
	}
	withTrailer := append(append([]byte(nil), raw...), []byte("not zero trailer")...)
	bad := chainwatchV5TestPinArchive(pins, withTrailer)
	if err := verifyChainwatchV5Archive(bytes.NewReader(withTrailer), bad); err == nil {
		t.Fatal("nonzero trailing archive data accepted")
	}
}

func TestChainwatchV5EmbeddedContractMatchesReviewedProducer(t *testing.T) {
	if got := chainwatchV5TestDigest(chainwatchV5ContractTemplate); got != "8d71e501db1000b3082f7875d645676643176e811a5bf8e224be5c4738c08ba3" {
		t.Fatalf("v5 producer template differs: %s", got)
	}
	if got := chainwatchV5TestDigest(chainwatchV5Capabilities); got != "a59008a4efd41dade495512b9e0c4f24fcd300feac7201966eacc9b7010133e8" {
		t.Fatalf("v5 capabilities differ: %s", got)
	}
}

// The existing parent producer requires independent active approval of the
// exact whole archive before its measured v5 alias can become a class proof.
func TestChainwatchV5ParentProducerApprovedArchive(t *testing.T) {
	f, request := parentPrepareFixture(t)
	entries, pins := chainwatchV5TestFixture(t)
	raw := chainwatchV5TestBundle(t, entries)
	pins = chainwatchV5TestPinArchive(pins, raw)
	if err := verifyChainwatchV5Archive(bytes.NewReader(raw), pins); err != nil {
		t.Fatal(err)
	}
	name := "synthetic-chainwatch-v5.tar"
	writeReleaseArtifact(t, f.svc.cfg.DistDir, componentrelease.ClassSidecar, name, raw)
	chain := f.component.Chain
	chain.Kind = componentrelease.AuthoritySidecarIdentity
	chain.SidecarID = "chainwatch-v2"
	chain.KeyVersion = 1
	global, _, err := primitives.DeriveGlobalSidecar(seedCascadeMaster(), chain.SidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	local, _, err := primitives.DeriveLocalSidecar(f.license, chain.SidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	identity, _, err := primitives.DeriveSidecarIdentity(f.license, chain.SidecarID, chain.KeyVersion, programID)
	if err != nil {
		t.Fatal(err)
	}
	chain.GlobalApprovalPDA, chain.LocalApprovalPDA, chain.IdentityPDA = global.Base58(), local.Base58(), identity.Base58()
	hash := sha256.Sum256(raw)
	seedValidCascade(t, f.m, f.license, chain.SidecarID, hash)
	row := &request.Rows[0]
	row.ID, row.Class, row.KeyCustody = "chainwatch", componentrelease.AuthoritySidecarIdentity, "sidecar-held-identity"
	row.ArtifactName, row.SHA256, row.SizeBytes, row.Chain = name, pins.ArchiveSHA256, pins.ArchiveSize, &chain
	delete(f.m.rawAccounts, local.Base58())
	if _, err := f.svc.classesFromParentStagedRequest(context.Background(), request, strings.Repeat("a", 64), time.Now().UTC()); err != nil {
		t.Fatalf("independently approved exact v5 archive refused: %v", err)
	}
	delete(f.m.rawAccounts, global.Base58())
	if _, err := f.svc.classesFromParentStagedRequest(context.Background(), request, strings.Repeat("a", 64), time.Now().UTC()); err == nil {
		t.Fatal("self-declared v5 archive accepted without independent Global approval")
	}
}
