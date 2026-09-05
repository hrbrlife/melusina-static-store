package main

import (
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const (
	testProg   = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	testMaster = "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe"
)

func composePolicy() GenerationPolicy {
	return GenerationPolicy{
		StoreID:      "melusina-os-root-store",
		BundleOrigin: "https://bazaar.melusina-os.org",
		Channel:      "dev",
	}
}

func shellComp(id, sha, version string) componentrelease.ComponentRelease {
	return componentrelease.ComponentRelease{
		ComponentID:    id,
		ComponentClass: componentrelease.ClassShell,
		Version:        version,
		ArtifactName:   id + "-" + sha[:8] + ".tar.xz",
		SHA256:         sha,
		SizeBytes:      1024,
		BundleURL:      "https://bazaar.melusina-os.org/releases/shell/" + id + "-" + sha[:8] + ".tar.xz",
		ReleaseHash:    strings.Repeat("d", 64),
		StageID:        strings.Repeat("e", 64),
		Chain: componentrelease.ChainAuthority{
			Kind:          componentrelease.AuthorityInstallerRelease,
			Program:       testProg,
			MasterNftMint: testMaster,
			ReleasePDA:    "FMRFyGPzrefaYiETSLTDw8fHqix8GVcGuri31qTZVtgY",
		},
	}
}

func sidecarComp(id, sha, version string) componentrelease.ComponentRelease {
	return componentrelease.ComponentRelease{
		ComponentID:    id,
		ComponentClass: componentrelease.ClassSidecar,
		Version:        version,
		ArtifactName:   id + "-" + sha[:8] + ".bin",
		SHA256:         sha,
		SizeBytes:      2048,
		BundleURL:      "https://bazaar.melusina-os.org/releases/sidecar/" + id + "-" + sha[:8] + ".bin",
		ReleaseHash:    strings.Repeat("d", 64),
		StageID:        strings.Repeat("e", 64),
		Chain: componentrelease.ChainAuthority{
			Kind:              componentrelease.AuthoritySidecarIdentity,
			Program:           testProg,
			LicenseNftMint:    testLicenseMint,
			MasterNftMint:     testMaster,
			SidecarID:         id,
			KeyVersion:        1,
			IdentityPDA:       "H95UEaQMdoXk2s6y8kY6oYcU1r8Fq3aVqk6t6Z9y1abc",
			GlobalApprovalPDA: "G1oba1Approva1PdaFor5tore5idecarXyz123456789",
			LocalApprovalPDA:  "Loca1Approva1PdaFor5tore5idecarAbc987654321",
		},
	}
}

func TestMintComponentVersion(t *testing.T) {
	got := mintComponentVersion(64, "deadbeefcafef00d0000000000000000000000000000000000000000000000ff")
	if got != "gen-64-deadbeef" {
		t.Fatalf("mintComponentVersion = %q", got)
	}
}

func TestComposeGenesisSignsAndVerifies(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	// Version empty -> the composer must mint one.
	updates := []componentrelease.ComponentRelease{shellComp("sandstorm-shell", strings.Repeat("a", 64), "")}
	next, err := composeNextGeneration(nil, composePolicy(), 1784281821, updates)
	if err != nil {
		t.Fatalf("compose genesis: %v", err)
	}
	if next.GenerationID != 1 || next.PreviousGeneration != 0 {
		t.Fatalf("genesis gen ids: id=%d prev=%d", next.GenerationID, next.PreviousGeneration)
	}
	if next.Components[0].Version != mintComponentVersion(1, strings.Repeat("a", 64)) {
		t.Fatalf("version not minted: %q", next.Components[0].Version)
	}
	signed, err := componentrelease.Sign(op, next)
	if err != nil {
		t.Fatalf("sign composed genesis: %v", err)
	}
	pub, _ := operatorSignPublicKey(op)
	if err := componentrelease.Verify(pub, "melusina-os-root-store", signed); err != nil {
		t.Fatalf("verify composed genesis: %v", err)
	}
}

func TestComposeUpdateCarryForwardAndRollbackFloor(t *testing.T) {
	op := newTestIdentity(t, "store-operator", testLicenseMint, "bazaar.melusina-os.org")
	oldShellSHA := strings.Repeat("a", 64)
	sidecarSHA := strings.Repeat("b", 64)
	current := componentrelease.DesiredGeneration{
		GenerationID: 63,
		Components: []componentrelease.ComponentRelease{
			shellComp("sandstorm-shell", oldShellSHA, "build-63"),
			sidecarComp("melusina-store-sidecar", sidecarSHA, "1.0.7"),
		},
	}
	// Publish a NEW shell; leave the sidecar unchanged (not in updates).
	newShellSHA := strings.Repeat("1", 64)
	updates := []componentrelease.ComponentRelease{shellComp("sandstorm-shell", newShellSHA, "build-64")}

	next, err := composeNextGeneration(&current, composePolicy(), 1784281900, updates)
	if err != nil {
		t.Fatalf("compose update: %v", err)
	}
	if next.GenerationID != 64 || next.PreviousGeneration != 63 {
		t.Fatalf("update gen ids: id=%d prev=%d", next.GenerationID, next.PreviousGeneration)
	}
	if len(next.Components) != 2 {
		t.Fatalf("expected 2 components (1 changed + 1 carried), got %d", len(next.Components))
	}
	byID := map[string]componentrelease.ComponentRelease{}
	for _, c := range next.Components {
		byID[c.ComponentID] = c
	}
	// The CHANGED shell rolls back to the OLD artifact.
	shell := byID["sandstorm-shell"]
	if shell.SHA256 != newShellSHA {
		t.Fatalf("changed shell sha not applied: %s", shell.SHA256)
	}
	if shell.PreviousSHA256 != oldShellSHA || shell.PreviousVersion != "build-63" {
		t.Fatalf("changed shell rollback floor wrong: prevSha=%s prevVer=%s", shell.PreviousSHA256, shell.PreviousVersion)
	}
	// The UNCHANGED sidecar's rollback floor is itself.
	sc := byID["melusina-store-sidecar"]
	if sc.SHA256 != sidecarSHA || sc.PreviousSHA256 != sidecarSHA || sc.PreviousVersion != "1.0.7" {
		t.Fatalf("carried sidecar wrong: sha=%s prevSha=%s prevVer=%s", sc.SHA256, sc.PreviousSHA256, sc.PreviousVersion)
	}
	signed, err := componentrelease.Sign(op, next)
	if err != nil {
		t.Fatalf("sign composed update: %v", err)
	}
	pub, _ := operatorSignPublicKey(op)
	if err := componentrelease.Verify(pub, "melusina-os-root-store", signed); err != nil {
		t.Fatalf("verify composed update: %v", err)
	}
}

func TestComposeRejectsEmptyUpdateSet(t *testing.T) {
	if _, err := composeNextGeneration(nil, composePolicy(), 1, nil); err == nil {
		t.Fatal("compose accepted an empty update set")
	}
}

func TestComposeRenamesOneSidecarIdentityWithoutCarryingAnAlias(t *testing.T) {
	old := sidecarComp("fineract-v2", strings.Repeat("a", 64), "0.0.83")
	old.Chain.SidecarID = "fineract-v2"
	current := componentrelease.DesiredGeneration{
		GenerationID: 204,
		Components: []componentrelease.ComponentRelease{
			old,
			shellComp("sandstorm-shell", strings.Repeat("b", 64), "build-104"),
		},
	}
	replacement := old
	replacement.ComponentID = "fineract-sidecar"
	replacement.ArtifactName = "fineract-sidecar-" + replacement.SHA256[:8] + ".bin"
	replacement.BundleURL = "https://bazaar.melusina-os.org/releases/sidecar/" + replacement.ArtifactName
	replacement.PreviousSHA256 = strings.Repeat("c", 64)
	replacement.PreviousVersion = "legacy-105ae22b"

	next, err := composeNextGeneration(&current, composePolicy(), 1788066000, []componentrelease.ComponentRelease{replacement})
	if err != nil {
		t.Fatalf("compose sidecar identity rename: %v", err)
	}
	if len(next.Components) != 2 {
		t.Fatalf("rename must replace, not duplicate, the sidecar component: %#v", next.Components)
	}
	if _, found := next.Component("fineract-v2"); found {
		t.Fatal("historical component alias survived the identity-bound rename")
	}
	got, found := next.Component("fineract-sidecar")
	if !found {
		t.Fatal("renamed sidecar component is absent")
	}
	if got.Chain.SidecarID != "fineract-v2" || got.PreviousSHA256 != replacement.PreviousSHA256 || got.PreviousVersion != replacement.PreviousVersion {
		t.Fatalf("renamed component lost its chain identity or explicit physical rollback floor: %#v", got)
	}
}

func TestComposeRejectsTwoComponentNamesForOneSidecarIdentity(t *testing.T) {
	first := sidecarComp("fineract-v2", strings.Repeat("a", 64), "0.0.83")
	first.Chain.SidecarID = "fineract-v2"
	second := first
	second.ComponentID = "fineract-sidecar"
	second.ArtifactName = "fineract-sidecar-" + second.SHA256[:8] + ".bin"
	second.BundleURL = "https://bazaar.melusina-os.org/releases/sidecar/" + second.ArtifactName

	if _, err := composeNextGeneration(nil, composePolicy(), 1788066000, []componentrelease.ComponentRelease{first, second}); err == nil || !strings.Contains(err.Error(), "same sidecar authority identity") {
		t.Fatalf("duplicate sidecar authority updates were not refused: %v", err)
	}
}

func TestComposeRejectsAmbiguousCurrentAliasesDuringRename(t *testing.T) {
	first := sidecarComp("fineract-v2", strings.Repeat("a", 64), "0.0.83")
	first.Chain.SidecarID = "fineract-v2"
	second := first
	second.ComponentID = "fineract-old-alias"
	current := componentrelease.DesiredGeneration{GenerationID: 204, Components: []componentrelease.ComponentRelease{first, second}}
	replacement := first
	replacement.ComponentID = "fineract-sidecar"

	if _, err := composeNextGeneration(&current, composePolicy(), 1788066000, []componentrelease.ComponentRelease{replacement}); err == nil || !strings.Contains(err.Error(), "ambiguously matches current aliases") {
		t.Fatalf("ambiguous current aliases were not refused: %v", err)
	}
}

func TestGenerationCAS(t *testing.T) {
	current := &componentrelease.DesiredGeneration{GenerationID: 63}
	next := componentrelease.DesiredGeneration{GenerationID: 64, PreviousGeneration: 63}
	if v := generationCAS(current, next, 63); v != "" {
		t.Fatalf("valid single-step advance rejected: %s", v)
	}
	// Stale: publisher believed current was 62.
	if generationCAS(current, next, 62) == "" {
		t.Fatal("stale expected-current accepted")
	}
	// Non-monotonic: skips a generation.
	if generationCAS(current, componentrelease.DesiredGeneration{GenerationID: 65, PreviousGeneration: 63}, 63) == "" {
		t.Fatal("non-monotonic advance accepted")
	}
	// Wrong previousGeneration.
	if generationCAS(current, componentrelease.DesiredGeneration{GenerationID: 64, PreviousGeneration: 62}, 63) == "" {
		t.Fatal("mismatched previousGeneration accepted")
	}
	// Genesis: no current, expected 0, next gen 1.
	if v := generationCAS(nil, componentrelease.DesiredGeneration{GenerationID: 1, PreviousGeneration: 0}, 0); v != "" {
		t.Fatalf("valid genesis promote rejected: %s", v)
	}
}
