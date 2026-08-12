package componentrelease

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func testOperator(t *testing.T) (*identity.Private, ed25519.PublicKey) {
	t.Helper()
	var signSeed, boxSeed [32]byte
	if _, err := rand.Read(signSeed[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(boxSeed[:]); err != nil {
		t.Fatal(err)
	}
	ref := identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     "solana:devnet",
		ProgramID:   "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
		LicenseMint: "35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN",
		Domain:      "bazaar.melusina-os.org",
		PDA:         "11111111111111111111111111111111",
		SidecarID:   "store-operator",
		KeyVersion:  1,
	}
	priv, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		t.Fatalf("NewPrivate: %v", err)
	}
	pub, err := priv.Public().SignPublicKey()
	if err != nil {
		t.Fatalf("SignPublicKey: %v", err)
	}
	return priv, pub
}

func sampleGeneration() DesiredGeneration {
	return DesiredGeneration{
		GenerationID:       63,
		StoreID:            "melusina-os-root-store",
		BundleOrigin:       "https://bazaar.melusina-os.org",
		Channel:            "dev",
		SignedAtUnix:       1784281821,
		PreviousGeneration: 62,
		Components: []ComponentRelease{
			{
				ComponentID:     "melusina-store-sidecar",
				ComponentClass:  ClassSidecar,
				Version:         "1.0.7",
				ArtifactName:    "melusina-store-sidecar-1.0.7.bin",
				SHA256:          "a78567eb117efdcf1e31449b63dfacac1ec25f85a5ee32a970e73bd9f5a0d6af",
				SizeBytes:       12345678,
				BundleURL:       "https://bazaar.melusina-os.org/releases/sidecar/melusina-store-sidecar-1.0.7.bin",
				ReleaseHash:     "1111111111111111111111111111111111111111111111111111111111111111",
				StageID:         "2222222222222222222222222222222222222222222222222222222222222222",
				PreviousSHA256:  "3333333333333333333333333333333333333333333333333333333333333333",
				PreviousVersion: "1.0.6",
				Chain: ChainAuthority{
					Kind:              AuthoritySidecarIdentity,
					Program:           "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
					LicenseNftMint:    "35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN",
					MasterNftMint:     "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe",
					SidecarID:         "melusina-store-sidecar",
					KeyVersion:        1,
					IdentityPDA:       "H95UEaQMdoXk2s6y8kY6oYcU1r8Fq3aVqk6t6Z9y1abc",
					GlobalApprovalPDA: "G1oba1Approva1PdaFor5tore5idecarXyz123456789",
					LocalApprovalPDA:  "Loca1Approva1PdaFor5tore5idecarAbc987654321",
				},
			},
			{
				ComponentID:     "sandstorm-shell",
				ComponentClass:  ClassShell,
				Version:         "build-63",
				Build:           63,
				ArtifactName:    "sandstorm-4b8b4c6b5ca595a39c3e7427103dbcd776ae9fb70492057836cf768a312b0356.tar.xz",
				SHA256:          "4b8b4c6b5ca595a39c3e7427103dbcd776ae9fb70492057836cf768a312b0356",
				SizeBytes:       176787848,
				BundleURL:       "https://bazaar.melusina-os.org/releases/shell/sandstorm-4b8b4c6b5ca595a39c3e7427103dbcd776ae9fb70492057836cf768a312b0356.tar.xz",
				ReleaseHash:     "4444444444444444444444444444444444444444444444444444444444444444",
				StageID:         "5555555555555555555555555555555555555555555555555555555555555555",
				PreviousSHA256:  "6666666666666666666666666666666666666666666666666666666666666666",
				PreviousVersion: "build-62",
				Chain: ChainAuthority{
					Kind:          AuthorityInstallerRelease,
					Program:       "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
					MasterNftMint: "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe",
					ReleasePDA:    "FMRFyGPzrefaYiETSLTDw8fHqix8GVcGuri31qTZVtgY",
				},
				Requires: []ComponentDependency{
					{ComponentID: "melusina-store-sidecar", MinVersion: "1.0.7"},
				},
			},
		},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	op, pub := testOperator(t)
	signed, err := Sign(op, sampleGeneration())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed.Schema != DesiredGenerationSchema {
		t.Fatalf("schema not set: %q", signed.Schema)
	}
	if signed.OperatorPubkey != primitives.EncodeBase58(pub) {
		t.Fatalf("operator pubkey mismatch")
	}
	if signed.GenerationHash == "" || signed.OperatorSignature == "" {
		t.Fatalf("generation hash / signature not filled")
	}
	// Components must come back sorted by id (melusina-store-sidecar < sandstorm-shell).
	if signed.Components[0].ComponentID != "melusina-store-sidecar" {
		t.Fatalf("components not canonically sorted: %s", signed.Components[0].ComponentID)
	}
	if err := Verify(pub, "melusina-os-root-store", signed); err != nil {
		t.Fatalf("Verify (valid): %v", err)
	}
	// Survives a JSON marshal/unmarshal round trip (the wire form).
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	var back DesiredGeneration
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, "melusina-os-root-store", back); err != nil {
		t.Fatalf("Verify after json round trip: %v", err)
	}
}

func TestVerifyRejectsTamperedComponent(t *testing.T) {
	op, pub := testOperator(t)
	signed, err := Sign(op, sampleGeneration())
	if err != nil {
		t.Fatal(err)
	}
	// Flip one artifact hash: content hash no longer matches (generation drift),
	// and the signature would fail too.
	signed.Components[1].SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := Verify(pub, "melusina-os-root-store", signed); err == nil {
		t.Fatal("Verify accepted a tampered component sha256")
	}
}

func TestVerifyRejectsGenerationHashDrift(t *testing.T) {
	op, pub := testOperator(t)
	signed, err := Sign(op, sampleGeneration())
	if err != nil {
		t.Fatal(err)
	}
	// Keep components but lie about the content hash.
	signed.GenerationHash = "deadbeef" + signed.GenerationHash[8:]
	if err := Verify(pub, "melusina-os-root-store", signed); err == nil {
		t.Fatal("Verify accepted a drifted generation hash")
	}
}

func TestVerifyRejectsWrongDestination(t *testing.T) {
	op, pub := testOperator(t)
	signed, err := Sign(op, sampleGeneration())
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, "some-other-store", signed); err == nil {
		t.Fatal("Verify accepted a wrong destination storeId")
	}
}

func TestVerifyRejectsWrongSigner(t *testing.T) {
	op, _ := testOperator(t)
	_, otherPub := testOperator(t)
	signed, err := Sign(op, sampleGeneration())
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(otherPub, "melusina-os-root-store", signed); err == nil {
		t.Fatal("Verify accepted a signature under an unauthorized key")
	}
}

func TestValidateRejectsGitHubBundle(t *testing.T) {
	op, _ := testOperator(t)
	gen := sampleGeneration()
	gen.Components[0].BundleURL = "https://github.com/melusina/releases/x.bin"
	if _, err := Sign(op, gen); err == nil {
		t.Fatal("Sign accepted a GitHub bundle url")
	}
}

func TestValidateRejectsNonMonotonicPrevious(t *testing.T) {
	op, _ := testOperator(t)
	gen := sampleGeneration()
	gen.PreviousGeneration = gen.GenerationID // must be strictly less
	if _, err := Sign(op, gen); err == nil {
		t.Fatal("Sign accepted previousGeneration >= generationId")
	}
}

func TestValidateRejectsDanglingDependency(t *testing.T) {
	op, _ := testOperator(t)
	gen := sampleGeneration()
	gen.Components[1].Requires = []ComponentDependency{{ComponentID: "nonexistent-component"}}
	if _, err := Sign(op, gen); err == nil {
		t.Fatal("Sign accepted a dependency on a component absent from the generation")
	}
}

func TestValidateRejectsIncompleteSidecarCascade(t *testing.T) {
	op, _ := testOperator(t)
	gen := sampleGeneration()
	// Components[0] (melusina-store-sidecar) uses the sidecar_identity three-PDA
	// cascade; dropping one PDA must be refused.
	gen.Components[0].Chain.LocalApprovalPDA = ""
	if _, err := Sign(op, gen); err == nil {
		t.Fatal("Sign accepted a sidecar_identity component missing a cascade PDA")
	}
}

func TestValidateRejectsSidecarWithoutLicenseMint(t *testing.T) {
	op, _ := testOperator(t)
	gen := sampleGeneration()
	gen.Components[0].Chain.LicenseNftMint = ""
	if _, err := Sign(op, gen); err == nil {
		t.Fatal("Sign accepted a sidecar_identity component without a licenseNftMint")
	}
}

func TestUpdateSidecarDoesNotRequireAppStageIdentity(t *testing.T) {
	// Sidecars are sealed by SidecarIdentity.binary_hash and the signed desired
	// generation; releaseHash/stageId are app-SPK staging identities and must not
	// be fabricated for a binary-replace N+1.
	op, _ := testOperator(t)
	gen := sampleGeneration()
	gen.Components = gen.Components[:1]
	gen.Components[0].ReleaseHash = ""
	gen.Components[0].StageID = ""
	if _, err := Sign(op, gen); err != nil {
		t.Fatalf("Sign rejected a sidecar update without app stage identity: %v", err)
	}
}

func writeRegistry(t *testing.T, reg ComponentRegistry) string {
	t.Helper()
	raw, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "component-registry.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func sampleRegistry() ComponentRegistry {
	return ComponentRegistry{
		Schema: ComponentRegistrySchema,
		Components: map[string]ComponentInstall{
			"sandstorm-shell": {
				ComponentID:    "sandstorm-shell",
				ComponentClass: ClassShell,
				ApplyKind:      ApplyTarballSymlinkSwap,
				InstallRoot:    "/opt/sandstorm",
				StagingDir:     "/opt/sandstorm/staging",
				CurrentSymlink: "/opt/sandstorm/latest",
				ServiceUnit:    "sandstorm.service",
				HealthCommand:  []string{"/opt/melusina/bin/shell-health"},
				SelfReportURL:  "http://127.0.0.1/melusina/release-info",
				KeepOldBuilds:  2,
			},
			"melusina-store-sidecar": {
				ComponentID:    "melusina-store-sidecar",
				ComponentClass: ClassSidecar,
				ApplyKind:      ApplyBinaryReplace,
				InstallRoot:    "/usr/local/bin/melusina-store-sidecar",
				StagingDir:     "/var/lib/melusina-store/staging",
				ServiceUnit:    "melusina-store.service",
				HealthCommand:  []string{"/usr/local/bin/store-health"},
				RuntimeEnvFile: "/var/lib/melusina-update/runtime/melusina-store-sidecar.env",
			},
		},
	}
}

func TestRegistryParseAndResolveAllowlist(t *testing.T) {
	// Content is validated via parseComponentRegistry so this passes in a non-root
	// test env; LoadComponentRegistry's on-host trust gate (root owner / perms /
	// no-symlink) is exercised by the adversarial overlay's negative cases.
	raw, err := json.Marshal(sampleRegistry())
	if err != nil {
		t.Fatal(err)
	}
	reg, err := parseComponentRegistry(raw)
	if err != nil {
		t.Fatalf("parseComponentRegistry: %v", err)
	}
	// A component in the allowlist with matching class resolves.
	shell := ComponentRelease{ComponentID: "sandstorm-shell", ComponentClass: ClassShell}
	if _, err := reg.ResolveComponent(shell); err != nil {
		t.Fatalf("ResolveComponent(allowlisted): %v", err)
	}
	// A component NOT in the allowlist is refused (no host action can be introduced).
	unknown := ComponentRelease{ComponentID: "rogue-daemon", ComponentClass: ClassSidecar}
	if _, err := reg.ResolveComponent(unknown); err == nil {
		t.Fatal("ResolveComponent accepted a component absent from the allowlist")
	}
	// A class disagreement between remote doc and local registry is refused.
	wrongClass := ComponentRelease{ComponentID: "sandstorm-shell", ComponentClass: ClassSidecar}
	if _, err := reg.ResolveComponent(wrongClass); err == nil {
		t.Fatal("ResolveComponent accepted a class disagreement")
	}
}

func TestRegistryRejectsMissingHealthCommand(t *testing.T) {
	reg := sampleRegistry()
	e := reg.Components["melusina-store-sidecar"]
	e.HealthCommand = nil
	reg.Components["melusina-store-sidecar"] = e
	if err := reg.Validate(); err == nil {
		t.Fatal("Validate accepted a registry entry with no health command")
	}
}

func TestRegistryRejectsUnknownApplyKind(t *testing.T) {
	reg := sampleRegistry()
	e := reg.Components["sandstorm-shell"]
	e.ApplyKind = "rm-rf-and-pray"
	reg.Components["sandstorm-shell"] = e
	if err := reg.Validate(); err == nil {
		t.Fatal("Validate accepted an unknown apply kind")
	}
}

func TestRegistryPythonVenvRequiresSymlink(t *testing.T) {
	reg := sampleRegistry()
	reg.Components["creeper"] = ComponentInstall{
		ComponentID:    "creeper",
		ComponentClass: ClassSidecar,
		ApplyKind:      ApplyPythonVenv,
		InstallRoot:    "/opt/creeper",
		StagingDir:     "/opt/creeper/staging",
		// CurrentSymlink deliberately omitted -> python-venv installs into a
		// versioned <gen> dir and requires it.
		ServiceUnit:   "creeper.service",
		HealthCommand: []string{"/opt/melusina/bin/creeper-health"},
	}
	if err := reg.Validate(); err == nil {
		t.Fatal("Validate accepted python-venv without a currentSymlink")
	}
}

func TestRegistryRejectsNonCanonicalRuntimeEnvFile(t *testing.T) {
	reg := sampleRegistry()
	e := reg.Components["melusina-store-sidecar"]
	e.RuntimeEnvFile = "/var/lib/melusina-update/runtime/../attacker.env"
	reg.Components[e.ComponentID] = e
	if err := reg.Validate(); err == nil {
		t.Fatal("Validate accepted a non-canonical runtimeEnvFile")
	}
}
