package componentrelease

// The signed sidecar class (seam audit round 4, finding 6; STORE_FIRST_INSTALL
// spec, round-4 decision 1, Store commit 11). A sidecar component's chain.kind
// is the signed declaration of which chain rule gates it:
//
//   - sidecar_identity: key-bearing, the default; SidecarIdentityEntry plus the
//     five-fact cascade;
//   - sidecar_cascade: keyless, declared; the five-fact cascade alone with the
//     served sha256 pinned on Global and Local.
//
// These tests hold the structural half: the new kind is admitted for the
// sidecar class only, a keyless entry that names an identity is refused by
// name, an unknown kind is refused by name, and the kind is covered by the
// operator signature so it cannot be flipped after signing.

import (
	"errors"
	"strings"
	"testing"
)

func keylessSidecarComponent() ComponentRelease {
	return ComponentRelease{
		ComponentID:    "mermail",
		ComponentClass: ClassSidecar,
		Version:        "0.4.1",
		ArtifactName:   "mermail-0.4.1.tar.zst",
		SHA256:         "7b089c418d7fafa854630f329a5da4f9fe50dadf9a43f4bea477cc0e5e63c20f",
		SizeBytes:      4096,
		BundleURL:      "https://bazaar.melusina-os.org/releases/sidecar/mermail-0.4.1.tar.zst",
		Chain: ChainAuthority{
			Kind:              AuthoritySidecarCascade,
			Program:           "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
			LicenseNftMint:    "35csavs4vjGKt24cbQRzsAjjQxBL2QP9mQf6iShHFCmN",
			MasterNftMint:     "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe",
			SidecarID:         "mermail",
			GlobalApprovalPDA: "G1oba1Approva1PdaFor5tore5idecarXyz123456789",
			LocalApprovalPDA:  "Loca1Approva1PdaFor5tore5idecarAbc987654321",
		},
	}
}

func keylessGeneration() DesiredGeneration {
	doc := sampleGeneration()
	doc.PreviousGeneration = 0
	doc.GenerationID = 1
	for i := range doc.Components {
		doc.Components[i].PreviousSHA256 = ""
		doc.Components[i].PreviousVersion = ""
	}
	doc.Components = append(doc.Components, keylessSidecarComponent())
	return doc
}

func TestKeylessSidecarClassSignsAndVerifies(t *testing.T) {
	op, pub := testOperator(t)
	signed, err := Sign(op, keylessGeneration())
	if err != nil {
		t.Fatalf("keyless-sidecar-class-refused: a declared keyless sidecar with its two approval PDAs did not sign: %v", err)
	}
	if err := Verify(pub, "melusina-os-root-store", signed); err != nil {
		t.Fatalf("keyless-sidecar-class-refused: Verify: %v", err)
	}
	c, ok := signed.Component("mermail")
	if !ok || !IsKeylessSidecar(c) || !IsSidecarAuthority(c.Chain.Kind) {
		t.Fatalf("keyless-sidecar-class-lost: the signed generation does not carry mermail as a keyless sidecar: %+v", c)
	}
	// The key-bearing default is not keyless.
	if keyBearing, _ := signed.Component("melusina-store-sidecar"); IsKeylessSidecar(keyBearing) {
		t.Fatal("key-bearing-sidecar-read-as-keyless: sidecar_identity was classified keyless")
	}
}

// TestSidecarKindIsCoveredByTheOperatorSignature: flipping a signed sidecar's
// kind in either direction breaks the signature, so the class is the
// publisher's signed claim and nobody downstream can re-declare it.
func TestSidecarKindIsCoveredByTheOperatorSignature(t *testing.T) {
	op, pub := testOperator(t)
	signed, err := Sign(op, keylessGeneration())
	if err != nil {
		t.Fatal(err)
	}
	for i := range signed.Components {
		c := signed.Components[i]
		if !IsSidecarAuthority(c.Chain.Kind) {
			continue
		}
		flipped := signed
		flipped.Components = append([]ComponentRelease(nil), signed.Components...)
		if c.Chain.Kind == AuthoritySidecarCascade {
			flipped.Components[i].Chain.Kind = AuthoritySidecarIdentity
		} else {
			// The reverse flip must also drop the identity fields, or the
			// structural refusal (not the signature) would be what fails.
			flipped.Components[i].Chain.Kind = AuthoritySidecarCascade
			flipped.Components[i].Chain.IdentityPDA = ""
			flipped.Components[i].Chain.KeyVersion = 0
		}
		err := Verify(pub, "melusina-os-root-store", flipped)
		if err == nil {
			t.Fatalf("sidecar-kind-not-signed: component %s verified after its kind was flipped from %s", c.ComponentID, c.Chain.Kind)
		}
		// A sidecar_identity entry flipped to keyless keeps no IdentityPDA, so
		// it is still structurally valid: the refusal must be the signature's.
		if c.Chain.Kind == AuthoritySidecarIdentity && !strings.Contains(err.Error(), "content hash") {
			t.Fatalf("sidecar-kind-not-signed: the flip was refused for another reason: %v", err)
		}
	}
}

func TestKeylessSidecarNamingAnIdentityIsRefusedByName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ChainAuthority)
	}{
		{"identity_pda", func(ca *ChainAuthority) { ca.IdentityPDA = "H95UEaQMdoXk2s6y8kY6oYcU1r8Fq3aVqk6t6Z9y1abc" }},
		{"key_version", func(ca *ChainAuthority) { ca.KeyVersion = 1 }},
		// A key-bearing entry re-declared keyless: every identity field kept.
		{"key_bearing_entry_declared_keyless", func(ca *ChainAuthority) {
			ca.IdentityPDA = "H95UEaQMdoXk2s6y8kY6oYcU1r8Fq3aVqk6t6Z9y1abc"
			ca.KeyVersion = 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := keylessSidecarComponent()
			tc.mutate(&c.Chain)
			err := c.validate()
			if !errors.Is(err, ErrKeylessSidecarNamesIdentity) {
				t.Fatalf("keyless-sidecar-names-identity-accepted: err=%v", err)
			}
			if !strings.Contains(err.Error(), "keyless-sidecar-names-identity") {
				t.Fatalf("refusal does not carry its name: %v", err)
			}
		})
	}
}

// TestKeyBearingSidecarWithoutIdentityIsRefused is the reverse confusion: an
// entry that carries no identity but declares sidecar_identity is refused, so
// a keyless sidecar cannot be smuggled through the key-bearing kind with its
// identity fields left empty.
func TestKeyBearingSidecarWithoutIdentityIsRefused(t *testing.T) {
	c := keylessSidecarComponent()
	c.Chain.Kind = AuthoritySidecarIdentity
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "three-PDA cascade") {
		t.Fatalf("key-bearing-sidecar-without-identity-accepted: err=%v", err)
	}
}

func TestKeylessSidecarNeedsBothApprovalPDAsAndItsSeeds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ChainAuthority)
		want   string
	}{
		{"no_local_pda", func(ca *ChainAuthority) { ca.LocalApprovalPDA = "" }, "both required"},
		{"no_global_pda", func(ca *ChainAuthority) { ca.GlobalApprovalPDA = "" }, "both required"},
		{"no_license_mint", func(ca *ChainAuthority) { ca.LicenseNftMint = "" }, "empty licenseNftMint"},
		{"no_master_mint", func(ca *ChainAuthority) { ca.MasterNftMint = "" }, "empty masterNftMint"},
		{"unsafe_sidecar_id", func(ca *ChainAuthority) { ca.SidecarID = "../mermail" }, "not a safe identity token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := keylessSidecarComponent()
			tc.mutate(&c.Chain)
			if err := c.validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("keyless-sidecar-incomplete-accepted: want %q, err=%v", tc.want, err)
			}
		})
	}
}

func TestUnknownAuthorityKindIsRefusedByName(t *testing.T) {
	for _, kind := range []string{"", "sidecar_keyless", "keyless", "SIDECAR_CASCADE", "sidecar_identity "} {
		c := keylessSidecarComponent()
		c.Chain.Kind = kind
		err := c.validate()
		if !errors.Is(err, ErrUnknownAuthorityKind) {
			t.Fatalf("unknown-authority-kind-accepted: kind %q err=%v", kind, err)
		}
	}
}

func TestSidecarKindsBelongToTheSidecarClassOnly(t *testing.T) {
	for _, kind := range []string{AuthoritySidecarIdentity, AuthoritySidecarCascade} {
		if !classAdmitsAuthority(ClassSidecar, kind) {
			t.Fatalf("sidecar-class-refuses-sidecar-kind: %s", kind)
		}
		for _, class := range []string{ClassShell, ClassData, ClassApp, "", "sidecars"} {
			if classAdmitsAuthority(class, kind) {
				t.Fatalf("class-rides-sidecar-kind: class %q admits %s", class, kind)
			}
		}
	}
	// A shell that names the keyless sidecar kind with every sidecar field is
	// refused by the class rule, by name.
	c := keylessSidecarComponent()
	c.ComponentClass = ClassShell
	c.BundleURL = "https://bazaar.melusina-os.org/releases/shell/" + c.ArtifactName
	if err := c.validate(); !errors.Is(err, ErrClassAuthorityMismatch) {
		t.Fatalf("class-authority-mismatch-accepted: shell riding sidecar_cascade: %v", err)
	}
	// A sidecar that names installer_release is refused the same way.
	c = keylessSidecarComponent()
	c.Chain = ChainAuthority{Kind: AuthorityInstallerRelease, Program: c.Chain.Program, MasterNftMint: c.Chain.MasterNftMint, ReleasePDA: "FMRFyGPzrefaYiETSLTDw8fHqix8GVcGuri31qTZVtgY"}
	if err := c.validate(); !errors.Is(err, ErrClassAuthorityMismatch) {
		t.Fatalf("class-authority-mismatch-accepted: sidecar riding installer_release: %v", err)
	}
}
