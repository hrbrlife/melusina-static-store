package componentrelease

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// signSkippingValidation signs doc exactly as Sign does but without
// validateUnsigned, standing in for a generation signed before this rule (or by
// a foreign producer). It lets a test prove Verify — the gate every serve path
// and host consumer runs — refuses such bytes on its own.
func signSkippingValidation(t *testing.T, op *identity.Private, doc DesiredGeneration) DesiredGeneration {
	t.Helper()
	doc.Schema = DesiredGenerationSchema
	doc.Components = sortedComponents(doc.Components)
	pub, err := op.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	doc.OperatorPubkey = primitives.EncodeBase58(pub)
	contentHash := GenerationContentHash(doc.Components)
	doc.GenerationHash = hex.EncodeToString(contentHash[:])
	doc.OperatorSignature = primitives.EncodeBase58(op.Sign(desiredGenerationMessage(doc, contentHash)))
	return doc
}

func componentByID(t *testing.T, doc *DesiredGeneration, id string) *ComponentRelease {
	t.Helper()
	for i := range doc.Components {
		if doc.Components[i].ComponentID == id {
			return &doc.Components[i]
		}
	}
	t.Fatalf("fixture has no component %q", id)
	return nil
}

func dataComponent(origin string) ComponentRelease {
	name := "opensanctions-20260924.tar.zst"
	return ComponentRelease{
		ComponentID:     "opensanctions-dataset",
		ComponentClass:  ClassData,
		Version:         "20260924",
		ArtifactName:    name,
		SHA256:          strings.Repeat("7", 64),
		SizeBytes:       4096,
		BundleURL:       origin + "/releases/data/" + name,
		PreviousSHA256:  strings.Repeat("8", 64),
		PreviousVersion: "20260923",
		Chain: ChainAuthority{
			Kind:          AuthorityInstallerRelease,
			Program:       "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb",
			MasterNftMint: "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe",
			ReleasePDA:    "FMRFyGPzrefaYiETSLTDw8fHqix8GVcGuri31qTZVtgY",
		},
	}
}

// TestGenerationRefusesBundleLocationTheInstallerRefuses covers seam-audit round
// 2 findings 11 and 12: the Store must not sign, and must not accept as
// verified, a component whose artifactName is not the escaped bundleUrl
// basename (the deployer's storegeneration rule), nor a host component whose
// bundleUrl is not exactly <origin>/releases/<componentClass>/<artifactName>
// (the path the release gate turns into X-Store-Release-Class).
func TestGenerationRefusesBundleLocationTheInstallerRefuses(t *testing.T) {
	op, pub := testOperator(t)
	const storeID = "melusina-os-root-store"
	origin := sampleGeneration().BundleOrigin

	// POSITIVE CONTROLS. The fixture (a sidecar and a shell, plus a data
	// component) signs and verifies, and the unvalidated signer produces bytes
	// Verify accepts — so every refusal below is the location rule alone.
	base := sampleGeneration()
	base.Components = append(base.Components, dataComponent(origin))
	signed, err := Sign(op, base)
	if err != nil {
		t.Fatalf("positive control: well-placed generation refused by Sign: %v", err)
	}
	if err := Verify(pub, storeID, signed); err != nil {
		t.Fatalf("positive control: well-placed generation refused by Verify: %v", err)
	}
	if err := Verify(pub, storeID, signSkippingValidation(t, op, base)); err != nil {
		t.Fatalf("positive control: the unvalidated signer does not produce verifiable bytes: %v", err)
	}

	shellName := componentByID(t, &base, "sandstorm-shell").ArtifactName
	sidecarName := componentByID(t, &base, "melusina-store-sidecar").ArtifactName
	cases := []struct {
		name   string
		id     string
		mutate func(c *ComponentRelease)
		want   error
	}{
		{"finding 11: shell artifactName is not the bundleUrl basename", "sandstorm-shell", func(c *ComponentRelease) {
			c.ArtifactName = "sandstorm-build-63.tar.xz"
		}, ErrArtifactNameNotBundleBasename},
		{"finding 12: shell staged under /releases/deployer/", "sandstorm-shell", func(c *ComponentRelease) {
			c.BundleURL = origin + "/releases/deployer/" + shellName
		}, ErrBundleURLNotReleasePath},
		{"sidecar served under the shell class segment", "melusina-store-sidecar", func(c *ComponentRelease) {
			c.BundleURL = origin + "/releases/shell/" + sidecarName
		}, ErrBundleURLNotReleasePath},
		{"data served under the shell class segment", "opensanctions-dataset", func(c *ComponentRelease) {
			c.BundleURL = origin + "/releases/shell/" + c.ArtifactName
		}, ErrBundleURLNotReleasePath},
		{"shell with no class segment", "sandstorm-shell", func(c *ComponentRelease) {
			c.BundleURL = origin + "/releases/" + shellName
		}, ErrBundleURLNotReleasePath},
		{"shell nested below its class segment", "sandstorm-shell", func(c *ComponentRelease) {
			c.BundleURL = origin + "/releases/shell/extra/" + shellName
		}, ErrBundleURLNotReleasePath},
		{"shell outside /releases/", "sandstorm-shell", func(c *ComponentRelease) {
			c.BundleURL = origin + "/packages/" + shellName
		}, ErrBundleURLNotReleasePath},
		{"shell bundleUrl with a query", "sandstorm-shell", func(c *ComponentRelease) {
			c.BundleURL = origin + "/releases/shell/" + shellName + "?v=2"
		}, ErrBundleURLNotReleasePath},
		{"shell bundleUrl with a fragment", "sandstorm-shell", func(c *ComponentRelease) {
			c.BundleURL = origin + "/releases/shell/" + shellName + "#x"
		}, ErrBundleURLNotReleasePath},
		{"artifactName whose escaped form differs (space)", "sandstorm-shell", func(c *ComponentRelease) {
			c.ArtifactName = "sandstorm 63.tar.xz"
			c.BundleURL = origin + "/releases/shell/sandstorm 63.tar.xz"
		}, ErrArtifactNameNotBundleBasename},
		{"percent-encoded artifactName names a different decoded file", "sandstorm-shell", func(c *ComponentRelease) {
			c.ArtifactName = "sandstorm%2D63.tar.xz"
			c.BundleURL = origin + "/releases/shell/sandstorm%2D63.tar.xz"
		}, ErrBundleURLNotReleasePath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := sampleGeneration()
			doc.Components = append(doc.Components, dataComponent(origin))
			tc.mutate(componentByID(t, &doc, tc.id))

			_, err := Sign(op, doc)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Sign: want %v, got %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), "component "+tc.id+":") {
				t.Fatalf("Sign refusal does not name component %s: %v", tc.id, err)
			}

			err = Verify(pub, storeID, signSkippingValidation(t, op, doc))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify of operator-signed bytes: want %v, got %v", tc.want, err)
			}
		})
	}
}

// TestValidateBundleLocationAppKeepsBasenameRuleOnly: an app entry (readable in
// history, never originated) keeps the deployer's basename rule and is exempt
// from the /releases/ shape, since apps were served from /packages/.
func TestValidateBundleLocationAppKeepsBasenameRuleOnly(t *testing.T) {
	const origin = "https://bazaar.melusina-os.org"
	app := ComponentRelease{
		ComponentID:    "some-app",
		ComponentClass: ClassApp,
		ArtifactName:   "0123456789abcdef0123456789abcdef",
		BundleURL:      origin + "/packages/0123456789abcdef0123456789abcdef",
	}
	if err := ValidateBundleLocation(origin, app); err != nil {
		t.Fatalf("positive control: historical app location refused: %v", err)
	}
	renamed := app
	renamed.ArtifactName = "some-app-1.0.0.spk"
	if err := ValidateBundleLocation(origin, renamed); !errors.Is(err, ErrArtifactNameNotBundleBasename) {
		t.Fatalf("app whose artifactName is not the bundleUrl basename: want %v, got %v", ErrArtifactNameNotBundleBasename, err)
	}
	unknown := app
	unknown.ComponentClass = "deployer"
	if err := ValidateBundleLocation(origin, unknown); err == nil || !strings.Contains(err.Error(), `invalid class "deployer"`) {
		t.Fatalf("unknown class must be refused by name, got %v", err)
	}
	// ReleaseBundleURL is the one construction the sidecar serve gate and this
	// rule share; a trailing slash on the origin must not double the separator.
	if got := ReleaseBundleURL(origin+"/", ClassShell, "x.tar.xz"); got != origin+"/releases/shell/x.tar.xz" {
		t.Fatalf("ReleaseBundleURL = %q", got)
	}
}
