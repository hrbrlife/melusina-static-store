package releaseevidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/catalogselection"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/finalizationinput"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func selectedArtifactsFixture(t *testing.T) (SelectionTrust, Artifacts, time.Time) {
	t.Helper()
	now := time.Unix(1788900000, 0).UTC()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x58}, 32))
	trust := SelectionTrust{AppID: strings.Repeat("a", 52), Domain: "bazaar.example.test", OperatorPublicKey: key.Public().(ed25519.PublicKey)}
	a := Artifacts{SPK: []byte("synthetic package bytes; no SPK or Core authority asserted")}
	sha := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	spkSHA := sha(a.SPK)
	a.Metadata, _ = json.Marshal(map[string]any{"appId": trust.AppID, "version": "1.2.3", "packageId": spkSHA[:32], "sha256": spkSHA, "title": "Original title"})
	appHash, err := apphash.Canonical(bytes.NewReader(a.SPK), a.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	a.RuntimeContract, _ = json.Marshal(runtimecontract.Contract{SchemaURL: runtimecontract.SchemaURL, Schema: runtimecontract.Schema, App: runtimecontract.App{AppID: trust.AppID, Version: "1.2.3", SPKSHA256: spkSHA, AppHash: appHash}, Sidecars: []runtimecontract.Sidecar{}, LaunchProbe: runtimecontract.VisibleProbe{Kind: "visible-ui", Steps: []runtimecontract.ProbeStep{{Action: "Open the normal app screen.", ExpectedResult: "The app screen renders."}}, ExpectedResult: "The app opens."}, Fixtures: []runtimecontract.Fixture{}, Cleanup: runtimecontract.Cleanup{Steps: []string{"No test data retained."}}})
	r := ReleaseClaims{Schema: "melusina-release-v1", AppHash: appHash, Version: "1.2.3", ReleaseNonce: "fixture-nonce", SignedAtUnix: now.Add(-time.Hour).Unix(), MasterNftMint: "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe", LicenseSquadsVault: "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3", ReleaseEntryPDA: "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe", AuthorSig: base64.StdEncoding.EncodeToString(make([]byte, 64)), QuorumPolicy: finalizationinput.ReleaseQuorum{Threshold: 3, MemberCount: 4, MultisigPDA: "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V"}, RuntimeContractSHA256: sha(a.RuntimeContract), RuntimeContractSchema: runtimecontract.Schema}
	r.ReleaseHash = sha([]byte(r.AppHash + r.Version + r.ReleaseNonce))
	a.Release, _ = json.MarshalIndent(r, "", "  ")
	a.Index = []byte(`{"apps":[{"appId":"` + trust.AppID + `","packageId":"` + spkSHA[:32] + `","title":"Original title"}]}`)
	domain := primitives.StoreDomainHash(trust.Domain)
	p := catalogselection.Pointer{Schema: catalogselection.Schema, AppID: trust.AppID, PackageID: spkSHA[:32], Version: r.Version, AppHash: r.AppHash, ReleaseHash: r.ReleaseHash, StageID: strings.Repeat("e", 64), CatalogSHA256: sha(a.Index), ServingDomainHash: hex.EncodeToString(domain[:]), PublishedAt: now.Add(-time.Minute).Unix()}
	message, err := catalogselection.Message(p)
	if err != nil {
		t.Fatal(err)
	}
	p.OperatorSignature = primitives.EncodeBase58(ed25519.Sign(key, message))
	a.Pointer, _ = json.MarshalIndent(p, "", "  ")
	return trust, a, now
}

func TestSelectedArtifactsOriginalTupleAndRefusals(t *testing.T) {
	trust, original, now := selectedArtifactsFixture(t)
	before, _ := json.Marshal(original)
	selected, err := VerifySelectedArtifacts(trust, original, now)
	if err != nil || selected.Pointer.AppID != trust.AppID || selected.Release.RuntimeContractSHA256 == "" {
		t.Fatalf("selected tuple: %v", err)
	}
	after, _ := json.Marshal(original)
	if !bytes.Equal(before, after) {
		t.Fatal("original artifacts changed")
	}
	for name, edit := range map[string]func(*SelectionTrust, *Artifacts, *time.Time){
		"foreign operator":             func(c *SelectionTrust, _ *Artifacts, _ *time.Time) { c.OperatorPublicKey = bytes.Repeat([]byte{1}, 32) },
		"missing independent operator": func(c *SelectionTrust, _ *Artifacts, _ *time.Time) { c.OperatorPublicKey = nil },
		"foreign Store domain":         func(c *SelectionTrust, _ *Artifacts, _ *time.Time) { c.Domain = "other.example.test" },
		"foreign app":                  func(c *SelectionTrust, _ *Artifacts, _ *time.Time) { c.AppID = strings.Repeat("b", 52) },
		"future pointer":               func(_ *SelectionTrust, _ *Artifacts, n *time.Time) { *n = n.Add(-time.Hour) },
		"changed exact index":          func(_ *SelectionTrust, a *Artifacts, _ *time.Time) { a.Index = append(bytes.Clone(a.Index), ' ') },
		"changed exact SPK":            func(_ *SelectionTrust, a *Artifacts, _ *time.Time) { a.SPK = append(bytes.Clone(a.SPK), '!') },
		"changed metadata":             func(_ *SelectionTrust, a *Artifacts, _ *time.Time) { a.Metadata = append(bytes.Clone(a.Metadata), ' ') },
		"changed runtime": func(_ *SelectionTrust, a *Artifacts, _ *time.Time) {
			a.RuntimeContract = append(bytes.Clone(a.RuntimeContract), ' ')
		},
		"missing runtime": func(_ *SelectionTrust, a *Artifacts, _ *time.Time) { a.RuntimeContract = nil },
		"pointer duplicate": func(_ *SelectionTrust, a *Artifacts, _ *time.Time) {
			a.Pointer = bytes.Replace(a.Pointer, []byte("{"), []byte(`{"schema":"melusina-app-catalog-pointer-v1",`), 1)
		},
		"pointer alias": func(_ *SelectionTrust, a *Artifacts, _ *time.Time) {
			a.Pointer = bytes.Replace(a.Pointer, []byte(`"appId"`), []byte(`"APPID"`), 1)
		},
		"asserted source": func(_ *SelectionTrust, a *Artifacts, _ *time.Time) {
			a.Release = bytes.Replace(a.Release, []byte("{"), []byte(`{"sourceBaselineAuthenticated":true,`), 1)
		},
		"unknown release schema": func(_ *SelectionTrust, a *Artifacts, _ *time.Time) {
			a.Release = bytes.Replace(a.Release, []byte("melusina-release-v1"), []byte("melusina-release-v2"), 1)
		},
		"oversize pointer": func(_ *SelectionTrust, a *Artifacts, _ *time.Time) { a.Pointer = make([]byte, (1<<20)+1) },
		"oversize SPK":     func(_ *SelectionTrust, a *Artifacts, _ *time.Time) { a.SPK = make([]byte, (64<<20)+1) },
	} {
		t.Run(name, func(t *testing.T) {
			c, a, n := trust, original, now
			edit(&c, &a, &n)
			if _, err := VerifySelectedArtifacts(c, a, n); err == nil {
				t.Fatal("untrusted selected tuple accepted")
			}
		})
	}
}
