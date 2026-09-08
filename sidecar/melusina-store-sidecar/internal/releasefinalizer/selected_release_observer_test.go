package releasefinalizer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/finalizationinput"
)

func (f *observerFixture) selectedRelease(t *testing.T) []byte {
	t.Helper()
	var ceremony struct {
		ReleaseNonce string `json:"releaseNonce"`
	}
	if err := json.Unmarshal(f.sdk.Ceremony, &ceremony); err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(finalizationinput.ReleaseClaims{Schema: "melusina-release-v1", AppHash: f.want.AppHash, ReleaseHash: f.want.Release, Version: f.want.Version, SignedAtUnix: f.sdk.Now, MasterNftMint: f.sdk.Pins.Master, LicenseSquadsVault: f.sdk.Pins.Vault, ReleaseEntryPDA: f.sdk.Release.Address, AuthorSig: f.sdk.AuthorSignatureBase64, QuorumPolicy: finalizationinput.ReleaseQuorum{Threshold: 3, MemberCount: 4, MultisigPDA: f.sdk.Pins.Multisig}, ReleaseNonce: ceremony.ReleaseNonce}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func TestSelectedReleaseAdapterObservesOriginalSDKExecutionAndRetries(t *testing.T) {
	f := newObserverFixture(t)
	original := f.selectedRelease(t)
	before := bytes.Clone(original)
	observed, err := f.o.ObserveSelectedRelease(t.Context(), f.want.AppID, f.want.StageID, f.want.Reference, original)
	if err != nil {
		t.Fatal(err)
	}
	if observed.State != ProposalExecuted || observed.Digest != f.want.Digest || observed.Reference != f.want.Reference || observed.AppHash != f.want.AppHash || observed.Release != f.want.Release || observed.RegisteredAt.Unix() != f.sdk.Now || observed.AuthorSignatureBase64 != f.sdk.AuthorSignatureBase64 || f.calls != 3 {
		t.Fatalf("selected execution differs: %#v calls=%d", observed, f.calls)
	}
	if !bytes.Equal(original, before) {
		t.Fatal("selected adapter rewrote original RELEASE bytes")
	}
	again, err := f.o.ObserveSelectedRelease(t.Context(), f.want.AppID, f.want.StageID, f.want.Reference, original)
	if err != nil || again != observed || f.calls != 6 {
		t.Fatal("selected retry did not independently reobserve exact original execution")
	}
	f.accounts[3].Data[len(f.accounts[3].Data)-3] = 1
	if _, err := f.o.ObserveSelectedRelease(t.Context(), f.want.AppID, f.want.StageID, f.want.Reference, original); err == nil {
		t.Fatal("selected adapter cached a subsequently revoked registration")
	}
}

func TestSelectedReleaseAdapterRefusesOriginalDescriptorAndScopeDrift(t *testing.T) {
	for name, mutate := range map[string]func(*finalizationinput.ReleaseClaims){
		"author signature": func(r *finalizationinput.ReleaseClaims) {
			r.AuthorSig = base64.StdEncoding.EncodeToString(make([]byte, 64))
		},
		"claimed registration time": func(r *finalizationinput.ReleaseClaims) { r.SignedAtUnix-- },
		"other registered PDA":      func(r *finalizationinput.ReleaseClaims) { r.ReleaseEntryPDA = coreReleasePublisher },
		"release nonce":             func(r *finalizationinput.ReleaseClaims) { r.ReleaseNonce = "different-nonce" },
		"other master":              func(r *finalizationinput.ReleaseClaims) { r.MasterNftMint = coreReleaseMaster },
		"different quorum":          func(r *finalizationinput.ReleaseClaims) { r.QuorumPolicy.Threshold = 2 },
		"unknown schema":            func(r *finalizationinput.ReleaseClaims) { r.Schema = "melusina-release-v2" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newObserverFixture(t)
			var claims finalizationinput.ReleaseClaims
			if json.Unmarshal(f.selectedRelease(t), &claims) != nil {
				t.Fatal("fixture")
			}
			mutate(&claims)
			raw, _ := json.Marshal(claims)
			if _, err := f.o.ObserveSelectedRelease(t.Context(), f.want.AppID, f.want.StageID, f.want.Reference, raw); err == nil {
				t.Fatal("selected descriptor drift accepted")
			}
		})
	}
	for name, edit := range map[string]func([]byte) []byte{
		"duplicate": func(b []byte) []byte {
			return bytes.Replace(b, []byte("{"), []byte(`{"$schema":"melusina-release-v1",`), 1)
		},
		"alias":            func(b []byte) []byte { return bytes.Replace(b, []byte(`"appHash"`), []byte(`"APPHASH"`), 1) },
		"source assertion": func(b []byte) []byte { return bytes.Replace(b, []byte("{"), []byte(`{"sourceCommit":"untrusted",`), 1) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newObserverFixture(t)
			if _, err := f.o.ObserveSelectedRelease(t.Context(), f.want.AppID, f.want.StageID, f.want.Reference, edit(f.selectedRelease(t))); err == nil || f.calls != 0 {
				t.Fatal("ambiguous descriptor reached chain observation")
			}
		})
	}
	f := newObserverFixture(t)
	if _, err := f.o.ObserveSelectedRelease(t.Context(), strings.Repeat("b", 52), f.want.StageID, f.want.Reference, f.selectedRelease(t)); err == nil {
		t.Fatal("foreign app borrowed selected release authority")
	}
	if _, err := f.o.ObserveSelectedRelease(t.Context(), f.want.AppID, f.want.StageID, f.want.Reference+"/other", f.selectedRelease(t)); err == nil {
		t.Fatal("noncanonical proposal locator accepted")
	}
}

func TestSelectedReleaseAdapterCannotTreatPreparedOrPendingAsExecuted(t *testing.T) {
	f := newObserverFixture(t)
	if _, err := f.o.ObserveSelectedRelease(t.Context(), f.want.AppID, f.want.StageID, f.want.Reference, f.sdk.Ceremony); err == nil || f.calls != 0 {
		t.Fatal("dry-run ceremony substituted for original final RELEASE")
	}
	original := f.selectedRelease(t)
	f.accounts[2] = f.account(f.sdk.PendingProposal)
	f.accounts[3].Data = nil
	if _, err := f.o.ObserveSelectedRelease(t.Context(), f.want.AppID, f.want.StageID, f.want.Reference, original); err == nil {
		t.Fatal("pending proposal substituted for execution")
	}
}
