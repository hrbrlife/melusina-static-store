package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// installerGateFixture is a controller chain gate bound to one estate profile
// and reading a real JSON-RPC server that serves exactly the given accounts.
type installerGateFixture struct {
	gate      *solanaChainGate
	cfg       ControllerConfig
	profile   releasetest.Profile
	hash      [32]byte
	pda       primitives.Pubkey
	component componentrelease.ComponentRelease
	accounts  map[string][]byte
}

func newInstallerGateFixture(t *testing.T, profile releasetest.Profile) *installerGateFixture {
	t.Helper()
	f := &installerGateFixture{profile: profile, accounts: map[string][]byte{}}
	f.cfg = estateBoundConfig(t, profile)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var req struct {
			Params []json.RawMessage `json:"params"`
		}
		var addr string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Params) == 0 || json.Unmarshal(req.Params[0], &addr) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var value any
		if data, ok := f.accounts[addr]; ok {
			value = map[string]any{"data": []string{base64.StdEncoding.EncodeToString(data), "base64"}, "owner": f.cfg.ProgramID}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"context": map[string]any{}, "value": value}})
	}))
	t.Cleanup(server.Close)
	f.cfg.SolanaRPCURL = server.URL
	g, err := newSolanaChainGate(f.cfg)
	if err != nil {
		t.Fatalf("construct chain gate: %v", err)
	}
	f.gate = g
	f.hash = sha256.Sum256([]byte("sandstorm-shell bundle bytes"))
	program := mustPubkey(t, f.cfg.ProgramID)
	master := mustPubkey(t, f.cfg.MasterNftMint)
	if f.pda, _, err = primitives.DeriveInstallerRelease(master, f.hash, program); err != nil {
		t.Fatal(err)
	}
	f.component = componentrelease.ComponentRelease{
		ComponentID:    "sandstorm-shell",
		ComponentClass: componentrelease.ClassShell,
		SHA256:         hex.EncodeToString(f.hash[:]),
		Chain: componentrelease.ChainAuthority{
			Kind:          componentrelease.AuthorityInstallerRelease,
			Program:       f.cfg.ProgramID,
			MasterNftMint: f.cfg.MasterNftMint,
			ReleasePDA:    f.pda.Base58(),
		},
	}
	return f
}

func (f *installerGateFixture) serve(account []byte) { f.accounts[f.pda.Base58()] = account }

func (f *installerGateFixture) run() error {
	return f.gate.gate(context.Background(), f.component, componentrelease.ComponentInstall{})
}

func newEstateProfile(t *testing.T) releasetest.Profile {
	t.Helper()
	return releasetest.LoadProfileVector(t, controllerProfileVectors, releasetest.NewEstateVector)
}

func requireGateRefusal(t *testing.T, err, want error) {
	t.Helper()
	if err == nil || !errors.Is(err, want) || !strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("got %v, want refusal %q", err, want)
	}
}

func TestInstallerReleaseGateAdmitsTheEstatesTrustedPublisher(t *testing.T) {
	f := newInstallerGateFixture(t, newEstateProfile(t))
	f.serve(releasetest.Encode(releasetest.Entry(t, f.profile.Profile, f.hash, "1.0.64", releasetest.TrustedPublisher())))
	if err := f.run(); err != nil {
		t.Fatalf("custodian-registered entry under a trusted publisher refused: %v", err)
	}
}

// The chain accepts this entry (the custodian registered it and the program
// verified this publisher's signature); the controller refuses it only
// because the estate profile does not name the key.
func TestInstallerReleaseGateRefusesAnUntrustedPublisher(t *testing.T) {
	f := newInstallerGateFixture(t, newEstateProfile(t))
	f.serve(releasetest.Encode(releasetest.Entry(t, f.profile.Profile, f.hash, "1.0.64", releasetest.UntrustedPublisher())))
	requireGateRefusal(t, f.run(), installerrelease.ErrPublisherUntrusted)
}

// The trusted set is the pinned profile's, not a compiled value: re-signing
// the profile to name the other key and pinning its digest flips both
// verdicts.
func TestInstallerReleaseGateTrustIsThePinnedProfilesReleaseTrust(t *testing.T) {
	moved := releasetest.WithPublishers(t, newEstateProfile(t), 1, releasetest.UntrustedPublisher())
	f := newInstallerGateFixture(t, moved)
	f.serve(releasetest.Encode(releasetest.Entry(t, f.profile.Profile, f.hash, "1.0.64", releasetest.UntrustedPublisher())))
	if err := f.run(); err != nil {
		t.Fatalf("key the pinned profile names was refused: %v", err)
	}
	f.serve(releasetest.Encode(releasetest.Entry(t, f.profile.Profile, f.hash, "1.0.64", releasetest.TrustedPublisher())))
	requireGateRefusal(t, f.run(), installerrelease.ErrPublisherUntrusted)
}

func TestInstallerReleaseGateRefusesAnEntryThatIsNotActive(t *testing.T) {
	for _, status := range []verify.AttestationStatus{verify.AttestationStatusRevoked, verify.AttestationStatusSuperseded} {
		t.Run(status.String(), func(t *testing.T) {
			f := newInstallerGateFixture(t, newEstateProfile(t))
			e := releasetest.Entry(t, f.profile.Profile, f.hash, "1.0.64", releasetest.TrustedPublisher())
			e.Status = status
			at := int64(1790000100)
			e.RevokedAt = &at
			f.serve(releasetest.Encode(e))
			requireGateRefusal(t, f.run(), installerrelease.ErrNotActive)
		})
	}
}

func TestInstallerReleaseGateRefusesAnythingButTheK3Layout(t *testing.T) {
	f := newInstallerGateFixture(t, newEstateProfile(t))
	e := releasetest.Entry(t, f.profile.Profile, f.hash, "1.0.64", releasetest.TrustedPublisher())
	// The pre-K3 account: same prefix through `status`, then revoked_at and
	// bump, 191 bytes. A prefix reader would call it Active and matching.
	legacy := releasetest.Encode(e)[:8+32+32+4+len(e.Version)+32+32+8+1]
	legacy = append(legacy, 0, e.Bump)
	legacy = append(legacy, make([]byte, 191-len(legacy))...)
	f.serve(legacy)
	err := f.run()
	requireGateRefusal(t, err, installerrelease.ErrMalformed)
	if !strings.Contains(err.Error(), "installer-release-entry-malformed:size") {
		t.Fatalf("pre-K3 account refused for the wrong reason: %v", err)
	}
	// Another account type at the address is refused by its discriminator.
	other := releasetest.Encode(e)
	binary.LittleEndian.PutUint64(other[:8], 0x0102030405060708)
	f.serve(other)
	if err := f.run(); err == nil || !strings.Contains(err.Error(), "installer-release-entry-malformed:discriminator") {
		t.Fatalf("foreign account type: %v", err)
	}
}

func TestInstallerReleaseGateRefusesAnAbsentEntry(t *testing.T) {
	f := newInstallerGateFixture(t, newEstateProfile(t))
	if err := f.run(); !errors.Is(err, verify.ErrPDANotFound) {
		t.Fatalf("absent entry: %v", err)
	}
}

func TestNewSolanaChainGateRefusesAConfigFromAnotherEstate(t *testing.T) {
	profile := newEstateProfile(t)
	other := releasetest.LoadProfileVector(t, controllerProfileVectors, "new-estate-revision-2-migrate")
	cases := []struct {
		name string
		edit func(*ControllerConfig)
		want string
	}{
		{"program is not the profile's", func(c *ControllerConfig) { c.ProgramID = randPubkeyB58(t) }, installerrelease.ErrEstateMismatch.Error() + ":programId"},
		{"master mint is not the profile's", func(c *ControllerConfig) { c.MasterNftMint = randPubkeyB58(t) }, installerrelease.ErrEstateMismatch.Error() + ":masterNftMint"},
		{"pin names another profile", func(c *ControllerConfig) { c.EstateProfileSha256 = other.SHA256 }, installerrelease.ErrProfile.Error()},
		{"profile file absent", func(c *ControllerConfig) { c.EstateProfilePath += ".absent" }, installerrelease.ErrProfile.Error()},
		{"no profile bound", func(c *ControllerConfig) { c.EstateProfilePath, c.EstateProfileSha256 = "", "" }, installerrelease.ErrProfile.Error()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := estateBoundConfig(t, profile)
			c.edit(&cfg)
			if _, err := newSolanaChainGate(cfg); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
	// Positive control: the unedited config constructs.
	if _, err := newSolanaChainGate(estateBoundConfig(t, profile)); err != nil {
		t.Fatalf("control: %v", err)
	}
}
