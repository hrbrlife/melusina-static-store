package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The chain half of this command is proven live (an Active InstallerReleaseEntry
// for the installed controller; refusals for an unauthorized artifact, for a
// sidecar binary whose authority class is sidecar_identity rather than
// installer_release, and for a symlink). These cover the offline refusals, which
// must fail BEFORE any network call so a malformed ceremony never touches RPC.
func TestRunRefusesRelativePaths(t *testing.T) {
	if err := run("etc/config.json", "/abs/artifact"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative config accepted: %v", err)
	}
	if err := run("/etc/config.json", "artifact"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative artifact accepted: %v", err)
	}
}

func TestRunRefusesConfigMissingChainPins(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	// a syntactically valid controller config that omits the pins this ceremony
	// needs must refuse by name, never fall back to a default program or RPC.
	if err := os.WriteFile(cfg, []byte(`{"schema":"melusina-update-controller-config-v1","autoApply":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	art := filepath.Join(dir, "artifact")
	if err := os.WriteFile(art, []byte("bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := run(cfg, art)
	if err == nil || !strings.Contains(err.Error(), "masterNftMint") {
		t.Fatalf("config without chain pins accepted: %v", err)
	}
}

func TestHashNoFollowRefusesSymlinkAndDirectory(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("controller"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hashNoFollow(link); err == nil {
		t.Fatal("symlinked artifact accepted — the ceremony could attest to bytes other than those installed")
	}
	if _, _, err := hashNoFollow(dir); err == nil {
		t.Fatal("directory accepted as an artifact")
	}
	sum, size, err := hashNoFollow(real)
	if err != nil {
		t.Fatalf("regular file rejected: %v", err)
	}
	if size != int64(len("controller")) || sum == [32]byte{} {
		t.Fatalf("unexpected hash result: size=%d sum=%x", size, sum)
	}
}

// ── the chain half, against a JSON-RPC server that serves exact accounts ──

type ceremonyFixture struct {
	config, artifact string
	profile          releasetest.Profile
	hash             [32]byte
	pda              string
	accounts         map[string][]byte
}

func newCeremonyFixture(t *testing.T) *ceremonyFixture {
	t.Helper()
	f := &ceremonyFixture{accounts: map[string][]byte{}}
	f.profile = releasetest.LoadProfileVector(t, "../../testdata/estate-profile-vectors.json", releasetest.NewEstateVector)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Params []json.RawMessage `json:"params"`
		}
		var addr string
		if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Params) == 0 || json.Unmarshal(req.Params[0], &addr) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var value any
		if data, ok := f.accounts[addr]; ok {
			value = map[string]any{"data": []string{base64.StdEncoding.EncodeToString(data), "base64"}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"context": map[string]any{}, "value": value}})
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	f.artifact = filepath.Join(dir, "melusina-update-controller")
	if err := os.WriteFile(f.artifact, []byte("controller artifact bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.hash = sha256.Sum256([]byte("controller artifact bytes"))
	program := releasetest.ProgramID(t, f.profile.Profile)
	master, _ := primitives.PubkeyFromBase58(f.profile.Profile.Anchors.MasterMint)
	programKey, _ := primitives.PubkeyFromBase58(program)
	pda, _, err := primitives.DeriveInstallerRelease(master, f.hash, programKey)
	if err != nil {
		t.Fatal(err)
	}
	f.pda = pda.Base58()
	body, _ := json.Marshal(map[string]any{
		"schema": "melusina-update-controller-config-v1", "programId": program,
		"masterNftMint": f.profile.Profile.Anchors.MasterMint, "solanaRpcUrl": server.URL,
		"estateProfilePath": releasetest.Write(t, f.profile), "estateProfileSha256": f.profile.SHA256,
	})
	f.config = filepath.Join(dir, "config.json")
	if err := os.WriteFile(f.config, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRunAdmitsOnlyATrustedActiveEntry(t *testing.T) {
	f := newCeremonyFixture(t)
	if err := run(f.config, f.artifact); err == nil || !errors.Is(err, verify.ErrPDANotFound) {
		t.Fatalf("absent entry: %v", err)
	}
	f.accounts[f.pda] = releasetest.Encode(releasetest.Entry(t, f.profile.Profile, f.hash, "1.0.60", releasetest.TrustedPublisher()))
	if err := run(f.config, f.artifact); err != nil {
		t.Fatalf("trusted Active entry refused: %v", err)
	}
	f.accounts[f.pda] = releasetest.Encode(releasetest.Entry(t, f.profile.Profile, f.hash, "1.0.60", releasetest.UntrustedPublisher()))
	if err := run(f.config, f.artifact); !errors.Is(err, installerrelease.ErrPublisherUntrusted) {
		t.Fatalf("untrusted publisher: %v", err)
	}
	superseded := releasetest.Entry(t, f.profile.Profile, f.hash, "1.0.60", releasetest.TrustedPublisher())
	superseded.Status = verify.AttestationStatusSuperseded
	at := int64(1790000200)
	superseded.RevokedAt = &at
	f.accounts[f.pda] = releasetest.Encode(superseded)
	if err := run(f.config, f.artifact); !errors.Is(err, installerrelease.ErrNotActive) {
		t.Fatalf("superseded entry: %v", err)
	}
}

func TestRunRefusesAConfigWithoutTheEstateProfilePin(t *testing.T) {
	f := newCeremonyFixture(t)
	raw, _ := os.ReadFile(f.config)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	delete(m, "estateProfileSha256")
	raw, _ = json.Marshal(m)
	if err := os.WriteFile(f.config, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(f.config, f.artifact); err == nil || !strings.Contains(err.Error(), "estateProfileSha256") {
		t.Fatalf("config without the profile pin: %v", err)
	}
}
