package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
	"github.com/hrbrlife/melusina-store-sidecar/internal/storesecurity"
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

// ── the chain half, against a pinned TLS JSON-RPC server that serves exact accounts ──

// rpcFixture is one JSON-RPC endpoint: the genesis it reports, the accounts
// it serves with their owners, and how many requests of each method reached it.
type rpcFixture struct {
	mu       sync.Mutex
	genesis  string
	accounts map[string][]byte
	owners   map[string]string
	program  string
	calls    map[string]int
}

func (r *rpcFixture) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var request struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(req.Body).Decode(&request) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls[request.Method]++
		switch request.Method {
		case "getGenesisHash":
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": r.genesis})
		case "getAccountInfo":
			var addr string
			if len(request.Params) == 0 || json.Unmarshal(request.Params[0], &addr) != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			var value any
			if data, ok := r.accounts[addr]; ok {
				owner, named := r.owners[addr]
				if !named {
					owner = r.program
				}
				value = map[string]any{"data": []string{base64.StdEncoding.EncodeToString(data), "base64"}, "owner": owner}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"context": map[string]any{}, "value": value}})
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
		}
	})
}

func (r *rpcFixture) count(method string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[method]
}

func (r *rpcFixture) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := 0
	for _, n := range r.calls {
		total += n
	}
	return total
}

type ceremonyFixture struct {
	dir, config, artifact, factsPath string
	profile                          releasetest.Profile
	program                          string
	hash                             [32]byte
	pda                              string
	rpc                              *rpcFixture
	server                           *httptest.Server
	facts                            signedStoreHostFacts
	configFields                     map[string]any
}

// spkiPin is the owner-signed pin of the certificate a test server presents.
func spkiPin(server *httptest.Server) string {
	sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	return spkiPinPrefix + hex.EncodeToString(sum[:])
}

func newCeremonyFixture(t *testing.T) *ceremonyFixture {
	t.Helper()
	f := &ceremonyFixture{dir: t.TempDir(), configFields: map[string]any{}}
	f.profile = releasetest.LoadProfileVector(t, "../../testdata/estate-profile-vectors.json", releasetest.NewEstateVector)
	f.program = releasetest.ProgramID(t, f.profile.Profile)
	f.rpc = &rpcFixture{genesis: f.profile.Profile.Network.GenesisHash, accounts: map[string][]byte{},
		owners: map[string]string{}, program: f.program, calls: map[string]int{}}
	f.server = httptest.NewTLSServer(f.rpc.handler())
	t.Cleanup(f.server.Close)
	f.artifact = filepath.Join(f.dir, "melusina-update-controller")
	if err := os.WriteFile(f.artifact, []byte("controller artifact bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.hash = sha256.Sum256([]byte("controller artifact bytes"))
	master, _ := primitives.PubkeyFromBase58(f.profile.Profile.Anchors.MasterMint)
	programKey, _ := primitives.PubkeyFromBase58(f.program)
	pda, _, err := primitives.DeriveInstallerRelease(master, f.hash, programKey)
	if err != nil {
		t.Fatal(err)
	}
	f.pda = pda.Base58()
	f.facts = signedStoreHostFacts{Schema: storeHostFactsSchema,
		LicenseNFTMint: "G7yFvXK6AuBHzybrVbmNbQ8P8JGFCoHbgfaBXQ22DT5E", LicenseRegistryProgramID: f.program,
		ChainID: "solana:" + f.profile.Profile.Network.Label, OperatorDomain: f.profile.Profile.Store.RootDomain,
		RPCURL: f.server.URL, RPCAttempts: 2, RPCTLSSPKIPins: []string{spkiPin(f.server)},
		SecurityProfile: storesecurity.Profile{Schema: storesecurity.Schema, EstateProfileSHA256: f.profile.SHA256,
			StoreID: f.profile.Profile.Store.StoreID, ControlListenAddr: "10.77.0.2:9443",
			StoreLinkClientCertSHA256: strings.Repeat("c", 64), ScannerEd25519PublicKey: strings.Repeat("d", 64),
			Signatures: []estateprofile.SignatureV1{}},
		ControlTLSBundlePath: "/var/lib/melusina-first-store/enrolled-f0/control-tls-bundle.json"}
	f.factsPath = f.writeFacts(t, "facts.json", f.ownerSigned(t, f.facts, "owner-a", "owner-b"))
	f.configFields = map[string]any{
		"schema": "melusina-update-controller-config-v1", "programId": f.program,
		"masterNftMint":     f.profile.Profile.Anchors.MasterMint,
		"estateProfilePath": releasetest.Write(t, f.profile), "estateProfileSha256": f.profile.SHA256,
		"storeHostFactsPath": f.factsPath,
	}
	f.writeConfig(t)
	return f
}

// ownerSigned signs facts' digest with the named owners of the vector
// profile's owner policy, in keyId order.
func (f *ceremonyFixture) ownerSigned(t *testing.T, facts signedStoreHostFacts, owners ...string) signedStoreHostFacts {
	t.Helper()
	digest, err := storeHostFactsDigest(facts)
	if err != nil {
		t.Fatal(err)
	}
	facts.Signatures = nil
	for _, keyID := range owners {
		key := releasetest.VectorKey(f.profile.Profile.OwnerPolicy.PolicyID + "/" + keyID)
		facts.Signatures = append(facts.Signatures, estateprofile.SignatureV1{KeyID: keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(digest)))})
	}
	return facts
}

func (f *ceremonyFixture) writeFacts(t *testing.T, name string, facts signedStoreHostFacts) string {
	t.Helper()
	raw, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (f *ceremonyFixture) writeConfig(t *testing.T) {
	t.Helper()
	body, err := json.Marshal(f.configFields)
	if err != nil {
		t.Fatal(err)
	}
	f.config = filepath.Join(f.dir, "config.json")
	if err := os.WriteFile(f.config, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// useFacts points the config at an owner-signed (or deliberately unsigned)
// facts document.
func (f *ceremonyFixture) useFacts(t *testing.T, name string, facts signedStoreHostFacts) {
	t.Helper()
	f.configFields["storeHostFactsPath"] = f.writeFacts(t, name, facts)
	f.writeConfig(t)
}

func (f *ceremonyFixture) setEntry(entry installerrelease.Entry) {
	f.rpc.mu.Lock()
	defer f.rpc.mu.Unlock()
	f.rpc.accounts[f.pda] = releasetest.Encode(entry)
}

func (f *ceremonyFixture) trustEntry(t *testing.T) {
	t.Helper()
	f.setEntry(releasetest.Entry(t, f.profile.Profile, f.hash, "1.0.60", releasetest.TrustedPublisher()))
}

func TestRunAdmitsOnlyATrustedActiveEntry(t *testing.T) {
	f := newCeremonyFixture(t)
	if err := run(f.config, f.artifact); err == nil || !errors.Is(err, verify.ErrPDANotFound) {
		t.Fatalf("absent entry: %v", err)
	}
	f.trustEntry(t)
	if err := run(f.config, f.artifact); err != nil {
		t.Fatalf("RPC_PINNED_ENDPOINT_REFUSED: trusted Active entry over the owner-pinned endpoint refused: %v", err)
	}
	if f.rpc.count("getGenesisHash") == 0 {
		t.Fatal("RPC_GENESIS_NOT_READ: the entry was admitted without reading the cluster genesis")
	}
	f.setEntry(releasetest.Entry(t, f.profile.Profile, f.hash, "1.0.60", releasetest.UntrustedPublisher()))
	if err := run(f.config, f.artifact); !errors.Is(err, installerrelease.ErrPublisherUntrusted) {
		t.Fatalf("untrusted publisher: %v", err)
	}
	superseded := releasetest.Entry(t, f.profile.Profile, f.hash, "1.0.60", releasetest.TrustedPublisher())
	superseded.Status = verify.AttestationStatusSuperseded
	at := int64(1790000200)
	superseded.RevokedAt = &at
	f.setEntry(superseded)
	if err := run(f.config, f.artifact); !errors.Is(err, installerrelease.ErrNotActive) {
		t.Fatalf("superseded entry: %v", err)
	}
}

func TestRunRefusesAConfigWithoutTheEstateProfilePin(t *testing.T) {
	f := newCeremonyFixture(t)
	delete(f.configFields, "estateProfileSha256")
	f.writeConfig(t)
	if err := run(f.config, f.artifact); err == nil || !strings.Contains(err.Error(), "estateProfileSha256") {
		t.Fatalf("config without the profile pin: %v", err)
	}
}

// The RPC endpoint comes only from the owner-signed facts. Every refusal
// below happens before any request reaches an endpoint; the positive control
// (a trusted entry, the signed facts, the signed URL repeated in the config)
// proves the fixture would otherwise be admitted.
func TestRunTakesTheEndpointOnlyFromTheOwnerSignedFacts(t *testing.T) {
	f := newCeremonyFixture(t)
	f.trustEntry(t)
	f.configFields["solanaRpcUrl"] = f.server.URL
	f.writeConfig(t)
	if err := run(f.config, f.artifact); err != nil {
		t.Fatalf("RPC_SIGNED_ENDPOINT_REPEATED_IN_CONFIG_REFUSED: %v", err)
	}

	// A plaintext endpoint that would serve every right answer: only the
	// https requirement stands between it and an admitted entry.
	f.rpc.mu.Lock()
	plain := &rpcFixture{genesis: f.rpc.genesis, accounts: map[string][]byte{f.pda: f.rpc.accounts[f.pda]},
		owners: map[string]string{}, program: f.program, calls: map[string]int{}}
	f.rpc.mu.Unlock()
	plainServer := httptest.NewServer(plain.handler())
	t.Cleanup(plainServer.Close)

	other := httptest.NewTLSServer(f.rpc.handler())
	t.Cleanup(other.Close)

	cases := []struct {
		name   string
		mutate func(t *testing.T)
		want   error
	}{
		{"RPC_PLAINTEXT_ENDPOINT_ACCEPTED", func(t *testing.T) {
			facts := f.facts
			facts.RPCURL = plainServer.URL
			f.useFacts(t, "plain.json", f.ownerSigned(t, facts, "owner-a", "owner-b"))
		}, errRPCNotHTTPS},
		{"RPC_CONFIG_ENDPOINT_ACCEPTED", func(t *testing.T) {
			f.configFields["solanaRpcUrl"] = other.URL
			f.writeConfig(t)
		}, errRPCEndpointUnsigned},
		{"RPC_CONFIG_PLAINTEXT_ENDPOINT_ACCEPTED", func(t *testing.T) {
			f.configFields["solanaRpcUrl"] = plainServer.URL
			f.writeConfig(t)
		}, errRPCEndpointUnsigned},
		{"RPC_TRUST_ABSENT_ACCEPTED", func(t *testing.T) {
			delete(f.configFields, "storeHostFactsPath")
			f.writeConfig(t)
		}, errRPCTrustAbsent},
		{"RPC_TRUST_RELATIVE_PATH_ACCEPTED", func(t *testing.T) {
			f.configFields["storeHostFactsPath"] = "facts.json"
			f.writeConfig(t)
		}, errRPCTrustAbsent},
		{"RPC_TRUST_UNSIGNED_ACCEPTED", func(t *testing.T) {
			f.useFacts(t, "unsigned.json", f.facts)
		}, errRPCTrustUnsigned},
		{"RPC_TRUST_SUBTHRESHOLD_ACCEPTED", func(t *testing.T) {
			f.useFacts(t, "one-owner.json", f.ownerSigned(t, f.facts, "owner-a"))
		}, errRPCTrustUnsigned},
		{"RPC_TRUST_TAMPERED_ACCEPTED", func(t *testing.T) {
			tampered := f.ownerSigned(t, f.facts, "owner-a", "owner-b")
			tampered.RPCURL = other.URL
			f.useFacts(t, "tampered.json", tampered)
		}, errRPCTrustUnsigned},
		{"RPC_TRUST_FOREIGN_PROFILE_ACCEPTED", func(t *testing.T) {
			facts := f.facts
			facts.SecurityProfile.EstateProfileSHA256 = strings.Repeat("e", 64)
			f.useFacts(t, "foreign-profile.json", f.ownerSigned(t, facts, "owner-a", "owner-b"))
		}, errRPCTrustForeign},
		{"RPC_TRUST_FOREIGN_REGISTRY_ACCEPTED", func(t *testing.T) {
			facts := f.facts
			facts.LicenseRegistryProgramID = "CydR6d4QUsWGwVaRVYXTebJSKHb8nYn3R8WqC6GJjAR5"
			f.useFacts(t, "foreign-registry.json", f.ownerSigned(t, facts, "owner-a", "owner-b"))
		}, errRPCTrustForeign},
		{"RPC_TRUST_FOREIGN_NETWORK_ACCEPTED", func(t *testing.T) {
			facts := f.facts
			facts.ChainID = "solana:other-network"
			f.useFacts(t, "foreign-network.json", f.ownerSigned(t, facts, "owner-a", "owner-b"))
		}, errRPCTrustForeign},
		{"RPC_TLS_PIN_ABSENT_ACCEPTED", func(t *testing.T) {
			facts := f.facts
			facts.RPCTLSSPKIPins = nil
			f.useFacts(t, "no-pin.json", f.ownerSigned(t, facts, "owner-a", "owner-b"))
		}, errRPCTLSPinAbsent},
		{"RPC_TLS_PIN_MALFORMED_ACCEPTED", func(t *testing.T) {
			facts := f.facts
			facts.RPCTLSSPKIPins = []string{"sha256:" + strings.Repeat("a", 64)}
			f.useFacts(t, "bad-pin.json", f.ownerSigned(t, facts, "owner-a", "owner-b"))
		}, errRPCTLSPinAbsent},
		{"RPC_TLS_PIN_DUPLICATED_ACCEPTED", func(t *testing.T) {
			facts := f.facts
			facts.RPCTLSSPKIPins = []string{spkiPin(f.server), spkiPin(f.server)}
			f.useFacts(t, "dup-pin.json", f.ownerSigned(t, facts, "owner-a", "owner-b"))
		}, errRPCTLSPinAbsent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			saved := map[string]any{}
			for key, value := range f.configFields {
				saved[key] = value
			}
			defer func() {
				f.configFields = saved
				f.writeConfig(t)
			}()
			c.mutate(t)
			// f.rpc counts both the signed server and other (they share it).
			before, plainBefore := f.rpc.total(), plain.total()
			err := run(f.config, f.artifact)
			if !errors.Is(err, c.want) || !strings.HasPrefix(err.Error(), c.want.Error()) {
				t.Fatalf("%s: want %v, got %v", c.name, c.want, err)
			}
			if f.rpc.total() != before || plain.total() != plainBefore {
				t.Fatalf("%s_CONTACTED_AN_ENDPOINT: a refused ceremony reached RPC", c.name)
			}
		})
	}
}

// TLS trust is the owner-signed SPKI pin, never the system CA pool: a server
// whose key the owners did not pin is refused during the handshake, before
// any JSON-RPC request is read.
func TestRunRefusesAnUnpinnedRPCCertificate(t *testing.T) {
	f := newCeremonyFixture(t)
	f.trustEntry(t)
	if err := run(f.config, f.artifact); err != nil {
		t.Fatalf("RPC_PINNED_ENDPOINT_REFUSED: %v", err)
	}
	other := sha256.Sum256([]byte("verify-installer-release-test/unpinned-key"))
	facts := f.facts
	facts.RPCTLSSPKIPins = []string{spkiPinPrefix + hex.EncodeToString(other[:])}
	f.useFacts(t, "unpinned.json", f.ownerSigned(t, facts, "owner-a", "owner-b"))
	before := f.rpc.total()
	err := run(f.config, f.artifact)
	if err == nil {
		t.Fatal("RPC_TLS_UNPINNED_CERT_ACCEPTED: an endpoint presenting a key the owners did not pin was trusted")
	}
	if !errors.Is(err, errRPCTLSPin) || !strings.HasPrefix(err.Error(), errRPCTLSPin.Error()) {
		t.Fatalf("RPC_TLS_REFUSAL_NOT_NAMED: %v", err)
	}
	if f.rpc.total() != before {
		t.Fatal("RPC_TLS_UNPINNED_ENDPOINT_READ: a request reached the unpinned endpoint")
	}
	// A second pin naming the presented key restores admission: the pin set,
	// not the first entry, is what is trusted.
	facts.RPCTLSSPKIPins = append(facts.RPCTLSSPKIPins, spkiPin(f.server))
	f.useFacts(t, "two-pins.json", f.ownerSigned(t, facts, "owner-a", "owner-b"))
	if err := run(f.config, f.artifact); err != nil {
		t.Fatalf("RPC_SECOND_PIN_REFUSED: %v", err)
	}
}

// The cluster is the signed profile's genesis, read before any account.
func TestRunRefusesAnEndpointOnAnotherGenesis(t *testing.T) {
	f := newCeremonyFixture(t)
	f.trustEntry(t)
	for name, genesis := range map[string]string{
		"RPC_WRONG_GENESIS_ACCEPTED":     "So11111111111111111111111111111111111111112",
		"RPC_MAINNET_GENESIS_ACCEPTED":   estateprofile.MainnetBetaGenesisHash,
		"RPC_MALFORMED_GENESIS_ACCEPTED": "not-a-genesis-hash",
	} {
		t.Run(name, func(t *testing.T) {
			f.rpc.mu.Lock()
			f.rpc.genesis = genesis
			f.rpc.mu.Unlock()
			accountsBefore := f.rpc.count("getAccountInfo")
			err := run(f.config, f.artifact)
			if !errors.Is(err, errRPCGenesis) || !strings.HasPrefix(err.Error(), errRPCGenesis.Error()) {
				t.Fatalf("%s: %v", name, err)
			}
			if f.rpc.count("getAccountInfo") != accountsBefore {
				t.Fatalf("%s_ACCOUNT_READ: an account was read from an endpoint on another cluster", name)
			}
		})
	}
	f.rpc.mu.Lock()
	f.rpc.genesis = f.profile.Profile.Network.GenesisHash
	f.rpc.mu.Unlock()
	if err := run(f.config, f.artifact); err != nil {
		t.Fatalf("RPC_PROFILE_GENESIS_REFUSED: %v", err)
	}
}

// Bytes at the derived address count only when the pinned program owns them.
func TestRunRefusesAnEntryOwnedByAnotherProgram(t *testing.T) {
	f := newCeremonyFixture(t)
	f.trustEntry(t)
	for name, owner := range map[string]string{
		"FOREIGN_OWNED_ENTRY_ACCEPTED":  "11111111111111111111111111111111",
		"OTHER_REGISTRY_ENTRY_ACCEPTED": "CydR6d4QUsWGwVaRVYXTebJSKHb8nYn3R8WqC6GJjAR5",
		"OWNERLESS_ENTRY_ACCEPTED":      "",
	} {
		t.Run(name, func(t *testing.T) {
			f.rpc.mu.Lock()
			f.rpc.owners[f.pda] = owner
			f.rpc.mu.Unlock()
			err := run(f.config, f.artifact)
			if !errors.Is(err, errAccountOwner) || !strings.HasPrefix(err.Error(), errAccountOwner.Error()) {
				t.Fatalf("%s: %v", name, err)
			}
		})
	}
	f.rpc.mu.Lock()
	delete(f.rpc.owners, f.pda)
	f.rpc.mu.Unlock()
	if err := run(f.config, f.artifact); err != nil {
		t.Fatalf("PROGRAM_OWNED_ENTRY_REFUSED: %v", err)
	}
}
