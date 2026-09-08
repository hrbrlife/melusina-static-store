package releasefinalizer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/squadsproof"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type registerFixtureAccount struct{ Address, Owner, DataBase64 string }
type registerSDKFixture struct {
	SDKVersion, Web3Version string
	Now                     int64
	Pins                    struct {
		Registry, Master, Multisig, Vault, Publisher string
		Members                                      [4]string
	}
	Expectation                                               ProposalExpectation
	Transaction, Multisig, Proposal, PendingProposal, Release registerFixtureAccount
	AuthorSignatureBase64                                     string
	Candidate, Ceremony                                       json.RawMessage
}
type observerFixture struct {
	t           *testing.T
	sdk         registerSDKFixture
	o           *CoreProposalObserver
	want        ProposalExpectation
	accounts    []squadsproof.Account
	calls       int
	mutateReply func(int, map[string]any)
	rawReply    func([]byte) []byte
}

func newObserverFixture(t *testing.T) *observerFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/register-release-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	f := &observerFixture{t: t}
	if err := json.Unmarshal(raw, &f.sdk); err != nil {
		t.Fatal(err)
	}
	if f.sdk.SDKVersion != "2.1.4" || f.sdk.Web3Version != "1.98.4" {
		t.Fatal("unpinned SDK fixture")
	}
	f.want = f.sdk.Expectation
	f.accounts = []squadsproof.Account{f.account(f.sdk.Transaction), f.account(f.sdk.Multisig), f.account(f.sdk.Proposal), f.account(f.sdk.Release)}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	f.o, err = NewCoreProposalObserver(CoreProposalObserverConfig{RPCURL: server.URL, Members: f.sdk.Pins.Members})
	if err != nil {
		t.Fatal(err)
	}
	// Only tests replace fixed production authority with this SDK-generated
	// synthetic authority. The public constructor exposes no such selector.
	f.o.pins = coreObserverPins{registry: observerKey(f.sdk.Pins.Registry), master: observerKey(f.sdk.Pins.Master), multisig: observerKey(f.sdk.Pins.Multisig), vault: observerKey(f.sdk.Pins.Vault), publisher: observerKey(f.sdk.Pins.Publisher)}
	for i, key := range f.sdk.Pins.Members {
		f.o.pins.members[i] = observerKey(key)
	}
	f.o.client.Transport.(*http.Transport).TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	f.o.now = func() time.Time { return time.Unix(f.sdk.Now, 0).UTC() }
	return f
}

func (f *observerFixture) account(value registerFixtureAccount) squadsproof.Account {
	f.t.Helper()
	raw, err := base64.StdEncoding.DecodeString(value.DataBase64)
	if err != nil {
		f.t.Fatal(err)
	}
	return squadsproof.Account{Address: observerKey(value.Address), Owner: observerKey(value.Owner), Data: raw}
}

func (f *observerFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.calls++
	var request struct {
		JSONRPC string            `json:"jsonrpc"`
		ID      int               `json:"id"`
		Method  string            `json:"method"`
		Params  []json.RawMessage `json:"params"`
	}
	if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || json.NewDecoder(r.Body).Decode(&request) != nil || request.JSONRPC != "2.0" || request.ID != 1 || request.Method != "getMultipleAccounts" || len(request.Params) != 2 {
		f.t.Error("observer sent an unexpected RPC operation or credential")
		http.Error(w, "bad", 400)
		return
	}
	var keys []string
	var options struct {
		Encoding       string `json:"encoding"`
		Commitment     string `json:"commitment"`
		MinContextSlot uint64 `json:"minContextSlot"`
	}
	if json.Unmarshal(request.Params[0], &keys) != nil || json.Unmarshal(request.Params[1], &options) != nil || options.Encoding != "base64" || options.Commitment != "finalized" || (len(keys) != 1 && len(keys) != 4) || (len(keys) == 4 && options.MinContextSlot != 1000) {
		f.t.Error("observer did not request a bounded consistent finalized cohort")
		http.Error(w, "bad", 400)
		return
	}
	values := make([]any, len(keys))
	for i, key := range keys {
		if key != primitives.EncodeBase58(f.accounts[i].Address[:]) {
			f.t.Errorf("unexpected derived account %d", i)
			http.Error(w, "bad", 400)
			return
		}
		account := f.accounts[i]
		if len(account.Data) == 0 {
			continue
		}
		values[i] = map[string]any{"owner": primitives.EncodeBase58(account.Owner[:]), "data": []string{base64.StdEncoding.EncodeToString(account.Data), "base64"}, "executable": false, "lamports": 1, "rentEpoch": uint64(0)}
	}
	reply := map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"context": map[string]any{"slot": uint64(1000), "apiVersion": "fixture"}, "value": values}}
	if f.mutateReply != nil {
		f.mutateReply(len(keys), reply)
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		f.t.Error(err)
		return
	}
	if f.rawReply != nil {
		raw = f.rawReply(raw)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

func (f *observerFixture) rebindDigest() {
	f.t.Helper()
	value, err := RegisterProposalDigest(f.accounts[0])
	if err != nil {
		f.t.Fatalf("mutation must remain a parseable SDK transaction: %v", err)
	}
	f.want.Digest = value
}

func TestCoreObserverReadsSDKProposalAndExactActiveRelease(t *testing.T) {
	f := newObserverFixture(t)
	got, err := f.o.ObserveExecution(context.Background(), f.want)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != ProposalExecuted || got.Digest != f.sdk.Expectation.Digest || got.ReleaseEntryPDA != f.sdk.Release.Address || got.VerifiedSlot != 1000 || got.RegisteredAt.Unix() != f.sdk.Now || got.ExecutedAt.Unix() != f.sdk.Now || got.AuthorSignatureBase64 != f.sdk.AuthorSignatureBase64 || f.calls != 2 {
		t.Fatalf("incorrect verified observation: %#v calls=%d", got, f.calls)
	}
	// An exact resume re-reads finalized chain state; no result cache can make
	// a revoked release or changed live authority remain valid.
	again, err := f.o.ObserveExecution(context.Background(), f.want)
	if err != nil || again != got || f.calls != 4 {
		t.Fatalf("exact resume: %v calls=%d", err, f.calls)
	}
	f.accounts[3].Data[len(f.accounts[3].Data)-3] = 1
	if _, err := f.o.ObserveExecution(context.Background(), f.want); err == nil {
		t.Fatal("resume accepted a subsequently revoked release")
	}
}

func TestCoreObserverPendingHasNoInventedRegistration(t *testing.T) {
	f := newObserverFixture(t)
	f.accounts[2] = f.account(f.sdk.PendingProposal)
	f.accounts[3].Data = nil
	got, err := f.o.ObserveExecution(context.Background(), f.want)
	if err != nil || got.State != ProposalPending || !got.RegisteredAt.IsZero() || got.ReleaseEntryPDA != "" || got.AuthorSignatureBase64 != "" {
		t.Fatalf("pending manufactured a final release: %#v %v", got, err)
	}
	f.accounts[2] = f.account(f.sdk.Proposal)
	f.accounts[3] = f.account(f.sdk.Release)
	if got, err := f.o.ObserveExecution(context.Background(), f.want); err != nil || got.State != ProposalExecuted {
		t.Fatalf("normal pending-to-executed resume failed: %#v %v", got, err)
	}
}

func TestCoreObserverRefusesAuthorityInstructionAndReleaseDrift(t *testing.T) {
	cases := map[string]func(*observerFixture){
		"foreign digest":      func(f *observerFixture) { f.want.Digest = strings.Repeat("a", 64) },
		"foreign app":         func(f *observerFixture) { f.want.AppID = strings.Repeat("a", 52) },
		"foreign version":     func(f *observerFixture) { f.want.Version = "0.1.33" },
		"foreign release":     func(f *observerFixture) { f.want.Release = strings.Repeat("a", 64) },
		"foreign owner":       func(f *observerFixture) { f.accounts[0].Owner = f.o.pins.registry },
		"configured author":   func(f *observerFixture) { f.o.pins.publisher = f.o.pins.members[0] },
		"configured members":  func(f *observerFixture) { f.o.pins.members[3] = f.o.pins.publisher },
		"threshold downgrade": func(f *observerFixture) { binary.LittleEndian.PutUint16(f.accounts[1].Data[72:74], 2) },
		"insufficient votes": func(f *observerFixture) {
			d := f.accounts[2].Data
			binary.LittleEndian.PutUint32(d[58:62], 2)
			f.accounts[2].Data = append(d[:126], d[158:]...)
		},
		"rejected proposal": func(f *observerFixture) { f.accounts[2].Data[48] = byte(squadsproof.ProposalStatusRejected) },
		"future execution": func(f *observerFixture) {
			binary.LittleEndian.PutUint64(f.accounts[2].Data[49:57], uint64(f.sdk.Now+121))
		},
		"absent active entry": func(f *observerFixture) { f.accounts[3].Data = nil },
		"foreign entry owner": func(f *observerFixture) { f.accounts[3].Owner = squadsproof.DefaultProgramID },
		"revoked entry":       func(f *observerFixture) { f.accounts[3].Data[len(f.accounts[3].Data)-3] = 1 },
		"registration time": func(f *observerFixture) {
			d := f.accounts[3].Data
			binary.LittleEndian.PutUint64(d[len(d)-11:len(d)-3], uint64(f.sdk.Now-1))
		},
		"entry author payload": func(f *observerFixture) { f.accounts[3].Data[70] ^= 1 },
		"entry unknown bytes":  func(f *observerFixture) { f.accounts[3].Data = append(f.accounts[3].Data, 1) },
		"additional signer":    func(f *observerFixture) { f.accounts[0].Data[87] = 2; f.rebindDigest() },
		"changed instruction author signature": func(f *observerFixture) {
			d := sha256.Sum256([]byte("global:register_release_entry"))
			i := bytes.Index(f.accounts[0].Data, d[:8])
			f.accounts[0].Data[i+108+len(f.want.Version)+64] ^= 1
			f.rebindDigest()
		},
		"changed instruction release": func(f *observerFixture) {
			d := sha256.Sum256([]byte("global:register_release_entry"))
			i := bytes.Index(f.accounts[0].Data, d[:8])
			f.accounts[0].Data[i+72] ^= 1
			f.rebindDigest()
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newObserverFixture(t)
			mutate(f)
			if _, err := f.o.ObserveExecution(context.Background(), f.want); err == nil {
				t.Fatal("drift accepted")
			}
		})
	}
}

func TestCoreObserverAcceptsOnlyKnownZeroReleaseAllocationPadding(t *testing.T) {
	f := newObserverFixture(t)
	f.accounts[3].Data = append(f.accounts[3].Data, make([]byte, 383-len(f.accounts[3].Data))...)
	if _, err := f.o.ObserveExecution(context.Background(), f.want); err != nil {
		t.Fatalf("canonical Anchor allocation refused: %v", err)
	}
	f.accounts[3].Data[len(f.accounts[3].Data)-1] = 1
	if _, err := f.o.ObserveExecution(context.Background(), f.want); err == nil {
		t.Fatal("unknown account extension accepted")
	}
}

func TestCoreObserverRPCRefusesStaleAmbiguousAndOversizedSnapshots(t *testing.T) {
	for name, mutate := range map[string]func(*observerFixture){
		"old cohort": func(f *observerFixture) {
			f.mutateReply = func(count int, r map[string]any) {
				if count == 4 {
					r["result"].(map[string]any)["context"].(map[string]any)["slot"] = 999
				}
			}
		},
		"missing cohort account": func(f *observerFixture) {
			f.mutateReply = func(count int, r map[string]any) {
				if count == 4 {
					r["result"].(map[string]any)["value"] = []any{}
				}
			}
		},
		"executable account": func(f *observerFixture) {
			f.mutateReply = func(_ int, r map[string]any) {
				r["result"].(map[string]any)["value"].([]any)[0].(map[string]any)["executable"] = true
			}
		},
		"duplicate slot": func(f *observerFixture) {
			f.rawReply = func(raw []byte) []byte {
				return bytes.Replace(raw, []byte(`"slot":1000`), []byte(`"slot":1000,"slot":1000`), 1)
			}
		},
		"case alias": func(f *observerFixture) {
			f.rawReply = func(raw []byte) []byte { return bytes.Replace(raw, []byte(`"slot"`), []byte(`"Slot"`), 1) }
		},
		"trailing JSON": func(f *observerFixture) { f.rawReply = func(raw []byte) []byte { return append(raw, []byte(`{}`)...) } },
		"oversized reply": func(f *observerFixture) {
			f.rawReply = func(raw []byte) []byte { return append(raw, bytes.Repeat([]byte(" "), coreObserverMaxRPCBytes)...) }
		},
		"changed immutable transaction": func(f *observerFixture) {
			f.mutateReply = func(count int, r map[string]any) {
				if count == 4 {
					data := append([]byte(nil), f.accounts[0].Data...)
					data[40] ^= 1
					r["result"].(map[string]any)["value"].([]any)[0].(map[string]any)["data"] = []string{base64.StdEncoding.EncodeToString(data), "base64"}
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newObserverFixture(t)
			mutate(f)
			if _, err := f.o.ObserveExecution(context.Background(), f.want); err == nil {
				t.Fatal("invalid RPC snapshot accepted")
			}
		})
	}
}

func TestCoreObserverConstructorAndCancellationDoNotExposeAnRPCRouter(t *testing.T) {
	f := newObserverFixture(t)
	for _, endpoint := range []string{"http://localhost:1234", "https://user:pass@example.com", "https://example.com/path", "https://example.com?method=sendTransaction"} {
		if _, err := NewCoreProposalObserver(CoreProposalObserverConfig{RPCURL: endpoint, Members: f.sdk.Pins.Members}); err == nil {
			t.Fatalf("unbounded origin accepted: %s", endpoint)
		}
	}
	members := f.sdk.Pins.Members
	members[3] = members[0]
	if _, err := NewCoreProposalObserver(CoreProposalObserverConfig{RPCURL: "https://api.devnet.solana.com", Members: members}); err == nil {
		t.Fatal("duplicate fixed members accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.o.ObserveExecution(ctx, f.want); err == nil || f.calls != 0 {
		t.Fatalf("cancelled observer performed work: %v calls=%d", err, f.calls)
	}
}
