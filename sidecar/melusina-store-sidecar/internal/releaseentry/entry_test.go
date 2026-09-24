package releaseentry

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// ── the Rust source (testdata/license-registry-excerpt.rs) ────────────────

func rustSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "license-registry-excerpt.rs"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func rustStructFields(t *testing.T, src, name string) []Field {
	t.Helper()
	m := regexp.MustCompile(`(?s)#\[account\]\npub struct ` + name + ` \{\n(.*?)\n\}`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("struct %s not in the excerpt", name)
	}
	var out []Field
	for _, line := range strings.Split(m[1], "\n") {
		f := regexp.MustCompile(`^\s*pub (\w+): ([^,]+),$`).FindStringSubmatch(line)
		if f == nil {
			t.Fatalf("unparsed struct line %q", line)
		}
		out = append(out, Field{Name: f[1], Type: f[2]})
	}
	return out
}

func rustEnumVariants(t *testing.T, src, name string) []string {
	t.Helper()
	m := regexp.MustCompile(`(?s)pub enum ` + name + ` \{\n(.*?)\n\}`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("enum %s not in the excerpt", name)
	}
	var out []string
	for _, line := range strings.Split(m[1], "\n") {
		out = append(out, strings.TrimSuffix(strings.TrimSpace(line), ","))
	}
	return out
}

// rustLen evaluates `impl <name> { pub const LEN: usize = <expr>; }` with the
// excerpt's usize constants substituted. The expression is a sum of integers
// and parenthesised sums; anything else fails the test.
func rustLen(t *testing.T, src, name string) int {
	t.Helper()
	m := regexp.MustCompile(`(?s)impl ` + name + ` \{\s*pub const LEN: usize =\s*(.*?);`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s::LEN not in the excerpt", name)
	}
	expr := m[1]
	for _, c := range regexp.MustCompile(`pub const (\w+): usize = (\d+);`).FindAllStringSubmatch(src, -1) {
		expr = strings.ReplaceAll(expr, c[1], c[2])
	}
	expr = strings.NewReplacer("(", " ", ")", " ", "\n", " ").Replace(expr)
	total := 0
	for _, term := range strings.Split(expr, "+") {
		n, err := strconv.Atoi(strings.TrimSpace(term))
		if err != nil {
			t.Fatalf("LEN term %q: %v", term, err)
		}
		total += n
	}
	return total
}

func rustPayloadPreimage(t *testing.T, src string) []string {
	t.Helper()
	m := regexp.MustCompile(`(?s)fn release_payload_hash\(.*?hashv\(&\[\n(.*?)\n\s*\]\)`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("release_payload_hash hashv list not in the excerpt")
	}
	var out []string
	for _, line := range strings.Split(m[1], "\n") {
		out = append(out, strings.TrimSuffix(strings.TrimSpace(line), ","))
	}
	return out
}

// TestLayoutIsTheRustStruct: the decoder's field table, LEN, status
// discriminants, version bound, payload preimage and the account's creation
// (exactly LEN bytes at ["release_v2", master, app_hash]) are the program's.
func TestLayoutIsTheRustStruct(t *testing.T) {
	src := rustSource(t)
	if got := rustStructFields(t, src, AccountName); !reflect.DeepEqual(got, Layout) {
		t.Fatalf("Layout != Rust struct\n got  %v\n rust %v", Layout, got)
	}
	if got := rustLen(t, src, AccountName); got != Len || Len != 383 {
		t.Fatalf("Len = %d, Rust LEN = %d, want 383", Len, got)
	}
	if m := regexp.MustCompile(`pub const MAX_RELEASE_VERSION_LEN: usize = (\d+);`).FindStringSubmatch(src); m == nil || m[1] != strconv.Itoa(MaxVersionLen) {
		t.Fatalf("MaxVersionLen %d != excerpt %v", MaxVersionLen, m)
	}
	variants := rustEnumVariants(t, src, "AttestationStatus")
	for i, want := range []Status{StatusActive, StatusRevoked, StatusSuperseded} {
		if i >= len(variants) || variants[i] != want.String() || uint8(want) != uint8(i) {
			t.Fatalf("AttestationStatus variant %d = %v, decoder maps %d to %s", i, variants, want, want)
		}
	}
	if len(variants) != 3 {
		t.Fatalf("AttestationStatus has %d variants, decoder knows 3", len(variants))
	}
	wantPreimage := []string{`b"` + PayloadDomain + `"`, "master_nft_mint.as_ref()", "app_hash.as_ref()", "app_id.as_ref()", "release_hash.as_ref()", "version.as_bytes()", "publisher_squads_vault.as_ref()", "publisher_ed25519_pubkey.as_ref()"}
	if got := rustPayloadPreimage(t, src); !reflect.DeepEqual(got, wantPreimage) {
		t.Fatalf("payload preimage\n got  %v\n want %v", got, wantPreimage)
	}
	for _, creation := range []string{
		"space = ReleaseEntry::LEN,",
		`seeds = [b"release_v2", master_nft_mint.key().as_ref(), app_hash.as_ref()],`,
	} {
		if !strings.Contains(src, creation) {
			t.Fatalf("the excerpt's RegisterReleaseEntry no longer has %q", creation)
		}
	}
	disc := Discriminator()
	if hex.EncodeToString(disc[:]) != "f87a4976ee689e00" {
		t.Fatalf("discriminator %x", disc)
	}
}

// ── vectors (testdata/release-entry-vectors.json) ─────────────────────────

type vectorFile struct {
	Len                int         `json:"len"`
	DiscriminatorHex   string      `json:"discriminatorHex"`
	PayloadDomain      string      `json:"payloadDomain"`
	FieldOrder         [][2]string `json:"fieldOrder"`
	StatusVariants     []string    `json:"statusVariants"`
	PublisherSeedLabel string      `json:"publisherSeedLabel"`
	Vectors            []struct {
		Name             string                     `json:"name"`
		AppIDText        string                     `json:"appIdText"`
		ReleaseNonce     string                     `json:"releaseNonce"`
		Fields           map[string]json.RawMessage `json:"fields"`
		SerializedLength int                        `json:"serializedLength"`
		AccountHex       string                     `json:"accountHex"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "release-entry-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) != 2 {
		t.Fatalf("want 2 vectors, got %d", len(v.Vectors))
	}
	return v
}

func mustHex(t *testing.T, s string, n int) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || (n > 0 && len(b) != n) {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func vectorString(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("field %s: %v", raw, err)
	}
	return s
}

// borshByRustType encodes one vector field by its Rust type (parsed from the
// excerpt, not from Layout): an encoder independent of Decode.
func borshByRustType(t *testing.T, rustType string, raw json.RawMessage, statusVariants []string) []byte {
	t.Helper()
	switch rustType {
	case "Pubkey":
		k, err := primitives.PubkeyFromBase58(vectorString(t, raw))
		if err != nil {
			t.Fatal(err)
		}
		return k[:]
	case "[u8; 32]":
		return mustHex(t, vectorString(t, raw), 32)
	case "[u8; 64]":
		return mustHex(t, vectorString(t, raw), 64)
	case "String":
		s := vectorString(t, raw)
		out := binary.LittleEndian.AppendUint32(nil, uint32(len(s)))
		return append(out, s...)
	case "i64":
		var n int64
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatal(err)
		}
		return binary.LittleEndian.AppendUint64(nil, uint64(n))
	case "u8":
		var n uint8
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatal(err)
		}
		return []byte{n}
	case "AttestationStatus":
		s := vectorString(t, raw)
		for i, v := range statusVariants {
			if v == s {
				return []byte{byte(i)}
			}
		}
		t.Fatalf("status %q", s)
	case "Option<i64>":
		if string(raw) == "null" {
			return []byte{0}
		}
		var n int64
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatal(err)
		}
		return append([]byte{1}, binary.LittleEndian.AppendUint64(nil, uint64(n))...)
	}
	t.Fatalf("no Borsh rule for %s", rustType)
	return nil
}

// TestDecodeReadsTheRustVectorsExactly: the committed vectors were produced
// from the Rust source by gen_release_entry_vectors.py; this test encodes them
// again from the Rust types, then decodes them and compares every field. It
// also recomputes the two derivations the release tools register (app_id from
// the appId text, release_hash from appHash, version and nonce).
func TestDecodeReadsTheRustVectorsExactly(t *testing.T) {
	src := rustSource(t)
	fields := rustStructFields(t, src, AccountName)
	v := loadVectors(t)
	if v.Len != Len || v.DiscriminatorHex != "f87a4976ee689e00" || v.PayloadDomain != PayloadDomain {
		t.Fatalf("vector len %d disc %s domain %s", v.Len, v.DiscriminatorHex, v.PayloadDomain)
	}
	for i, f := range fields {
		if v.FieldOrder[i] != [2]string{f.Name, f.Type} {
			t.Fatalf("vector field order %v != Rust %v", v.FieldOrder, fields)
		}
	}
	disc := Discriminator()
	for _, vec := range v.Vectors {
		t.Run(vec.Name, func(t *testing.T) {
			account := mustHex(t, vec.AccountHex, Len)
			encoded := append([]byte(nil), disc[:]...)
			for _, f := range fields {
				encoded = append(encoded, borshByRustType(t, f.Type, vec.Fields[f.Name], v.StatusVariants)...)
			}
			if len(encoded) != vec.SerializedLength {
				t.Fatalf("serialized %d, vector says %d", len(encoded), vec.SerializedLength)
			}
			encoded = append(encoded, make([]byte, Len-len(encoded))...)
			if hex.EncodeToString(encoded) != vec.AccountHex {
				t.Fatalf("Rust-typed re-encoding differs from the committed account bytes")
			}

			e, err := Decode(account)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			pk := func(name string) [32]byte {
				k, err := primitives.PubkeyFromBase58(vectorString(t, vec.Fields[name]))
				if err != nil {
					t.Fatal(err)
				}
				return k
			}
			h32 := func(name string) [32]byte { return [32]byte(mustHex(t, vectorString(t, vec.Fields[name]), 32)) }
			var registeredAt int64
			_ = json.Unmarshal(vec.Fields["registered_at"], &registeredAt)
			var bump uint8
			_ = json.Unmarshal(vec.Fields["bump"], &bump)
			var revokedAt *int64
			if string(vec.Fields["revoked_at"]) != "null" {
				var n int64
				_ = json.Unmarshal(vec.Fields["revoked_at"], &n)
				revokedAt = &n
			}
			var status Status
			for i, name := range v.StatusVariants {
				if name == vectorString(t, vec.Fields["status"]) {
					status = Status(i)
				}
			}
			want := Entry{
				MasterNFTMint:          pk("master_nft_mint"),
				AppHash:                h32("app_hash"),
				AppID:                  h32("app_id"),
				ReleaseHash:            h32("release_hash"),
				Version:                vectorString(t, vec.Fields["version"]),
				PublisherSquadsVault:   pk("publisher_squads_vault"),
				PublisherEd25519Pubkey: h32("publisher_ed25519_pubkey"),
				Signature:              [64]byte(mustHex(t, vectorString(t, vec.Fields["signature"]), 64)),
				SignedPayloadHash:      h32("signed_payload_hash"),
				RegisteredBy:           pk("registered_by"),
				RegisteredAt:           registeredAt,
				Status:                 status,
				RevokedAt:              revokedAt,
				Bump:                   bump,
			}
			if !reflect.DeepEqual(e, want) {
				t.Fatalf("decoded\n %+v\nwant\n %+v", e, want)
			}
			if got := PayloadHash(e.MasterNFTMint, e.AppHash, e.AppID, e.ReleaseHash, e.Version, e.PublisherSquadsVault, e.PublisherEd25519Pubkey); got != e.SignedPayloadHash {
				t.Fatalf("PayloadHash %x != vector signed_payload_hash %x", got, e.SignedPayloadHash)
			}
			if !ed25519.Verify(ed25519.PublicKey(e.PublisherEd25519Pubkey[:]), e.SignedPayloadHash[:], e.Signature[:]) {
				t.Fatal("vector signature does not verify")
			}
			if AppIDHash(vec.AppIDText) != e.AppID {
				t.Fatalf("AppIDHash(%q) is not the vector's app_id", vec.AppIDText)
			}
			if got := sha256.Sum256([]byte(hex.EncodeToString(e.AppHash[:]) + e.Version + vec.ReleaseNonce)); got != e.ReleaseHash {
				t.Fatal("release_hash is not sha256(appHash hex + version + nonce)")
			}
		})
	}
}

// ── fixtures for refusal and admission tests ──────────────────────────────

func vectorPublisher(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte(loadVectors(t).PublisherSeedLabel))
	return ed25519.NewKeyFromSeed(seed[:])
}

func otherPublisher() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("melusina-release-entry-vector-not-enrolled-publisher"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func activeVector(t *testing.T) ([]byte, Entry) {
	t.Helper()
	account := mustHex(t, loadVectors(t).Vectors[0].AccountHex, Len)
	e, err := Decode(account)
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != StatusActive || e.RevokedAt != nil {
		t.Fatal("vector 0 is not the Active entry")
	}
	return account, e
}

func expectationOf(e Entry) Expectation {
	return Expectation{AppHash: e.AppHash, AppID: e.AppID, ReleaseHash: e.ReleaseHash, Version: e.Version}
}

func vectorTrust(t *testing.T, e Entry, publishers ...[32]byte) *Trust {
	t.Helper()
	if len(publishers) == 0 {
		publishers = [][32]byte{e.PublisherEd25519Pubkey}
	}
	trust, err := NewTrust(e.MasterNFTMint, e.PublisherSquadsVault, publishers, 1)
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

// resign recomputes the digest from e's fields and signs it with key, the way
// the program requires a real registration to look.
func resign(e Entry, key ed25519.PrivateKey) Entry {
	copy(e.PublisherEd25519Pubkey[:], key.Public().(ed25519.PublicKey))
	e.SignedPayloadHash = PayloadHash(e.MasterNFTMint, e.AppHash, e.AppID, e.ReleaseHash, e.Version, e.PublisherSquadsVault, e.PublisherEd25519Pubkey)
	copy(e.Signature[:], ed25519.Sign(key, e.SignedPayloadHash[:]))
	return e
}

func requireRefusal(t *testing.T, err, want error, name string) {
	t.Helper()
	if err == nil || !errors.Is(err, want) || !strings.HasPrefix(err.Error(), want.Error()) {
		t.Fatalf("%s: got %v, want refusal %q", name, err, want)
	}
}

func TestDecodeRefusesAnythingButTheExactLayout(t *testing.T) {
	account, e := activeVector(t)
	versionOffset := 8 + 32 + 32 + 32 + 32
	statusOffset := versionOffset + 4 + len(e.Version) + 32 + 32 + 64 + 32 + 32 + 8
	revokedOffset := statusOffset + 1
	mutate := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), account...)) }
	cases := []struct {
		name  string
		data  []byte
		field string
	}{
		{"wrong discriminator", mutate(func(b []byte) []byte { b[0] ^= 1; return b }), "discriminator"},
		{"empty", nil, "discriminator"},
		{"an InstallerReleaseEntry-sized account", account[:319], "size"},
		{"one byte short", account[:Len-1], "size"},
		{"one byte long", append(append([]byte(nil), account...), 0), "size"},
		{"version longer than MAX_RELEASE_VERSION_LEN", mutate(func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[versionOffset:], MaxVersionLen+1)
			return b
		}), "version"},
		{"version not UTF-8", mutate(func(b []byte) []byte { b[versionOffset+4] = 0xff; return b }), "version"},
		{"unknown status", mutate(func(b []byte) []byte { b[statusOffset] = 3; return b }), "status"},
		{"Option tag 2", mutate(func(b []byte) []byte { b[revokedOffset] = 2; return b }), "revoked_at"},
		{"non-zero padding", mutate(func(b []byte) []byte { b[Len-1] = 1; return b }), "padding"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode(c.data)
			if err == nil || !errors.Is(err, ErrMalformed) || !strings.HasPrefix(err.Error(), ErrMalformed.Error()+":"+c.field) {
				t.Fatalf("got %v, want %s:%s", err, ErrMalformed, c.field)
			}
		})
	}
	// Positive control: the unmutated account decodes.
	if _, err := Decode(account); err != nil {
		t.Fatalf("positive control: %v", err)
	}
}

// TestAdmitAcceptsTheRegisteredRelease is the positive control every refusal
// below is measured against: the committed Active vector, signed by the
// enrolled publisher, admitted for exactly the release it attests.
func TestAdmitAcceptsTheRegisteredRelease(t *testing.T) {
	_, e := activeVector(t)
	if e.PublisherEd25519Pubkey != [32]byte(vectorPublisher(t).Public().(ed25519.PublicKey)) {
		t.Fatal("the vector is not signed by the vector publisher")
	}
	if err := vectorTrust(t, e).Admit(e, expectationOf(e)); err != nil {
		t.Fatalf("Admit: %v", err)
	}
	// A trust naming more publishers than the signer still admits it.
	var other [32]byte
	copy(other[:], otherPublisher().Public().(ed25519.PublicKey))
	if err := vectorTrust(t, e, other, e.PublisherEd25519Pubkey).Admit(e, expectationOf(e)); err != nil {
		t.Fatalf("Admit with two enrolled publishers: %v", err)
	}
}

// TestAdmitRefusesByName: each mutation is refused by its own name. The
// wrong-publisher case is a valid registration (the program would accept its
// signature) by a key the estate never enrolled; the recalled cases are what
// revoke_release_entry leaves.
func TestAdmitRefusesByName(t *testing.T) {
	_, e := activeVector(t)
	trust := vectorTrust(t, e)
	want := expectationOf(e)
	flip := func(b [32]byte) [32]byte { b[0] ^= 1; return b }
	at := int64(1790000123)
	cases := []struct {
		name  string
		entry func() Entry
		want  func() Expectation
		trust func() *Trust
		err   error
	}{
		{"wrong publisher key (validly signed, not enrolled)", func() Entry { return resign(e, otherPublisher()) }, nil, nil, ErrPublisherUntrusted},
		{"wrong app hash", nil, func() Expectation { w := want; w.AppHash = flip(w.AppHash); return w }, nil, ErrAppHashMismatch},
		{"wrong app id", nil, func() Expectation { w := want; w.AppID = flip(w.AppID); return w }, nil, ErrAppIDMismatch},
		{"wrong release hash", nil, func() Expectation { w := want; w.ReleaseHash = flip(w.ReleaseHash); return w }, nil, ErrReleaseHashMismatch},
		{"wrong version", nil, func() Expectation { w := want; w.Version = "2.4.2"; return w }, nil, ErrVersionMismatch},
		{"recalled (Revoked, revoked_at set)", func() Entry { r := e; r.Status = StatusRevoked; r.RevokedAt = &at; return r }, nil, nil, ErrRecalled},
		{"superseded", func() Entry { r := e; r.Status = StatusSuperseded; return r }, nil, nil, ErrRecalled},
		{"Active with a revocation time", func() Entry { r := e; r.RevokedAt = &at; return r }, nil, nil, ErrRecalled},
		{"another estate's master mint", nil, nil, func() *Trust {
			tr, err := NewTrust(flip(e.MasterNFTMint), e.PublisherSquadsVault, [][32]byte{e.PublisherEd25519Pubkey}, 1)
			if err != nil {
				t.Fatal(err)
			}
			return tr
		}, ErrMasterMismatch},
		{"registered by another vault than it names", func() Entry { r := e; r.RegisteredBy = flip(r.RegisteredBy); return r }, nil, nil, ErrCustodianMismatch},
		{"custodian is not the estate's release custodian", nil, nil, func() *Trust {
			tr, err := NewTrust(e.MasterNFTMint, flip(e.PublisherSquadsVault), [][32]byte{e.PublisherEd25519Pubkey}, 1)
			if err != nil {
				t.Fatal(err)
			}
			return tr
		}, ErrCustodianMismatch},
		{"a field changed after signing", func() Entry { r := e; r.Version = "2.4.2"; return r }, func() Expectation { w := want; w.Version = "2.4.2"; return w }, nil, ErrPayloadHashMismatch},
		{"signature over another digest", func() Entry { r := e; r.Signature[0] ^= 1; return r }, nil, nil, ErrSignatureInvalid},
		{"releaseTrust.threshold 2", nil, nil, func() *Trust {
			var other [32]byte
			copy(other[:], otherPublisher().Public().(ed25519.PublicKey))
			tr, err := NewTrust(e.MasterNFTMint, e.PublisherSquadsVault, [][32]byte{e.PublisherEd25519Pubkey, other}, 2)
			if err != nil {
				t.Fatal(err)
			}
			return tr
		}, ErrThresholdUnmet},
		{"no trust bound", nil, nil, func() *Trust { return nil }, ErrTrustUnconfigured},
		{"incomplete expectation", nil, func() Expectation { w := want; w.Version = ""; return w }, nil, ErrExpectationIncomplete},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entry, expectation, tr := e, want, trust
			if c.entry != nil {
				entry = c.entry()
			}
			if c.want != nil {
				expectation = c.want()
			}
			if c.trust != nil {
				tr = c.trust()
			}
			requireRefusal(t, tr.Admit(entry, expectation), c.err, c.name)
		})
	}
	// Positive control: the unmutated entry, expectation and trust admit.
	if err := trust.Admit(e, want); err != nil {
		t.Fatalf("positive control: %v", err)
	}
}

// TestRecalledVectorIsRefused: the committed Revoked vector decodes (a recall
// is a legal account) and is refused as recalled, whatever else matches.
func TestRecalledVectorIsRefused(t *testing.T) {
	e, err := Decode(mustHex(t, loadVectors(t).Vectors[1].AccountHex, Len))
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != StatusRevoked || e.RevokedAt == nil {
		t.Fatalf("vector 1 is not a recall: %s", e.Status)
	}
	requireRefusal(t, vectorTrust(t, e).Admit(e, expectationOf(e)), ErrRecalled, "committed Revoked vector")
}

func TestNewTrustRefusesAnIncompleteTrust(t *testing.T) {
	_, e := activeVector(t)
	var zero [32]byte
	key := [][32]byte{e.PublisherEd25519Pubkey}
	for name, build := range map[string]func() (*Trust, error){
		"no master mint":     func() (*Trust, error) { return NewTrust(zero, e.PublisherSquadsVault, key, 1) },
		"no custodian":       func() (*Trust, error) { return NewTrust(e.MasterNFTMint, zero, key, 1) },
		"no publisher":       func() (*Trust, error) { return NewTrust(e.MasterNFTMint, e.PublisherSquadsVault, nil, 1) },
		"zero publisher key": func() (*Trust, error) { return NewTrust(e.MasterNFTMint, e.PublisherSquadsVault, [][32]byte{zero}, 1) },
		"zero threshold":     func() (*Trust, error) { return NewTrust(e.MasterNFTMint, e.PublisherSquadsVault, key, 0) },
	} {
		if _, err := build(); !errors.Is(err, ErrTrustUnconfigured) {
			t.Fatalf("%s: got %v, want %s", name, err, ErrTrustUnconfigured)
		}
	}
}

const releaseentrytestImport = "github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry/releaseentrytest"

// TestReleaseentrytestIsImportedOnlyByTests: the fixture package encodes and
// signs entries with whatever key a test hands it. No production file of this
// module may link it.
func TestReleaseentrytestIsImportedOnlyByTests(t *testing.T) {
	root := filepath.Join("..", "..")
	var testImporters int
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", ".git", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range file.Imports {
			if p, _ := strconv.Unquote(spec.Path.Value); p == releaseentrytestImport {
				if !strings.HasSuffix(path, "_test.go") {
					t.Errorf("production file %s imports the test fixture package", path)
				}
				testImporters++
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Positive control: the walk does see the tests that use it.
	if testImporters == 0 {
		t.Fatal("no test imports releaseentrytest; the scan walked the wrong tree")
	}
}
