package installerrelease

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
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
	m := regexp.MustCompile(`(?s)fn installer_release_payload_hash\(.*?hashv\(&\[\n(.*?)\n\s*\]\)`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("installer_release_payload_hash hashv list not in the excerpt")
	}
	var out []string
	for _, line := range strings.Split(m[1], "\n") {
		out = append(out, strings.TrimSuffix(strings.TrimSpace(line), ","))
	}
	return out
}

// TestLayoutIsTheRustStruct: the decoder's field table, LEN, status
// discriminants, version bound and payload preimage are the program's.
func TestLayoutIsTheRustStruct(t *testing.T) {
	src := rustSource(t)
	if got := rustStructFields(t, src, AccountName); !reflect.DeepEqual(got, Layout) {
		t.Fatalf("Layout != Rust struct\n got  %v\n rust %v", Layout, got)
	}
	if got := rustLen(t, src, AccountName); got != Len || Len != 319 {
		t.Fatalf("Len = %d, Rust LEN = %d, contracts K3 records 319", Len, got)
	}
	if m := regexp.MustCompile(`pub const MAX_RELEASE_VERSION_LEN: usize = (\d+);`).FindStringSubmatch(src); m == nil || m[1] != strconv.Itoa(MaxVersionLen) {
		t.Fatalf("MaxVersionLen %d != excerpt %v", MaxVersionLen, m)
	}
	variants := rustEnumVariants(t, src, "AttestationStatus")
	for i, want := range []verify.AttestationStatus{verify.AttestationStatusActive, verify.AttestationStatusRevoked, verify.AttestationStatusSuperseded} {
		if i >= len(variants) || variants[i] != want.String() || uint8(want) != uint8(i) {
			t.Fatalf("AttestationStatus variant %d = %v, decoder maps %d to %s", i, variants, want, want)
		}
	}
	if len(variants) != 3 {
		t.Fatalf("AttestationStatus has %d variants, decoder knows 3", len(variants))
	}
	wantPreimage := []string{`b"` + PayloadDomain + `"`, "master_nft_mint.as_ref()", "installer_hash.as_ref()", "version.as_bytes()", "publisher_squads_vault.as_ref()", "publisher_ed25519_pubkey.as_ref()"}
	if got := rustPayloadPreimage(t, src); !reflect.DeepEqual(got, wantPreimage) {
		t.Fatalf("payload preimage\n got  %v\n want %v", got, wantPreimage)
	}
	disc := Discriminator()
	if hex.EncodeToString(disc[:]) != "25e0b4bac29dadf4" {
		t.Fatalf("discriminator %x", disc)
	}
}

// ── vectors (testdata/installer-release-entry-vectors.json) ───────────────

type vectorFile struct {
	Len                int         `json:"len"`
	DiscriminatorHex   string      `json:"discriminatorHex"`
	FieldOrder         [][2]string `json:"fieldOrder"`
	StatusVariants     []string    `json:"statusVariants"`
	PublisherSeedLabel string      `json:"publisherSeedLabel"`
	Vectors            []struct {
		Name             string                     `json:"name"`
		Fields           map[string]json.RawMessage `json:"fields"`
		SerializedLength int                        `json:"serializedLength"`
		AccountHex       string                     `json:"accountHex"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "installer-release-entry-vectors.json"))
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
// from the Rust source by gen_installer_release_vectors.py; this test encodes
// them again from the Rust types, then decodes them and compares every field.
func TestDecodeReadsTheRustVectorsExactly(t *testing.T) {
	src := rustSource(t)
	fields := rustStructFields(t, src, AccountName)
	v := loadVectors(t)
	if v.Len != Len || v.DiscriminatorHex != "25e0b4bac29dadf4" {
		t.Fatalf("vector len %d disc %s", v.Len, v.DiscriminatorHex)
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
			var status verify.AttestationStatus
			for i, name := range v.StatusVariants {
				if name == vectorString(t, vec.Fields["status"]) {
					status = verify.AttestationStatus(i)
				}
			}
			want := Entry{
				MasterNFTMint:          pk("master_nft_mint"),
				InstallerHash:          h32("installer_hash"),
				Version:                vectorString(t, vec.Fields["version"]),
				PublisherSquadsVault:   pk("publisher_squads_vault"),
				RegisteredBy:           pk("registered_by"),
				RegisteredAt:           registeredAt,
				Status:                 status,
				PublisherEd25519Pubkey: h32("publisher_ed25519_pubkey"),
				PublisherSignature:     [64]byte(mustHex(t, vectorString(t, vec.Fields["publisher_signature"]), 64)),
				SignedPayloadHash:      h32("signed_payload_hash"),
				RevokedAt:              revokedAt,
				Bump:                   bump,
			}
			if !reflect.DeepEqual(e, want) {
				t.Fatalf("decoded\n %+v\nwant\n %+v", e, want)
			}
			if got := PayloadHash(e.MasterNFTMint, e.InstallerHash, e.Version, e.PublisherSquadsVault, e.PublisherEd25519Pubkey); got != e.SignedPayloadHash {
				t.Fatalf("PayloadHash %x != vector signed_payload_hash %x", got, e.SignedPayloadHash)
			}
			if !ed25519.Verify(ed25519.PublicKey(e.PublisherEd25519Pubkey[:]), e.SignedPayloadHash[:], e.PublisherSignature[:]) {
				t.Fatal("vector signature does not verify")
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

func activeVector(t *testing.T) ([]byte, Entry) {
	t.Helper()
	account := mustHex(t, loadVectors(t).Vectors[0].AccountHex, Len)
	e, err := Decode(account)
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != verify.AttestationStatusActive || e.RevokedAt != nil {
		t.Fatal("vector 0 is not the Active entry")
	}
	return account, e
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
	e.SignedPayloadHash = PayloadHash(e.MasterNFTMint, e.InstallerHash, e.Version, e.PublisherSquadsVault, e.PublisherEd25519Pubkey)
	copy(e.PublisherSignature[:], ed25519.Sign(key, e.SignedPayloadHash[:]))
	return e
}

func requireRefusal(t *testing.T, err, want error, name string) {
	t.Helper()
	if err == nil || !errors.Is(err, want) || !strings.HasPrefix(err.Error(), want.Error()) {
		t.Fatalf("%s: got %v, want refusal %q", name, err, want)
	}
}

// preK3Account is the layout before contracts K3: the same prefix through
// `status`, then revoked_at and bump, LEN 191, no publisher binding.
func preK3Account(e Entry) []byte {
	disc := Discriminator()
	b := append([]byte(nil), disc[:]...)
	b = append(b, e.MasterNFTMint[:]...)
	b = append(b, e.InstallerHash[:]...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(e.Version)))
	b = append(b, e.Version...)
	b = append(b, e.PublisherSquadsVault[:]...)
	b = append(b, e.RegisteredBy[:]...)
	b = binary.LittleEndian.AppendUint64(b, uint64(e.RegisteredAt))
	b = append(b, byte(e.Status), 0, e.Bump)
	return append(b, make([]byte, 191-len(b))...)
}

func TestDecodeRefusesAnythingButTheExactLayout(t *testing.T) {
	account, e := activeVector(t)
	versionOffset := 8 + 32 + 32
	statusOffset := versionOffset + 4 + len(e.Version) + 32 + 32 + 8
	revokedOffset := statusOffset + 1 + 32 + 64 + 32
	mutate := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), account...)) }
	cases := []struct {
		name  string
		data  []byte
		field string
	}{
		{"wrong discriminator", mutate(func(b []byte) []byte { b[0] ^= 1; return b }), "discriminator"},
		{"empty", nil, "discriminator"},
		{"pre-K3 191-byte layout", preK3Account(e), "size"},
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
		t.Fatalf("control: %v", err)
	}
}

func TestAdmitAcceptsTheTrustedCustodianRegisteredEntry(t *testing.T) {
	_, e := activeVector(t)
	if err := vectorTrust(t, e).Admit(e, e.InstallerHash); err != nil {
		t.Fatalf("valid entry refused: %v", err)
	}
	// A second trusted key in the set does not change the verdict.
	other := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if err := vectorTrust(t, e, [32]byte(other), e.PublisherEd25519Pubkey).Admit(e, e.InstallerHash); err != nil {
		t.Fatalf("valid entry refused under a two-key trust: %v", err)
	}
}

// An entry the custodian registered under a key the profile does not name is
// valid on chain (the program verified that key's signature) and refused here
// only because of the key.
func TestAdmitRefusesAnUntrustedPublisher(t *testing.T) {
	_, e := activeVector(t)
	trust := vectorTrust(t, e)
	intruderSeed := sha256.Sum256([]byte("melusina-installer-release-vector-untrusted-publisher"))
	intruder := resign(e, ed25519.NewKeyFromSeed(intruderSeed[:]))
	if !ed25519.Verify(ed25519.PublicKey(intruder.PublisherEd25519Pubkey[:]), intruder.SignedPayloadHash[:], intruder.PublisherSignature[:]) {
		t.Fatal("fixture: the intruder entry must carry a valid signature")
	}
	requireRefusal(t, trust.Admit(intruder, e.InstallerHash), ErrPublisherUntrusted, "untrusted publisher")
	// Control: the same construction with the trusted key is admitted.
	if err := trust.Admit(resign(e, vectorPublisher(t)), e.InstallerHash); err != nil {
		t.Fatalf("control: %v", err)
	}
}

func TestAdmitRefusesAnEntryThatIsNotActive(t *testing.T) {
	v := loadVectors(t)
	superseded, err := Decode(mustHex(t, v.Vectors[1].AccountHex, Len))
	if err != nil {
		t.Fatal(err)
	}
	trust := vectorTrust(t, superseded)
	requireRefusal(t, trust.Admit(superseded, superseded.InstallerHash), ErrNotActive, "superseded vector")

	_, e := activeVector(t)
	for _, status := range []verify.AttestationStatus{verify.AttestationStatusRevoked, verify.AttestationStatusSuperseded} {
		revoked := e
		revoked.Status = status
		at := int64(1790000000)
		revoked.RevokedAt = &at
		requireRefusal(t, vectorTrust(t, e).Admit(revoked, e.InstallerHash), ErrNotActive, status.String())
	}
	// An Active entry that records a revocation time was not written by the program.
	inconsistent := e
	at := int64(1)
	inconsistent.RevokedAt = &at
	requireRefusal(t, vectorTrust(t, e).Admit(inconsistent, e.InstallerHash), ErrMalformed, "Active with revoked_at")
}

func TestAdmitRefusesEachBrokenBinding(t *testing.T) {
	_, e := activeVector(t)
	trust := vectorTrust(t, e)
	var other [32]byte
	copy(other[:], "another thirty-two byte value!!!")
	cases := []struct {
		name  string
		entry Entry
		hash  [32]byte
		trust *Trust
		want  error
	}{
		{"artifact hash differs", e, other, trust, ErrHashMismatch},
		{"another estate's master mint", func() Entry { x := e; x.MasterNFTMint = other; return resign(x, vectorPublisher(t)) }(), e.InstallerHash, trust, ErrMasterMismatch},
		{"registered_by is not the vault", func() Entry { x := e; x.RegisteredBy = other; return x }(), e.InstallerHash, trust, ErrCustodianMismatch},
		{"vault is not the estate core vault", func() Entry {
			x := e
			x.PublisherSquadsVault, x.RegisteredBy = other, other
			return resign(x, vectorPublisher(t))
		}(), e.InstallerHash, trust, ErrCustodianMismatch},
		{"digest is not over the entry's fields", func() Entry { x := e; x.Version = "9.9.9"; return x }(), e.InstallerHash, trust, ErrPayloadHashMismatch},
		{"signature does not verify", func() Entry { x := e; x.PublisherSignature[0] ^= 1; return x }(), e.InstallerHash, trust, ErrSignatureInvalid},
		{"profile threshold above one signature", e, e.InstallerHash, func() *Trust {
			tr, err := NewTrust(e.MasterNFTMint, e.PublisherSquadsVault, [][32]byte{e.PublisherEd25519Pubkey, other}, 2)
			if err != nil {
				t.Fatal(err)
			}
			return tr
		}(), ErrThresholdUnmet},
		{"no trust bound", e, e.InstallerHash, nil, ErrTrustUnconfigured},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requireRefusal(t, c.trust.Admit(c.entry, c.hash), c.want, c.name)
		})
	}
}

func TestNewTrustRefusesAnIncompleteTrust(t *testing.T) {
	var k [32]byte
	k[0] = 1
	for name, build := range map[string]func() (*Trust, error){
		"no master":     func() (*Trust, error) { return NewTrust([32]byte{}, k, [][32]byte{k}, 1) },
		"no custodian":  func() (*Trust, error) { return NewTrust(k, [32]byte{}, [][32]byte{k}, 1) },
		"no publishers": func() (*Trust, error) { return NewTrust(k, k, nil, 1) },
		"zero key":      func() (*Trust, error) { return NewTrust(k, k, [][32]byte{{}}, 1) },
		"threshold 0":   func() (*Trust, error) { return NewTrust(k, k, [][32]byte{k}, 0) },
	} {
		if _, err := build(); !errors.Is(err, ErrTrustUnconfigured) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}
