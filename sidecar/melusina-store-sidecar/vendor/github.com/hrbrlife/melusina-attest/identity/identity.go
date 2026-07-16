package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hrbrlife/melusina-attest/canonical"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const CurrentVersion = 1

// DigestDomainTag is the frozen domain-separation prefix for Public.Digest
// (§4.5). It is versioned independently of the envelope wire tag: this digest
// is an identity-local encoding that the envelope CONSUMES (CanonicalPayload
// binds Source.DigestHex()), not the envelope's own contract.
const DigestDomainTag = "melusina-attest-identity-v1"

type Kind string

const (
	KindPearl   Kind = "pearl"
	KindSidecar Kind = "sidecar"
)

type Ref struct {
	Kind        Kind   `json:"kind"`
	ChainID     string `json:"chain_id"`
	ProgramID   string `json:"program_id"`
	LicenseMint string `json:"license_mint"`
	Domain      string `json:"domain"`
	PDA         string `json:"pda"`
	AppHashHex  string `json:"app_hash_hex,omitempty"`
	PearlIDHash string `json:"pearl_id_hash,omitempty"`
	SidecarID   string `json:"sidecar_id,omitempty"`
	KeyVersion  uint32 `json:"key_version"`
}

type Public struct {
	Version       int    `json:"version"`
	Ref           Ref    `json:"ref"`
	SignPubkeyB58 string `json:"sign_pubkey_b58"`
	BoxPubkeyB58  string `json:"box_pubkey_b58"`
}

type Private struct {
	ref    Ref
	sign   ed25519.PrivateKey
	signPk [32]byte
	box    *ecdh.PrivateKey
	boxPk  [32]byte
}

func NewPrivate(ref Ref, signSeed, boxSeed [32]byte) (*Private, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	sign := ed25519.NewKeyFromSeed(signSeed[:])
	var signPk [32]byte
	copy(signPk[:], sign.Public().(ed25519.PublicKey))
	box, err := ecdh.X25519().NewPrivateKey(boxSeed[:])
	if err != nil {
		return nil, fmt.Errorf("attest identity: x25519 private key: %w", err)
	}
	var boxPk [32]byte
	copy(boxPk[:], box.PublicKey().Bytes())
	return &Private{ref: ref, sign: sign, signPk: signPk, box: box, boxPk: boxPk}, nil
}

func (r Ref) Validate() error {
	if r.Kind != KindPearl && r.Kind != KindSidecar {
		return fmt.Errorf("attest identity: unsupported kind %q", r.Kind)
	}
	for name, value := range map[string]string{
		"chain_id":     r.ChainID,
		"program_id":   r.ProgramID,
		"license_mint": r.LicenseMint,
		"domain":       r.Domain,
		"pda":          r.PDA,
	} {
		if value == "" {
			return fmt.Errorf("attest identity: %s is required", name)
		}
	}
	if r.Kind == KindSidecar {
		if err := primitives.ValidateSidecarID(r.SidecarID); err != nil {
			return err
		}
	}
	if r.Kind == KindPearl && r.PearlIDHash == "" {
		return errors.New("attest identity: pearl requires pearl_id_hash")
	}
	return nil
}

func (p *Private) Public() Public {
	return Public{
		Version:       CurrentVersion,
		Ref:           p.ref,
		SignPubkeyB58: primitives.EncodeBase58(p.signPk[:]),
		BoxPubkeyB58:  primitives.EncodeBase58(p.boxPk[:]),
	}
}

func (p *Private) Sign(message []byte) []byte {
	return ed25519.Sign(p.sign, message)
}

func (p *Private) BoxPrivateKey() *ecdh.PrivateKey {
	return p.box
}

func (p Public) Verify(message, signature []byte) bool {
	pub, err := p.SignPublicKey()
	if err != nil {
		return false
	}
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, message, signature)
}

func (p Public) Validate() error {
	if p.Version != CurrentVersion {
		return fmt.Errorf("attest identity: unsupported public version %d", p.Version)
	}
	if err := p.Ref.Validate(); err != nil {
		return err
	}
	if _, err := p.SignPublicKey(); err != nil {
		return err
	}
	if _, err := p.BoxPublicKey(); err != nil {
		return err
	}
	return nil
}

func (p Public) SignPublicKey() (ed25519.PublicKey, error) {
	raw, err := decodeB58Len(p.SignPubkeyB58, ed25519.PublicKeySize, "sign_pubkey_b58")
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(raw), nil
}

func (p Public) BoxPublicKey() (*ecdh.PublicKey, error) {
	raw, err := decodeB58Len(p.BoxPubkeyB58, 32, "box_pubkey_b58")
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// Digest is sha256 over the canonical length-prefixed, domain-tagged encoding
// of Public (§4.5). It MUST NOT depend on a JSON encoder, and the JSON-marshal
// path is DELETED, not deprecated.
//
// WHY, stated once so nobody reintroduces it: Go's encoding/json HTML-escapes
// `<`, `>` and `&` (to <, >, &); Python's
// json.dumps(ensure_ascii=False) and JavaScript's JSON.stringify do not. A
// JSON-marshal digest therefore agrees across Go/Python/TypeScript only on
// ASCII-safe data — the Python port's own comment conceded exactly that. And
// because envelope.CanonicalPayload binds Source.DigestHex()/
// Destination.DigestHex(), that divergence is not identity-local: it forks the
// canonical bytes of EVERY envelope, and surfaces at a relying party as a bare
// hash mismatch with no diagnostic (R-36). This is the latent, silent,
// cross-language class the programme exists to stop, so the encoder is bound
// to `canonical` — the same primitive every other contract uses (§4.1, Rule 5:
// one encoding, one contract).
//
// Field order is FROZEN and matches the Ref/Public declaration order above.
// §4.6's extension rule applies: append only, never insert; bump this tag and
// delete the prior emitter in the same change; emit every field
// unconditionally (zero-length when absent) so the canonical bytes never
// depend on content.
func (p Public) Digest() [32]byte {
	return sha256.Sum256(canonical.Encode(DigestDomainTag, []string{
		canonical.Int(int64(p.Version)),
		string(p.Ref.Kind),
		p.Ref.ChainID,
		p.Ref.ProgramID,
		p.Ref.LicenseMint,
		p.Ref.Domain,
		p.Ref.PDA,
		p.Ref.AppHashHex,
		p.Ref.PearlIDHash,
		p.Ref.SidecarID,
		canonical.Uint(uint64(p.Ref.KeyVersion)),
		p.SignPubkeyB58,
		p.BoxPubkeyB58,
	}))
}

func (p Public) DigestHex() string {
	d := p.Digest()
	return hex.EncodeToString(d[:])
}

func ParsePublicJSON(b []byte) (Public, error) {
	var p Public
	if err := json.Unmarshal(b, &p); err != nil {
		return Public{}, err
	}
	return p, p.Validate()
}

func decodeB58Len(s string, n int, field string) ([]byte, error) {
	raw, err := primitives.DecodeBase58(s)
	if err != nil {
		return nil, fmt.Errorf("attest identity: decode %s: %w", field, err)
	}
	if len(raw) != n {
		return nil, fmt.Errorf("attest identity: %s must be %d bytes, got %d", field, n, len(raw))
	}
	return raw, nil
}
