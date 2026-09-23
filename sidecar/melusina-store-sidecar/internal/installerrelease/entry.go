// Package installerrelease is the Store's one reader of the license-registry
// InstallerReleaseEntry account (PDA ["installer_release", master_nft_mint,
// installer_hash]) and its one admission rule.
//
// Since contracts K3 (melusina-os-smartcontract 1f4c783, 08c32e6) the program
// lets only the master NFT custodian register, revoke or supersede an entry,
// and the entry records the Ed25519 publisher key the program verified, that
// key's signature and the signed 32-byte digest. The program does not decide
// which publisher an estate trusts; its owners do, in the signed estate
// profile's releaseTrust. Admit is where the Store holds an entry to that.
//
// Decode reads exactly the account the program writes: the Anchor
// discriminator, exactly LEN bytes, every field in declaration order, closed
// enum and Option tags, and zero padding after the last field. The layout
// before K3 (191 bytes, no publisher binding) is refused by size, never read
// as a prefix. testdata/license-registry-excerpt.rs holds the Rust source this
// is checked against.
package installerrelease

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

const (
	// AccountName is the Rust type name; the Anchor discriminator is
	// sha256("account:" + AccountName)[:8].
	AccountName = "InstallerReleaseEntry"
	// MaxVersionLen is constants.rs MAX_RELEASE_VERSION_LEN.
	MaxVersionLen = 32
	// Len is InstallerReleaseEntry::LEN, the exact size of every entry: the
	// program creates it with `space = LEN` and no instruction reallocates it.
	Len = 8 + 32 + 32 + (4 + MaxVersionLen) + 32 + 32 + 8 + 1 + 32 + 64 + 32 + (1 + 8) + 1
	// PayloadDomain is the first hashv input of installer_release_payload_hash.
	PayloadDomain = "melusina-installer-release-v1"
)

// Field is one struct field as the Rust source declares it.
type Field struct {
	Name string
	Type string
}

// Layout is the struct's fields in declaration order, with their Rust types.
// Decode walks exactly this list; a test compares it with the Rust source.
var Layout = []Field{
	{"master_nft_mint", "Pubkey"},
	{"installer_hash", "[u8; 32]"},
	{"version", "String"},
	{"publisher_squads_vault", "Pubkey"},
	{"registered_by", "Pubkey"},
	{"registered_at", "i64"},
	{"status", "AttestationStatus"},
	{"publisher_ed25519_pubkey", "[u8; 32]"},
	{"publisher_signature", "[u8; 64]"},
	{"signed_payload_hash", "[u8; 32]"},
	{"revoked_at", "Option<i64>"},
	{"bump", "u8"},
}

// Refusals. Every error Decode or Admit returns wraps exactly one of these,
// and its text starts with the name.
var (
	ErrMalformed           = errors.New("installer-release-entry-malformed")
	ErrNotActive           = errors.New("installer-release-not-active")
	ErrHashMismatch        = errors.New("installer-release-hash-mismatch")
	ErrMasterMismatch      = errors.New("installer-release-master-mismatch")
	ErrCustodianMismatch   = errors.New("installer-release-custodian-mismatch")
	ErrPayloadHashMismatch = errors.New("installer-release-payload-hash-mismatch")
	ErrPublisherUntrusted  = errors.New("installer-release-publisher-untrusted")
	ErrThresholdUnmet      = errors.New("installer-release-publisher-threshold-unmet")
	ErrSignatureInvalid    = errors.New("installer-release-signature-invalid")
	ErrTrustUnconfigured   = errors.New("installer-release-trust-unconfigured")
)

// Entry is a decoded InstallerReleaseEntry, every field.
type Entry struct {
	MasterNFTMint          [32]byte
	InstallerHash          [32]byte
	Version                string
	PublisherSquadsVault   [32]byte
	RegisteredBy           [32]byte
	RegisteredAt           int64
	Status                 verify.AttestationStatus
	PublisherEd25519Pubkey [32]byte
	PublisherSignature     [64]byte
	SignedPayloadHash      [32]byte
	// RevokedAt is nil for None.
	RevokedAt *int64
	Bump      uint8
}

// Discriminator returns sha256("account:InstallerReleaseEntry")[:8].
func Discriminator() [8]byte {
	sum := sha256.Sum256([]byte("account:" + AccountName))
	var out [8]byte
	copy(out[:], sum[:8])
	return out
}

type reader struct {
	data   []byte
	offset int
}

func (r *reader) take(field string, n int) ([]byte, error) {
	if n < 0 || r.offset+n > len(r.data) {
		return nil, fmt.Errorf("%w:%s: truncated", ErrMalformed, field)
	}
	out := r.data[r.offset : r.offset+n]
	r.offset += n
	return out, nil
}

func (r *reader) fixed(field string, dst []byte) error {
	raw, err := r.take(field, len(dst))
	if err != nil {
		return err
	}
	copy(dst, raw)
	return nil
}

func (r *reader) byteValue(field string) (byte, error) {
	raw, err := r.take(field, 1)
	if err != nil {
		return 0, err
	}
	return raw[0], nil
}

func (r *reader) i64(field string) (int64, error) {
	raw, err := r.take(field, 8)
	if err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(raw)), nil
}

// Decode reads data as an InstallerReleaseEntry account. It does not judge
// the entry; Admit does.
func Decode(data []byte) (Entry, error) {
	var e Entry
	disc := Discriminator()
	if len(data) < len(disc) || !bytes.Equal(data[:len(disc)], disc[:]) {
		return e, fmt.Errorf("%w:discriminator: account is not an %s", ErrMalformed, AccountName)
	}
	if len(data) != Len {
		return e, fmt.Errorf("%w:size: account is %d bytes, not the %d-byte %s::LEN (another account layout)", ErrMalformed, len(data), Len, AccountName)
	}
	r := &reader{data: data, offset: len(disc)}
	if err := r.fixed("master_nft_mint", e.MasterNFTMint[:]); err != nil {
		return Entry{}, err
	}
	if err := r.fixed("installer_hash", e.InstallerHash[:]); err != nil {
		return Entry{}, err
	}
	lenRaw, err := r.take("version", 4)
	if err != nil {
		return Entry{}, err
	}
	versionLen := binary.LittleEndian.Uint32(lenRaw)
	if versionLen > MaxVersionLen {
		return Entry{}, fmt.Errorf("%w:version: %d bytes exceeds MAX_RELEASE_VERSION_LEN %d", ErrMalformed, versionLen, MaxVersionLen)
	}
	version, err := r.take("version", int(versionLen))
	if err != nil {
		return Entry{}, err
	}
	if !utf8.Valid(version) {
		return Entry{}, fmt.Errorf("%w:version: not UTF-8", ErrMalformed)
	}
	e.Version = string(version)
	if err := r.fixed("publisher_squads_vault", e.PublisherSquadsVault[:]); err != nil {
		return Entry{}, err
	}
	if err := r.fixed("registered_by", e.RegisteredBy[:]); err != nil {
		return Entry{}, err
	}
	if e.RegisteredAt, err = r.i64("registered_at"); err != nil {
		return Entry{}, err
	}
	status, err := r.byteValue("status")
	if err != nil {
		return Entry{}, err
	}
	if status > uint8(verify.AttestationStatusSuperseded) {
		return Entry{}, fmt.Errorf("%w:status: unknown AttestationStatus %d", ErrMalformed, status)
	}
	e.Status = verify.AttestationStatus(status)
	if err := r.fixed("publisher_ed25519_pubkey", e.PublisherEd25519Pubkey[:]); err != nil {
		return Entry{}, err
	}
	if err := r.fixed("publisher_signature", e.PublisherSignature[:]); err != nil {
		return Entry{}, err
	}
	if err := r.fixed("signed_payload_hash", e.SignedPayloadHash[:]); err != nil {
		return Entry{}, err
	}
	tag, err := r.byteValue("revoked_at")
	if err != nil {
		return Entry{}, err
	}
	switch tag {
	case 0:
	case 1:
		revokedAt, err := r.i64("revoked_at")
		if err != nil {
			return Entry{}, err
		}
		e.RevokedAt = &revokedAt
	default:
		return Entry{}, fmt.Errorf("%w:revoked_at: Option tag %d", ErrMalformed, tag)
	}
	if e.Bump, err = r.byteValue("bump"); err != nil {
		return Entry{}, err
	}
	// The program serializes the struct from offset 0 of a zeroed LEN-byte
	// account and no field ever shrinks, so everything after the last field
	// is zero. Anything else was not written by this layout.
	for i := r.offset; i < len(data); i++ {
		if data[i] != 0 {
			return Entry{}, fmt.Errorf("%w:padding: non-zero byte at offset %d after the last field", ErrMalformed, i)
		}
	}
	return e, nil
}

// PayloadHash is installer_release_payload_hash: sha256 over the domain,
// master mint, installer hash, version bytes, publisher Squads vault and
// publisher key, concatenated.
func PayloadHash(masterNFTMint, installerHash [32]byte, version string, publisherSquadsVault, publisherKey [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(PayloadDomain))
	h.Write(masterNFTMint[:])
	h.Write(installerHash[:])
	h.Write([]byte(version))
	h.Write(publisherSquadsVault[:])
	h.Write(publisherKey[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Trust is what an estate's owners decided about installer releases: the
// master mint that seeds every entry, the master NFT custodian (the profile's
// core vault) that alone registers one, and the publisher keys and threshold
// of the profile's releaseTrust. It holds no private key.
type Trust struct {
	masterNFTMint [32]byte
	custodian     [32]byte
	publishers    map[[32]byte]struct{}
	threshold     uint32
}

// NewTrust builds a Trust. Every argument is required; an empty publisher set
// or a zero threshold is refused.
func NewTrust(masterNFTMint, custodian [32]byte, publisherKeys [][32]byte, threshold uint32) (*Trust, error) {
	if masterNFTMint == ([32]byte{}) {
		return nil, fmt.Errorf("%w: no master NFT mint", ErrTrustUnconfigured)
	}
	if custodian == ([32]byte{}) {
		return nil, fmt.Errorf("%w: no master NFT custodian", ErrTrustUnconfigured)
	}
	if len(publisherKeys) == 0 {
		return nil, fmt.Errorf("%w: no publisher key", ErrTrustUnconfigured)
	}
	if threshold == 0 {
		return nil, fmt.Errorf("%w: zero publisher threshold", ErrTrustUnconfigured)
	}
	publishers := make(map[[32]byte]struct{}, len(publisherKeys))
	for _, key := range publisherKeys {
		if key == ([32]byte{}) {
			return nil, fmt.Errorf("%w: zero publisher key", ErrTrustUnconfigured)
		}
		publishers[key] = struct{}{}
	}
	return &Trust{masterNFTMint: masterNFTMint, custodian: custodian, publishers: publishers, threshold: threshold}, nil
}

// MasterNFTMint is the mint every admitted entry must name.
func (t *Trust) MasterNFTMint() [32]byte { return t.masterNFTMint }

// Admit accepts e as the authority for installerHash, or refuses by name. It
// checks, in order: Active with no revocation time, the hash, the master
// mint, the custodian (registered_by == publisher_squads_vault == the core
// vault), the recorded digest against one recomputed from the entry's own
// fields, the publisher key against releaseTrust.publisherKeys, the
// threshold (an entry records ONE publisher signature), and that signature
// over the digest.
func (t *Trust) Admit(e Entry, installerHash [32]byte) error {
	if t == nil || len(t.publishers) == 0 {
		return fmt.Errorf("%w: no estate release trust is bound", ErrTrustUnconfigured)
	}
	if e.Status != verify.AttestationStatusActive {
		return fmt.Errorf("%w: status %s", ErrNotActive, e.Status)
	}
	if e.RevokedAt != nil {
		return fmt.Errorf("%w:revoked_at: an Active entry records a revocation time", ErrMalformed)
	}
	if e.InstallerHash != installerHash {
		return fmt.Errorf("%w: entry installer_hash %x != artifact %x", ErrHashMismatch, e.InstallerHash[:], installerHash[:])
	}
	if e.MasterNFTMint != t.masterNFTMint {
		return fmt.Errorf("%w: entry master_nft_mint %x is not the estate master mint %x", ErrMasterMismatch, e.MasterNFTMint[:], t.masterNFTMint[:])
	}
	if e.RegisteredBy != e.PublisherSquadsVault {
		return fmt.Errorf("%w: registered_by %x != publisher_squads_vault %x", ErrCustodianMismatch, e.RegisteredBy[:], e.PublisherSquadsVault[:])
	}
	if e.PublisherSquadsVault != t.custodian {
		return fmt.Errorf("%w: publisher_squads_vault %x is not the estate core vault %x", ErrCustodianMismatch, e.PublisherSquadsVault[:], t.custodian[:])
	}
	if want := PayloadHash(e.MasterNFTMint, e.InstallerHash, e.Version, e.PublisherSquadsVault, e.PublisherEd25519Pubkey); e.SignedPayloadHash != want {
		return fmt.Errorf("%w: signed_payload_hash %x != recomputed %x", ErrPayloadHashMismatch, e.SignedPayloadHash[:], want[:])
	}
	if _, ok := t.publishers[e.PublisherEd25519Pubkey]; !ok {
		return fmt.Errorf("%w: publisher key %x is not in the estate profile's releaseTrust.publisherKeys", ErrPublisherUntrusted, e.PublisherEd25519Pubkey[:])
	}
	if t.threshold > 1 {
		return fmt.Errorf("%w: the entry records one publisher signature; releaseTrust.threshold is %d", ErrThresholdUnmet, t.threshold)
	}
	if !ed25519.Verify(ed25519.PublicKey(e.PublisherEd25519Pubkey[:]), e.SignedPayloadHash[:], e.PublisherSignature[:]) {
		return fmt.Errorf("%w: publisher %x", ErrSignatureInvalid, e.PublisherEd25519Pubkey[:])
	}
	return nil
}
