// Package releaseentry is the release tools' reader of the license-registry
// ReleaseEntry account, the on-chain attestation of one app release (PDA
// ["release_v2", master_nft_mint, app_hash]), and its one admission rule.
//
// `mel-release approve` registers no entry and approves or executes no
// register proposal. The owner-authorized runner registers each ReleaseEntry
// through the master NFT custodian's vault (spec R5: one governed vault
// transaction per entry), and approve reads the entry back and admits it here
// before it promotes anything. Admission holds
// the entry to the release the approver froze at publish (app_hash, app_id,
// release_hash, version), to the estate (master mint and release custodian),
// and to the publisher the estate's owners enrolled in the signed profile's
// releaseTrust: the program verifies an Ed25519 signature by whichever key
// the registration names, and this is where a key the owners never enrolled
// is refused (the app-release counterpart of the installer-release rule,
// contracts K3).
//
// Decode reads exactly the account the program writes: the Anchor
// discriminator, exactly LEN bytes (the program creates the account with
// `space = ReleaseEntry::LEN` and no instruction reallocates it), every field
// in declaration order, closed enum and Option tags, and zero padding after
// the last field. testdata/license-registry-excerpt.rs holds the Rust source
// this is checked against.
package releaseentry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	// AccountName is the Rust type name; the Anchor discriminator is
	// sha256("account:" + AccountName)[:8].
	AccountName = "ReleaseEntry"
	// MaxVersionLen is constants.rs MAX_RELEASE_VERSION_LEN.
	MaxVersionLen = 32
	// Len is ReleaseEntry::LEN, the exact size of every entry.
	Len = 8 + 32 + 32 + 32 + 32 + (4 + MaxVersionLen) + 32 + 32 + 64 + 32 + 32 + 8 + 1 + (1 + 8) + 1
	// PayloadDomain is the first hashv input of release_payload_hash.
	PayloadDomain = "melusina-release-entry-v1"
)

// Status is the program's AttestationStatus, as its Borsh ordinal.
type Status uint8

const (
	StatusActive     Status = 0
	StatusRevoked    Status = 1
	StatusSuperseded Status = 2
)

func (s Status) String() string {
	switch s {
	case StatusActive:
		return "Active"
	case StatusRevoked:
		return "Revoked"
	case StatusSuperseded:
		return "Superseded"
	default:
		return fmt.Sprintf("AttestationStatus(%d)", uint8(s))
	}
}

// Field is one struct field as the Rust source declares it.
type Field struct {
	Name string
	Type string
}

// Layout is the struct's fields in declaration order, with their Rust types.
// Decode walks exactly this list; a test compares it with the Rust source.
var Layout = []Field{
	{"master_nft_mint", "Pubkey"},
	{"app_hash", "[u8; 32]"},
	{"app_id", "[u8; 32]"},
	{"release_hash", "[u8; 32]"},
	{"version", "String"},
	{"publisher_squads_vault", "Pubkey"},
	{"publisher_ed25519_pubkey", "[u8; 32]"},
	{"signature", "[u8; 64]"},
	{"signed_payload_hash", "[u8; 32]"},
	{"registered_by", "Pubkey"},
	{"registered_at", "i64"},
	{"status", "AttestationStatus"},
	{"revoked_at", "Option<i64>"},
	{"bump", "u8"},
}

// Refusals. Every error Decode or Admit returns wraps exactly one of these,
// and its text starts with the name. ErrMissing and ErrOwnerMismatch are for
// the caller that reads the account: no account at the derived address, or
// an account another program owns.
var (
	ErrMissing               = errors.New("release-entry-missing")
	ErrOwnerMismatch         = errors.New("release-entry-owner-mismatch")
	ErrMalformed             = errors.New("release-entry-malformed")
	ErrRecalled              = errors.New("release-entry-recalled")
	ErrMasterMismatch        = errors.New("release-entry-master-mismatch")
	ErrAppHashMismatch       = errors.New("release-entry-app-hash-mismatch")
	ErrAppIDMismatch         = errors.New("release-entry-app-id-mismatch")
	ErrReleaseHashMismatch   = errors.New("release-entry-release-hash-mismatch")
	ErrVersionMismatch       = errors.New("release-entry-version-mismatch")
	ErrCustodianMismatch     = errors.New("release-entry-custodian-mismatch")
	ErrPayloadHashMismatch   = errors.New("release-entry-payload-hash-mismatch")
	ErrPublisherUntrusted    = errors.New("release-entry-publisher-untrusted")
	ErrThresholdUnmet        = errors.New("release-entry-publisher-threshold-unmet")
	ErrSignatureInvalid      = errors.New("release-entry-signature-invalid")
	ErrTrustUnconfigured     = errors.New("release-entry-trust-unconfigured")
	ErrExpectationIncomplete = errors.New("release-entry-expectation-incomplete")
)

// Entry is a decoded ReleaseEntry, every field.
type Entry struct {
	MasterNFTMint          [32]byte
	AppHash                [32]byte
	AppID                  [32]byte
	ReleaseHash            [32]byte
	Version                string
	PublisherSquadsVault   [32]byte
	PublisherEd25519Pubkey [32]byte
	Signature              [64]byte
	SignedPayloadHash      [32]byte
	RegisteredBy           [32]byte
	RegisteredAt           int64
	Status                 Status
	// RevokedAt is nil for None.
	RevokedAt *int64
	Bump      uint8
}

// Discriminator returns sha256("account:ReleaseEntry")[:8].
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

// Decode reads data as a ReleaseEntry account. It does not judge the entry;
// Admit does.
func Decode(data []byte) (Entry, error) {
	var e Entry
	disc := Discriminator()
	if len(data) < len(disc) || !bytes.Equal(data[:len(disc)], disc[:]) {
		return e, fmt.Errorf("%w:discriminator: account is not a %s", ErrMalformed, AccountName)
	}
	if len(data) != Len {
		return e, fmt.Errorf("%w:size: account is %d bytes, not the %d-byte %s::LEN (another account layout)", ErrMalformed, len(data), Len, AccountName)
	}
	r := &reader{data: data, offset: len(disc)}
	for _, step := range []struct {
		name string
		dst  []byte
	}{
		{"master_nft_mint", e.MasterNFTMint[:]},
		{"app_hash", e.AppHash[:]},
		{"app_id", e.AppID[:]},
		{"release_hash", e.ReleaseHash[:]},
	} {
		if err := r.fixed(step.name, step.dst); err != nil {
			return Entry{}, err
		}
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
	for _, step := range []struct {
		name string
		dst  []byte
	}{
		{"publisher_squads_vault", e.PublisherSquadsVault[:]},
		{"publisher_ed25519_pubkey", e.PublisherEd25519Pubkey[:]},
		{"signature", e.Signature[:]},
		{"signed_payload_hash", e.SignedPayloadHash[:]},
		{"registered_by", e.RegisteredBy[:]},
	} {
		if err := r.fixed(step.name, step.dst); err != nil {
			return Entry{}, err
		}
	}
	if e.RegisteredAt, err = r.i64("registered_at"); err != nil {
		return Entry{}, err
	}
	status, err := r.byteValue("status")
	if err != nil {
		return Entry{}, err
	}
	if status > uint8(StatusSuperseded) {
		return Entry{}, fmt.Errorf("%w:status: unknown AttestationStatus %d", ErrMalformed, status)
	}
	e.Status = Status(status)
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

// PayloadHash is release_payload_hash: sha256 over the domain, master mint,
// app hash, app id, release hash, version bytes, publisher Squads vault and
// publisher key, concatenated.
func PayloadHash(masterNFTMint, appHash, appID, releaseHash [32]byte, version string, publisherSquadsVault, publisherKey [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(PayloadDomain))
	h.Write(masterNFTMint[:])
	h.Write(appHash[:])
	h.Write(appID[:])
	h.Write(releaseHash[:])
	h.Write([]byte(version))
	h.Write(publisherSquadsVault[:])
	h.Write(publisherKey[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// AppIDHash is the entry's app_id for a Sandstorm appId: sha256 of its text,
// the value the release tools register and list-active-releases filters by.
func AppIDHash(appID string) [32]byte { return sha256.Sum256([]byte(appID)) }

// Trust is what the estate decided about app release entries: the master
// mint that seeds every entry, the release custodian vault that alone
// registers one (the vault the Store checks served releases against), and the
// publisher keys and threshold of the owner-signed profile's releaseTrust. It
// holds no private key.
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
		return nil, fmt.Errorf("%w: no release custodian vault", ErrTrustUnconfigured)
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

// Expectation is the one release an approver froze at publish: the entry must
// attest exactly this, or it attests something else.
type Expectation struct {
	AppHash     [32]byte
	AppID       [32]byte
	ReleaseHash [32]byte
	Version     string
}

// Attests is the part of Admit that needs no estate trust: want names a
// complete release, and e attests exactly it (app_hash, app_id, release_hash
// and version). Admit runs it after the recall and master-mint checks. A
// caller with no enrolled estate profile, which therefore has no publisher
// keys to judge by, can still refuse a release the entry does not attest.
func (e Entry) Attests(want Expectation) error {
	if want.AppHash == ([32]byte{}) || want.AppID == ([32]byte{}) || want.ReleaseHash == ([32]byte{}) || want.Version == "" {
		return fmt.Errorf("%w: the frozen release names no app_hash, app_id, release_hash or version", ErrExpectationIncomplete)
	}
	if e.AppHash != want.AppHash {
		return fmt.Errorf("%w: entry app_hash %x != frozen release %x", ErrAppHashMismatch, e.AppHash[:], want.AppHash[:])
	}
	if e.AppID != want.AppID {
		return fmt.Errorf("%w: entry app_id %x != frozen release %x", ErrAppIDMismatch, e.AppID[:], want.AppID[:])
	}
	if e.ReleaseHash != want.ReleaseHash {
		return fmt.Errorf("%w: entry release_hash %x != frozen release %x", ErrReleaseHashMismatch, e.ReleaseHash[:], want.ReleaseHash[:])
	}
	if e.Version != want.Version {
		return fmt.Errorf("%w: entry version %q != frozen release %q", ErrVersionMismatch, e.Version, want.Version)
	}
	return nil
}

// Admit accepts e as the on-chain attestation of want, or refuses by name.
// It checks, in order: Active with no revocation time (a recalled entry is
// never admitted), the master mint, app_hash, app_id, release_hash and
// version (Attests), the custodian (registered_by == publisher_squads_vault
// == the estate's release custodian), the recorded digest against one
// recomputed from the entry's own fields, the publisher key against the
// estate's releaseTrust.publisherKeys, the threshold (an entry records ONE
// publisher signature), and that signature over the digest.
func (t *Trust) Admit(e Entry, want Expectation) error {
	if t == nil || len(t.publishers) == 0 {
		return fmt.Errorf("%w: no estate release trust is bound", ErrTrustUnconfigured)
	}
	if want.AppHash == ([32]byte{}) || want.AppID == ([32]byte{}) || want.ReleaseHash == ([32]byte{}) || want.Version == "" {
		return fmt.Errorf("%w: the frozen release names no app_hash, app_id, release_hash or version", ErrExpectationIncomplete)
	}
	if e.Status != StatusActive {
		return fmt.Errorf("%w: status %s", ErrRecalled, e.Status)
	}
	if e.RevokedAt != nil {
		return fmt.Errorf("%w: an Active entry records revoked_at %d", ErrRecalled, *e.RevokedAt)
	}
	if e.MasterNFTMint != t.masterNFTMint {
		return fmt.Errorf("%w: entry master_nft_mint %x is not the estate master mint %x", ErrMasterMismatch, e.MasterNFTMint[:], t.masterNFTMint[:])
	}
	if err := e.Attests(want); err != nil {
		return err
	}
	if e.RegisteredBy != e.PublisherSquadsVault {
		return fmt.Errorf("%w: registered_by %x != publisher_squads_vault %x", ErrCustodianMismatch, e.RegisteredBy[:], e.PublisherSquadsVault[:])
	}
	if e.PublisherSquadsVault != t.custodian {
		return fmt.Errorf("%w: publisher_squads_vault %x is not the estate release custodian %x", ErrCustodianMismatch, e.PublisherSquadsVault[:], t.custodian[:])
	}
	if got := PayloadHash(e.MasterNFTMint, e.AppHash, e.AppID, e.ReleaseHash, e.Version, e.PublisherSquadsVault, e.PublisherEd25519Pubkey); e.SignedPayloadHash != got {
		return fmt.Errorf("%w: signed_payload_hash %x != recomputed %x", ErrPayloadHashMismatch, e.SignedPayloadHash[:], got[:])
	}
	if _, ok := t.publishers[e.PublisherEd25519Pubkey]; !ok {
		return fmt.Errorf("%w: publisher key %x is not in the estate profile's releaseTrust.publisherKeys", ErrPublisherUntrusted, e.PublisherEd25519Pubkey[:])
	}
	if t.threshold > 1 {
		return fmt.Errorf("%w: the entry records one publisher signature; releaseTrust.threshold is %d", ErrThresholdUnmet, t.threshold)
	}
	if !ed25519.Verify(ed25519.PublicKey(e.PublisherEd25519Pubkey[:]), e.SignedPayloadHash[:], e.Signature[:]) {
		return fmt.Errorf("%w: publisher %x", ErrSignatureInvalid, e.PublisherEd25519Pubkey[:])
	}
	return nil
}
