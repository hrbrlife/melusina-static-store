package verify

// blacklist_status.go — THE one reader of the license registry's blacklist.
//
// The greenfield program keeps an explicit, always-present status per target
// (contracts programs/license-registry/src/state/blacklist_status.rs): one
// BlacklistStatusEntry at ["blacklist_status", kind seed, target]. In the
// program's own words, "A missing account is not a cryptographic statement.
// Consumers MUST require this account to exist and to contain
// BlacklistStatus::Clear before a positive authorization decision. There is
// deliberately no legacy absence-means-clear representation in the greenfield
// program."
//
// So this file reads exactly that account, with the rules the authorization
// daemon (authz pkg/grainauth/control_facts.go DecodeBlacklistStatus) and the
// Store (melusina-store-sidecar/blacklist_status.go) apply, and there is no
// other blacklist reader in this module: the legacy [blacklist, target]
// account, whose absence the old readers treated as clear, is a PDA the
// greenfield program never creates, and its readers are deleted.
//
// The decision is RequireBlacklistClear. Only a present account, owned by the
// registry, that decodes exactly, is the canonical record of the requested kind
// and target (canonical bump included), and reads Clear, is a clearance.
// Absent, Blocked, foreign-owned, malformed and non-canonical accounts are each
// refused, by errors.Is-matchable cause.
//
// PDA derivation needs the Ed25519 curve check, which this dependency-free
// module does not carry: derive the address and canonical bump with
// melusina-solana-primitives DeriveBlacklistStatus (or melusina-attest
// pda.BlacklistStatus) and pass the bump in.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// BlacklistType is the program's BlacklistType: the identity namespace of a
// blacklist target. Its wire values are the consumer ABI and stay ordered
// (License=0, App=1, Author=2); melusina-solana-primitives BlacklistStatusKindSeed
// maps each to its PDA seed.
type BlacklistType uint8

const (
	// BlacklistTypeLicense: the target is the licence NFT mint's key.
	BlacklistTypeLicense BlacklistType = 0
	// BlacklistTypeApp: the target is the decoded, stable 32-byte Sandstorm
	// appId — not SHA-256 of the appId text (ReleaseEntry.app_id), not a
	// release hash, and never the Foundation master NFT mint.
	BlacklistTypeApp BlacklistType = 1
	// BlacklistTypeAuthor: the target is the author's key.
	BlacklistTypeAuthor BlacklistType = 2
)

func (t BlacklistType) String() string {
	switch t {
	case BlacklistTypeLicense:
		return "License"
	case BlacklistTypeApp:
		return "App"
	case BlacklistTypeAuthor:
		return "Author"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(t))
	}
}

// BlacklistStatus is the program's BlacklistStatus (Clear=0, Blocked=1). Only
// a present, canonical Clear is affirmative evidence that a target is not
// blacklisted.
type BlacklistStatus uint8

const (
	BlacklistStatusClear   BlacklistStatus = 0
	BlacklistStatusBlocked BlacklistStatus = 1
)

func (s BlacklistStatus) String() string {
	switch s {
	case BlacklistStatusClear:
		return "Clear"
	case BlacklistStatusBlocked:
		return "Blocked"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// BlacklistStatusEntryLen is BlacklistStatusEntry::LEN, discriminator included.
const BlacklistStatusEntryLen = 131

// DiscriminatorBlacklistStatusEntry is Anchor's account discriminator for
// BlacklistStatusEntry: the first 8 bytes of SHA-256("account:BlacklistStatusEntry").
var DiscriminatorBlacklistStatusEntry = func() (d [8]byte) {
	sum := sha256.Sum256([]byte("account:BlacklistStatusEntry"))
	copy(d[:], sum[:8])
	return d
}()

// BlacklistStatusEntry is one decoded BlacklistStatusEntry. The fixed layout
// (contracts state/blacklist_status.rs) is:
//
//	discriminator    0..8
//	entry_type       8..9
//	target           9..41
//	status          41..42
//	reason_hash     42..74
//	revision        74..82   u64 LE
//	last_nonce      82..90   u64 LE
//	updated_by      90..122
//	updated_at     122..130  i64 LE
//	bump                 130
type BlacklistStatusEntry struct {
	Kind       BlacklistType
	Target     [32]byte
	Status     BlacklistStatus
	ReasonHash [32]byte
	Revision   uint64
	LastNonce  uint64
	UpdatedBy  [32]byte
	UpdatedAt  int64
	Bump       uint8
}

var (
	// ErrBlacklistStatusForeignOwner: the account at a clearance address is
	// not owned by the license registry. Anyone can fund any address; an
	// account the program does not own is not the record the address names.
	ErrBlacklistStatusForeignOwner = errors.New("blacklist status: account is not owned by the license registry")
	// ErrBlacklistStatusNotCanonical: the record is not the canonical record
	// of the requested kind and target (another kind or target, or a
	// non-canonical bump).
	ErrBlacklistStatusNotCanonical = errors.New("blacklist status: not the canonical record of this kind and target")
	// ErrBlacklistBlocked: the registry records the target as Blocked.
	ErrBlacklistBlocked = errors.New("blacklist status: Blocked")
)

// validate applies the program's invariants for a written record, with the
// authz decoder's rules: in-range kind and status, a nonzero target, a zero
// reason hash exactly when Clear, and nonzero revision, last_nonce and
// updated_by. Every record set_blacklist_status writes satisfies them.
func (e BlacklistStatusEntry) validate() error {
	if e.Kind > BlacklistTypeAuthor {
		return fmt.Errorf("%w: blacklist status: invalid entry_type %d", ErrBorshDecode, uint8(e.Kind))
	}
	if e.Target == ([32]byte{}) {
		return fmt.Errorf("%w: blacklist status: target is missing", ErrBorshDecode)
	}
	if e.Status > BlacklistStatusBlocked {
		return fmt.Errorf("%w: blacklist status: invalid status %d", ErrBorshDecode, uint8(e.Status))
	}
	if (e.Status == BlacklistStatusClear) != (e.ReasonHash == [32]byte{}) {
		return fmt.Errorf("%w: blacklist status: Clear requires a zero reason hash and Blocked a nonzero one", ErrBorshDecode)
	}
	if e.Revision == 0 {
		return fmt.Errorf("%w: blacklist status: revision must be nonzero", ErrBorshDecode)
	}
	if e.LastNonce == 0 {
		return fmt.Errorf("%w: blacklist status: last_nonce must be nonzero", ErrBorshDecode)
	}
	if e.UpdatedBy == ([32]byte{}) {
		return fmt.Errorf("%w: blacklist status: updated_by must be nonzero", ErrBorshDecode)
	}
	return nil
}

// DecodeBlacklistStatusEntry decodes a BlacklistStatusEntry account exactly:
// 131 bytes (so no trailing bytes), the type's discriminator, and the record
// invariants. Any other shape is an ErrBorshDecode.
func DecodeBlacklistStatusEntry(data []byte) (BlacklistStatusEntry, error) {
	if len(data) != BlacklistStatusEntryLen {
		return BlacklistStatusEntry{}, fmt.Errorf("%w: blacklist status: account length %d != %d", ErrBorshDecode, len(data), BlacklistStatusEntryLen)
	}
	if [8]byte(data[:8]) != DiscriminatorBlacklistStatusEntry {
		return BlacklistStatusEntry{}, fmt.Errorf("%w: blacklist status: discriminator mismatch", ErrBorshDecode)
	}
	e := BlacklistStatusEntry{
		Kind:      BlacklistType(data[8]),
		Target:    [32]byte(data[9:41]),
		Status:    BlacklistStatus(data[41]),
		Revision:  binary.LittleEndian.Uint64(data[74:82]),
		LastNonce: binary.LittleEndian.Uint64(data[82:90]),
		UpdatedAt: int64(binary.LittleEndian.Uint64(data[122:130])),
		Bump:      data[130],
	}
	e.ReasonHash = [32]byte(data[42:74])
	e.UpdatedBy = [32]byte(data[90:122])
	if err := e.validate(); err != nil {
		return BlacklistStatusEntry{}, err
	}
	return e, nil
}

// EncodeBlacklistStatusEntry is the inverse of DecodeBlacklistStatusEntry: the
// 131 bytes the program stores for e. It writes whatever it is given; it exists
// so fixtures and tools build real account bytes, which every reader then
// decodes through DecodeBlacklistStatusEntry.
func EncodeBlacklistStatusEntry(e BlacklistStatusEntry) []byte {
	b := make([]byte, BlacklistStatusEntryLen)
	copy(b[:8], DiscriminatorBlacklistStatusEntry[:])
	b[8] = uint8(e.Kind)
	copy(b[9:41], e.Target[:])
	b[41] = uint8(e.Status)
	copy(b[42:74], e.ReasonHash[:])
	binary.LittleEndian.PutUint64(b[74:82], e.Revision)
	binary.LittleEndian.PutUint64(b[82:90], e.LastNonce)
	copy(b[90:122], e.UpdatedBy[:])
	binary.LittleEndian.PutUint64(b[122:130], uint64(e.UpdatedAt))
	b[130] = e.Bump
	return b
}

// RequireBlacklistClear is THE clearance decision over one fetched account:
// account is what the RPC returned at the address derived for (kind, target)
// under registryProgramB58, and canonicalBump is that derivation's bump.
//
// It returns the decoded entry only when the target is affirmatively Clear:
//
//	nil account          ErrPDANotFound       absence is not a clearance statement
//	foreign owner        ErrBlacklistStatusForeignOwner
//	malformed bytes      ErrBorshDecode
//	other kind/target    ErrBlacklistStatusNotCanonical
//	non-canonical bump   ErrBlacklistStatusNotCanonical
//	Blocked              ErrBlacklistBlocked
//
// An empty registryProgramB58 is refused: without the program there is no
// owner to check against.
func RequireBlacklistClear(account *Account, registryProgramB58 string, kind BlacklistType, target [32]byte, canonicalBump uint8) (BlacklistStatusEntry, error) {
	if registryProgramB58 == "" {
		return BlacklistStatusEntry{}, errors.New("blacklist status: no license registry program to check the owner against")
	}
	if account == nil {
		return BlacklistStatusEntry{}, fmt.Errorf("%w: no BlacklistStatusEntry for %s target %x; an absent record is not Clear", ErrPDANotFound, kind, target[:])
	}
	if account.Owner != registryProgramB58 {
		return BlacklistStatusEntry{}, fmt.Errorf("%w: owner %q, registry %s", ErrBlacklistStatusForeignOwner, account.Owner, registryProgramB58)
	}
	entry, err := DecodeBlacklistStatusEntry(account.Data)
	if err != nil {
		return BlacklistStatusEntry{}, err
	}
	if err := CheckBlacklistClear(entry, kind, target, canonicalBump); err != nil {
		return BlacklistStatusEntry{}, err
	}
	return entry, nil
}

// CheckBlacklistClear applies RequireBlacklistClear's decision to an entry
// already decoded from a registry-owned account (a batched read, say). It
// re-checks the record invariants, so a hand-built entry cannot skip them.
func CheckBlacklistClear(entry BlacklistStatusEntry, kind BlacklistType, target [32]byte, canonicalBump uint8) error {
	if err := entry.validate(); err != nil {
		return err
	}
	if entry.Kind != kind || entry.Target != target {
		return fmt.Errorf("%w: the record is %s %x, not %s %x", ErrBlacklistStatusNotCanonical, entry.Kind, entry.Target[:], kind, target[:])
	}
	if entry.Bump != canonicalBump {
		return fmt.Errorf("%w: the record's bump is %d, the canonical bump is %d", ErrBlacklistStatusNotCanonical, entry.Bump, canonicalBump)
	}
	switch entry.Status {
	case BlacklistStatusClear:
		return nil
	case BlacklistStatusBlocked:
		return fmt.Errorf("%w: %s target %x (revision %d)", ErrBlacklistBlocked, kind, target[:], entry.Revision)
	default: // unreachable: validate bounds the status
		return fmt.Errorf("%w: blacklist status: invalid status %d", ErrBorshDecode, uint8(entry.Status))
	}
}
