package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The licence registry's blacklist is an explicit status per target
// (contracts programs/license-registry/src/state/blacklist_status.rs): one
// BlacklistStatusEntry at ["blacklist_status", kind seed, target]. A missing
// account is not a statement ("There is deliberately no legacy
// absence-means-clear representation in the greenfield program"), so the
// Store, like the authorization daemon (authz pkg/grainauth/control_facts.go),
// requires the account to exist, to be the program's canonical record of that
// kind and target, and to read Clear. Absent, Blocked, malformed, foreign-owned
// and wrong-identity accounts are each refused by name. There is no other
// blacklist representation: the legacy ["blacklist", target] account the
// program never creates is not read anywhere in this module
// (blacklist_status_test.go scans for it).

// blacklistStatusSeed is BLACKLIST_STATUS_SEED.
const blacklistStatusSeed = "blacklist_status"

// blacklistStatusEntryLen is BlacklistStatusEntry::LEN, discriminator included.
const blacklistStatusEntryLen = 131

// blacklistTargetKind is the program's BlacklistType. Its wire values are the
// consumer ABI (License=0, App=1, Author=2).
type blacklistTargetKind uint8

const (
	blacklistTargetLicense blacklistTargetKind = 0
	blacklistTargetApp     blacklistTargetKind = 1
	blacklistTargetAuthor  blacklistTargetKind = 2
)

// seed is BlacklistType::seed().
func (k blacklistTargetKind) seed() ([]byte, error) {
	switch k {
	case blacklistTargetLicense:
		return []byte("license"), nil
	case blacklistTargetApp:
		return []byte("app"), nil
	case blacklistTargetAuthor:
		return []byte("author"), nil
	default:
		return nil, fmt.Errorf("unknown blacklist target kind %d", uint8(k))
	}
}

func (k blacklistTargetKind) String() string {
	switch k {
	case blacklistTargetLicense:
		return "License"
	case blacklistTargetApp:
		return "App"
	case blacklistTargetAuthor:
		return "Author"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(k))
	}
}

// blacklistStatus is the program's BlacklistStatus (Clear=0, Blocked=1).
type blacklistStatus uint8

const (
	blacklistStatusClear   blacklistStatus = 0
	blacklistStatusBlocked blacklistStatus = 1
)

func (s blacklistStatus) String() string {
	switch s {
	case blacklistStatusClear:
		return "Clear"
	case blacklistStatusBlocked:
		return "Blocked"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// blacklistStatusEntry is one decoded BlacklistStatusEntry and the address it
// was read from.
type blacklistStatusEntry struct {
	PDA        string
	Kind       blacklistTargetKind
	Target     [32]byte
	Status     blacklistStatus
	ReasonHash [32]byte
	Revision   uint64
	LastNonce  uint64
	UpdatedBy  [32]byte
	UpdatedAt  int64
	Bump       uint8
}

var discriminatorBlacklistStatusEntry = accountDiscriminator("BlacklistStatusEntry")

// errBlacklistStatusForeignOwner marks an account at a clearance address that
// the licence registry does not own. Anyone can fund any address; what sits
// there without being the program's account is not the record the address
// names.
var errBlacklistStatusForeignOwner = errors.New("account is not owned by the license registry")

// deriveBlacklistStatusPDA is ["blacklist_status", kind seed, target] under the
// pinned registry program, with its canonical bump.
func deriveBlacklistStatusPDA(kind blacklistTargetKind, target [32]byte) (pda.Pubkey, uint8, error) {
	seed, err := kind.seed()
	if err != nil {
		return pda.Pubkey{}, 0, err
	}
	return primitives.FindProgramAddress([][]byte{[]byte(blacklistStatusSeed), seed, target[:]}, licenseRegistryProgramID(), nil)
}

// decodeBlacklistStatusEntry reads the 131-byte account with authz
// DecodeBlacklistStatus's rules: exact length, the type's discriminator,
// in-range enum tags, a nonzero target, a zero reason hash exactly when Clear,
// nonzero revision, last_nonce and updated_by, and no trailing bytes.
func decodeBlacklistStatusEntry(data []byte) (blacklistStatusEntry, error) {
	var zero blacklistStatusEntry
	if len(data) != blacklistStatusEntryLen {
		return zero, fmt.Errorf("blacklist-status: account length %d != %d", len(data), blacklistStatusEntryLen)
	}
	if !bytes.Equal(data[:8], discriminatorBlacklistStatusEntry) {
		return zero, errors.New("blacklist-status: discriminator mismatch")
	}
	var entry blacklistStatusEntry
	if data[8] > uint8(blacklistTargetAuthor) {
		return zero, fmt.Errorf("blacklist-status: invalid target kind %d", data[8])
	}
	entry.Kind = blacklistTargetKind(data[8])
	copy(entry.Target[:], data[9:41])
	if entry.Target == ([32]byte{}) {
		return zero, errors.New("blacklist-status: target is missing")
	}
	if data[41] > uint8(blacklistStatusBlocked) {
		return zero, fmt.Errorf("blacklist-status: invalid status %d", data[41])
	}
	entry.Status = blacklistStatus(data[41])
	copy(entry.ReasonHash[:], data[42:74])
	if (entry.Status == blacklistStatusClear) != (entry.ReasonHash == [32]byte{}) {
		return zero, errors.New("blacklist-status: Clear requires zero reason hash and Blocked requires nonzero")
	}
	entry.Revision = binary.LittleEndian.Uint64(data[74:82])
	if entry.Revision == 0 {
		return zero, errors.New("blacklist-status: revision must be nonzero")
	}
	entry.LastNonce = binary.LittleEndian.Uint64(data[82:90])
	if entry.LastNonce == 0 {
		return zero, errors.New("blacklist-status: last_nonce must be nonzero")
	}
	copy(entry.UpdatedBy[:], data[90:122])
	if entry.UpdatedBy == ([32]byte{}) {
		return zero, errors.New("blacklist-status: updated_by must be nonzero")
	}
	entry.UpdatedAt = int64(binary.LittleEndian.Uint64(data[122:130]))
	entry.Bump = data[130]
	return entry, nil
}

// readBlacklistStatusAccount is the one reader of a fetched clearance account,
// shared by the live RPC read and the catalog prime: the registry must own it
// and its bytes must decode exactly.
func readBlacklistStatusAccount(addr string, data []byte, owner string) (blacklistStatusEntry, error) {
	if owner != licenseRegistryProgramID().Base58() {
		return blacklistStatusEntry{}, fmt.Errorf("%w (owner %q)", errBlacklistStatusForeignOwner, owner)
	}
	entry, err := decodeBlacklistStatusEntry(data)
	if err != nil {
		return blacklistStatusEntry{}, err
	}
	entry.PDA = addr
	return entry, nil
}

// FetchBlacklistStatus reads one clearance account with its owner. An absent
// account is verify.ErrPDANotFound, never a Clear.
func (c *storeRPCReader) FetchBlacklistStatus(ctx context.Context, addr string) (blacklistStatusEntry, error) {
	account, err := c.GetAccount(ctx, addr)
	if err != nil {
		return blacklistStatusEntry{}, err
	}
	if account == nil {
		return blacklistStatusEntry{}, verify.ErrPDANotFound
	}
	return readBlacklistStatusAccount(addr, account.Data, account.Owner)
}

// sandstormBase32Digits is Sandstorm's base32 alphabet (sandstorm util.c++;
// contracts lib/blacklist-clearance.mjs SANDSTORM_BASE32_DIGITS; authz
// sandstorm_appid.go).
const sandstormBase32Digits = "0123456789acdefghjkmnpqrstuvwxyz"

// decodeSandstormAppIDKey is the decoded, stable 32-byte Sandstorm appId: the
// App clearance target. It is NOT SHA-256 of the appId text (that is
// ReleaseEntry.app_id) and never a master mint or a release hash. Only the
// canonical text is accepted: exactly 52 characters of the alphabet, the last
// one's four padding bits zero, so one appId has one text.
func decodeSandstormAppIDKey(text string) ([32]byte, error) {
	var out [32]byte
	if len(text) != 52 {
		return out, fmt.Errorf("a Sandstorm appId is exactly 52 characters, got %d", len(text))
	}
	var acc uint32
	bits := 0
	n := 0
	for i := 0; i < len(text); i++ {
		digit := strings.IndexByte(sandstormBase32Digits, text[i])
		if digit < 0 {
			return out, fmt.Errorf("a Sandstorm appId uses only the lower-case Sandstorm base32 alphabet (character %d is %q)", i, text[i])
		}
		acc = acc<<5 | uint32(digit)
		bits += 5
		if bits >= 8 {
			bits -= 8
			out[n] = byte(acc >> bits)
			n++
			acc &= (1 << bits) - 1
		}
	}
	// 52 x 5 = 260 bits: 256 bits of key, then four padding bits.
	if bits != 4 || n != 32 || acc != 0 {
		return [32]byte{}, errors.New("a Sandstorm appId's padding bits must be zero (non-canonical text)")
	}
	return out, nil
}

// verifyLicenseClear requires the licence's explicit Clear record.
func verifyLicenseClear(ctx context.Context, cr chainReader, licenseMint pda.Pubkey) error {
	return verifyBlacklistClear(ctx, cr, blacklistTargetLicense, [32]byte(licenseMint), "license")
}

// verifyAppClear requires the app's explicit Clear record. Its target is the
// decoded Sandstorm appId of appIDText. When the release's on-chain
// ReleaseEntry is known, releaseAppID is its app_id and must be SHA-256 of
// appIDText (the release ceremony's AppIDHash), which binds the target to the
// chain whatever carried the text; before a ReleaseEntry exists (a private
// stage) it is nil and the candidate's own appId is checked, to be bound when
// the release is promoted.
func verifyAppClear(ctx context.Context, cr chainReader, appIDText string, releaseAppID *[32]byte) error {
	key, err := decodeSandstormAppIDKey(appIDText)
	if err != nil {
		return fmt.Errorf("check=blacklist[app]: app-id-invalid: %q: %w", appIDText, err)
	}
	if releaseAppID != nil {
		if got := sha256.Sum256([]byte(appIDText)); got != *releaseAppID {
			return fmt.Errorf("check=blacklist[app]: app-id-not-the-release-app: SHA-256 of appId %s is %x, ReleaseEntry.app_id is %x", appIDText, got[:], releaseAppID[:])
		}
	}
	return verifyBlacklistClear(ctx, cr, blacklistTargetApp, key, "app")
}

// verifyBlacklistClear is the one clearance check. label names it in the
// error ("app" / "license"). Every outcome but the canonical Clear record of
// exactly this kind and target refuses, each by name:
//
//	clearance-absent        no account: absence is not a clearance statement
//	blacklisted             the Foundation recorded Blocked
//	clearance-not-canonical another kind or target, or a non-canonical bump
//	fetch                   an RPC, owner or decode failure (fail closed)
func verifyBlacklistClear(ctx context.Context, cr chainReader, kind blacklistTargetKind, target [32]byte, label string) error {
	addr, bump, err := deriveBlacklistStatusPDA(kind, target)
	if err != nil {
		return fmt.Errorf("check=blacklist[%s]: derive PDA: %w", label, err)
	}
	entry, err := cr.FetchBlacklistStatus(ctx, addr.Base58())
	if errors.Is(err, verify.ErrPDANotFound) {
		return fmt.Errorf("check=blacklist[%s]: clearance-absent: no BlacklistStatusEntry at %s for %s target %x; an absent record is not Clear", label, addr.Base58(), kind, target[:])
	}
	if err != nil {
		return fmt.Errorf("check=blacklist[%s]: fetch %s: %w", label, addr.Base58(), err)
	}
	if entry.Kind != kind || entry.Target != target {
		return fmt.Errorf("check=blacklist[%s]: clearance-not-canonical: %s holds a %s record for %x, not %s %x", label, addr.Base58(), entry.Kind, entry.Target[:], kind, target[:])
	}
	if entry.Bump != bump {
		return fmt.Errorf("check=blacklist[%s]: clearance-not-canonical: %s records bump %d, the canonical bump is %d", label, addr.Base58(), entry.Bump, bump)
	}
	switch entry.Status {
	case blacklistStatusClear:
		return nil
	case blacklistStatusBlocked:
		return fmt.Errorf("check=blacklist[%s]: blacklisted: %s target %x is Blocked (revision %d)", label, kind, target[:], entry.Revision)
	default:
		return fmt.Errorf("check=blacklist[%s]: invalid status %d", label, uint8(entry.Status))
	}
}
