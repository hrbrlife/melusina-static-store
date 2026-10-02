package verify

// global_app_approval.go — the strict reader of an app's GlobalAppApproval,
// for the fact a blacklist decision takes from it: the app's AUTHOR.
//
// The authorization daemon's launch path requires three explicit Clears for
// an app: the App (its decoded appId), the licence, and the Author. The Author
// target is never chosen by a caller. It is GlobalAppApproval.author of the
// app's approval at ["global_app", master_nft_mint, decoded appId] (authz
// pkg/grainauth gate.go and control_facts.go, which read the witnessed
// approval's author; contracts scripts/estate/lib/blacklist-clearance.mjs
// appClearances, which proposes that author's Clear). This file decodes that
// account with the program's layout (contracts
// programs/license-registry/src/state/app_approval.rs) and binds it to the app
// and Foundation it was derived for. RequireActiveGlobalAppApproval then
// decides whether the app is approved at all, as the authz cascade decides its
// global tier. The Author clearance itself is judged by RequireBlacklistClear,
// like every other target.
//
// PDA derivation needs the Ed25519 curve check, which this dependency-free
// module does not carry: derive the address and canonical bump with
// melusina-solana-primitives DeriveGlobalApp (or melusina-attest pda.GlobalApp)
// and pass the bump in.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

// AccountGlobalAppApproval is the Anchor account name of GlobalAppApproval.
const AccountGlobalAppApproval = "GlobalAppApproval"

// DiscriminatorGlobalAppApproval is SHA-256("account:GlobalAppApproval")[:8].
var DiscriminatorGlobalAppApproval = AnchorAccountDiscriminator(AccountGlobalAppApproval)

// GlobalAppApprovalLen is GlobalAppApproval::LEN, discriminator included: the
// space approve_global_app's `init` allocates, so every GlobalAppApproval the
// program writes is exactly this long, zero-padded after its bump.
const GlobalAppApprovalLen = 553

// The program's string bounds for this account (constants.rs MAX_APP_NAME_LEN,
// MAX_VERSION_LEN, MAX_REASON_LEN; approve_global_app and revoke_global_app
// refuse longer values).
const (
	globalAppMaxAppNameLen = 64
	globalAppMaxVersionLen = 32
	globalAppMaxReasonLen  = 256
)

// GlobalAppApproval is one decoded GlobalAppApproval. The Borsh layout is:
//
//	discriminator    8
//	app_hash         32   the approval key: the decoded appId
//	app_id           32   the decoded appId
//	app_name         4+N  String, N <= 64
//	version          4+N  String, N <= 32
//	author           32   the Author blacklist target
//	author_approved  1    bool
//	master_nft_mint  32
//	approved_by      32
//	status           1    ApprovalStatus
//	approved_at      8    i64
//	revoked_at       1+8  Option<i64>
//	revoke_reason    1+4+N Option<String>, N <= 256
//	bump             1
//	zero padding to GlobalAppApprovalLen
type GlobalAppApproval struct {
	AppHash         [32]byte
	AppID           [32]byte
	AppName         string
	Version         string
	Author          [32]byte
	AuthorApproved  bool
	MasterNftMint   [32]byte
	ApprovedBy      [32]byte
	Status          ApprovalStatus
	ApprovedAt      int64
	HasRevokedAt    bool
	RevokedAt       int64
	HasRevokeReason bool
	RevokeReason    string
	Bump            uint8
}

var (
	// ErrGlobalAppApprovalForeignOwner: the account at an app's approval
	// address is not owned by the license registry. Anyone can fund any
	// address; an account the program does not own is not its approval.
	ErrGlobalAppApprovalForeignOwner = errors.New("global app approval: account is not owned by the license registry")
	// ErrGlobalAppApprovalNotCanonical: the record at the app's approval
	// address is not that app's approval under this Foundation (another
	// app_hash or app_id, another master NFT mint, a non-canonical bump), or
	// it names no author.
	ErrGlobalAppApprovalNotCanonical = errors.New("global app approval: not the canonical approval of this app")

	// ErrGlobalAppApprovalRevoked: the approval's status is Revoked. The
	// Foundation withdrew the app (revoke_global_app, or the final chunk of
	// revoke_global_app_chunk). The authz cascade denies it as
	// cascade-blocked:global:revoked.
	ErrGlobalAppApprovalRevoked = errors.New("global app approval: Revoked")
	// ErrGlobalAppApprovalRevokingCascadeInProgress: the approval's status is
	// RevokingCascadeInProgress. A chunked cascade revoke of the app is in
	// flight (revoke_global_app_chunk before its final chunk), and the
	// program's enum says verify paths must not accept it. The authz cascade
	// denies it as cascade-blocked:global:revoking-cascade-in-progress.
	ErrGlobalAppApprovalRevokingCascadeInProgress = errors.New("global app approval: RevokingCascadeInProgress, a cascade revoke is in flight")
	// ErrGlobalAppApprovalRevokedAtWhileActive: the status is Active but the
	// approval carries a revoked_at. The program never writes that:
	// approve_global_app sets Active with revoked_at None, and every write of
	// revoked_at = Some sets Revoked. An approval in that state is not an
	// Active one.
	ErrGlobalAppApprovalRevokedAtWhileActive = errors.New("global app approval: Active but carries a revoked_at")
)

// globalAppReader walks the account strictly. Every read is bounded by the
// buffer; a short buffer is an ErrBorshDecode naming the field.
type globalAppReader struct {
	buf []byte
	off int
}

func (r *globalAppReader) take(n int, field string) ([]byte, error) {
	if n < 0 || r.off+n > len(r.buf) {
		return nil, fmt.Errorf("%w: global app approval: %s runs past the account", ErrBorshDecode, field)
	}
	out := r.buf[r.off : r.off+n]
	r.off += n
	return out, nil
}

func (r *globalAppReader) key(field string) ([32]byte, error) {
	b, err := r.take(32, field)
	if err != nil {
		return [32]byte{}, err
	}
	return [32]byte(b), nil
}

func (r *globalAppReader) tag(field string) (bool, error) {
	b, err := r.take(1, field)
	if err != nil {
		return false, err
	}
	switch b[0] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("%w: global app approval: %s tag %d is not 0 or 1", ErrBorshDecode, field, b[0])
	}
}

func (r *globalAppReader) i64(field string) (int64, error) {
	b, err := r.take(8, field)
	if err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(b)), nil
}

func (r *globalAppReader) str(field string, max int) (string, error) {
	lenBytes, err := r.take(4, field+" length")
	if err != nil {
		return "", err
	}
	n := binary.LittleEndian.Uint32(lenBytes)
	if n > uint32(max) {
		return "", fmt.Errorf("%w: global app approval: %s is %d bytes, the program allows %d", ErrBorshDecode, field, n, max)
	}
	b, err := r.take(int(n), field)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", fmt.Errorf("%w: global app approval: %s is not UTF-8", ErrBorshDecode, field)
	}
	return string(b), nil
}

// DecodeGlobalAppApproval decodes a GlobalAppApproval account exactly:
// GlobalAppApprovalLen bytes, the type's discriminator, every field in the
// program's order with in-range tags (bool, status, Option), the program's
// string bounds, and zero bytes after the bump. Any other shape is an
// ErrBorshDecode. It does not judge status or bindings; see
// RequireCanonicalGlobalAppApproval.
func DecodeGlobalAppApproval(data []byte) (GlobalAppApproval, error) {
	if len(data) != GlobalAppApprovalLen {
		return GlobalAppApproval{}, fmt.Errorf("%w: global app approval: account length %d != %d", ErrBorshDecode, len(data), GlobalAppApprovalLen)
	}
	if [AccountDiscriminatorLen]byte(data[:AccountDiscriminatorLen]) != DiscriminatorGlobalAppApproval {
		return GlobalAppApproval{}, fmt.Errorf("%w: global app approval: discriminator mismatch", ErrBorshDecode)
	}
	r := &globalAppReader{buf: data, off: AccountDiscriminatorLen}
	var a GlobalAppApproval
	var err error
	if a.AppHash, err = r.key("app_hash"); err != nil {
		return GlobalAppApproval{}, err
	}
	if a.AppID, err = r.key("app_id"); err != nil {
		return GlobalAppApproval{}, err
	}
	if a.AppName, err = r.str("app_name", globalAppMaxAppNameLen); err != nil {
		return GlobalAppApproval{}, err
	}
	if a.Version, err = r.str("version", globalAppMaxVersionLen); err != nil {
		return GlobalAppApproval{}, err
	}
	if a.Author, err = r.key("author"); err != nil {
		return GlobalAppApproval{}, err
	}
	if a.AuthorApproved, err = r.tag("author_approved"); err != nil {
		return GlobalAppApproval{}, err
	}
	if a.MasterNftMint, err = r.key("master_nft_mint"); err != nil {
		return GlobalAppApproval{}, err
	}
	if a.ApprovedBy, err = r.key("approved_by"); err != nil {
		return GlobalAppApproval{}, err
	}
	status, err := r.take(1, "status")
	if err != nil {
		return GlobalAppApproval{}, err
	}
	if status[0] > uint8(ApprovalStatusRevokingCascadeInProgress) {
		return GlobalAppApproval{}, fmt.Errorf("%w: global app approval: status tag %d is out of range", ErrBorshDecode, status[0])
	}
	a.Status = ApprovalStatus(status[0])
	if a.ApprovedAt, err = r.i64("approved_at"); err != nil {
		return GlobalAppApproval{}, err
	}
	if a.HasRevokedAt, err = r.tag("revoked_at"); err != nil {
		return GlobalAppApproval{}, err
	}
	if a.HasRevokedAt {
		if a.RevokedAt, err = r.i64("revoked_at"); err != nil {
			return GlobalAppApproval{}, err
		}
	}
	if a.HasRevokeReason, err = r.tag("revoke_reason"); err != nil {
		return GlobalAppApproval{}, err
	}
	if a.HasRevokeReason {
		if a.RevokeReason, err = r.str("revoke_reason", globalAppMaxReasonLen); err != nil {
			return GlobalAppApproval{}, err
		}
	}
	bump, err := r.take(1, "bump")
	if err != nil {
		return GlobalAppApproval{}, err
	}
	a.Bump = bump[0]
	for i, b := range data[r.off:] {
		if b != 0 {
			return GlobalAppApproval{}, fmt.Errorf("%w: global app approval: non-zero byte at offset %d after the bump", ErrBorshDecode, r.off+i)
		}
	}
	return a, nil
}

// EncodeGlobalAppApproval is the inverse of DecodeGlobalAppApproval: the
// GlobalAppApprovalLen bytes the program stores for a. It writes whatever it
// is given (strings are not bounded here, and one that overflows the account
// panics); it exists so fixtures and tools build real account bytes, which
// every reader then decodes through DecodeGlobalAppApproval.
func EncodeGlobalAppApproval(a GlobalAppApproval) []byte {
	out := append([]byte(nil), DiscriminatorGlobalAppApproval[:]...)
	putStr := func(s string) {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(s)))
		out = append(out, s...)
	}
	putBool := func(v bool) {
		if v {
			out = append(out, 1)
		} else {
			out = append(out, 0)
		}
	}
	out = append(out, a.AppHash[:]...)
	out = append(out, a.AppID[:]...)
	putStr(a.AppName)
	putStr(a.Version)
	out = append(out, a.Author[:]...)
	putBool(a.AuthorApproved)
	out = append(out, a.MasterNftMint[:]...)
	out = append(out, a.ApprovedBy[:]...)
	out = append(out, uint8(a.Status))
	out = binary.LittleEndian.AppendUint64(out, uint64(a.ApprovedAt))
	putBool(a.HasRevokedAt)
	if a.HasRevokedAt {
		out = binary.LittleEndian.AppendUint64(out, uint64(a.RevokedAt))
	}
	putBool(a.HasRevokeReason)
	if a.HasRevokeReason {
		putStr(a.RevokeReason)
	}
	out = append(out, a.Bump)
	if len(out) > GlobalAppApprovalLen {
		panic(fmt.Sprintf("EncodeGlobalAppApproval: %d bytes exceed the account's %d", len(out), GlobalAppApprovalLen))
	}
	return append(out, make([]byte, GlobalAppApprovalLen-len(out))...)
}

// RequireCanonicalGlobalAppApproval is THE reader of an app's author: account
// is what the RPC returned at the address derived for (masterNftMint, appKey)
// under registryProgramB58 — seeds ["global_app", master_nft_mint, appKey] —
// and canonicalBump is that derivation's bump. appKey is the app's decoded
// Sandstorm appId, the key the approval tiers and the App blacklist target
// share.
//
// It returns the decoded approval only when it is that app's approval under
// that Foundation:
//
//	nil account           ErrPDANotFound                     an unapproved app has no author of record
//	foreign owner         ErrGlobalAppApprovalForeignOwner
//	malformed bytes       ErrBorshDecode
//	app_hash != appKey    ErrGlobalAppApprovalNotCanonical
//	app_id != appKey      ErrGlobalAppApprovalNotCanonical   authz takes the App target from app_id
//	another master        ErrGlobalAppApprovalNotCanonical
//	non-canonical bump    ErrGlobalAppApprovalNotCanonical
//	zero author           ErrGlobalAppApprovalNotCanonical   no Author target to clear
//
// It does not judge Status: the author of a revoked approval is still its
// author. A caller that requires an Active approval passes the result to
// RequireActiveGlobalAppApproval. The author's clearance is
// RequireBlacklistClear(BlacklistTypeAuthor, Author).
//
// An empty registryProgramB58 is refused: without the program there is no
// owner to check against.
func RequireCanonicalGlobalAppApproval(account *Account, registryProgramB58 string, masterNftMint, appKey [32]byte, canonicalBump uint8) (GlobalAppApproval, error) {
	if registryProgramB58 == "" {
		return GlobalAppApproval{}, errors.New("global app approval: no license registry program to check the owner against")
	}
	if account == nil {
		return GlobalAppApproval{}, fmt.Errorf("%w: no GlobalAppApproval for app %x", ErrPDANotFound, appKey[:])
	}
	if account.Owner != registryProgramB58 {
		return GlobalAppApproval{}, fmt.Errorf("%w: owner %q, registry %s", ErrGlobalAppApprovalForeignOwner, account.Owner, registryProgramB58)
	}
	a, err := DecodeGlobalAppApproval(account.Data)
	if err != nil {
		return GlobalAppApproval{}, err
	}
	if a.AppHash != appKey {
		return GlobalAppApproval{}, fmt.Errorf("%w: app_hash %x, the app key is %x", ErrGlobalAppApprovalNotCanonical, a.AppHash[:], appKey[:])
	}
	if a.AppID != appKey {
		return GlobalAppApproval{}, fmt.Errorf("%w: app_id %x, the app key is %x", ErrGlobalAppApprovalNotCanonical, a.AppID[:], appKey[:])
	}
	if a.MasterNftMint != masterNftMint {
		return GlobalAppApproval{}, fmt.Errorf("%w: master_nft_mint %x, the Foundation's is %x", ErrGlobalAppApprovalNotCanonical, a.MasterNftMint[:], masterNftMint[:])
	}
	if a.Bump != canonicalBump {
		return GlobalAppApproval{}, fmt.Errorf("%w: the record's bump is %d, the canonical bump is %d", ErrGlobalAppApprovalNotCanonical, a.Bump, canonicalBump)
	}
	if a.Author == ([32]byte{}) {
		return GlobalAppApproval{}, fmt.Errorf("%w: the approval names no author", ErrGlobalAppApprovalNotCanonical)
	}
	return a, nil
}

// RequireActiveGlobalAppApproval returns nil only for an Active approval with
// no revoked_at: the one state in which an app is approved. It judges the
// status as the authz cascade judges the global tier (pkg/grainauth
// cascade.go CascadeVerify and EvalCachedCascade: Active passes, Revoked and
// RevokingCascadeInProgress deny, anything else is an unknown status and
// denies), and it refuses an Active approval that carries a revoked_at, the
// way R-14 reads a licence's status together with its revoked_at. authz
// decides on the status byte alone. The program writes revoked_at = Some only
// together with Revoked, so the two decide identically on every approval the
// program can hold.
//
//	Active, revoked_at None         nil
//	Revoked                         ErrGlobalAppApprovalRevoked
//	RevokingCascadeInProgress       ErrGlobalAppApprovalRevokingCascadeInProgress
//	Active, revoked_at Some         ErrGlobalAppApprovalRevokedAtWhileActive
//	any other status                ErrStatusNotActive (unknown status)
//
// Every refusal also matches ErrStatusNotActive. It judges an approval that
// RequireCanonicalGlobalAppApproval has already bound to its app and
// Foundation; it does not repeat those checks.
func RequireActiveGlobalAppApproval(a GlobalAppApproval) error {
	switch a.Status {
	case ApprovalStatusActive:
	case ApprovalStatusRevoked:
		return fmt.Errorf("%w: %w", ErrStatusNotActive, ErrGlobalAppApprovalRevoked)
	case ApprovalStatusRevokingCascadeInProgress:
		return fmt.Errorf("%w: %w", ErrStatusNotActive, ErrGlobalAppApprovalRevokingCascadeInProgress)
	default:
		return fmt.Errorf("%w: global app approval: unknown status %s", ErrStatusNotActive, a.Status)
	}
	if a.HasRevokedAt {
		return fmt.Errorf("%w: %w (revoked_at %d)", ErrStatusNotActive, ErrGlobalAppApprovalRevokedAtWhileActive, a.RevokedAt)
	}
	return nil
}
