package sidecarresult

import (
	"context"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// Root is the chain + program a ChainReader is bound to. The verifier's own
// values are BUILD-PINNED constants (Rule 7) and must equal these, or the read
// is happening somewhere the verifier did not pin (R-03a).
type Root struct {
	ChainID   string
	ProgramID string
}

// ChainReader is the narrow port through which this package reaches chain
// state. Every method returns FRESHLY READ state.
//
// Implementations live in trustmaster (over verify.RPCClient — the RPC client,
// Borsh walkers, PDA derivers and status enums ALL EXIST and
// melusina-identity-gate is already a go.mod dependency; §7.3: "Do not write a
// new RPC client, Borsh walker, PDA deriver, or status enum"). This package
// deliberately does not construct one: a library that dials RPC is a library
// nobody can test offline, and the seam is where trustmaster plugs in.
//
// # Freshness is a CONTRACT TERM, not an adjective (§7.3.2)
//
// Every read returns ReadAtMs and the verifier ENFORCES it against
// MaxAuthorityStaleness (R-44). v1 wrote "freshly resolved on every
// verification" and gave the sentence no enforcement point, no error and no
// test — while mandating a type literally named a *cache*. The first latency
// complaint then adds a 5-minute TTL, every clause still holds ("non-nil and
// chain-backed"), and a revoked license verifies green for the cache's lifetime.
// An implementation MAY cache pubkeys and immutable bindings; it MUST NOT cache
// status, revocation, or blacklist status, and ReadAtMs is how that is
// checkable rather than promised.
//
// # Errors
//
// Return verify.ErrPDANotFound for a missing account and verify.ErrRPCUnreachable
// (or any other error) for a failed read. BOTH become REJECTIONS (R-42/R-43) —
// never "unknown", never retriable. An attacker who partitions the verifier from
// RPC must not be able to convert REVOKED into UNKNOWN.
type ChainReader interface {
	// Root reports the chain + program this reader is bound to. It is compared
	// against the verifier's build-pinned root before any read is trusted.
	Root() Root

	// ReadCurrentSidecarKeyVersion resolves the CURRENT key_version for
	// {licenseNFTMint, sidecarID} from an AUTHORITATIVE POINTER — never from the
	// result's carried KeyVersion (§6.3.1, R-11b).
	//
	// BLOCKED ON A PROGRAM CHANGE (§12, verified §0.3/27): there is no
	// `sidecar_identity_current` pointer PDA. `sidecar_identity`'s seed contains
	// key_version (attestation.rs:1018) and the account is `init`, so a new
	// version is a NEW account and the old one stays Active FOREVER — status is
	// written once (`= Active`, :291) and no instruction can rewrite it (grep
	// revoke_sidecar_identity|supersede_sidecar_identity → empty). So an attacker
	// holding a leaked v1 key emits a result naming KeyVersion:1 and every row
	// goes green. This method is the seam that closes it the moment the pointer
	// (or an in-place update) lands; until then a compromised sidecar signing key
	// CANNOT BE REVOKED AT ALL. Say it plainly rather than ship a green check
	// over it.
	ReadCurrentSidecarKeyVersion(ctx context.Context, licenseNFTMint, sidecarID string) (SidecarKeyVersion, error)

	// ReadSidecarIdentity fetches the SidecarIdentityEntry at pdaB58, fresh.
	//
	// Implementations wrap verify.ReadSidecarIdentity (approvals.go:1257) — with
	// the §7.4 two-line fix: the decoder today SkipPubkey's
	// `global_sidecar_approval` (approvals.go:1298), THROWING AWAY THE POINTER TO
	// THE ONE REVOCABLE RECORD, which is why the EXISTING revoke_global_sidecar
	// (lib.rs:1326) has had zero effect on anything. GlobalSidecarApprovalPDA
	// below is that field; an implementation that cannot supply it cannot satisfy
	// this port.
	ReadSidecarIdentity(ctx context.Context, pdaB58 string) (SidecarIdentity, error)

	// ReadGlobalSidecarApproval fetches the GlobalSidecarApproval at pdaB58,
	// fresh. The verifier reaches it ONLY via
	// SidecarIdentityEntry.global_sidecar_approval, cross-checked against the
	// independently derived PDA — never via a result-carried pointer (§6.3.2,
	// Rule 7).
	ReadGlobalSidecarApproval(ctx context.Context, pdaB58 string) (GlobalSidecarApproval, error)

	// ReadBlacklistStatus fetches the account at pdaB58, fresh, with the owner
	// the RPC reported. pdaB58 is a BlacklistStatusEntry address the VERIFIER
	// derived (pda.BlacklistStatus under its build-pinned program), never one a
	// result carried.
	//
	// The license registry keeps an EXPLICIT status per target
	// (["blacklist_status", kind seed, target]); a missing account is not a
	// clearance statement. So an absent account is verify.ErrPDANotFound like
	// every other authority read, and the verifier REJECTS it (R-43). The port
	// does not judge: the verifier applies verify.RequireBlacklistClear to the
	// bytes and owner returned here.
	ReadBlacklistStatus(ctx context.Context, pdaB58 string) (BlacklistStatusAccount, error)
}

// SidecarKeyVersion is the authoritative current key_version for a sidecar.
type SidecarKeyVersion struct {
	// ReadAtMs is when this liveness state was read from chain (R-44).
	ReadAtMs   int64
	KeyVersion uint32
}

// SidecarIdentity is SidecarIdentityEntry (state/attestation.rs:134-151) as this
// contract consumes it — the HOST-AUTHORITY-MEASURED record, complete on chain.
//
// EVERY FIELD BELOW IS READ BY THE VERIFIER. That is a rule, not a coincidence:
// "a field no verifier reads is deleted or bound; there is no third option"
// (§4.4.1). An unread field on THIS struct is the worst kind, because it is the
// authoritative value — a reviewer sees the verifier holding the chain's own
// answer and reasonably assumes it is consulted.
//
// So this struct does NOT mirror verify.SidecarIdentity (approvals.go:1229)
// field-for-field, and an earlier version of this comment claiming it did was
// false in both directions: that struct also carries TLSCertFingerprint and
// EncryptionPubkey, neither of which this contract binds. It carries the fields
// SidecarResult verification BINDS, plus GlobalSidecarApprovalPDA — the pointer
// the upstream decoder SkipPubkey's away (§7.4). It reuses
// verify.AttestationStatus rather than declaring a rival status enum.
//
// EncryptionPubkey is deliberately absent: nothing in SidecarResult verification
// performs ECDH. trustmaster's PearlIdentity binds it (graincert.go:419) because
// the GrainCert contract has a subject box key to bind it TO; this one does not.
// Carrying it here would be an unbound authority field, which is the exact defect
// this struct's own doc forbids.
type SidecarIdentity struct {
	// ReadAtMs is when this state was read from chain (R-44).
	ReadAtMs int64

	// BinaryHash is the digest the HOST measured at registration — the ONLY
	// authority for "which build spoke" (§6.3, R-11).
	BinaryHash [32]byte
	// DomainHash is the domain the HOST registered this sidecar identity FOR —
	// the ONLY chain corroboration that the install a result claims is the install
	// the sidecar is registered on (§6.3, R-11f). Without reading it, the domain
	// binding is the result-blob agreeing with the caller and nothing else.
	DomainHash [32]byte
	// SigningPubkey is the authority for R-10. The result's carried key is a
	// diagnostic and is never used to verify the signature (Rule 2).
	SigningPubkey [32]byte
	// KeyVersion is the version THIS record is for. The verifier derived the PDA
	// from an independently resolved current version and requires this to agree
	// (R-11g) — a port that ignores its pdaB58 argument and returns some other
	// registration is caught here rather than trusted.
	KeyVersion uint32

	// GlobalSidecarApprovalPDA is the host-written pointer at
	// state/attestation.rs:141 — the ONLY route to the approval (§6.3.2).
	GlobalSidecarApprovalPDA string

	Status verify.AttestationStatus
}

// GlobalSidecarApproval is GlobalSidecarApproval (state/sidecar_approval.rs:42-58)
// as this contract consumes it.
type GlobalSidecarApproval struct {
	// ReadAtMs is when this state was read from chain (R-44).
	ReadAtMs int64

	// BinaryHash must equal SidecarIdentity.BinaryHash or the approval and the
	// identity describe DIFFERENT BUILDS (R-11e, §6.3.2): the approval PDA is
	// ["global_sidecar", master_nft_mint, sidecar_id] — no version, no
	// binary_hash in the seed — and handler_update_global_sidecar_binary_hash
	// (lib.rs:1292) mutates it IN PLACE, while SidecarIdentityEntry is init-once
	// and carries its own. Two accounts, two lifetimes.
	BinaryHash [32]byte

	// ReleasePolicyHashHex pins the MACHINE-CHECKED fail-closed attestation
	// (§6.4/§6.4.1).
	//
	// IT DOES NOT EXIST ON CHAIN TODAY (§0.2/17, verified at
	// state/sidecar_approval.rs:42-58 — sidecar_id, binary_hash, version,
	// san_list, required_permissions, author, master_nft_mint, approved_by,
	// status, approved_at, revoked_at, revoke_reason, bump; NO policy field.
	// ReleaseEntry likewise). An implementation reading today's program MUST
	// leave this EMPTY, and the verifier then rejects every VERIFIED_DECISION
	// (R-12a). That is the honest, load-bearing consequence of the canon's own
	// ruling — not a warning, not a default, not a parameter (§12).
	ReleasePolicyHashHex string

	Status verify.ApprovalStatus
}

// BlacklistStatusAccount is a fresh read of one BlacklistStatusEntry address:
// the account as the RPC returned it (data and owner). It is judged only by
// verify.RequireBlacklistClear.
type BlacklistStatusAccount struct {
	// ReadAtMs is when this state was read from chain (R-44).
	ReadAtMs int64
	Account  verify.Account
}
