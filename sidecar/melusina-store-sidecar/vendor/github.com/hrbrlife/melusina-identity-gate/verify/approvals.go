package verify

import (
	"errors"
	"fmt"
)

// ApprovalStatus mirrors the Anchor enum at
// melusina_solana_dev-license104/programs/license-registry/src/state/app_approval.rs.
// Active=0, Revoked=1, RevokingCascadeInProgress=2. Reused across
// every approval-family PDA: app and sidecar cascades both.
//
// InstallAdminStatus and OrganizationMemberStatus at
// state/admin.rs and state/organization_member.rs both use the same
// numbering (Active=0, Revoked=1) — their byte representation is
// identical to ApprovalStatus, so readers in this package cover all
// three without needing separate enums.
type ApprovalStatus uint8

const (
	ApprovalStatusActive                    ApprovalStatus = 0
	ApprovalStatusRevoked                   ApprovalStatus = 1
	ApprovalStatusRevokingCascadeInProgress ApprovalStatus = 2
)

func (s ApprovalStatus) String() string {
	switch s {
	case ApprovalStatusActive:
		return "Active"
	case ApprovalStatusRevoked:
		return "Revoked"
	case ApprovalStatusRevokingCascadeInProgress:
		return "RevokingCascadeInProgress"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// RequireActive returns nil iff s == Active; otherwise a typed error
// consumers can match on via errors.Is(err, ErrStatusNotActive).
func (s ApprovalStatus) RequireActive() error {
	if s == ApprovalStatusActive {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrStatusNotActive, s)
}

// AttestationStatus mirrors the Anchor enum at state/attestation.rs:7
// (Active=0, Revoked=1, Superseded=2). Used by ReleaseEntry and the
// identity-entry family. Distinct from ApprovalStatus because it adds the
// `Superseded` variant the federated cascade (FEDERATED-STORE-MVP §C4)
// must DENY: a superseded release is not below-floor, it is structurally
// retired.
type AttestationStatus uint8

const (
	AttestationStatusActive     AttestationStatus = 0
	AttestationStatusRevoked    AttestationStatus = 1
	AttestationStatusSuperseded AttestationStatus = 2
)

func (s AttestationStatus) String() string {
	switch s {
	case AttestationStatusActive:
		return "Active"
	case AttestationStatusRevoked:
		return "Revoked"
	case AttestationStatusSuperseded:
		return "Superseded"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// RequireActive returns nil iff s == Active. C2.3's re-hash==app_hash gate
// pairs this with the app_hash check before accepting a release.
func (s AttestationStatus) RequireActive() error {
	if s == AttestationStatusActive {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrStatusNotActive, s)
}

// AuthorizationStatus mirrors the Anchor enum at state/attestation.rs:21
// (Active=0, Revoked=1) — the two-variant status carried by
// StoreOperatorAuthorization and StoreReleaseListing (FEDERATED-STORE-MVP
// §C1). Separate type from ApprovalStatus so a reader can't accidentally
// admit the (impossible-for-this-enum) RevokingCascadeInProgress=2 byte.
type AuthorizationStatus uint8

const (
	AuthorizationStatusActive  AuthorizationStatus = 0
	AuthorizationStatusRevoked AuthorizationStatus = 1
)

func (s AuthorizationStatus) String() string {
	switch s {
	case AuthorizationStatusActive:
		return "Active"
	case AuthorizationStatusRevoked:
		return "Revoked"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// RequireActive returns nil iff s == Active; otherwise a typed error
// consumers match via errors.Is(err, ErrStatusNotActive). The store-operate
// gate (§C1) and the cascade store stage (§C4) both fail-closed on non-Active.
func (s AuthorizationStatus) RequireActive() error {
	if s == AuthorizationStatusActive {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrStatusNotActive, s)
}

// ── Borsh walkers ────────────────────────────────────────────────────────
//
// Several Melusina PDAs have variable-length String and Option<T>
// fields before the status byte. Fixed offsets don't work. These
// primitives walk the layout explicitly so every status read agrees
// on where bytes live.

// AccountDiscriminatorLen is Anchor's fixed 8-byte discriminator.
const AccountDiscriminatorLen = 8

// skip advances offset past n bytes or returns an error.
func skip(data []byte, offset, n int) (int, error) {
	next := offset + n
	if next > len(data) {
		return 0, fmt.Errorf("buffer too short: need %d bytes at offset %d, have %d",
			n, offset, len(data)-offset)
	}
	return next, nil
}

// SkipBorshString advances past a Borsh-encoded String (u32 LE length +
// contents) and returns the new offset.
func SkipBorshString(data []byte, offset int) (int, error) {
	if offset+4 > len(data) {
		return 0, errors.New("buffer too short for Borsh string length prefix")
	}
	length := int(uint32(data[offset]) |
		uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 |
		uint32(data[offset+3])<<24)
	next := offset + 4 + length
	if next > len(data) {
		return 0, errors.New("buffer too short for Borsh string contents")
	}
	return next, nil
}

// SkipBorshOption advances past an Option<T>. The Option tag is 1
// byte; if the tag is 1 (Some), the caller-provided `inner` function
// advances past the T.
func SkipBorshOption(data []byte, offset int, inner func(data []byte, offset int) (int, error)) (int, error) {
	if offset >= len(data) {
		return 0, errors.New("buffer too short for Option tag")
	}
	tag := data[offset]
	offset++
	switch tag {
	case 0:
		return offset, nil
	case 1:
		return inner(data, offset)
	default:
		return 0, fmt.Errorf("invalid Option tag: %d", tag)
	}
}

// SkipPubkey advances past a fixed 32-byte Pubkey.
func SkipPubkey(data []byte, offset int) (int, error) { return skip(data, offset, 32) }

// SkipI64 advances past a fixed 8-byte i64 / u64.
func SkipI64(data []byte, offset int) (int, error) { return skip(data, offset, 8) }

// ReadStatusByte reads one byte at offset and returns it as
// ApprovalStatus. Rejects unknown variants > RevokingCascadeInProgress.
func ReadStatusByte(data []byte, offset int) (ApprovalStatus, error) {
	if offset < 0 || offset >= len(data) {
		return 0, errors.New("status offset out of range")
	}
	b := data[offset]
	if b > uint8(ApprovalStatusRevokingCascadeInProgress) {
		return ApprovalStatus(b), fmt.Errorf("unknown ApprovalStatus byte: %d", b)
	}
	return ApprovalStatus(b), nil
}

// ── PDA-specific readers ────────────────────────────────────────────────

// ReadInstallAdminStatus decodes an InstallAdminEntry account and
// returns its status byte. The account is laid out at
// state/install_admin.rs as:
//
//	[0..8)         discriminator
//	[8..40)        license: Pubkey
//	[40..72)       admin_wallet: Pubkey
//	[72..)         admin_name: String
//	               permissions: u64 (AdminPermissionSet.SIZE = 8)
//	               designated_by: Pubkey
//	               designated_via_operation: Option<Pubkey>
//	               designated_at: i64
//	               status: InstallAdminStatus (u8)  ← here
//	               ...
//
// InstallAdminStatus uses the same Active=0 / Revoked=1 byte values
// as ApprovalStatus.
func ReadInstallAdminStatus(data []byte) (ApprovalStatus, error) {
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipPubkey(data, offset); err != nil { // license
		return 0, fmt.Errorf("install_admin: license: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // admin_wallet
		return 0, fmt.Errorf("install_admin: admin_wallet: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // admin_name
		return 0, fmt.Errorf("install_admin: admin_name: %w", err)
	}
	if offset, err = skip(data, offset, 8); err != nil { // permissions u64
		return 0, fmt.Errorf("install_admin: permissions: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // designated_by
		return 0, fmt.Errorf("install_admin: designated_by: %w", err)
	}
	if offset, err = SkipBorshOption(data, offset, SkipPubkey); err != nil { // designated_via_operation
		return 0, fmt.Errorf("install_admin: designated_via_operation: %w", err)
	}
	if offset, err = SkipI64(data, offset); err != nil { // designated_at
		return 0, fmt.Errorf("install_admin: designated_at: %w", err)
	}
	return ReadStatusByte(data, offset)
}

// ReadInstallAdminPermissions decodes the permissions u64 bitset
// from an InstallAdminEntry account. Cross-refs with
// MelusinaPermissions.capnp in the Anchor program.
func ReadInstallAdminPermissions(data []byte) (uint64, error) {
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipPubkey(data, offset); err != nil {
		return 0, err
	}
	if offset, err = SkipPubkey(data, offset); err != nil {
		return 0, err
	}
	if offset, err = SkipBorshString(data, offset); err != nil {
		return 0, err
	}
	if offset+8 > len(data) {
		return 0, errors.New("buffer too short for permissions u64")
	}
	perms := uint64(data[offset]) |
		uint64(data[offset+1])<<8 |
		uint64(data[offset+2])<<16 |
		uint64(data[offset+3])<<24 |
		uint64(data[offset+4])<<32 |
		uint64(data[offset+5])<<40 |
		uint64(data[offset+6])<<48 |
		uint64(data[offset+7])<<56
	return perms, nil
}

// ReadOrganizationMemberStatus decodes an OrganizationMemberEntry
// account's status byte. Layout at state/organization_member.rs
// (2026-04-22: permissions: OrgMemberPermissionSet u64 field was
// added between member_name and designated_by; the decoder walks
// it explicitly):
//
//	discriminator | license | member_wallet | member_name (String)
//	  | permissions (u64, OrgMemberPermissionSet::SIZE = 8)
//	  | designated_by | designated_via_operation (Option<Pubkey>)
//	  | designated_at (i64) | status (u8)
func ReadOrganizationMemberStatus(data []byte) (ApprovalStatus, error) {
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipPubkey(data, offset); err != nil {
		return 0, fmt.Errorf("organization_member: license: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil {
		return 0, fmt.Errorf("organization_member: member_wallet: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil {
		return 0, fmt.Errorf("organization_member: member_name: %w", err)
	}
	if offset, err = skip(data, offset, 8); err != nil { // permissions u64
		return 0, fmt.Errorf("organization_member: permissions: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil {
		return 0, fmt.Errorf("organization_member: designated_by: %w", err)
	}
	if offset, err = SkipBorshOption(data, offset, SkipPubkey); err != nil {
		return 0, fmt.Errorf("organization_member: designated_via_operation: %w", err)
	}
	if offset, err = SkipI64(data, offset); err != nil {
		return 0, fmt.Errorf("organization_member: designated_at: %w", err)
	}
	return ReadStatusByte(data, offset)
}

// ReadOrganizationMemberPermissions returns the OrgMemberPermissionSet
// u64 bitfield from an OrganizationMemberEntry. Apps that enforce
// permission bits (ORG_MEMBER_KYC_APPROVE, ...) call this before
// admitting a signer to a compliance flow.
func ReadOrganizationMemberPermissions(data []byte) (uint64, error) {
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipPubkey(data, offset); err != nil {
		return 0, err
	}
	if offset, err = SkipPubkey(data, offset); err != nil {
		return 0, err
	}
	if offset, err = SkipBorshString(data, offset); err != nil {
		return 0, err
	}
	if offset+8 > len(data) {
		return 0, errors.New("buffer too short for org-member permissions u64")
	}
	perms := uint64(data[offset]) |
		uint64(data[offset+1])<<8 |
		uint64(data[offset+2])<<16 |
		uint64(data[offset+3])<<24 |
		uint64(data[offset+4])<<32 |
		uint64(data[offset+5])<<40 |
		uint64(data[offset+6])<<48 |
		uint64(data[offset+7])<<56
	return perms, nil
}

// ReadLocalAppApprovalStatus decodes a LocalAppApproval account.
// Layout at state/app_approval.rs (simpler than Global):
//
//	discriminator | app_hash [u8;32] | license_nft_mint (Pubkey)
//	  | approved_by (Pubkey) | status (u8)
//
// All prefix fields are fixed-size, so the status offset is constant.
func ReadLocalAppApprovalStatus(data []byte) (ApprovalStatus, error) {
	const fixedOffset = AccountDiscriminatorLen + 32 + 32 + 32
	return ReadStatusByte(data, fixedOffset)
}

// LocalAppApprovalStatusOffset is the fixed byte offset for
// ReadLocalAppApprovalStatus — exported for fuzzing / alternative
// decoders.
const LocalAppApprovalStatusOffset = AccountDiscriminatorLen + 32 + 32 + 32

// ReadLicenseEntryTLSFingerprint returns the [32]byte
// tls_cert_fingerprint field from a LicenseEntry account. Layout from
// state/license.rs (only the fields up to and including the
// fingerprint are walked; trailing fields are not needed for the
// cross-check):
//
//	discriminator | license_nft_mint (Pubkey) | reseller_nft_mint (Pubkey)
//	  | MasterNftMint (Pubkey) | edition_number (u64)
//	  | domain (String) | install_url (String)
//	  | tls_cert_fingerprint ([u8;32])  ← here
//	  | ... (unlock_threshold, custody, etc.)
func ReadLicenseEntryTLSFingerprint(data []byte) ([32]byte, error) {
	var fp [32]byte
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipPubkey(data, offset); err != nil { // license_nft_mint
		return fp, fmt.Errorf("license: license_nft_mint: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // reseller_nft_mint
		return fp, fmt.Errorf("license: reseller_nft_mint: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // MasterNftMint
		return fp, fmt.Errorf("license: MasterNftMint: %w", err)
	}
	if offset, err = skip(data, offset, 8); err != nil { // edition_number u64
		return fp, fmt.Errorf("license: edition_number: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // domain
		return fp, fmt.Errorf("license: domain: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // install_url
		return fp, fmt.Errorf("license: install_url: %w", err)
	}
	if offset+32 > len(data) {
		return fp, errors.New("buffer too short for tls_cert_fingerprint")
	}
	copy(fp[:], data[offset:offset+32])
	return fp, nil
}

// ReadLicenseEntrySandstormVersion returns the on-chain
// `sandstorm_version: String` pin from a LicenseEntry account. The
// field sits between `dev_permissive: bool` (1 byte) and the trailing
// `trust_bundle_uri: String`. Empty string is a documented "not yet
// pinned" state per B10 — callers that surface it (B11 verifier-side
// launch comparison) treat empty as "accept any version" and warn,
// but a populated pin that diverges from the on-disk version is
// fail-closed (Inv 5).
//
// Layout walked (from state/license.rs):
//
//	discriminator | license_nft_mint (Pubkey) | reseller_nft_mint (Pubkey)
//	  | MasterNftMint (Pubkey) | edition_number (u64)
//	  | domain (String) | install_url (String)
//	  | tls_cert_fingerprint ([u8;32])
//	  | unlock_threshold (u8) | total_keyholders (u8) | active_keyholders (u8)
//	  | owner (Pubkey) | custody_mode (u8 enum)
//	  | squads_vault (Option<Pubkey>) | squads_multisig (Option<Pubkey>)
//	  | status (u8) | activated_at (i64) | revoked_at (Option<i64>)
//	  | total_shares (u32) | active_shares (u32)
//	  | total_signers (u8) | active_signers (u8)
//	  | authz_identity_pubkey (Pubkey)
//	  | dev_permissive (bool, 1 byte)
//	  | sandstorm_version (String)  ← here
//	  | trust_bundle_uri (String)
//	  | bump (u8)
func ReadLicenseEntrySandstormVersion(data []byte) (string, error) {
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipPubkey(data, offset); err != nil { // license_nft_mint
		return "", fmt.Errorf("license: license_nft_mint: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // reseller_nft_mint
		return "", fmt.Errorf("license: reseller_nft_mint: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // MasterNftMint
		return "", fmt.Errorf("license: MasterNftMint: %w", err)
	}
	if offset, err = skip(data, offset, 8); err != nil { // edition_number u64
		return "", fmt.Errorf("license: edition_number: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // domain
		return "", fmt.Errorf("license: domain: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // install_url
		return "", fmt.Errorf("license: install_url: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // tls_cert_fingerprint [u8;32]
		return "", fmt.Errorf("license: tls_cert_fingerprint: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // unlock_threshold u8
		return "", fmt.Errorf("license: unlock_threshold: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // total_keyholders u8
		return "", fmt.Errorf("license: total_keyholders: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // active_keyholders u8
		return "", fmt.Errorf("license: active_keyholders: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // owner
		return "", fmt.Errorf("license: owner: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // custody_mode (u8 enum)
		return "", fmt.Errorf("license: custody_mode: %w", err)
	}
	if offset, err = SkipBorshOption(data, offset, SkipPubkey); err != nil { // squads_vault
		return "", fmt.Errorf("license: squads_vault: %w", err)
	}
	if offset, err = SkipBorshOption(data, offset, SkipPubkey); err != nil { // squads_multisig
		return "", fmt.Errorf("license: squads_multisig: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // status (u8 enum)
		return "", fmt.Errorf("license: status: %w", err)
	}
	if offset, err = SkipI64(data, offset); err != nil { // activated_at i64
		return "", fmt.Errorf("license: activated_at: %w", err)
	}
	if offset, err = SkipBorshOption(data, offset, SkipI64); err != nil { // revoked_at Option<i64>
		return "", fmt.Errorf("license: revoked_at: %w", err)
	}
	if offset, err = skip(data, offset, 4); err != nil { // total_shares u32
		return "", fmt.Errorf("license: total_shares: %w", err)
	}
	if offset, err = skip(data, offset, 4); err != nil { // active_shares u32
		return "", fmt.Errorf("license: active_shares: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // total_signers u8
		return "", fmt.Errorf("license: total_signers: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // active_signers u8
		return "", fmt.Errorf("license: active_signers: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // authz_identity_pubkey
		return "", fmt.Errorf("license: authz_identity_pubkey: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // dev_permissive bool
		return "", fmt.Errorf("license: dev_permissive: %w", err)
	}
	// sandstorm_version: String — read u32 LE length + bytes.
	if offset+4 > len(data) {
		return "", errors.New("license: buffer too short for sandstorm_version length prefix")
	}
	length := int(uint32(data[offset]) |
		uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 |
		uint32(data[offset+3])<<24)
	offset += 4
	if offset+length > len(data) {
		return "", errors.New("license: buffer too short for sandstorm_version contents")
	}
	return string(data[offset : offset+length]), nil
}

// ReadLicenseEntryTrustBundleURI returns the on-chain
// `trust_bundle_uri: String` pin from a LicenseEntry account (D20).
// The field sits at the tail of the LicenseEntry layout, immediately
// after `sandstorm_version: String` and before `bump: u8`. Empty
// string is the documented "not yet pinned" state — deployer pins
// the URI via a follow-up update once the well-known endpoint is
// live. A populated URI is the canonical address from which a
// verifier fetches the signed trust bundle via
// `bundle.FetchFromURL`; sealed receipts (D21) embed it alongside
// the bundle hash so a verifier can re-fetch and re-check the
// detached Ed25519 signature against the pubkey published in this
// same `LicenseEntry.authz_identity_pubkey`.
//
// Layout walked here is the same prefix as
// ReadLicenseEntrySandstormVersion above, plus one extra
// SkipBorshString to step over sandstorm_version itself.
func ReadLicenseEntryTrustBundleURI(data []byte) (string, error) {
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipPubkey(data, offset); err != nil { // license_nft_mint
		return "", fmt.Errorf("license: license_nft_mint: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // reseller_nft_mint
		return "", fmt.Errorf("license: reseller_nft_mint: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // MasterNftMint
		return "", fmt.Errorf("license: MasterNftMint: %w", err)
	}
	if offset, err = skip(data, offset, 8); err != nil { // edition_number u64
		return "", fmt.Errorf("license: edition_number: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // domain
		return "", fmt.Errorf("license: domain: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // install_url
		return "", fmt.Errorf("license: install_url: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // tls_cert_fingerprint
		return "", fmt.Errorf("license: tls_cert_fingerprint: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // unlock_threshold u8
		return "", fmt.Errorf("license: unlock_threshold: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // total_keyholders u8
		return "", fmt.Errorf("license: total_keyholders: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // active_keyholders u8
		return "", fmt.Errorf("license: active_keyholders: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // owner
		return "", fmt.Errorf("license: owner: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // custody_mode u8 enum
		return "", fmt.Errorf("license: custody_mode: %w", err)
	}
	if offset, err = SkipBorshOption(data, offset, SkipPubkey); err != nil { // squads_vault
		return "", fmt.Errorf("license: squads_vault: %w", err)
	}
	if offset, err = SkipBorshOption(data, offset, SkipPubkey); err != nil { // squads_multisig
		return "", fmt.Errorf("license: squads_multisig: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // status u8 enum
		return "", fmt.Errorf("license: status: %w", err)
	}
	if offset, err = SkipI64(data, offset); err != nil { // activated_at i64
		return "", fmt.Errorf("license: activated_at: %w", err)
	}
	if offset, err = SkipBorshOption(data, offset, SkipI64); err != nil { // revoked_at Option<i64>
		return "", fmt.Errorf("license: revoked_at: %w", err)
	}
	if offset, err = skip(data, offset, 4); err != nil { // total_shares u32
		return "", fmt.Errorf("license: total_shares: %w", err)
	}
	if offset, err = skip(data, offset, 4); err != nil { // active_shares u32
		return "", fmt.Errorf("license: active_shares: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // total_signers u8
		return "", fmt.Errorf("license: total_signers: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // active_signers u8
		return "", fmt.Errorf("license: active_signers: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // authz_identity_pubkey
		return "", fmt.Errorf("license: authz_identity_pubkey: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // dev_permissive bool
		return "", fmt.Errorf("license: dev_permissive: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // sandstorm_version
		return "", fmt.Errorf("license: sandstorm_version: %w", err)
	}
	// trust_bundle_uri: String — read u32 LE length + bytes.
	if offset+4 > len(data) {
		return "", errors.New("license: buffer too short for trust_bundle_uri length prefix")
	}
	length := int(uint32(data[offset]) |
		uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 |
		uint32(data[offset+3])<<24)
	offset += 4
	if offset+length > len(data) {
		return "", errors.New("license: buffer too short for trust_bundle_uri contents")
	}
	return string(data[offset : offset+length]), nil
}

// LicenseEntrySummary holds the fields the launch-prep operator CLI
// (`melusina-installhealth`) needs to walk a LicenseEntry account
// once and answer multiple checks (status, dev_permissive, authz
// pubkey, squads_vault, install_url, sandstorm_version,
// trust_bundle_uri). The intent is to amortize one PDA read across
// 5+ checks rather than fetch the same blob N times.
//
// The struct deliberately mirrors the on-chain layout in
// state/license.rs — every field name maps to the Rust struct field
// 1:1. Fields that aren't useful to the operator-side CLI (bump,
// edition_number, share counters) are walked but not surfaced.
//
// SquadsVault / RevokedAt are nullable: HasSquadsVault / HasRevokedAt
// distinguish None from a zero-valued Some.
type LicenseEntrySummary struct {
	LicenseNFTMint      [32]byte
	ResellerNFTMint     [32]byte
	MasterNftMint       [32]byte
	Domain              string
	InstallURL          string
	TLSCertFingerprint  [32]byte
	Owner               [32]byte
	HasSquadsVault      bool
	SquadsVault         [32]byte
	Status              ApprovalStatus
	HasRevokedAt        bool
	RevokedAt           int64
	AuthzIdentityPubkey [32]byte
	DevPermissive       bool
	SandstormVersion    string
	TrustBundleURI      string
	// EnabledFeatures is the G1/B1 vertical launch-gate bitmask
	// (LicenseEntry.enabled_features). 0 = no vertical may launch
	// (fail-closed). melusina-recover materializes it to
	// /run/melusina/enabled-features for the shell launch-gate (1.4).
	EnabledFeatures uint64
}

// ReadLicenseEntrySummary walks the entire LicenseEntry layout once
// and returns a LicenseEntrySummary. Pinned to state/license.rs —
// any future reorder there has to land in this function in the same
// commit (Inv 5: better fail-closed than silently mis-decode).
//
// Status uses the same Active=0/Revoked=1 byte values as
// ApprovalStatus (LicenseStatus is a separate Anchor enum but its
// discriminants line up by happy coincidence; the launch-prep CLI
// surfaces this via .Status.RequireActive()).
func ReadLicenseEntrySummary(data []byte) (LicenseEntrySummary, error) {
	var s LicenseEntrySummary
	offset := AccountDiscriminatorLen
	var err error

	// license_nft_mint
	if offset+32 > len(data) {
		return s, errors.New("license: buffer too short for license_nft_mint")
	}
	copy(s.LicenseNFTMint[:], data[offset:offset+32])
	offset += 32

	// reseller_nft_mint
	if offset+32 > len(data) {
		return s, errors.New("license: buffer too short for reseller_nft_mint")
	}
	copy(s.ResellerNFTMint[:], data[offset:offset+32])
	offset += 32

	// MasterNftMint
	if offset+32 > len(data) {
		return s, errors.New("license: buffer too short for MasterNftMint")
	}
	copy(s.MasterNftMint[:], data[offset:offset+32])
	offset += 32

	if offset, err = skip(data, offset, 8); err != nil { // edition_number u64
		return s, fmt.Errorf("license: edition_number: %w", err)
	}

	// domain (String)
	s.Domain, offset, err = readBorshString(data, offset)
	if err != nil {
		return s, fmt.Errorf("license: domain: %w", err)
	}
	// install_url (String)
	s.InstallURL, offset, err = readBorshString(data, offset)
	if err != nil {
		return s, fmt.Errorf("license: install_url: %w", err)
	}

	// tls_cert_fingerprint
	if offset+32 > len(data) {
		return s, errors.New("license: buffer too short for tls_cert_fingerprint")
	}
	copy(s.TLSCertFingerprint[:], data[offset:offset+32])
	offset += 32

	if offset, err = skip(data, offset, 1); err != nil { // unlock_threshold u8
		return s, fmt.Errorf("license: unlock_threshold: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // total_keyholders u8
		return s, fmt.Errorf("license: total_keyholders: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // active_keyholders u8
		return s, fmt.Errorf("license: active_keyholders: %w", err)
	}

	// owner Pubkey
	if offset+32 > len(data) {
		return s, errors.New("license: buffer too short for owner")
	}
	copy(s.Owner[:], data[offset:offset+32])
	offset += 32

	if offset, err = skip(data, offset, 1); err != nil { // custody_mode u8 enum
		return s, fmt.Errorf("license: custody_mode: %w", err)
	}

	// squads_vault Option<Pubkey>
	if offset >= len(data) {
		return s, errors.New("license: buffer too short for squads_vault tag")
	}
	switch data[offset] {
	case 0:
		offset++
	case 1:
		offset++
		if offset+32 > len(data) {
			return s, errors.New("license: buffer too short for Some(squads_vault)")
		}
		s.HasSquadsVault = true
		copy(s.SquadsVault[:], data[offset:offset+32])
		offset += 32
	default:
		return s, fmt.Errorf("license: invalid Option tag for squads_vault: %d", data[offset])
	}

	// squads_multisig Option<Pubkey> — walked but not exposed.
	if offset, err = SkipBorshOption(data, offset, SkipPubkey); err != nil {
		return s, fmt.Errorf("license: squads_multisig: %w", err)
	}

	// status u8 (LicenseStatus: Active=0, Revoked=1)
	if offset >= len(data) {
		return s, errors.New("license: buffer too short for status")
	}
	s.Status = ApprovalStatus(data[offset])
	offset++

	// activated_at i64 — walked but not exposed.
	if offset, err = SkipI64(data, offset); err != nil {
		return s, fmt.Errorf("license: activated_at: %w", err)
	}
	// revoked_at Option<i64>
	if offset >= len(data) {
		return s, errors.New("license: buffer too short for revoked_at tag")
	}
	switch data[offset] {
	case 0:
		offset++
	case 1:
		offset++
		if offset+8 > len(data) {
			return s, errors.New("license: buffer too short for Some(revoked_at)")
		}
		s.HasRevokedAt = true
		s.RevokedAt = int64(uint64(data[offset]) |
			uint64(data[offset+1])<<8 |
			uint64(data[offset+2])<<16 |
			uint64(data[offset+3])<<24 |
			uint64(data[offset+4])<<32 |
			uint64(data[offset+5])<<40 |
			uint64(data[offset+6])<<48 |
			uint64(data[offset+7])<<56)
		offset += 8
	default:
		return s, fmt.Errorf("license: invalid Option tag for revoked_at: %d", data[offset])
	}

	if offset, err = skip(data, offset, 4); err != nil { // total_shares u32
		return s, fmt.Errorf("license: total_shares: %w", err)
	}
	if offset, err = skip(data, offset, 4); err != nil { // active_shares u32
		return s, fmt.Errorf("license: active_shares: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // total_signers u8
		return s, fmt.Errorf("license: total_signers: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // active_signers u8
		return s, fmt.Errorf("license: active_signers: %w", err)
	}

	// authz_identity_pubkey Pubkey
	if offset+32 > len(data) {
		return s, errors.New("license: buffer too short for authz_identity_pubkey")
	}
	copy(s.AuthzIdentityPubkey[:], data[offset:offset+32])
	offset += 32

	// dev_permissive bool
	if offset >= len(data) {
		return s, errors.New("license: buffer too short for dev_permissive")
	}
	s.DevPermissive = data[offset] != 0
	offset++

	// sandstorm_version String
	s.SandstormVersion, offset, err = readBorshString(data, offset)
	if err != nil {
		return s, fmt.Errorf("license: sandstorm_version: %w", err)
	}

	// trust_bundle_uri String
	s.TrustBundleURI, offset, err = readBorshString(data, offset)
	if err != nil {
		return s, fmt.Errorf("license: trust_bundle_uri: %w", err)
	}

	// accepted_stores Vec<Pubkey> — u32 LE length prefix + N*32 bytes (C1).
	if offset+4 > len(data) {
		return s, errors.New("license: buffer too short for accepted_stores length")
	}
	n := int(uint32(data[offset]) | uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24)
	offset += 4
	if n < 0 || offset+n*32 > len(data) {
		return s, errors.New("license: accepted_stores length out of range")
	}
	offset += n * 32

	// root_store_domain_hash [u8;32] (C1)
	if offset+32 > len(data) {
		return s, errors.New("license: buffer too short for root_store_domain_hash")
	}
	offset += 32

	// enabled_features u64 LE (G1/B1) — the vertical launch-gate bitmask.
	if offset+8 > len(data) {
		return s, errors.New("license: buffer too short for enabled_features")
	}
	s.EnabledFeatures = uint64(data[offset]) | uint64(data[offset+1])<<8 |
		uint64(data[offset+2])<<16 | uint64(data[offset+3])<<24 |
		uint64(data[offset+4])<<32 | uint64(data[offset+5])<<40 |
		uint64(data[offset+6])<<48 | uint64(data[offset+7])<<56

	return s, nil
}

// readBorshString returns the decoded String value AND the new offset.
// The other Skip* helpers throw away the value, which is wasteful when
// the caller actually needs it; this one keeps both ends honest.
func readBorshString(data []byte, offset int) (string, int, error) {
	if offset+4 > len(data) {
		return "", 0, errors.New("buffer too short for Borsh string length prefix")
	}
	length := int(uint32(data[offset]) |
		uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 |
		uint32(data[offset+3])<<24)
	offset += 4
	if offset+length > len(data) {
		return "", 0, errors.New("buffer too short for Borsh string contents")
	}
	return string(data[offset : offset+length]), offset + length, nil
}

// ReadGlobalAppApprovalAppHash returns the [32]byte app_hash field
// from a GlobalAppApproval account. Used by the trust-bundle loader's
// CrossCheckOnChain helper (B8) to assert the bundle's
// authorized_app.app_hash matches the on-chain pin.
func ReadGlobalAppApprovalAppHash(data []byte) ([32]byte, error) {
	var hash [32]byte
	if len(data) < AccountDiscriminatorLen+32 {
		return hash, errors.New("buffer too short for GlobalAppApproval.app_hash")
	}
	copy(hash[:], data[AccountDiscriminatorLen:AccountDiscriminatorLen+32])
	return hash, nil
}

// ReadGlobalAppApprovalStatus decodes a GlobalAppApproval account.
// Layout:
//
//	discriminator | app_hash [u8;32] | app_id [u8;32]
//	  | app_name (String) | version (String)
//	  | author (Pubkey) | author_approved (u8) | MasterNftMint (Pubkey)
//	  | approved_by (Pubkey) | status (u8)
//
// Two variable-length Strings before status, so we walk them.
func ReadGlobalAppApprovalStatus(data []byte) (ApprovalStatus, error) {
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = skip(data, offset, 32); err != nil { // app_hash
		return 0, fmt.Errorf("global_app: app_hash: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // app_id
		return 0, fmt.Errorf("global_app: app_id: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // app_name
		return 0, fmt.Errorf("global_app: app_name: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // version
		return 0, fmt.Errorf("global_app: version: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // author
		return 0, fmt.Errorf("global_app: author: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // author_approved bool
		return 0, fmt.Errorf("global_app: author_approved: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // MasterNftMint
		return 0, fmt.Errorf("global_app: MasterNftMint: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // approved_by
		return 0, fmt.Errorf("global_app: approved_by: %w", err)
	}
	return ReadStatusByte(data, offset)
}

// ReadSidecarApprovalStatusLocal decodes a LocalSidecarApproval PDA
// blob. Pinned to the layout in
// melusina_solana_dev-license104/programs/license-registry/src/state/sidecar_approval.rs:
//
//	discriminator | sidecar_id (String) | license_nft_mint (Pubkey)
//	  | binary_hash (Option<[u8;32]>) | scope (SidecarScope u8)
//	  | approved_by (Pubkey) | status (u8)
//
// scope is the B13 hostname-tier discriminant; readers that care
// about the tier itself use ReadSidecarApprovalScopeLocal below.
func ReadSidecarApprovalStatusLocal(data []byte) (ApprovalStatus, error) {
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipBorshString(data, offset); err != nil { // sidecar_id
		return 0, fmt.Errorf("local_sidecar: sidecar_id: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // license_nft_mint
		return 0, fmt.Errorf("local_sidecar: license_nft_mint: %w", err)
	}
	// binary_hash: Option<[u8;32]>
	if offset, err = SkipBorshOption(data, offset, func(d []byte, o int) (int, error) {
		return skip(d, o, 32)
	}); err != nil {
		return 0, fmt.Errorf("local_sidecar: binary_hash: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // scope u8
		return 0, fmt.Errorf("local_sidecar: scope: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // approved_by
		return 0, fmt.Errorf("local_sidecar: approved_by: %w", err)
	}
	return ReadStatusByte(data, offset)
}

// ReadLocalSidecarBinaryHash decodes the optional binary_hash field
// from a LocalSidecarApproval PDA. Returns (hash, true, nil) when the
// install pinned a specific build, (zero, false, nil) when the field
// is None, or (zero, false, err) on a parse failure.
//
// Used by the B11 runtime hash-attestation gate at sidecar boot: when
// the install elects to pin (Some), the on-disk SHA-256 must match;
// when it does not (None), the binary still has to match the Global
// pin. Either way the gate is fail-closed (Inv 5).
func ReadLocalSidecarBinaryHash(data []byte) ([32]byte, bool, error) {
	var zero [32]byte
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipBorshString(data, offset); err != nil { // sidecar_id
		return zero, false, fmt.Errorf("local_sidecar: sidecar_id: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // license_nft_mint
		return zero, false, fmt.Errorf("local_sidecar: license_nft_mint: %w", err)
	}
	// binary_hash: Option<[u8;32]>
	if offset >= len(data) {
		return zero, false, errors.New("local_sidecar: buffer too short for Option tag")
	}
	tag := data[offset]
	offset++
	switch tag {
	case 0:
		return zero, false, nil
	case 1:
		if offset+32 > len(data) {
			return zero, false, errors.New("local_sidecar: buffer too short for Some(binary_hash)")
		}
		var hash [32]byte
		copy(hash[:], data[offset:offset+32])
		return hash, true, nil
	default:
		return zero, false, fmt.Errorf("local_sidecar: invalid Option tag for binary_hash: %d", tag)
	}
}

// SkipBorshVecOfStrings advances past a Borsh-encoded Vec<String>
// (u32 LE count, then [u32 LE length + bytes] for each element).
func SkipBorshVecOfStrings(data []byte, offset int) (int, error) {
	if offset+4 > len(data) {
		return 0, errors.New("buffer too short for Vec<String> length prefix")
	}
	count := int(uint32(data[offset]) |
		uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 |
		uint32(data[offset+3])<<24)
	offset += 4
	var err error
	for i := 0; i < count; i++ {
		if offset, err = SkipBorshString(data, offset); err != nil {
			return 0, fmt.Errorf("Vec<String>[%d]: %w", i, err)
		}
	}
	return offset, nil
}

// ReadSidecarApprovalStatusReseller decodes a ResellerSidecarApproval
// PDA blob. Layout from state/sidecar_approval.rs:
//
//	discriminator | sidecar_id (String) | reseller_nft_mint (Pubkey)
//	  | approved_by (Pubkey) | status (u8) | ...
func ReadSidecarApprovalStatusReseller(data []byte) (ApprovalStatus, error) {
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipBorshString(data, offset); err != nil { // sidecar_id
		return 0, fmt.Errorf("reseller_sidecar: sidecar_id: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // reseller_nft_mint
		return 0, fmt.Errorf("reseller_sidecar: reseller_nft_mint: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // approved_by
		return 0, fmt.Errorf("reseller_sidecar: approved_by: %w", err)
	}
	return ReadStatusByte(data, offset)
}

// ReadGlobalSidecarBinaryHash decodes the [32]byte binary_hash field
// from a GlobalSidecarApproval PDA. The field sits immediately after
// the variable-length sidecar_id (String), so we walk past sidecar_id
// then copy 32 bytes. Used by the B11 runtime hash-attestation gate
// — Foundation's pin is the cascade root, every install inherits it
// when LocalSidecarApproval.binary_hash is None.
func ReadGlobalSidecarBinaryHash(data []byte) ([32]byte, error) {
	var zero [32]byte
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipBorshString(data, offset); err != nil { // sidecar_id
		return zero, fmt.Errorf("global_sidecar: sidecar_id: %w", err)
	}
	if offset+32 > len(data) {
		return zero, errors.New("global_sidecar: buffer too short for binary_hash")
	}
	var hash [32]byte
	copy(hash[:], data[offset:offset+32])
	return hash, nil
}

// ReadSidecarApprovalStatusGlobal decodes a GlobalSidecarApproval PDA
// blob. Layout from state/sidecar_approval.rs:
//
//	discriminator | sidecar_id (String) | binary_hash ([u8;32])
//	  | version (String) | san_list (Vec<String>)
//	  | required_permissions (u64) | author (Pubkey)
//	  | MasterNftMint (Pubkey) | approved_by (Pubkey)
//	  | status (u8) | ...
func ReadSidecarApprovalStatusGlobal(data []byte) (ApprovalStatus, error) {
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipBorshString(data, offset); err != nil { // sidecar_id
		return 0, fmt.Errorf("global_sidecar: sidecar_id: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // binary_hash [u8;32]
		return 0, fmt.Errorf("global_sidecar: binary_hash: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // version
		return 0, fmt.Errorf("global_sidecar: version: %w", err)
	}
	if offset, err = SkipBorshVecOfStrings(data, offset); err != nil { // san_list
		return 0, fmt.Errorf("global_sidecar: san_list: %w", err)
	}
	if offset, err = skip(data, offset, 8); err != nil { // required_permissions u64
		return 0, fmt.Errorf("global_sidecar: required_permissions: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // author
		return 0, fmt.Errorf("global_sidecar: author: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // MasterNftMint
		return 0, fmt.Errorf("global_sidecar: MasterNftMint: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // approved_by
		return 0, fmt.Errorf("global_sidecar: approved_by: %w", err)
	}
	return ReadStatusByte(data, offset)
}

// ── Federated-store readers (FEDERATED-STORE-MVP §C1/§C4) ─────────────────

// Pubkey is a 32-byte Solana public key. Local alias (not a primitives
// import) so the Fetch* signatures read intent-fully (`storeAuthority
// Pubkey`) without pulling melusina-solana-primitives into this module's
// dependency graph — the rest of this package already returns raw [32]byte
// for the same reason (FetchLicenseEntryTLSFingerprint, etc.). Byte-identical
// to primitives.Pubkey at the wire boundary.
type Pubkey = [32]byte

// ReadAttestationStatusByte reads one byte at offset as AttestationStatus.
// Rejects unknown variants > Superseded so a corrupt/forward-rolled account
// fails closed (Inv 5) rather than being silently treated as Active.
func ReadAttestationStatusByte(data []byte, offset int) (AttestationStatus, error) {
	if offset < 0 || offset >= len(data) {
		return 0, errors.New("attestation status offset out of range")
	}
	b := data[offset]
	if b > uint8(AttestationStatusSuperseded) {
		return AttestationStatus(b), fmt.Errorf("unknown AttestationStatus byte: %d", b)
	}
	return AttestationStatus(b), nil
}

// ReadAuthorizationStatusByte reads one byte at offset as AuthorizationStatus.
// Rejects unknown variants > Revoked (this two-variant enum has no byte 2).
func ReadAuthorizationStatusByte(data []byte, offset int) (AuthorizationStatus, error) {
	if offset < 0 || offset >= len(data) {
		return 0, errors.New("authorization status offset out of range")
	}
	b := data[offset]
	if b > uint8(AuthorizationStatusRevoked) {
		return AuthorizationStatus(b), fmt.Errorf("unknown AuthorizationStatus byte: %d", b)
	}
	return AuthorizationStatus(b), nil
}

// ReadReleaseEntry decodes a ReleaseEntry account (seeds
// ["release_v2", master_nft_mint, app_hash]; state/attestation.rs:29) and
// returns its app_hash + status. Used by C2.3's /publish gate: re-hash the
// SPK and assert it == app_hash, then assert status == Active.
//
// Layout:
//
//	discriminator | master_nft_mint (Pubkey) | app_hash ([u8;32])
//	  | app_id ([u8;32]) | release_hash ([u8;32]) | version (String)
//	  | publisher_squads_vault (Pubkey) | publisher_ed25519_pubkey ([u8;32])
//	  | signature ([u8;64]) | signed_payload_hash ([u8;32])
//	  | registered_by (Pubkey) | registered_at (i64)
//	  | status (AttestationStatus u8)  ← here
//	  | revoked_at (Option<i64>) | bump
//
// app_hash sits at the fixed offset 8+32; status follows the
// variable-length `version` String, so the walk past it is mandatory.
func ReadReleaseEntry(data []byte) (appHash [32]byte, status AttestationStatus, err error) {
	// app_hash: fixed offset, right after disc + master_nft_mint.
	const appHashOffset = AccountDiscriminatorLen + 32
	if len(data) < appHashOffset+32 {
		return appHash, 0, errors.New("release_v2: buffer too short for app_hash")
	}
	copy(appHash[:], data[appHashOffset:appHashOffset+32])

	offset := AccountDiscriminatorLen
	if offset, err = SkipPubkey(data, offset); err != nil { // master_nft_mint
		return appHash, 0, fmt.Errorf("release_v2: master_nft_mint: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // app_hash
		return appHash, 0, fmt.Errorf("release_v2: app_hash: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // app_id
		return appHash, 0, fmt.Errorf("release_v2: app_id: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // release_hash
		return appHash, 0, fmt.Errorf("release_v2: release_hash: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // version
		return appHash, 0, fmt.Errorf("release_v2: version: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // publisher_squads_vault
		return appHash, 0, fmt.Errorf("release_v2: publisher_squads_vault: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // publisher_ed25519_pubkey
		return appHash, 0, fmt.Errorf("release_v2: publisher_ed25519_pubkey: %w", err)
	}
	if offset, err = skip(data, offset, 64); err != nil { // signature
		return appHash, 0, fmt.Errorf("release_v2: signature: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // signed_payload_hash
		return appHash, 0, fmt.Errorf("release_v2: signed_payload_hash: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // registered_by
		return appHash, 0, fmt.Errorf("release_v2: registered_by: %w", err)
	}
	if offset, err = SkipI64(data, offset); err != nil { // registered_at
		return appHash, 0, fmt.Errorf("release_v2: registered_at: %w", err)
	}
	status, err = ReadAttestationStatusByte(data, offset)
	return appHash, status, err
}

// ReadReleaseEntryAppID decodes ONLY the `app_id` field of a ReleaseEntry
// account (seeds ["release_v2", master_nft_mint, app_hash]; state/attestation.rs:29).
//
// `app_id` is the STABLE per-application identity (distinct from `app_hash`,
// the per-release SPK hash) under which a FoundationAppEntry is keyed
// (["foundation_app", app_id]). The store-sidecar's /publish gate reads app_id
// from the on-chain ReleaseEntry — NEVER from the untrusted RELEASE.json — to
// derive the FoundationAppEntry and enforce the operator's tier ceiling
// (audit 2026-06-17 B1-05/B2-05). Trusting a publisher-supplied app_id would let
// a publisher name a Core-tier app_id to dodge the Standard-tier mask check.
//
// app_id sits at the FIXED offset disc + master_nft_mint + app_hash (8+32+32),
// so this is a plain fixed-offset read — no String/Option walk needed.
func ReadReleaseEntryAppID(data []byte) (appID [32]byte, err error) {
	const appIDOffset = AccountDiscriminatorLen + 32 + 32
	if len(data) < appIDOffset+32 {
		return appID, errors.New("release_v2: buffer too short for app_id")
	}
	copy(appID[:], data[appIDOffset:appIDOffset+32])
	return appID, nil
}

// SidecarIdentity holds the SidecarIdentityEntry fields the store-sidecar's
// boot-identity ceremony (audit 2026-06-17 B1-02) needs to bind its DERIVED
// operator identity to an on-chain, Foundation-cascade-gated attestation:
// binary_hash (the running binary), domain_hash (the served domain),
// tls_cert_fingerprint (the serving TLS cert), and the signing/encryption
// pubkeys (which MUST equal the keys derived from the three attest shards).
// Mirrors state/attestation.rs:134 field-for-field (the fields callers care
// about).
type SidecarIdentity struct {
	BinaryHash         [32]byte
	DomainHash         [32]byte
	TLSCertFingerprint [32]byte
	SigningPubkey      [32]byte
	EncryptionPubkey   [32]byte
	KeyVersion         uint32

	// GlobalSidecarApproval is the host-written pointer at
	// state/attestation.rs:141 — the ONLY route from a sidecar identity to its
	// approval, and therefore to the one record that can be REVOKED.
	//
	// This decoder used to SkipPubkey it away (PROVENANCE_CONTRACTS.md §7.4),
	// which is why the EXISTING revoke_global_sidecar instruction (lib.rs:1326)
	// has had zero effect on anything any verifier checks: nothing could reach
	// the account it revokes. Returning it is the whole fix.
	GlobalSidecarApproval Pubkey

	Status AttestationStatus
}

// ReadSidecarIdentity decodes a SidecarIdentityEntry account (seeds
// ["sidecar_identity", license_nft_mint, sidecar_id, key_version_le];
// state/attestation.rs:134). FAIL-CLOSED: a short/garbled buffer or an unknown
// status byte returns an error so the boot gate refuses to start (Inv 5).
//
// Layout:
//
//	discriminator (8) | license_nft_mint (Pubkey) | sidecar_id (String)
//	  | binary_hash ([u8;32]) | domain_hash ([u8;32])
//	  | tls_cert_fingerprint ([u8;32]) | ca_chain_hash ([u8;32])
//	  | signing_pubkey ([u8;32]) | encryption_pubkey ([u8;32])
//	  | key_version (u32 LE) | local_sidecar_approval (Pubkey)
//	  | global_sidecar_approval (Pubkey) | registered_by (Pubkey)
//	  | registered_at (i64) | status (AttestationStatus u8)  ← here
//	  | revoked_at (Option<i64>) | bump
//
// All six [u8;32] hash fields follow the variable-length `sidecar_id` String,
// so the walk past it is mandatory (no fixed offsets).
func ReadSidecarIdentity(data []byte) (SidecarIdentity, error) {
	var s SidecarIdentity
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipPubkey(data, offset); err != nil { // license_nft_mint
		return s, fmt.Errorf("sidecar_identity: license_nft_mint: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // sidecar_id
		return s, fmt.Errorf("sidecar_identity: sidecar_id: %w", err)
	}
	// binary_hash | domain_hash | tls_cert_fingerprint | ca_chain_hash |
	// signing_pubkey | encryption_pubkey — six contiguous [u8;32] fields.
	if offset, err = readFixed32(data, offset, "binary_hash", &s.BinaryHash); err != nil {
		return s, err
	}
	if offset, err = readFixed32(data, offset, "domain_hash", &s.DomainHash); err != nil {
		return s, err
	}
	if offset, err = readFixed32(data, offset, "tls_cert_fingerprint", &s.TLSCertFingerprint); err != nil {
		return s, err
	}
	if offset, err = skip(data, offset, 32); err != nil { // ca_chain_hash (unused by the boot gate)
		return s, fmt.Errorf("sidecar_identity: ca_chain_hash: %w", err)
	}
	if offset, err = readFixed32(data, offset, "signing_pubkey", &s.SigningPubkey); err != nil {
		return s, err
	}
	if offset, err = readFixed32(data, offset, "encryption_pubkey", &s.EncryptionPubkey); err != nil {
		return s, err
	}
	if offset+4 > len(data) { // key_version (u32 LE)
		return s, errors.New("sidecar_identity: buffer too short for key_version")
	}
	s.KeyVersion = uint32(data[offset]) |
		uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 |
		uint32(data[offset+3])<<24
	offset += 4
	if offset, err = SkipPubkey(data, offset); err != nil { // local_sidecar_approval
		return s, fmt.Errorf("sidecar_identity: local_sidecar_approval: %w", err)
	}
	// global_sidecar_approval — RETURNED, not skipped (§7.4): it is the only
	// pointer to the one revocable record.
	if offset, err = readFixed32(data, offset, "global_sidecar_approval", &s.GlobalSidecarApproval); err != nil {
		return s, err
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // registered_by
		return s, fmt.Errorf("sidecar_identity: registered_by: %w", err)
	}
	if offset, err = SkipI64(data, offset); err != nil { // registered_at
		return s, fmt.Errorf("sidecar_identity: registered_at: %w", err)
	}
	status, err := ReadAttestationStatusByte(data, offset)
	if err != nil {
		return s, fmt.Errorf("sidecar_identity: status: %w", err)
	}
	s.Status = status
	return s, nil
}

// readFixed32 copies a fixed 32-byte field at offset into dst and returns the
// advanced offset, naming the field on a short buffer.
func readFixed32(data []byte, offset int, field string, dst *[32]byte) (int, error) {
	if offset+32 > len(data) {
		return 0, fmt.Errorf("sidecar_identity: %s: buffer too short (need 32 at %d, have %d)", field, offset, len(data)-offset)
	}
	copy(dst[:], data[offset:offset+32])
	return offset + 32, nil
}

// StoreOperatorAuthz holds the StoreOperatorAuthorization fields the
// store-operate gate (§C1) and the cascade store stage (§C4) need. Mirrors
// state/store_operator.rs field-for-field (the fields callers care about).
type StoreOperatorAuthz struct {
	Status          AuthorizationStatus
	StoreAuthority  [32]byte
	AllowedTierMask uint8
	IsRoot          bool
	StoreDomainHash [32]byte
}

// ReadStoreOperatorAuthz decodes a StoreOperatorAuthorization account (seeds
// ["store_operator", license_nft_mint, store_domain_hash];
// state/store_operator.rs:30, LEN=193). Every field before `status` is
// fixed-size, so this is a straight fixed-offset walk — no String/Option
// prefix.
//
// Layout:
//
//	discriminator (8) | license_nft_mint ([32]) | store_domain_hash ([32])
//	  | store_authority ([32]) | tls_cert_fingerprint ([32])
//	  | is_root (bool, 1) | allowed_tier_mask (u8, 1) | max_listings (u32, 4)
//	  | status (AuthorizationStatus u8) | authorized_by ([32])
//	  | authorized_at (i64) | revoked_at (Option<i64>) | bump (u8)
func ReadStoreOperatorAuthz(data []byte) (StoreOperatorAuthz, error) {
	var a StoreOperatorAuthz
	// store_domain_hash: disc + license_nft_mint.
	const domainHashOffset = AccountDiscriminatorLen + 32
	// store_authority: + store_domain_hash.
	const storeAuthorityOffset = domainHashOffset + 32
	// is_root: + store_authority + tls_cert_fingerprint.
	const isRootOffset = storeAuthorityOffset + 32 + 32
	const tierMaskOffset = isRootOffset + 1
	const maxListingsOffset = tierMaskOffset + 1
	const statusOffset = maxListingsOffset + 4

	if len(data) < statusOffset+1 {
		return a, errors.New("store_operator: buffer too short for fixed prefix")
	}
	copy(a.StoreDomainHash[:], data[domainHashOffset:domainHashOffset+32])
	copy(a.StoreAuthority[:], data[storeAuthorityOffset:storeAuthorityOffset+32])
	a.IsRoot = data[isRootOffset] != 0
	a.AllowedTierMask = data[tierMaskOffset]
	status, err := ReadAuthorizationStatusByte(data, statusOffset)
	if err != nil {
		return a, fmt.Errorf("store_operator: status: %w", err)
	}
	a.Status = status
	return a, nil
}

// StoreReleaseListing holds the StoreReleaseListing fields the cascade store
// stage (§C4) needs: app_hash (which release), store_domain_hash (which
// serving domain the listing binds to), operator_authorization (the
// StoreOperatorAuthorization PDA that gated it, re-checkable for Active),
// and status. Mirrors the C1 layout in state/attestation.rs:308.
type StoreReleaseListing struct {
	AppHash               [32]byte
	StoreDomainHash       [32]byte
	OperatorAuthorization [32]byte
	Status                AuthorizationStatus
}

// ReadStoreReleaseListing decodes a StoreReleaseListing account (seeds
// ["store_release_listing", store_authority, app_hash];
// state/attestation.rs:308). C1 appended store_domain_hash +
// operator_authorization AFTER the `revoked_at: Option<i64>` field, so the
// walk past that Option is mandatory to reach them — a fixed offset would
// be wrong by 0 or 9 bytes depending on the Option tag.
//
// Layout (C1, LEN=251):
//
//	discriminator | store_authority (Pubkey) | app_hash ([u8;32])
//	  | release_entry (Pubkey) | store_cert_fingerprint ([u8;32])
//	  | listed_by (Pubkey) | listed_at (i64)
//	  | status (AuthorizationStatus u8)  ← read here
//	  | revoked_at (Option<i64>)         ← walk past
//	  | store_domain_hash ([u8;32])      ← C1 +32
//	  | operator_authorization (Pubkey)  ← C1 +32
//	  | bump (u8)
//
// app_hash is at the fixed offset disc + store_authority.
func ReadStoreReleaseListing(data []byte) (StoreReleaseListing, error) {
	var l StoreReleaseListing
	const appHashOffset = AccountDiscriminatorLen + 32
	if len(data) < appHashOffset+32 {
		return l, errors.New("store_release_listing: buffer too short for app_hash")
	}
	copy(l.AppHash[:], data[appHashOffset:appHashOffset+32])

	offset := AccountDiscriminatorLen
	var err error
	if offset, err = SkipPubkey(data, offset); err != nil { // store_authority
		return l, fmt.Errorf("store_release_listing: store_authority: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // app_hash
		return l, fmt.Errorf("store_release_listing: app_hash: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // release_entry
		return l, fmt.Errorf("store_release_listing: release_entry: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // store_cert_fingerprint
		return l, fmt.Errorf("store_release_listing: store_cert_fingerprint: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // listed_by
		return l, fmt.Errorf("store_release_listing: listed_by: %w", err)
	}
	if offset, err = SkipI64(data, offset); err != nil { // listed_at
		return l, fmt.Errorf("store_release_listing: listed_at: %w", err)
	}
	// status (read in place, then advance one byte).
	status, err := ReadAuthorizationStatusByte(data, offset)
	if err != nil {
		return l, fmt.Errorf("store_release_listing: status: %w", err)
	}
	l.Status = status
	if offset, err = skip(data, offset, 1); err != nil { // status u8
		return l, fmt.Errorf("store_release_listing: status advance: %w", err)
	}
	if offset, err = SkipBorshOption(data, offset, SkipI64); err != nil { // revoked_at Option<i64>
		return l, fmt.Errorf("store_release_listing: revoked_at: %w", err)
	}
	// store_domain_hash (C1 +32)
	if offset+32 > len(data) {
		return l, errors.New("store_release_listing: buffer too short for store_domain_hash")
	}
	copy(l.StoreDomainHash[:], data[offset:offset+32])
	offset += 32
	// operator_authorization (C1 +32)
	if offset+32 > len(data) {
		return l, errors.New("store_release_listing: buffer too short for operator_authorization")
	}
	copy(l.OperatorAuthorization[:], data[offset:offset+32])
	return l, nil
}

// BlacklistType mirrors the Anchor enum at state/app_approval.rs:22
// (License=0, App=1, Author=2). BlacklistEntry carries no status field — the
// PDA's mere EXISTENCE is the deny signal (§C4). PDA-not-found therefore
// means "not blacklisted".
type BlacklistType uint8

const (
	BlacklistTypeLicense BlacklistType = 0
	BlacklistTypeApp     BlacklistType = 1
	BlacklistTypeAuthor  BlacklistType = 2
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

// ReadBlacklistEntryType decodes the entry_type discriminant from a
// BlacklistEntry account (seeds ["blacklist", target]; state/app_approval.rs:109).
// The struct has NO status field — existence is the deny signal — so this
// reader returns the type discriminant only. entry_type is the very first
// field after the discriminator (fixed offset 8). Callers that fetched the
// account already know it exists; treat ErrPDANotFound from the Fetch wrapper
// as "not blacklisted".
func ReadBlacklistEntryType(data []byte) (BlacklistType, error) {
	if len(data) < AccountDiscriminatorLen+1 {
		return 0, errors.New("blacklist: buffer too short for entry_type")
	}
	b := data[AccountDiscriminatorLen]
	if b > uint8(BlacklistTypeAuthor) {
		return BlacklistType(b), fmt.Errorf("unknown BlacklistType byte: %d", b)
	}
	return BlacklistType(b), nil
}
