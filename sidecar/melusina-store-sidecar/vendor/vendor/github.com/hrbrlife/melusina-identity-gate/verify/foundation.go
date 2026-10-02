package verify

import (
	"errors"
	"fmt"
)

// FoundationAppTier mirrors the Anchor enum at state/foundation.rs:9
// (Core=0, Standard=1) — the basic-app classification the reseller
// store-sidecar's ROOT-MIRROR worker (FEDERATED-STORE-MVP §C2.6) re-checks
// against the tier the root advertised, so a Standard app cannot be silently
// promoted into a Core slot (or vice-versa) when mirrored.
type FoundationAppTier uint8

const (
	FoundationAppTierCore     FoundationAppTier = 0
	FoundationAppTierStandard FoundationAppTier = 1
)

func (t FoundationAppTier) String() string {
	switch t {
	case FoundationAppTierCore:
		return "Core"
	case FoundationAppTierStandard:
		return "Standard"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(t))
	}
}

// ReadFoundationAppTierByte reads one byte at offset as FoundationAppTier,
// rejecting unknown variants > Standard so a corrupt/forward-rolled account
// fails closed (Inv 5) rather than being silently admitted into a tier slot.
func ReadFoundationAppTierByte(data []byte, offset int) (FoundationAppTier, error) {
	if offset < 0 || offset >= len(data) {
		return 0, errors.New("foundation app tier offset out of range")
	}
	b := data[offset]
	if b > uint8(FoundationAppTierStandard) {
		return FoundationAppTier(b), fmt.Errorf("unknown FoundationAppTier byte: %d", b)
	}
	return FoundationAppTier(b), nil
}

// ReadInstallerReleaseEntry decodes an InstallerReleaseEntry account (seeds
// ["installer_release", master_nft_mint, installer_hash]; state/attestation.rs:282)
// and returns its installer_hash + status. Used by the reseller store-sidecar's
// ROOT-MIRROR worker (§C2.6): when re-serving the base Melusina installer
// binary mirrored from the root, the worker re-derives this PDA and asserts
// status == Active before serving the bytes — it NEVER originates the binary.
//
// Layout:
//
//	discriminator (8) | master_nft_mint (Pubkey) | installer_hash ([u8;32])
//	  | version (String) | publisher_squads_vault (Pubkey)
//	  | registered_by (Pubkey) | registered_at (i64)
//	  | status (AttestationStatus u8)  ← here
//	  | revoked_at (Option<i64>) | bump
//
// installer_hash sits at the fixed offset 8+32; status follows the
// variable-length `version` String, so the walk past it is mandatory.
func ReadInstallerReleaseEntry(data []byte) (installerHash [32]byte, status AttestationStatus, err error) {
	// installer_hash: fixed offset, right after disc + master_nft_mint.
	const installerHashOffset = AccountDiscriminatorLen + 32
	if len(data) < installerHashOffset+32 {
		return installerHash, 0, errors.New("installer_release: buffer too short for installer_hash")
	}
	copy(installerHash[:], data[installerHashOffset:installerHashOffset+32])

	offset := AccountDiscriminatorLen
	if offset, err = SkipPubkey(data, offset); err != nil { // master_nft_mint
		return installerHash, 0, fmt.Errorf("installer_release: master_nft_mint: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // installer_hash
		return installerHash, 0, fmt.Errorf("installer_release: installer_hash: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // version
		return installerHash, 0, fmt.Errorf("installer_release: version: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // publisher_squads_vault
		return installerHash, 0, fmt.Errorf("installer_release: publisher_squads_vault: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // registered_by
		return installerHash, 0, fmt.Errorf("installer_release: registered_by: %w", err)
	}
	if offset, err = SkipI64(data, offset); err != nil { // registered_at
		return installerHash, 0, fmt.Errorf("installer_release: registered_at: %w", err)
	}
	status, err = ReadAttestationStatusByte(data, offset)
	return installerHash, status, err
}

// FoundationAppEntry holds the FoundationAppEntry fields the ROOT-MIRROR
// worker (§C2.6) needs: app_id (which basic app), tier (Core/Standard, so a
// mirror cannot reclassify), and status (Active/Revoked/RevokingCascade —
// reuses the ApprovalStatus enum, since the on-chain field is
// AppApprovalStatus = ApprovalStatus). Mirrors state/foundation.rs:44.
type FoundationAppEntry struct {
	AppID  [32]byte
	Tier   FoundationAppTier
	Status ApprovalStatus
}

// ReadFoundationAppEntry decodes a FoundationAppEntry account (seeds
// ["foundation_app", app_id]; state/foundation.rs:44) and returns its app_id,
// tier, and status. Used by the reseller store-sidecar's ROOT-MIRROR worker
// (§C2.6): for each basic app mirrored from the root, re-derive this PDA and
// assert status == Active AND tier matches what the root advertised before
// re-serving the root's bytes. The store NEVER originates a basic app.
//
// Layout:
//
//	discriminator (8) | app_id ([u8;32]) | app_name (String)
//	  | interop_pubkey ([u8;32]) | pgp_fingerprint ([u8;20])
//	  | category (InteropCategory u8) | tier (FoundationAppTier u8)  ← tier here
//	  | added_by (Pubkey) | added_at (i64)
//	  | status (AppApprovalStatus u8)  ← status here
//	  | revoked_at (Option<i64>) | bump
//
// app_id is at the fixed offset 8; tier + status follow the variable-length
// `app_name` String, so the walk past it is mandatory.
func ReadFoundationAppEntry(data []byte) (FoundationAppEntry, error) {
	var e FoundationAppEntry
	// app_id: fixed offset, right after the discriminator.
	const appIDOffset = AccountDiscriminatorLen
	if len(data) < appIDOffset+32 {
		return e, errors.New("foundation_app: buffer too short for app_id")
	}
	copy(e.AppID[:], data[appIDOffset:appIDOffset+32])

	offset := AccountDiscriminatorLen
	var err error
	if offset, err = skip(data, offset, 32); err != nil { // app_id
		return e, fmt.Errorf("foundation_app: app_id: %w", err)
	}
	if offset, err = SkipBorshString(data, offset); err != nil { // app_name
		return e, fmt.Errorf("foundation_app: app_name: %w", err)
	}
	if offset, err = skip(data, offset, 32); err != nil { // interop_pubkey
		return e, fmt.Errorf("foundation_app: interop_pubkey: %w", err)
	}
	if offset, err = skip(data, offset, 20); err != nil { // pgp_fingerprint [u8;20]
		return e, fmt.Errorf("foundation_app: pgp_fingerprint: %w", err)
	}
	if offset, err = skip(data, offset, 1); err != nil { // category (InteropCategory u8)
		return e, fmt.Errorf("foundation_app: category: %w", err)
	}
	// tier (read in place, then advance one byte).
	tier, err := ReadFoundationAppTierByte(data, offset)
	if err != nil {
		return e, fmt.Errorf("foundation_app: tier: %w", err)
	}
	e.Tier = tier
	if offset, err = skip(data, offset, 1); err != nil { // tier u8
		return e, fmt.Errorf("foundation_app: tier advance: %w", err)
	}
	if offset, err = SkipPubkey(data, offset); err != nil { // added_by
		return e, fmt.Errorf("foundation_app: added_by: %w", err)
	}
	if offset, err = SkipI64(data, offset); err != nil { // added_at
		return e, fmt.Errorf("foundation_app: added_at: %w", err)
	}
	status, err := ReadStatusByte(data, offset) // AppApprovalStatus = ApprovalStatus
	if err != nil {
		return e, fmt.Errorf("foundation_app: status: %w", err)
	}
	e.Status = status
	return e, nil
}
