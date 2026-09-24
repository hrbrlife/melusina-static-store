// Verbatim excerpts of the license-registry program that define the
// ReleaseEntry account (the app release attestation), its signed payload and
// how it is created. The Store's decoder (../entry.go) and its tests are
// checked against these bytes, never the other way round. Nothing here is
// compiled.
//
// source: github.com/melusina-os/melusina-os-smartcontract, commit 2ab9ee3fbc4c954665a19f7fb1601fcbfd93d401
//   programs/license-registry/src/state/attestation.rs        blob 1313b36f6c081a794e44dc1754fc94b6222364c0 lines 6-11, 43-77
//   programs/license-registry/src/instructions/attestation.rs blob c9b7c70504bbbf016498c4e41f09c31e70095244 lines 960-970, 1612-1632
//   programs/license-registry/src/constants.rs                blob 92089962493bf902f1646474b4d3a393418a490f line 31
//
// Regenerate (each section is the exact line range above, in this order):
//   git show 2ab9ee3fbc4c954665a19f7fb1601fcbfd93d401:programs/license-registry/src/state/attestation.rs | sed -n '6,11p;43,77p'
//   git show 2ab9ee3fbc4c954665a19f7fb1601fcbfd93d401:programs/license-registry/src/instructions/attestation.rs | sed -n '960,970p;1612,1632p'
//   git show 2ab9ee3fbc4c954665a19f7fb1601fcbfd93d401:programs/license-registry/src/constants.rs | sed -n '31p'

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttestationStatus {
    Active,
    Revoked,
    Superseded,
}
#[account]
pub struct ReleaseEntry {
    pub master_nft_mint: Pubkey,
    pub app_hash: [u8; 32],
    pub app_id: [u8; 32],
    pub release_hash: [u8; 32],
    pub version: String,
    pub publisher_squads_vault: Pubkey,
    pub publisher_ed25519_pubkey: [u8; 32],
    pub signature: [u8; 64],
    pub signed_payload_hash: [u8; 32],
    pub registered_by: Pubkey,
    pub registered_at: i64,
    pub status: AttestationStatus,
    pub revoked_at: Option<i64>,
    pub bump: u8,
}

impl ReleaseEntry {
    pub const LEN: usize = 8
        + 32
        + 32
        + 32
        + 32
        + (4 + MAX_RELEASE_VERSION_LEN)
        + 32
        + 32
        + 64
        + 32
        + 32
        + 8
        + 1
        + (1 + 8)
        + 1;
}
#[derive(Accounts)]
#[instruction(app_hash: [u8; 32])]
pub struct RegisterReleaseEntry<'info> {
    #[account(
        init,
        payer = authority,
        space = ReleaseEntry::LEN,
        seeds = [b"release_v2", master_nft_mint.key().as_ref(), app_hash.as_ref()],
        bump
    )]
    pub release_entry: Account<'info, ReleaseEntry>,
fn release_payload_hash(
    master_nft_mint: Pubkey,
    app_hash: [u8; 32],
    app_id: [u8; 32],
    release_hash: [u8; 32],
    version: &str,
    publisher_squads_vault: Pubkey,
    publisher_ed25519_pubkey: [u8; 32],
) -> [u8; 32] {
    hashv(&[
        b"melusina-release-entry-v1",
        master_nft_mint.as_ref(),
        app_hash.as_ref(),
        app_id.as_ref(),
        release_hash.as_ref(),
        version.as_bytes(),
        publisher_squads_vault.as_ref(),
        publisher_ed25519_pubkey.as_ref(),
    ])
    .to_bytes()
}
pub const MAX_RELEASE_VERSION_LEN: usize = 32;
