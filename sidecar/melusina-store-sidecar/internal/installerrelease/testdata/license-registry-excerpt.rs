// Verbatim excerpts of the license-registry program that define the
// InstallerReleaseEntry account and its signed payload. The Store's decoder
// (../entry.go) and its tests are checked against these bytes, never the other
// way round. Nothing here is compiled.
//
// source: github.com/melusina-os/melusina-os-smartcontract, commit 26928ee1dc84d18f69bf0ee4bda94b8ba98328f6
//   programs/license-registry/src/state/attestation.rs        blob 1313b36f6c081a794e44dc1754fc94b6222364c0 lines 6-11, 309-328
//   programs/license-registry/src/instructions/attestation.rs blob c9b7c70504bbbf016498c4e41f09c31e70095244 lines 1634-1650
//   programs/license-registry/src/constants.rs                blob 92089962493bf902f1646474b4d3a393418a490f line 31
//
// Regenerate (each section is the exact line range above, in this order):
//   git show 26928ee1dc84d18f69bf0ee4bda94b8ba98328f6:programs/license-registry/src/state/attestation.rs | sed -n '6,11p;309,328p'
//   git show 26928ee1dc84d18f69bf0ee4bda94b8ba98328f6:programs/license-registry/src/instructions/attestation.rs | sed -n '1634,1650p'
//   git show 26928ee1dc84d18f69bf0ee4bda94b8ba98328f6:programs/license-registry/src/constants.rs | sed -n '31p'

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AttestationStatus {
    Active,
    Revoked,
    Superseded,
}
#[account]
pub struct InstallerReleaseEntry {
    pub master_nft_mint: Pubkey,
    pub installer_hash: [u8; 32],
    pub version: String,
    pub publisher_squads_vault: Pubkey,
    pub registered_by: Pubkey,
    pub registered_at: i64,
    pub status: AttestationStatus,
    pub publisher_ed25519_pubkey: [u8; 32],
    pub publisher_signature: [u8; 64],
    pub signed_payload_hash: [u8; 32],
    pub revoked_at: Option<i64>,
    pub bump: u8,
}

impl InstallerReleaseEntry {
    pub const LEN: usize =
        8 + 32 + 32 + (4 + MAX_RELEASE_VERSION_LEN) + 32 + 32 + 8 + 1 + 32 + 64 + 32 + (1 + 8) + 1;
}

fn installer_release_payload_hash(
    master_nft_mint: Pubkey,
    installer_hash: [u8; 32],
    version: &str,
    publisher_squads_vault: Pubkey,
    publisher_ed25519_pubkey: [u8; 32],
) -> [u8; 32] {
    hashv(&[
        b"melusina-installer-release-v1",
        master_nft_mint.as_ref(),
        installer_hash.as_ref(),
        version.as_bytes(),
        publisher_squads_vault.as_ref(),
        publisher_ed25519_pubkey.as_ref(),
    ])
    .to_bytes()
}

pub const MAX_RELEASE_VERSION_LEN: usize = 32;
