// Verbatim excerpts of the license-registry program that define the
// InstallerReleaseEntry account and its signed payload. The Store's decoder
// (../entry.go) and its tests are checked against these bytes, never the other
// way round. Nothing here is compiled.
//
// source: V-PUBLISHER-2OF3 contracts item; the section below follows
// programs/license-registry/src/state/attestation.rs InstallerReleaseEntry,
// programs/license-registry/src/instructions/attestation.rs
// installer_release_payload_hash and constants.rs MAX_RELEASE_VERSION_LEN.

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
    pub release_trust_profile_hash: [u8; 32],
    pub additional_publisher_signatures: Vec<InstallerPublisherSignature>,
}

impl InstallerReleaseEntry {
    pub const LEN: usize =
        8 + 32 + 32 + (4 + MAX_RELEASE_VERSION_LEN) + 32 + 32 + 8 + 1 + 32 + 64 + 32 + (1 + 8) + 1
        + 32 + 4 + 1440;
}

fn installer_release_payload_hash(
    master_nft_mint: Pubkey,
    installer_hash: [u8; 32],
    version: &str,
    publisher_squads_vault: Pubkey,
    publisher_ed25519_pubkey: [u8; 32],
    estate_profile_sha256: [u8; 32],
) -> [u8; 32] {
    hashv(&[
        b"melusina-installer-release-v2",
        master_nft_mint.as_ref(),
        installer_hash.as_ref(),
        version.as_bytes(),
        publisher_squads_vault.as_ref(),
        publisher_ed25519_pubkey.as_ref(),
        estate_profile_sha256.as_ref(),
    ])
    .to_bytes()
}

pub const MAX_RELEASE_VERSION_LEN: usize = 32;
