package pda

import (
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type Pubkey = primitives.Pubkey
type Bump = primitives.PDABump

var (
	FromBase58 = primitives.PubkeyFromBase58
	ToBase58   = primitives.EncodeBase58
)

func Release(masterMint Pubkey, appHash [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveReleaseV2(masterMint, appHash, programID)
}

func PearlAssignment(licenseMint Pubkey, pearlIDHash [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DerivePearlAssignment(licenseMint, pearlIDHash, programID)
}

func PearlIdentity(licenseMint Pubkey, pearlIDHash [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DerivePearlIdentity(licenseMint, pearlIDHash, programID)
}

func SidecarIdentity(licenseMint Pubkey, sidecarID string, keyVersion uint32, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveSidecarIdentity(licenseMint, sidecarID, keyVersion, programID)
}

// GlobalSidecar derives the GlobalSidecarApproval PDA, seeds
// ["global_sidecar", master_nft_mint, sidecar_id].
//
// It is a sidecar's release record: the account carrying binary_hash and — once
// the PROVENANCE_CONTRACTS.md §6.4 program change lands — release_policy_hash,
// the fail-closed guard pin that gates VERIFIED_DECISION.
//
// sidecarresult derives it FORWARD from the verifier's build-pinned master mint
// (Rule 7) and rejects any result whose carried ReleaseRef, or whose
// SidecarIdentityEntry.global_sidecar_approval pointer, disagrees. A carried PDA
// is a diagnostic, never a destination: if the blob names which account to read,
// the blob chose the authority and the read is theater.
//
// Note the seed has NO binary_hash and NO version, and
// handler_update_global_sidecar_binary_hash (lib.rs:1292) mutates the account in
// place — so one approval account describes whatever build was last written to
// it. That is why R-11e must bind approval.binary_hash to the init-once
// SidecarIdentityEntry.binary_hash (§6.3.2).
func GlobalSidecar(masterMint Pubkey, sidecarID string, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveGlobalSidecar(masterMint, sidecarID, programID)
}

func AppSidecarAuthorization(licenseMint Pubkey, appHash [32]byte, sidecarID string, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveAppSidecarAuthz(licenseMint, appHash, sidecarID, programID)
}

func AppCapnpAuthorization(licenseMint Pubkey, sourceAppHash, destAppHash [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveAppCapnpAuthz(licenseMint, sourceAppHash, destAppHash, programID)
}

func CrossLicenseHop(sourceLicense, destLicense Pubkey, hopHash [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveCrossLicenseHop(sourceLicense, destLicense, hopHash, programID)
}

func SensitivePolicy(licenseMint Pubkey, appHash, actionKindHash [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveSensitivePolicy(licenseMint, appHash, actionKindHash, programID)
}

func SensitiveRecord(licenseMint Pubkey, actionRecordHash [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveSensitiveRecord(licenseMint, actionRecordHash, programID)
}

func InstallerRelease(masterMint Pubkey, installerHash [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveInstallerRelease(masterMint, installerHash, programID)
}

func StoreReleaseListing(storeAuthority Pubkey, appHash [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveStoreReleaseListing(storeAuthority, appHash, programID)
}

func StoreOperatorAuthorization(licenseMint Pubkey, storeDomainHash [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveStoreOperatorAuthz(licenseMint, storeDomainHash, programID)
}

// BlacklistStatus derives the license registry's BlacklistStatusEntry PDA,
// seeds ["blacklist_status", kind seed, target], and its canonical bump — the
// only blacklist record the greenfield program writes. The target is the
// kind's identity: the licence NFT mint, the decoded Sandstorm appId key
// (primitives.DecodeSandstormAppID — never SHA-256 of the text, never the
// master mint), or the author's key.
//
// The record must exist and read Clear: pass the account read at this address
// and this bump to verify.RequireBlacklistClear. An absent account is NOT a
// clearance.
func BlacklistStatus(kind verify.BlacklistType, target [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveBlacklistStatus(uint8(kind), target, programID)
}

// GlobalApp derives the GlobalAppApproval PDA, seeds
// ["global_app", master_nft_mint, appKey], and its canonical bump. appKey is
// the app's DECODED Sandstorm appId (primitives.DecodeSandstormAppID) — the
// key the three approval tiers share, never a release/SPK hash and never
// ReleaseEntry.app_id. The account there names the app's author, the Author
// blacklist target: pass the account read at this address and this bump to
// verify.RequireCanonicalGlobalAppApproval.
func GlobalApp(masterMint Pubkey, appKey [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveGlobalApp(masterMint, appKey, programID)
}

// FoundationApp derives the FoundationAppEntry PDA, seeds
// ["foundation_app", app_id]. The reseller store-sidecar's ROOT-MIRROR worker
// (FEDERATED-STORE-MVP §C2.6) re-derives this per basic app to re-verify the
// root's pin is still Active before re-serving the mirrored bytes.
func FoundationApp(appID [32]byte, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveFoundationApp(appID, programID)
}

// StoreDomainHash re-exports the FROZEN canonical host → store_domain_hash
// normalization so attest-side callers (C2.3 sidecar) derive the same
// 32-byte seed the on-chain program pins.
func StoreDomainHash(host string) [32]byte {
	return primitives.StoreDomainHash(host)
}
