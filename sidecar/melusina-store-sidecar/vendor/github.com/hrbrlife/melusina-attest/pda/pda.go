package pda

import primitives "github.com/melusina-os/melusina-solana-primitives"

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

func BlacklistEntry(target Pubkey, programID Pubkey) (Pubkey, Bump, error) {
	return primitives.DeriveBlacklistEntry(target, programID)
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
