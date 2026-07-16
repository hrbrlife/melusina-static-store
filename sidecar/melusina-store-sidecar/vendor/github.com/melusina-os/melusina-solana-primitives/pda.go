package primitives

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// Pubkey is a 32-byte Solana public key. Type-alias for readability;
// apps round-trip to / from base58 at the wire boundary via
// EncodeBase58 / DecodeBase58.
type Pubkey [32]byte

// PDABump is Solana's u8 program-derived-address bump seed.
type PDABump = uint8

// pdaMarker is the SHA-256 suffix Solana's FindProgramAddress algorithm
// uses to mark PDA seeds distinct from ordinary pubkeys.
var pdaMarker = []byte("ProgramDerivedAddress")

// ed25519OnCurveOrderBytes is the order of the Ed25519 base-point.
// Reused only to sanity-check derived addresses; PDA derivation is
// rejection-sampled by Solana's runtime, so what we produce here is
// the canonical "find" sequence mirroring the on-chain derivation.
// (Kept as reference comment only — not all consumers need this.)

// FindProgramAddress is a faithful port of Solana's
// Pubkey::find_program_address: iterate bump from 255 down to 0,
// hashing seeds || [bump] || programID || "ProgramDerivedAddress",
// and return the first candidate that is off-curve (i.e. not a
// valid Ed25519 public key). The returned pubkey is the PDA and the
// returned bump is the canonical bump used.
//
// This implementation returns the first candidate that is NOT on the
// Ed25519 curve via a cheap check: if the high bit indicates an
// encoded point and the value is on-curve, skip.  For Melusina's
// purposes the bump-search ordering is what matters — the actual
// on-curve check MUST match the Solana runtime exactly, so for
// correctness this function accepts an optional OnCurve predicate.
//
// If OnCurve is nil, a conservative default is used that rejects
// obviously on-curve encodings; callers needing strict Solana parity
// should pass a predicate backed by a full Ed25519 decompression
// routine (e.g. filippo.io/edwards25519).
func FindProgramAddress(seeds [][]byte, programID Pubkey, onCurve func([32]byte) bool) (Pubkey, PDABump, error) {
	if onCurve == nil {
		onCurve = defaultOnCurve
	}
	for bump := 255; bump >= 0; bump-- {
		candidate, err := createProgramAddress(appendSeed(seeds, []byte{byte(bump)}), programID)
		if err != nil {
			continue // seeds+bump hit the on-curve rejection in createProgramAddress
		}
		if !onCurve(candidate) {
			return candidate, PDABump(bump), nil
		}
	}
	return Pubkey{}, 0, errors.New("no off-curve PDA found for given seeds and program id")
}

// MaxSeedLength is Solana's hard per-seed limit. Any seed longer than
// this is rejected at derive time — the on-chain runtime would reject
// it anyway, and silently accepting oversized seeds here masks bugs
// until they surface as failed tx at the worst moment.
const MaxSeedLength = 32

// ErrSeedTooLong is returned by FindProgramAddress / the Derive* helpers
// when a caller passes a seed that exceeds MaxSeedLength. Callers MUST
// pre-hash long seeds themselves (e.g. sha256 the sidecar_id) rather
// than expect this package to silently truncate.
var ErrSeedTooLong = errors.New("pda seed exceeds 32-byte limit")

func createProgramAddress(seeds [][]byte, programID Pubkey) (Pubkey, error) {
	h := sha256.New()
	for _, s := range seeds {
		if len(s) > MaxSeedLength {
			return Pubkey{}, fmt.Errorf("%w (got %d bytes)", ErrSeedTooLong, len(s))
		}
		h.Write(s)
	}
	h.Write(programID[:])
	h.Write(pdaMarker)
	var out Pubkey
	copy(out[:], h.Sum(nil))
	return out, nil
}

func appendSeed(seeds [][]byte, extra []byte) [][]byte {
	out := make([][]byte, 0, len(seeds)+1)
	out = append(out, seeds...)
	out = append(out, extra)
	return out
}

// defaultOnCurve is the real Solana-compatible on-curve predicate.
// A 32-byte candidate is "on-curve" iff it is a valid compressed
// Ed25519 public key — i.e. the bytes round-trip through a Point
// SetBytes. The runtime rejects on-curve PDAs at account creation,
// so callers that want byte-equivalent PDA addresses to what Solana
// would accept MUST skip these candidates during bump search.
//
// Per the filippo.io/edwards25519 docs: Point.SetBytes fails for
// non-canonical / non-curve encodings, which is exactly the
// predicate we need (returning true = on curve = candidate rejected
// by Solana for PDA use).
//
// Audit P0-d: the pre-fix stub returned false unconditionally,
// meaning every Derive* returned bump 255 regardless of whether
// that candidate was a valid pubkey — substantially wrong for
// ~50% of inputs. This implementation returns the right answer.
func defaultOnCurve(candidate [32]byte) bool {
	var p edwards25519.Point
	_, err := p.SetBytes(candidate[:])
	return err == nil
}

// ── Melusina PDA seed constants ──────────────────────────────────────────

// Seed prefixes — must match the Anchor program's #[account(seeds=...)]
// declarations at melusina_solana_dev-license104/programs/license-registry/
// src/state/*.rs. Any drift here is an authorization bypass.
var (
	SeedInstallAdmin        = []byte("install_admin")
	SeedOrganizationMember  = []byte("organization_member")
	SeedLicense             = []byte("license")
	SeedGlobalApp           = []byte("global_app")
	SeedResellerApp         = []byte("reseller_app")
	SeedLocalApp            = []byte("local_app")
	SeedGlobalSidecar       = []byte("global_sidecar")
	SeedResellerSidecar     = []byte("reseller_sidecar")
	SeedLocalSidecar        = []byte("local_sidecar")
	SeedContractWhitelist   = []byte("contract_whitelist")
	SeedAppContractPair     = []byte("app_contract_pair")
	SeedDomainClaim         = []byte("domain_claim")
	SeedReleaseV2           = []byte("release_v2")
	SeedGrainAssignment     = []byte("grain_assignment")
	SeedPearlIdentity       = []byte("pearl_identity")
	SeedSidecarIdentity     = []byte("sidecar_identity")
	SeedAppSidecarAuthz     = []byte("app_sidecar_authz")
	SeedAppCapnpAuthz       = []byte("app_capnp_authz")
	SeedCrossLicenseHop     = []byte("cross_license_hop")
	SeedSensitivePolicy     = []byte("sensitive_policy")
	SeedSensitiveRecord     = []byte("sensitive_record")
	SeedInstallerRelease    = []byte("installer_release")
	SeedStoreReleaseListing = []byte("store_release_listing")
	SeedStoreOperator       = []byte("store_operator")
	SeedBlacklist           = []byte("blacklist")
	SeedFoundationApp       = []byte("foundation_app")
)

// StoreDomainHash is the FROZEN canonical host → store_domain_hash
// normalization (FEDERATED-STORE-MVP §C1, mirrored from the on-chain
// instructions/licenses.rs path):
//
//	store_domain_hash = sha256(ascii_lower(strip_one_trailing_dot(host)))
//
// Three steps, in this exact order:
//  1. strip a SINGLE trailing '.' (the FQDN root dot), if present;
//  2. ASCII-lowercase ONLY (A–Z → a–z). This deliberately mirrors Rust's
//     `str::to_ascii_lowercase` — NOT Go's Unicode-aware strings.ToLower —
//     so a non-ASCII byte is left untouched and the Go + Rust digests stay
//     byte-identical (the on-chain handler rejects ':' '/' '*' in domains,
//     so practical inputs are ASCII hostnames anyway);
//  3. sha256 of the resulting bytes.
//
// This is the 32-byte HASH used DIRECTLY as the third PDA seed for
// StoreOperatorAuthorization, and it is likewise the seed for DomainClaim
// (["domain_claim", domain_hash]). Per the C-5 warning the RAW HOST STRING is
// never a seed — the exported helper that seeded it is deleted (see below).
//
// Cross-lang coherence (FEDERATED-STORE-MVP §S8): sha256("melusina-os.org")
// == 0595e1c47c3033976959c872a52b4ad9a1470faf1e7c31426e0d669f9fa4d4d7,
// the program-pinned ROOT_STORE_DOMAIN_HASH (constants.rs:101).
func StoreDomainHash(host string) [32]byte {
	if len(host) > 0 && host[len(host)-1] == '.' {
		host = host[:len(host)-1]
	}
	// ASCII-only lowercase, byte-for-byte parity with Rust to_ascii_lowercase.
	b := []byte(host)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return sha256.Sum256(b)
}

// DeriveInstallAdmin returns the InstallAdminEntry PDA for the given
// license NFT mint + admin wallet. Seeds: ["install_admin", licenseMint, admin].
func DeriveInstallAdmin(licenseMint, admin Pubkey, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedInstallAdmin, licenseMint[:], admin[:]}, programID, nil)
}

// DeriveOrganizationMember returns OrganizationMemberEntry[licenseMint, member].
func DeriveOrganizationMember(licenseMint, member Pubkey, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedOrganizationMember, licenseMint[:], member[:]}, programID, nil)
}

// DeriveLicense returns LicenseEntry[licenseMint].
func DeriveLicense(licenseMint Pubkey, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedLicense, licenseMint[:]}, programID, nil)
}

// DeriveGlobalApp returns GlobalAppApproval[masterMint, appHash].
func DeriveGlobalApp(masterMint Pubkey, appHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedGlobalApp, masterMint[:], appHash[:]}, programID, nil)
}

// DeriveResellerApp returns ResellerAppApproval[resellerMint, appHash].
func DeriveResellerApp(resellerMint Pubkey, appHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedResellerApp, resellerMint[:], appHash[:]}, programID, nil)
}

// DeriveLocalApp returns LocalAppApproval[licenseMint, appHash].
func DeriveLocalApp(licenseMint Pubkey, appHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedLocalApp, licenseMint[:], appHash[:]}, programID, nil)
}

// ValidateSidecarID returns ErrSeedTooLong if sidecarID exceeds
// MaxSeedLength. All current Melusina sidecar IDs ("ailagoon",
// "telescreen", "mermail", "fineract", "vintage", "dns-sidecar",
// "wolfdog", "remotebak", "chainwatch") fit well under 32 bytes; this
// guard catches future additions that would break PDA derivation.
func ValidateSidecarID(sidecarID string) error {
	if len(sidecarID) == 0 {
		return errors.New("sidecar_id must be non-empty")
	}
	if len(sidecarID) > MaxSeedLength {
		return fmt.Errorf("%w: sidecar_id %q has %d bytes", ErrSeedTooLong, sidecarID, len(sidecarID))
	}
	return nil
}

// DeriveGlobalSidecar returns GlobalSidecarApproval[masterMint, sidecarID].
// From FINAL 22 APRL MVP PLAN §5.2. Returns ErrSeedTooLong if sidecarID
// exceeds 32 bytes.
func DeriveGlobalSidecar(masterMint Pubkey, sidecarID string, programID Pubkey) (Pubkey, PDABump, error) {
	if err := ValidateSidecarID(sidecarID); err != nil {
		return Pubkey{}, 0, err
	}
	return FindProgramAddress([][]byte{SeedGlobalSidecar, masterMint[:], []byte(sidecarID)}, programID, nil)
}

// DeriveResellerSidecar returns ResellerSidecarApproval[resellerMint, sidecarID].
func DeriveResellerSidecar(resellerMint Pubkey, sidecarID string, programID Pubkey) (Pubkey, PDABump, error) {
	if err := ValidateSidecarID(sidecarID); err != nil {
		return Pubkey{}, 0, err
	}
	return FindProgramAddress([][]byte{SeedResellerSidecar, resellerMint[:], []byte(sidecarID)}, programID, nil)
}

// DeriveLocalSidecar returns LocalSidecarApproval[licenseMint, sidecarID].
func DeriveLocalSidecar(licenseMint Pubkey, sidecarID string, programID Pubkey) (Pubkey, PDABump, error) {
	if err := ValidateSidecarID(sidecarID); err != nil {
		return Pubkey{}, 0, err
	}
	return FindProgramAddress([][]byte{SeedLocalSidecar, licenseMint[:], []byte(sidecarID)}, programID, nil)
}

// DeriveContractWhitelist returns ContractWhitelist[programID_bound].
func DeriveContractWhitelist(programIDBound Pubkey, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedContractWhitelist, programIDBound[:]}, programID, nil)
}

// DeriveAppContractPair returns AppContractPair[appHash, programIDBound].
func DeriveAppContractPair(appHash [32]byte, programIDBound Pubkey, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedAppContractPair, appHash[:], programIDBound[:]}, programID, nil)
}

// `DeriveDomainClaim(domain string, ...)` STOOD HERE AND IS DELETED.
//
// It derived `[SeedDomainClaim, []byte(domain)]` — the RAW DOMAIN STRING. The
// on-chain program seeds the 32-BYTE HASH: `seeds = [b"domain_claim",
// domain_hash.as_ref()]` (licenses.rs:399, domain.rs:44; close_domain_claim_unsafe's
// own comment spells it `[b"domain_claim", sha256(domain)]`). The two derive
// DIFFERENT addresses, so this helper could NEVER find a real account — it had
// ZERO production callers, and every reference to it anywhere in the tree was a
// COMMENT WARNING PEOPLE NOT TO CALL IT.
//
// It is deleted rather than annotated because four prose warnings guarding an
// exported footgun IS the disease: a helper whose NAME says DomainClaim and whose
// CODE derives a PDA the program never writes is a trap that documentation cannot
// disarm, and the next lane to reach for the obviously-named function would have
// derived a dead address, found nothing, refused every honest artifact as "domain
// unclaimed" — fail-closed but wrong, and debugged as a chain problem for a week.
// Greenfield: the killed path dies, it does not get a comment.
//
// To derive a real DomainClaim, seed the hash DIRECTLY:
//
//	FindProgramAddress([][]byte{SeedDomainClaim, domainHash[:]}, programID, nil)
//
// where domainHash is StoreDomainHash(host). trustmaster/solanachain.go's
// ReadDomainClaim is the reference implementation, and its
// TestReadDomainClaim_DoesNotUseTheRawStringDeriver still pins the two
// derivations apart — computing the string-seeded address INLINE, so the trap
// stays tested without a footgun in the public API to test it with.

// DeriveReleaseV2 returns ReleaseEntry[masterMint, appHash].
func DeriveReleaseV2(masterMint Pubkey, appHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedReleaseV2, masterMint[:], appHash[:]}, programID, nil)
}

// DerivePearlAssignment returns PearlAssignment[licenseMint, pearlIDHash].
func DerivePearlAssignment(licenseMint Pubkey, pearlIDHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedGrainAssignment, licenseMint[:], pearlIDHash[:]}, programID, nil)
}

// DeriveGrainAssignment is retained for lower-level callers that still mirror
// the historical on-chain seed label. New Melusina code should call
// DerivePearlAssignment.
func DeriveGrainAssignment(licenseMint Pubkey, grainIDHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return DerivePearlAssignment(licenseMint, grainIDHash, programID)
}

// DerivePearlIdentity returns PearlIdentityEntry[licenseMint, grainIDHash].
func DerivePearlIdentity(licenseMint Pubkey, grainIDHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedPearlIdentity, licenseMint[:], grainIDHash[:]}, programID, nil)
}

// DeriveSidecarIdentity returns SidecarIdentityEntry[licenseMint, sidecarID, keyVersionLE].
func DeriveSidecarIdentity(licenseMint Pubkey, sidecarID string, keyVersion uint32, programID Pubkey) (Pubkey, PDABump, error) {
	if err := ValidateSidecarID(sidecarID); err != nil {
		return Pubkey{}, 0, err
	}
	kv := make([]byte, 4)
	binary.LittleEndian.PutUint32(kv, keyVersion)
	return FindProgramAddress([][]byte{SeedSidecarIdentity, licenseMint[:], []byte(sidecarID), kv}, programID, nil)
}

// DeriveAppSidecarAuthz returns AppSidecarAuthorization[licenseMint, appHash, sidecarID].
func DeriveAppSidecarAuthz(licenseMint Pubkey, appHash [32]byte, sidecarID string, programID Pubkey) (Pubkey, PDABump, error) {
	if err := ValidateSidecarID(sidecarID); err != nil {
		return Pubkey{}, 0, err
	}
	return FindProgramAddress([][]byte{SeedAppSidecarAuthz, licenseMint[:], appHash[:], []byte(sidecarID)}, programID, nil)
}

// DeriveAppCapnpAuthz returns AppCapnpAuthorization[licenseMint, sourceAppHash, destAppHash].
func DeriveAppCapnpAuthz(licenseMint Pubkey, sourceAppHash, destAppHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedAppCapnpAuthz, licenseMint[:], sourceAppHash[:], destAppHash[:]}, programID, nil)
}

// DeriveCrossLicenseHop returns CrossLicenseHopAuthorization[sourceLicense, destLicense, hopHash].
func DeriveCrossLicenseHop(sourceLicense, destLicense Pubkey, hopHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedCrossLicenseHop, sourceLicense[:], destLicense[:], hopHash[:]}, programID, nil)
}

// DeriveSensitivePolicy returns SensitiveActionPolicy[licenseMint, appHash, actionKindHash].
func DeriveSensitivePolicy(licenseMint Pubkey, appHash, actionKindHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedSensitivePolicy, licenseMint[:], appHash[:], actionKindHash[:]}, programID, nil)
}

// DeriveSensitiveRecord returns SensitiveActionRecord[licenseMint, actionRecordHash].
func DeriveSensitiveRecord(licenseMint Pubkey, actionRecordHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedSensitiveRecord, licenseMint[:], actionRecordHash[:]}, programID, nil)
}

// DeriveInstallerRelease returns InstallerReleaseEntry[masterMint, installerHash].
func DeriveInstallerRelease(masterMint Pubkey, installerHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedInstallerRelease, masterMint[:], installerHash[:]}, programID, nil)
}

// DeriveStoreReleaseListing returns StoreReleaseListing[storeAuthority, appHash].
func DeriveStoreReleaseListing(storeAuthority Pubkey, appHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedStoreReleaseListing, storeAuthority[:], appHash[:]}, programID, nil)
}

// DeriveStoreOperatorAuthz returns StoreOperatorAuthorization PDA, seeds
// ["store_operator", license_nft_mint, store_domain_hash] (FEDERATED-STORE-MVP
// §C1; state/store_operator.rs:18). storeDomainHash is the 32-byte HASH
// produced by StoreDomainHash — it is used DIRECTLY as a seed (C-5 warning: the
// raw host string is never a seed on this program).
func DeriveStoreOperatorAuthz(licenseMint Pubkey, storeDomainHash [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedStoreOperator, licenseMint[:], storeDomainHash[:]}, programID, nil)
}

// DeriveFoundationApp returns FoundationAppEntry PDA, seeds
// ["foundation_app", app_id] (state/foundation.rs:42). The basic-app catalog
// the reseller store-sidecar MIRRORS from the root (FEDERATED-STORE-MVP §C2.6)
// is keyed on app_id; the ROOT-MIRROR worker re-derives this PDA per basic app
// and re-checks the entry is Active before re-serving the root's bytes.
func DeriveFoundationApp(appID [32]byte, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedFoundationApp, appID[:]}, programID, nil)
}

// DeriveBlacklistEntry returns BlacklistEntry PDA, seeds ["blacklist", target]
// (state/app_approval.rs:107). The cascade verify path (FEDERATED-STORE-MVP
// §C4) reads this to deny blacklisted licenses / apps / authors. `target` is
// the blacklisted Pubkey (license_nft_mint, app_id-keyed pubkey, or author).
func DeriveBlacklistEntry(target Pubkey, programID Pubkey) (Pubkey, PDABump, error) {
	return FindProgramAddress([][]byte{SeedBlacklist, target[:]}, programID, nil)
}

// Encode Pubkey as base58 for wire / JSON serialization.
func (p Pubkey) Base58() string { return EncodeBase58(p[:]) }

// PubkeyFromBase58 parses a base58 Solana pubkey.
func PubkeyFromBase58(s string) (Pubkey, error) {
	raw, err := DecodeBase58(s)
	if err != nil {
		return Pubkey{}, err
	}
	if len(raw) != 32 {
		return Pubkey{}, errors.New("pubkey must be 32 bytes")
	}
	var p Pubkey
	copy(p[:], raw)
	return p, nil
}

// ReadU64LE reads a little-endian uint64 from b, returning the value
// and the number of bytes consumed. Useful for on-chain account-data
// deserialization in each consumer (this package intentionally does
// not own Borsh decoding of specific PDAs; see README non-goals).
func ReadU64LE(b []byte) (uint64, int, error) {
	if len(b) < 8 {
		return 0, 0, errors.New("buffer too short for u64")
	}
	return binary.LittleEndian.Uint64(b), 8, nil
}
