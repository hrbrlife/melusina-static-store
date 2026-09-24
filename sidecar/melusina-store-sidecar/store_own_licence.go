package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The Store's own licence, held to verify_license's rule wherever the Store
// acts under it.
//
// The contracts define a valid licence in one place, verify_license
// (programs/license-registry/src/instructions/licenses.rs handler_verify,
// M-02): the LicenseEntry ["license", license_nft_mint] is Active AND the
// ResellerEntry ["reseller", reseller_nft_mint] of the reseller that
// LicenseEntry names is Active. The Master revokes a reseller
// (resellers.rs handler_revoke) without touching any licence under it, and no
// fact the Store's gates read moves with it: the StoreOperatorAuthorization
// under the licence stays Active (store_operator.rs revokes it only by its own
// instruction), and so does the licence's BlacklistStatusEntry. The chain
// does not stop the Store either: register_store_release_listing reads the
// operator row, never the licence or its reseller (attestation.rs
// handler_register_store_release_listing).
//
// Before this rule the Store held its own licence to verify_license only at
// start (root_store_boot_cascade.go). A running Store whose licence, or whose
// licence's reseller, was revoked kept publishing, promoting, signing
// installer and trust-bundle artifacts, registering listings and serving its
// catalogue, while the authorization daemon refused every install from it
// (authz pkg/grainauth/store_licence.go storeOperatorLicence, 80ddc10:
// cascade-blocked:store:store-reseller-inactive).
//
// verifyStoreOwnLicence is that rule, refused by the daemon's names for the
// same facts:
//   - VerifyStoreOperator runs it after the operator row, so every gate that
//     acts on the Store's write authority refuses: /stage, /publish, installer
//     publish, generation promote, listing registration and bootstrap, host
//     apply and the root trust bundle;
//   - verifyStoreReleaseListing runs it after the operator row it re-reads at
//     serve time, so the package route and the catalogue refuse on the next
//     request, never from the verdict cache. It is a Store-wide refusal, so
//     the catalogue is 503, not an omission (catalogOmission).
//
// The reseller is always the one the LicenseEntry names, never a configured
// one: the Master can move a licence to another reseller
// (handler_reassign_license). Beyond verify_license, the LicenseEntry and its
// ResellerEntry must each be under this estate's master mint
// (release_master_nft_mint, which enrollment binds to the owner-signed
// profile's anchors.masterMint), as the daemon requires of both. Each account
// is read at the address the Store derives, must be owned by the pinned
// program and is decoded completely: every Option with its payload, every
// enum tag in range and every string within the program's cap (constants.rs),
// read as Anchor reads it (bytes after the logical end are not an error).
// An absent account refuses: the program closes neither account, and this
// Store reads the chain live, so absence is never a snapshot gap here.

// The own-licence refusals. They are the authorization daemon's names for the
// serving Store's licence (authz storeOperatorLicence), plus the two absences
// the daemon reports as proof-pending.
const (
	refusalStoreLicenseAbsent          = "store-license-absent"
	refusalStoreLicenseMalformed       = "store-license-malformed"
	refusalStoreLicenseMismatch        = "store-license-mismatch"
	refusalStoreLicenseMasterMismatch  = "store-license-master-mismatch"
	refusalStoreLicenseRevoked         = "store-license-revoked"
	refusalStoreResellerAbsent         = "store-reseller-absent"
	refusalStoreResellerMalformed      = "store-reseller-malformed"
	refusalStoreResellerMismatch       = "store-reseller-mismatch"
	refusalStoreResellerMasterMismatch = "store-reseller-master-mismatch"
	refusalStoreResellerInactive       = "store-reseller-inactive"
)

// storeOwnLicenceCheck prefixes every own-licence error.
const storeOwnLicenceCheck = "check=store_own_licence"

// storeOwnLicenceRefusal is a named verdict about the Store's own licence.
// An RPC failure is not one: it is returned wrapped, and refuses all the same.
type storeOwnLicenceRefusal struct {
	reason string
	detail string
}

func (e *storeOwnLicenceRefusal) Error() string {
	return storeOwnLicenceCheck + ": " + e.reason + ": " + e.detail
}

func refuseStoreOwnLicence(reason, format string, args ...any) error {
	return &storeOwnLicenceRefusal{reason: reason, detail: fmt.Sprintf(format, args...)}
}

// The program's caps (constants.rs, state/license.rs) that every writer of a
// LicenseEntry or ResellerEntry enforces.
const (
	licenceMaxDomainLen           = 253 // MAX_DOMAIN_LEN
	licenceMaxInstallURLLen       = 512 // MAX_INSTALL_URL_LEN
	licenceMaxSandstormVersionLen = 32  // MAX_SANDSTORM_VERSION_LEN
	licenceMaxTrustBundleURILen   = 256 // MAX_TRUST_BUNDLE_URI_LEN
	licenceMaxAcceptedStores      = 16  // MAX_ACCEPTED_STORES
	resellerMaxNameLen            = 64  // MAX_NAME_LEN
	resellerMaxTerritoryLen       = 64  // MAX_TERRITORY_LEN
	resellerMaxCategoryLen        = 32  // MAX_CATEGORY_LEN
	resellerMaxBaseDomainLen      = 128 // MAX_BASE_DOMAIN_LEN
)

// licenceStatus is state/license.rs LicenseStatus and state/reseller.rs
// ResellerStatus: Active=0, Revoked=1. Any other tag is malformed.
type licenceStatus uint8

const (
	licenceStatusActive  licenceStatus = 0
	licenceStatusRevoked licenceStatus = 1
)

func (s licenceStatus) String() string {
	switch s {
	case licenceStatusActive:
		return "Active"
	case licenceStatusRevoked:
		return "Revoked"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// storeLicenceEntry is the part of a LicenseEntry the own-licence rule reads,
// decoded from the whole account (decodeStoreLicenceEntry).
type storeLicenceEntry struct {
	PDA             string
	LicenseNFTMint  primitives.Pubkey
	ResellerNFTMint primitives.Pubkey
	MasterNFTMint   primitives.Pubkey
	Status          licenceStatus
	RevokedAt       *int64
}

// storeResellerEntry is the part of a ResellerEntry the own-licence rule
// reads, decoded from the whole account (decodeStoreResellerEntry).
type storeResellerEntry struct {
	PDA             string
	ResellerNFTMint primitives.Pubkey
	MasterNFTMint   primitives.Pubkey
	ParentReseller  *primitives.Pubkey
	Category        *string
	Status          licenceStatus
	RevokedAt       *int64
	BaseDomain      *string
}

var (
	discriminatorLicenseEntry  = accountDiscriminator("LicenseEntry")
	discriminatorResellerEntry = accountDiscriminator("ResellerEntry")
)

// errLicenceAccountForeignOwner marks an account at a licence or reseller
// address that the pinned program does not own: not the account the address
// names, so it is refused as absent.
var errLicenceAccountForeignOwner = errors.New("account is not owned by the license registry")

// licenceAccountReader reads Borsh fields in order and keeps the first error,
// named "<account>: <field>: <cause>". Every length is checked against the
// bytes that remain before anything is read.
type licenceAccountReader struct {
	data    []byte
	off     int
	account string
	err     error
}

func (r *licenceAccountReader) fail(field string, format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf("%s: %s: %s", r.account, field, fmt.Sprintf(format, args...))
	}
}

func (r *licenceAccountReader) take(field string, n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.data)-r.off {
		r.fail(field, "truncated: %d bytes needed at offset %d, %d remain", n, r.off, len(r.data)-r.off)
		return nil
	}
	out := r.data[r.off : r.off+n]
	r.off += n
	return out
}

func (r *licenceAccountReader) u8(field string) uint8 {
	b := r.take(field, 1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *licenceAccountReader) u32(field string) uint32 {
	b := r.take(field, 4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

func (r *licenceAccountReader) i64(field string) int64 {
	b := r.take(field, 8)
	if b == nil {
		return 0
	}
	return int64(binary.LittleEndian.Uint64(b))
}

func (r *licenceAccountReader) pubkey(field string) primitives.Pubkey {
	var key primitives.Pubkey
	if b := r.take(field, 32); b != nil {
		copy(key[:], b)
	}
	return key
}

// cappedString reads a String the program caps at max bytes.
func (r *licenceAccountReader) cappedString(field string, max int) string {
	n := r.u32(field)
	if r.err != nil {
		return ""
	}
	if uint64(n) > uint64(max) {
		r.fail(field, "length %d exceeds the program's cap %d", n, max)
		return ""
	}
	return string(r.take(field, int(n)))
}

// optionTag reads Borsh's canonical Option tag: 0 None, 1 Some.
func (r *licenceAccountReader) optionTag(field string) bool {
	tag := r.u8(field)
	if r.err != nil {
		return false
	}
	switch tag {
	case 0:
		return false
	case 1:
		return true
	default:
		r.fail(field, "non-canonical Option tag %d", tag)
		return false
	}
}

func (r *licenceAccountReader) optionPubkey(field string) *primitives.Pubkey {
	if !r.optionTag(field) {
		return nil
	}
	key := r.pubkey(field)
	return &key
}

func (r *licenceAccountReader) optionI64(field string) *int64 {
	if !r.optionTag(field) {
		return nil
	}
	v := r.i64(field)
	return &v
}

func (r *licenceAccountReader) optionCappedString(field string, max int) *string {
	if !r.optionTag(field) {
		return nil
	}
	s := r.cappedString(field, max)
	return &s
}

func (r *licenceAccountReader) status(field string) licenceStatus {
	tag := r.u8(field)
	if r.err == nil && tag > uint8(licenceStatusRevoked) {
		r.fail(field, "unknown status tag %d", tag)
	}
	return licenceStatus(tag)
}

func (r *licenceAccountReader) discriminator(want []byte) {
	if b := r.take("discriminator", 8); b != nil && !bytes.Equal(b, want) {
		r.fail("discriminator", "mismatch: the account is not a %s", r.account)
	}
}

// decodeStoreLicenceEntry decodes a LicenseEntry (state/license.rs) field by
// field, discriminator through bump. A truncated account, another account
// type, a non-canonical Option or enum tag, a string or vector above the
// program's cap, the historical layout that ended before sandstorm_version,
// and a zero licence, reseller or master mint are each malformed.
func decodeStoreLicenceEntry(data []byte) (storeLicenceEntry, error) {
	var e storeLicenceEntry
	r := &licenceAccountReader{data: data, account: "LicenseEntry"}
	r.discriminator(discriminatorLicenseEntry)
	e.LicenseNFTMint = r.pubkey("license_nft_mint")
	e.ResellerNFTMint = r.pubkey("reseller_nft_mint")
	e.MasterNFTMint = r.pubkey("master_nft_mint")
	r.take("edition_number", 8)
	r.cappedString("domain", licenceMaxDomainLen)
	r.cappedString("install_url", licenceMaxInstallURLLen)
	r.take("tls_cert_fingerprint", 32)
	r.take("unlock_threshold/total_keyholders/active_keyholders", 3)
	r.pubkey("owner")
	if custody := r.u8("custody_mode"); r.err == nil && custody > 2 {
		r.fail("custody_mode", "unknown LicenseCustodyMode tag %d", custody)
	}
	r.optionPubkey("squads_vault")
	r.optionPubkey("squads_multisig")
	e.Status = r.status("status")
	r.i64("activated_at")
	e.RevokedAt = r.optionI64("revoked_at")
	r.take("total_shares/active_shares/total_signers/active_signers", 4+4+1+1)
	r.pubkey("authz_identity_pubkey")
	if devPermissive := r.u8("dev_permissive"); r.err == nil && devPermissive > 1 {
		r.fail("dev_permissive", "non-canonical bool %d", devPermissive)
	}
	// The historical layout ended here with the bump. The greenfield program
	// has one schema; accepting the old one would read a missing Store policy
	// as an empty one.
	if r.err == nil && len(data)-r.off <= 1 {
		r.fail("sandstorm_version", "absent: the historical LicenseEntry layout is not accepted")
	}
	r.cappedString("sandstorm_version", licenceMaxSandstormVersionLen)
	r.cappedString("trust_bundle_uri", licenceMaxTrustBundleURILen)
	stores := r.u32("accepted_stores")
	if r.err == nil && stores > licenceMaxAcceptedStores {
		r.fail("accepted_stores", "length %d exceeds the program's cap %d", stores, licenceMaxAcceptedStores)
	}
	if r.err == nil {
		r.take("accepted_stores", int(stores)*32)
	}
	r.take("root_store_domain_hash", 32)
	r.take("enabled_features", 8)
	r.u8("bump")
	if r.err != nil {
		return storeLicenceEntry{}, r.err
	}
	var zero primitives.Pubkey
	if e.LicenseNFTMint == zero || e.ResellerNFTMint == zero || e.MasterNFTMint == zero {
		return storeLicenceEntry{}, errors.New("LicenseEntry: the licence, reseller and master mints must be nonzero")
	}
	return e, nil
}

// decodeStoreResellerEntry decodes a ResellerEntry (state/reseller.rs) field
// by field, discriminator through base_domain. Both Options before status
// (parent_reseller, category) are read with their payloads, so status is
// found where the program wrote it. A truncated account, another account
// type, a non-canonical Option or enum tag, a string above the program's cap
// and a zero reseller or master mint are each malformed.
func decodeStoreResellerEntry(data []byte) (storeResellerEntry, error) {
	var e storeResellerEntry
	r := &licenceAccountReader{data: data, account: "ResellerEntry"}
	r.discriminator(discriminatorResellerEntry)
	e.ResellerNFTMint = r.pubkey("reseller_nft_mint")
	e.MasterNFTMint = r.pubkey("master_nft_mint")
	r.take("edition_number", 8)
	r.pubkey("owner")
	r.cappedString("name", resellerMaxNameLen)
	r.cappedString("territory", resellerMaxTerritoryLen)
	r.take("issuance_limit/licenses_issued", 4+4)
	e.ParentReseller = r.optionPubkey("parent_reseller")
	r.take("total_sub_resellers/active_sub_resellers", 4+4)
	e.Category = r.optionCappedString("category", resellerMaxCategoryLen)
	e.Status = r.status("status")
	r.i64("activated_at")
	e.RevokedAt = r.optionI64("revoked_at")
	r.u8("bump")
	r.take("license_price_lamports", 8)
	e.BaseDomain = r.optionCappedString("base_domain", resellerMaxBaseDomainLen)
	if r.err != nil {
		return storeResellerEntry{}, r.err
	}
	var zero primitives.Pubkey
	if e.ResellerNFTMint == zero || e.MasterNFTMint == zero {
		return storeResellerEntry{}, errors.New("ResellerEntry: the reseller and master mints must be nonzero")
	}
	return e, nil
}

// readStoreLicenceAccount is the one reader of a fetched LicenseEntry, shared
// by the live RPC read and the test chain: the pinned program must own it and
// its bytes must decode completely.
func readStoreLicenceAccount(addr string, data []byte, owner string) (storeLicenceEntry, error) {
	if owner != licenseRegistryProgramID().Base58() {
		return storeLicenceEntry{}, fmt.Errorf("%w (owner %q)", errLicenceAccountForeignOwner, owner)
	}
	entry, err := decodeStoreLicenceEntry(data)
	if err != nil {
		return storeLicenceEntry{}, &licenceAccountMalformedError{err: err}
	}
	entry.PDA = addr
	return entry, nil
}

// readStoreResellerAccount is readStoreLicenceAccount for a ResellerEntry.
func readStoreResellerAccount(addr string, data []byte, owner string) (storeResellerEntry, error) {
	if owner != licenseRegistryProgramID().Base58() {
		return storeResellerEntry{}, fmt.Errorf("%w (owner %q)", errLicenceAccountForeignOwner, owner)
	}
	entry, err := decodeStoreResellerEntry(data)
	if err != nil {
		return storeResellerEntry{}, &licenceAccountMalformedError{err: err}
	}
	entry.PDA = addr
	return entry, nil
}

// licenceAccountMalformedError marks bytes the program's account at that
// address could not have: a verdict, not a transport failure.
type licenceAccountMalformedError struct{ err error }

func (e *licenceAccountMalformedError) Error() string { return e.err.Error() }
func (e *licenceAccountMalformedError) Unwrap() error { return e.err }

// FetchLicenseEntry reads one LicenseEntry with its owner. An absent account
// is verify.ErrPDANotFound.
func (c *storeRPCReader) FetchLicenseEntry(ctx context.Context, addr string) (storeLicenceEntry, error) {
	account, err := c.GetAccount(ctx, addr)
	if err != nil {
		return storeLicenceEntry{}, err
	}
	if account == nil {
		return storeLicenceEntry{}, verify.ErrPDANotFound
	}
	return readStoreLicenceAccount(addr, account.Data, account.Owner)
}

// FetchResellerEntry reads one ResellerEntry with its owner. An absent
// account is verify.ErrPDANotFound.
func (c *storeRPCReader) FetchResellerEntry(ctx context.Context, addr string) (storeResellerEntry, error) {
	account, err := c.GetAccount(ctx, addr)
	if err != nil {
		return storeResellerEntry{}, err
	}
	if account == nil {
		return storeResellerEntry{}, verify.ErrPDANotFound
	}
	return readStoreResellerAccount(addr, account.Data, account.Owner)
}

// verifyStoreOwnLicence holds the licence this Store operates under
// (license_nft_mint) to verify_license's rule under this estate's master
// mint. It returns nil, a *storeOwnLicenceRefusal naming the rule the chain
// fails, or a wrapped read error; every non-nil result refuses.
func verifyStoreOwnLicence(ctx context.Context, cr chainReader, cfg Config, licenseMint pda.Pubkey) error {
	if cr == nil {
		return fmt.Errorf("%s: no chain reader: the Store's own licence cannot be read", storeOwnLicenceCheck)
	}
	// The estate anchor both accounts must name, refused before any chain read.
	master, err := rootStoreBootMasterMint(cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", storeOwnLicenceCheck, err)
	}

	licencePDA, _, err := primitives.DeriveLicense(licenseMint, licenseRegistryProgramID())
	if err != nil {
		return fmt.Errorf("%s: derive LicenseEntry: %w", storeOwnLicenceCheck, err)
	}
	licence, err := cr.FetchLicenseEntry(ctx, licencePDA.Base58())
	if err != nil {
		return licenceReadRefusal(err, refusalStoreLicenseAbsent, refusalStoreLicenseMalformed, "LicenseEntry", licencePDA, "the Store's licence "+licenseMint.Base58())
	}
	switch {
	case licence.LicenseNFTMint != licenseMint:
		return refuseStoreOwnLicence(refusalStoreLicenseMismatch, "the LicenseEntry at %s names licence %s, the Store operates under %s", licencePDA.Base58(), licence.LicenseNFTMint.Base58(), licenseMint.Base58())
	case licence.MasterNFTMint != master:
		return refuseStoreOwnLicence(refusalStoreLicenseMasterMismatch, "the Store's LicenseEntry %s is under master mint %s, this estate's is %s", licencePDA.Base58(), licence.MasterNFTMint.Base58(), master.Base58())
	case licence.Status != licenceStatusActive:
		return refuseStoreOwnLicence(refusalStoreLicenseRevoked, "the Store's LicenseEntry %s is %s (revoked_at %s); verify_license refuses it", licencePDA.Base58(), licence.Status, revokedAtText(licence.RevokedAt))
	}

	// The reseller is the one the witnessed LicenseEntry names.
	resellerPDA, _, err := primitives.FindProgramAddress([][]byte{[]byte("reseller"), licence.ResellerNFTMint[:]}, licenseRegistryProgramID(), nil)
	if err != nil {
		return fmt.Errorf("%s: derive ResellerEntry: %w", storeOwnLicenceCheck, err)
	}
	reseller, err := cr.FetchResellerEntry(ctx, resellerPDA.Base58())
	if err != nil {
		return licenceReadRefusal(err, refusalStoreResellerAbsent, refusalStoreResellerMalformed, "ResellerEntry", resellerPDA, "reseller "+licence.ResellerNFTMint.Base58()+", named by the Store's licence "+licenseMint.Base58())
	}
	switch {
	case reseller.ResellerNFTMint != licence.ResellerNFTMint:
		return refuseStoreOwnLicence(refusalStoreResellerMismatch, "the ResellerEntry at %s names reseller %s, the Store's licence names %s", resellerPDA.Base58(), reseller.ResellerNFTMint.Base58(), licence.ResellerNFTMint.Base58())
	case reseller.MasterNFTMint != master:
		return refuseStoreOwnLicence(refusalStoreResellerMasterMismatch, "the ResellerEntry %s of the Store's licence is under master mint %s, this estate's is %s", resellerPDA.Base58(), reseller.MasterNFTMint.Base58(), master.Base58())
	case reseller.Status != licenceStatusActive:
		return refuseStoreOwnLicence(refusalStoreResellerInactive, "the ResellerEntry %s of reseller %s, named by the Store's licence %s, is %s (revoked_at %s); verify_license refuses every licence under it", resellerPDA.Base58(), licence.ResellerNFTMint.Base58(), licenseMint.Base58(), reseller.Status, revokedAtText(reseller.RevokedAt))
	}
	return nil
}

// licenceReadRefusal names a failed read of an own-licence account: absent or
// foreign-owned, malformed, or (unnamed, wrapped) a read failure.
func licenceReadRefusal(err error, absent, malformed, account string, at pda.Pubkey, what string) error {
	var bad *licenceAccountMalformedError
	switch {
	case errors.Is(err, verify.ErrPDANotFound):
		return refuseStoreOwnLicence(absent, "no %s at %s for %s", account, at.Base58(), what)
	case errors.Is(err, errLicenceAccountForeignOwner):
		return refuseStoreOwnLicence(absent, "the account at %s for %s is not the program's %s: %v", at.Base58(), what, account, err)
	case errors.As(err, &bad):
		return refuseStoreOwnLicence(malformed, "the %s at %s for %s: %v", account, at.Base58(), what, bad.err)
	default:
		return fmt.Errorf("%s: fetch %s %s: %w", storeOwnLicenceCheck, account, at.Base58(), err)
	}
}
