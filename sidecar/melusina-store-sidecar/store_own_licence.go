package main

import (
	"context"
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
// fact the Store's write and serve gates read moves with it: the
// StoreOperatorAuthorization under the licence stays Active
// (store_operator.rs revokes it only by its own instruction), and so does the
// licence's BlacklistStatusEntry. A reseller revoking the licence
// (licenses.rs handler_revoke) leaves the operator row Active too. The chain
// does not stop the Store either: register_store_release_listing reads the
// operator row, never the licence or its reseller (attestation.rs
// handler_register_store_release_listing).
//
// Before this rule the Store held its own licence to verify_license only at
// start (root_store_boot_cascade.go). A running Store whose licence, or whose
// licence's reseller, was revoked kept publishing, promoting, signing host
// apply plans and trust bundles, registering listings and serving its
// catalogue, while the authorization daemon refused every install from it
// (authz pkg/grainauth/store_licence.go storeOperatorLicence, 80ddc10:
// cascade-blocked:store:store-reseller-inactive).
//
// verifyStoreOwnLicence is that rule, refused by the daemon's names for the
// same facts. It runs wherever the Store reads its own operator row:
//   - VerifyStoreOperator runs it after the operator row, so every gate that
//     acts on the Store's write authority refuses: /stage, /publish, installer
//     publish, generation promote, listing registration and bootstrap, host
//     apply plan and issue, and the root trust bundle;
//   - verifyStoreReleaseListing runs it after the operator row it re-reads at
//     serve time, so the package route and the catalogue refuse on the next
//     request, never from the verdict cache. It is a Store-wide refusal, so
//     the catalogue is 503, never an omission (catalogOmission).
//
// The reseller is always the one the LicenseEntry names, never a configured
// one: the Master can move a licence to another reseller
// (handler_reassign_license). Beyond verify_license, the LicenseEntry and its
// ResellerEntry must each be under this estate's master mint
// (release_master_nft_mint, which enrollment binds to the owner-signed
// profile's anchors.masterMint, and which the boot cascade already requires),
// as the daemon requires of both.
//
// Each account is read at the address the Store derives, must be owned by the
// pinned program and carry its Anchor discriminator (requireDiscAndOwner), and
// is decoded by the reader the approval cascade, and so the boot cascade,
// already uses for it: the LicenseEntry by decodeLicenseEntryHead, the
// ResellerEntry by the vendored reader the cascade and the tenant update
// controller use (verify.DecodeResellerEntry), which reads parent_reseller and
// category with their payloads when they are Some and refuses any other
// Option tag and any status other than Active or Revoked. So the Store's own
// licence never reads one way at start and another at a gate. An absent
// account refuses: the program closes neither account, and this Store reads
// the chain live, so an absence is never a snapshot gap here.

// The own-licence refusals. They are the authorization daemon's names for
// the serving Store's licence (authz storeOperatorLicence and
// licenceReseller), plus the two absences the daemon holds proof-pending.
const (
	refusalStoreLicenseAbsent          = "store-license-absent"
	refusalStoreLicenseMalformed       = "store-license-malformed"
	refusalStoreLicenseMismatch        = "store-license-mismatch"
	refusalStoreLicenseMasterMismatch  = "store-license-master-mismatch"
	refusalStoreLicenseRevoked         = "store-license-revoked"
	refusalStoreNoReseller             = "store-no-reseller"
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

// readStoreLicenceAccount is the one reader of a fetched LicenseEntry, shared
// by the live RPC read and the test chain: owned by the pinned program,
// carrying the LicenseEntry discriminator, and decoded by the cascade's walk.
func readStoreLicenceAccount(data []byte, owner string) (licenseEntryHead, error) {
	if err := requireDiscAndOwner("LicenseEntry", data, owner); err != nil {
		return licenseEntryHead{}, err
	}
	head, err := decodeLicenseEntryHead(data)
	if err != nil {
		return licenseEntryHead{}, cascadeRefusal(errCascadeAccountMalformed, "LicenseEntry", "%v", err)
	}
	return head, nil
}

// readStoreResellerAccount is readStoreLicenceAccount for a ResellerEntry,
// decoded by the vendored reader the cascade uses.
func readStoreResellerAccount(data []byte, owner string) (verify.ResellerEntry, error) {
	if err := requireDiscAndOwner("ResellerEntry", data, owner); err != nil {
		return verify.ResellerEntry{}, err
	}
	entry, err := verify.DecodeResellerEntry(data)
	if err != nil {
		return verify.ResellerEntry{}, cascadeRefusal(errCascadeAccountMalformed, "ResellerEntry", "parse ResellerEntry: %v", err)
	}
	return entry, nil
}

// FetchLicenseEntry reads one LicenseEntry with its owner. An absent account
// is verify.ErrPDANotFound.
func (c *storeRPCReader) FetchLicenseEntry(ctx context.Context, addr string) (licenseEntryHead, error) {
	account, err := c.GetAccount(ctx, addr)
	if err != nil {
		return licenseEntryHead{}, err
	}
	if account == nil {
		return licenseEntryHead{}, verify.ErrPDANotFound
	}
	return readStoreLicenceAccount(account.Data, account.Owner)
}

// FetchResellerEntry reads one ResellerEntry with its owner. An absent
// account is verify.ErrPDANotFound.
func (c *storeRPCReader) FetchResellerEntry(ctx context.Context, addr string) (verify.ResellerEntry, error) {
	account, err := c.GetAccount(ctx, addr)
	if err != nil {
		return verify.ResellerEntry{}, err
	}
	if account == nil {
		return verify.ResellerEntry{}, verify.ErrPDANotFound
	}
	return readStoreResellerAccount(account.Data, account.Owner)
}

// verifyStoreOwnLicence holds the licence this Store operates under
// (license_nft_mint) to verify_license's rule under this estate's master
// mint. It returns nil, a *storeOwnLicenceRefusal naming the rule the chain
// fails, or a wrapped read error; every non-nil result refuses.
func verifyStoreOwnLicence(ctx context.Context, cr chainReader, cfg Config, licenseMint pda.Pubkey) error {
	if cr == nil {
		return fmt.Errorf("%s: no chain reader: the Store's own licence cannot be read", storeOwnLicenceCheck)
	}
	// The estate anchor both accounts must name, refused before any chain
	// read, by the boot cascade's names.
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
		return ownLicenceReadRefusal(err, refusalStoreLicenseAbsent, refusalStoreLicenseMalformed, "LicenseEntry", licencePDA, "the Store's licence "+licenseMint.Base58())
	}
	switch {
	case licence.LicenseNFTMint != licenseMint:
		return refuseStoreOwnLicence(refusalStoreLicenseMismatch, "the LicenseEntry at %s names licence %s, the Store operates under %s", licencePDA.Base58(), licence.LicenseNFTMint.Base58(), licenseMint.Base58())
	case licence.MasterNFTMint != master:
		return refuseStoreOwnLicence(refusalStoreLicenseMasterMismatch, "the Store's LicenseEntry %s is under master mint %s, this estate's is %s", licencePDA.Base58(), licence.MasterNFTMint.Base58(), master.Base58())
	case licence.Status != 0:
		return refuseStoreOwnLicence(refusalStoreLicenseRevoked, "the Store's LicenseEntry %s is %s; verify_license refuses it", licencePDA.Base58(), licenseStatusName(licence.Status))
	case licence.ResellerNFTMint == (primitives.Pubkey{}):
		return refuseStoreOwnLicence(refusalStoreNoReseller, "the Store's LicenseEntry %s names no reseller; verify_license cannot accept it", licencePDA.Base58())
	}

	// The reseller is the one the LicenseEntry just read names.
	resellerPDA, _, err := primitives.FindProgramAddress([][]byte{[]byte("reseller"), licence.ResellerNFTMint[:]}, licenseRegistryProgramID(), nil)
	if err != nil {
		return fmt.Errorf("%s: derive ResellerEntry: %w", storeOwnLicenceCheck, err)
	}
	reseller, err := cr.FetchResellerEntry(ctx, resellerPDA.Base58())
	if err != nil {
		return ownLicenceReadRefusal(err, refusalStoreResellerAbsent, refusalStoreResellerMalformed, "ResellerEntry", resellerPDA, "reseller "+licence.ResellerNFTMint.Base58()+", named by the Store's licence "+licenseMint.Base58())
	}
	switch {
	case primitives.Pubkey(reseller.ResellerNFTMint) != licence.ResellerNFTMint:
		return refuseStoreOwnLicence(refusalStoreResellerMismatch, "the ResellerEntry at %s names reseller %s, the Store's licence names %s", resellerPDA.Base58(), primitives.Pubkey(reseller.ResellerNFTMint).Base58(), licence.ResellerNFTMint.Base58())
	case primitives.Pubkey(reseller.MasterNftMint) != master:
		return refuseStoreOwnLicence(refusalStoreResellerMasterMismatch, "the ResellerEntry %s of the Store's licence is under master mint %s, this estate's is %s", resellerPDA.Base58(), primitives.Pubkey(reseller.MasterNftMint).Base58(), master.Base58())
	case reseller.Status != verify.ResellerStatusActive:
		return refuseStoreOwnLicence(refusalStoreResellerInactive, "the ResellerEntry %s of reseller %s, named by the Store's licence %s, is %s; verify_license refuses every licence under it", resellerPDA.Base58(), licence.ResellerNFTMint.Base58(), licenseMint.Base58(), reseller.Status)
	}
	return nil
}

// ownLicenceReadRefusal names a failed read of an own-licence account: absent
// or not the program's (another owner), malformed (another discriminator or
// bytes the program's layout cannot hold), or, unnamed and wrapped, a read
// failure.
func ownLicenceReadRefusal(err error, absent, malformed, account string, at pda.Pubkey, what string) error {
	switch {
	case errors.Is(err, verify.ErrPDANotFound):
		return refuseStoreOwnLicence(absent, "no %s at %s for %s", account, at.Base58(), what)
	case errors.Is(err, errCascadeAccountOwner):
		return refuseStoreOwnLicence(absent, "the account at %s for %s is not the program's %s: %v", at.Base58(), what, account, err)
	case errors.Is(err, errCascadeAccountDiscriminator), errors.Is(err, errCascadeAccountMalformed):
		return refuseStoreOwnLicence(malformed, "the %s at %s for %s: %v", account, at.Base58(), what, err)
	default:
		return fmt.Errorf("%s: fetch %s %s: %w", storeOwnLicenceCheck, account, at.Base58(), err)
	}
}
