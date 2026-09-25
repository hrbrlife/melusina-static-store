package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The licence registry's blacklist is an explicit status per target
// (contracts programs/license-registry/src/state/blacklist_status.rs): one
// BlacklistStatusEntry at ["blacklist_status", kind seed, target]. A missing
// account is not a statement ("There is deliberately no legacy
// absence-means-clear representation in the greenfield program").
//
// The Store keeps no reader of its own. The decision is the vendored
// verify.RequireBlacklistClear (melusina-identity-gate verify/blacklist_status.go,
// at the Melusina commit testdata/melusina-vendor/vendor.provenance.json names):
// a present account, owned by the pinned licence registry, of exactly 131
// bytes that decode with the authorization daemon's rules (authz
// pkg/grainauth/control_facts.go DecodeBlacklistStatus), that is the canonical
// record of this kind and target with its canonical bump, and that reads
// Clear. Absent, Blocked, foreign-owned, malformed and non-canonical accounts
// are each refused by name. The address and bump come from the vendored
// derivation (pda.BlacklistStatus). What only the Store checks stays here: the
// App target is the canonical text of the appId, bound to the release's
// on-chain app_id when that is known. There is no other blacklist
// representation: the legacy ["blacklist", target] account the program never
// creates is not read anywhere in this module or its vendored code
// (blacklist_status_test.go scans for it).

// deriveBlacklistStatusPDA is ["blacklist_status", kind seed, target] under the
// pinned registry program, with its canonical bump.
func deriveBlacklistStatusPDA(kind verify.BlacklistType, target [32]byte) (pda.Pubkey, uint8, error) {
	return pda.BlacklistStatus(kind, target, licenseRegistryProgramID())
}

// FetchBlacklistStatusAccount returns the account at a clearance address with
// the owner the RPC reported, undecoded. A nil account with no error is an
// absent account, never a Clear: verifyBlacklistClear hands it to
// verify.RequireBlacklistClear, which refuses it.
func (c *storeRPCReader) FetchBlacklistStatusAccount(ctx context.Context, addr string) (*verify.Account, error) {
	return c.GetAccount(ctx, addr)
}

// verifyLicenseClear requires the licence's explicit Clear record.
func verifyLicenseClear(ctx context.Context, cr chainReader, licenseMint pda.Pubkey) error {
	return verifyBlacklistClear(ctx, cr, verify.BlacklistTypeLicense, [32]byte(licenseMint), "license")
}

// verifyAppClear requires the app's explicit Clear record. Its target is the
// decoded Sandstorm appId of appIDText. When the release's on-chain
// ReleaseEntry is known, releaseAppID is its app_id and must be SHA-256 of
// appIDText (the release ceremony's AppIDHash), which binds the target to the
// chain whatever carried the text; before a ReleaseEntry exists (a private
// stage) it is nil and the candidate's own appId is checked, to be bound when
// the release is promoted.
func verifyAppClear(ctx context.Context, cr chainReader, appIDText string, releaseAppID *[32]byte) error {
	key, err := primitives.DecodeSandstormAppID(appIDText)
	if err != nil {
		return fmt.Errorf("check=blacklist[app]: app-id-invalid: %q: %w", appIDText, err)
	}
	if releaseAppID != nil {
		if got := sha256.Sum256([]byte(appIDText)); got != *releaseAppID {
			return fmt.Errorf("check=blacklist[app]: app-id-not-the-release-app: SHA-256 of appId %s is %x, ReleaseEntry.app_id is %x", appIDText, got[:], releaseAppID[:])
		}
	}
	return verifyBlacklistClear(ctx, cr, verify.BlacklistTypeApp, key, "app")
}

// verifyBlacklistClear is the one clearance check. label names it in the
// error ("app" / "license"). Every outcome but the canonical Clear record of
// exactly this kind and target refuses, each by name:
//
//	clearance-absent        no account: absence is not a clearance statement
//	blacklisted             the Foundation recorded Blocked
//	clearance-not-canonical another kind or target, or a non-canonical bump
//	fetch                   an RPC, owner or decode failure (fail closed)
func verifyBlacklistClear(ctx context.Context, cr chainReader, kind verify.BlacklistType, target [32]byte, label string) error {
	addr, bump, err := deriveBlacklistStatusPDA(kind, target)
	if err != nil {
		return fmt.Errorf("check=blacklist[%s]: derive PDA: %w", label, err)
	}
	account, err := cr.FetchBlacklistStatusAccount(ctx, addr.Base58())
	if errors.Is(err, verify.ErrPDANotFound) {
		// A reader that reports absence as an error: the same absent
		// account, which the decision below refuses.
		account, err = nil, nil
	}
	if err != nil {
		return fmt.Errorf("check=blacklist[%s]: fetch %s: %w", label, addr.Base58(), err)
	}
	_, err = verify.RequireBlacklistClear(account, licenseRegistryProgramID().Base58(), kind, target, bump)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, verify.ErrPDANotFound):
		return fmt.Errorf("check=blacklist[%s]: clearance-absent: no BlacklistStatusEntry at %s for %s target %x; an absent record is not Clear", label, addr.Base58(), kind, target[:])
	case errors.Is(err, verify.ErrBlacklistBlocked):
		return fmt.Errorf("check=blacklist[%s]: blacklisted: %w", label, err)
	case errors.Is(err, verify.ErrBlacklistStatusNotCanonical):
		return fmt.Errorf("check=blacklist[%s]: clearance-not-canonical: %s: %w", label, addr.Base58(), err)
	default:
		return fmt.Errorf("check=blacklist[%s]: fetch %s: %w", label, addr.Base58(), err)
	}
}
