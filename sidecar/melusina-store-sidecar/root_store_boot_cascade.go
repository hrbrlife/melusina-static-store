package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The root Store's own approval cascade, checked at every start.
//
// The boot-identity ceremony binds the operator to one SidecarIdentityEntry,
// and no license-registry instruction sets that entry to Revoked: the program's
// recall instructions reach the approvals (revoke_global_sidecar,
// revoke_local_sidecar and their cascade) and the licence, never the identity.
// So the identity alone cannot recall a Store build. After it,
// deriveVerifiedBootIdentity runs the same five-fact cascade that promote and
// serve run for a sidecar component (checkSidecarCascade), for this Store's own
// sidecar id and boot_identity licence, with the executable hash the identity
// pins as the artifact: LicenseEntry, GlobalSidecarApproval, LocalSidecarApproval,
// ResellerSidecarApproval and ResellerEntry, each owned by the pinned program,
// naming what its address was derived from, and Active, with the Global pin and
// a Some Local pin equal to that hash. The LicenseEntry must name this estate's
// master mint, which comes from release_master_nft_mint — the field the
// enrollment binds to the owner-signed profile's anchors.masterMint — and never
// from a default. A refusal is FATAL, as any boot-identity failure is, and is
// named as the sidecar boot gate names it (seam audit round 4, finding 7).

// Estate-anchor refusals for the master mint, spelled as the sidecar boot gate
// spells them (binhash ParseEstateAnchors).
const (
	refusalBootCascadeMasterAbsent    = "estate-anchor-absent:master-mint"
	refusalBootCascadeMasterMalformed = "estate-anchor-malformed:master-mint"
	// refusalBootCascadeMasterNotEnrolled: the master mint the boot cascade
	// pinned is not the enrolled profile's anchors.masterMint.
	refusalBootCascadeMasterNotEnrolled = "store-enrollment-facts-mismatch:bootCascadeMasterMint"
)

// errBootCascadeReaderUnsupported: the chain reader cannot read raw accounts,
// so the cascade cannot be checked. Every production reader can.
var errBootCascadeReaderUnsupported = errors.New("boot-cascade-reader-unsupported: the chain reader cannot read the raw sidecar approval accounts")

// rootStoreBootMasterMint parses the estate master mint the boot cascade pins.
// It reads release_master_nft_mint only: mirror.root_master_nft_mint is a
// mirror's upstream, not this estate's anchor, and there is no compiled or
// derived default. The enrollment gate proves the same field equals the
// enrolled profile's anchors.masterMint (requireLoadedConfigMatchesStoreDeclaration)
// and that the boot cascade used it (storeEnrollmentRuntimeFacts).
func rootStoreBootMasterMint(cfg Config) (primitives.Pubkey, error) {
	var zero primitives.Pubkey
	raw := strings.TrimSpace(cfg.ReleaseMasterNftMint)
	if raw == "" {
		return zero, fmt.Errorf("%s: release_master_nft_mint is required when boot_identity.shards_dir is set; it is the enrolled estate profile's anchors.masterMint, and this build carries no default", refusalBootCascadeMasterAbsent)
	}
	master, err := primitives.PubkeyFromBase58(raw)
	if err != nil {
		return zero, fmt.Errorf("%s: release_master_nft_mint is not a base58 32-byte key: %v", refusalBootCascadeMasterMalformed, err)
	}
	if master == zero {
		return zero, fmt.Errorf("%s: release_master_nft_mint must not be the all-zero key", refusalBootCascadeMasterMalformed)
	}
	if master == licenseRegistryProgramID() {
		return zero, fmt.Errorf("%s: release_master_nft_mint equals the license-registry program id; they are different accounts of the estate", refusalBootCascadeMasterMalformed)
	}
	return master, nil
}

// verifyRootStoreBootCascade requires this Store's own sidecar approval
// cascade to be Active and to pin binaryHash, the hash of the running
// executable that verifySidecarIdentity has just matched to the identity's
// binary_hash. A non-nil error refuses the start.
func verifyRootStoreBootCascade(ctx context.Context, cr chainReader, sidecarID string, licenseMint, masterMint primitives.Pubkey, binaryHash [32]byte) error {
	rr, ok := cr.(rawAccountReader)
	if !ok {
		return fmt.Errorf("check=sidecar_cascade: %w", errBootCascadeReaderUnsupported)
	}
	view := componentReleaseChainView{
		sidecarID:   sidecarID,
		licenseMint: licenseMint,
		pinMaster:   true,
		masterMint:  masterMint,
	}
	if err := checkSidecarCascade(ctx, rr, view, binaryHash); err != nil {
		return fmt.Errorf("check=sidecar_cascade: %w", err)
	}
	return nil
}
