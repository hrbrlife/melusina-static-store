// Package verify wraps Solana PDA reads for Melusina's authorization
// primitives. Every symbol is on-chain-live: there are no "last known
// active" caches for destructive actions (CLAUDE.md §1 Invariant 5),
// and the ApprovalStatus check is enforced on every call.
//
// This file pins the public API that every consuming service imports.
// The concrete Borsh decoder + RPC client implementation is ported
// incrementally from the fineract-sidecar reference at
// /home/user/Desktop/store-rebuild/melusina-fineract-sidecar/sidecar/melusina_verifier.go
package verify

import "errors"

// Verifier reads Melusina PDAs over Solana JSON-RPC. Concrete
// implementations hold an HTTP client, an RPC endpoint URL, and the
// license-registry program ID. Every method either returns nil (PDA
// present, status == Active) or an error describing the failure
// mode — not-found, status != Active, RPC-unreachable, etc.
//
// A Verifier is safe for concurrent use.
type Verifier interface {
	// VerifyLicenseActive reads LicenseEntry[licenseMint] and
	// requires status == Active.
	VerifyLicenseActive(licenseMint string) error

	// VerifyInstallAdminActive reads InstallAdminEntry[licenseMint,
	// adminWallet] and requires status == Active.
	VerifyInstallAdminActive(licenseMint, adminWallet string) error

	// VerifyOrganizationMemberActive reads
	// OrganizationMemberEntry[licenseMint, memberWallet] and requires
	// status == Active.
	//
	// This is the cross-app uniformity hook from plan §20.1. Apps
	// with a 4-eyes flow where the second signer is an org member —
	// ccash, instaco, AiTX Procedures, cyberteller quarantine-dispose —
	// all call through this interface rather than rolling their own
	// PDA derivation.
	VerifyOrganizationMemberActive(licenseMint, memberWallet string) error

	// VerifyAppApprovalChainActive enforces the
	// Global → Reseller → Local app-approval cascade (CLAUDE.md §1
	// Invariant 2). All three must be status == Active.
	VerifyAppApprovalChainActive(masterMint, resellerMint, licenseMint string, appHash [32]byte) error

	// VerifySidecarApprovalChainActive enforces the same cascade for
	// the sidecar-approval PDAs introduced in plan §5.2.
	VerifySidecarApprovalChainActive(masterMint, resellerMint, licenseMint, sidecarID string) error

	// VerifyContractActive reads ContractWhitelist[programID] and
	// requires status == Active.
	VerifyContractActive(programID string) error

	// VerifyAppContractPair reads AppContractPair[appHash, programID]
	// and requires status == Active.
	VerifyAppContractPair(appHash [32]byte, programID string) error
}

// Common error sentinels. Concrete verifiers wrap these with
// additional context (PDA address, program ID, status byte observed)
// but callers can use errors.Is to branch on category without
// coupling to the exact wrapping.
var (
	ErrRPCUnreachable  = errors.New("solana RPC unreachable")
	ErrPDANotFound     = errors.New("PDA account not found")
	ErrStatusNotActive = errors.New("PDA status is not Active")
	ErrBorshDecode     = errors.New("failed to Borsh-decode PDA account")
)
