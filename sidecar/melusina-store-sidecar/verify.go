package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// programID is the license-registry program the federated store verifies
// against (FEDERATED-STORE-MVP §1). Parsed once at init; a bad constant is a
// build/boot bug, not a runtime condition.
var programID = mustPubkey("7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb")

func mustPubkey(s string) pda.Pubkey {
	p, err := primitives.PubkeyFromBase58(s)
	if err != nil {
		panic("melusina-store-sidecar: bad hard-coded programID: " + err.Error())
	}
	return p
}

// chainReader is the subset of *verify.RPCClient the /publish gate needs. It is
// an interface so the live RPC client satisfies it in production AND tests can
// inject a deterministic mock (devnet is unreliable — see memory
// melusina-devnet-rpc; we NEVER hit a live RPC in unit tests).
type chainReader interface {
	FetchReleaseEntry(ctx context.Context, addrB58 string) (appHash [32]byte, status verify.AttestationStatus, err error)
	FetchStoreOperatorAuthz(ctx context.Context, addrB58 string) (status verify.AuthorizationStatus, storeAuthority verify.Pubkey, allowedTierMask uint8, isRoot bool, storeDomainHash [32]byte, err error)
	FetchBlacklistEntry(ctx context.Context, addrB58 string) (present bool, entryType verify.BlacklistType, err error)
	// FetchInstallerReleaseEntry + FetchFoundationAppEntry are the reseller
	// ROOT-MIRROR worker's re-verification reads (FEDERATED-STORE-MVP §C2.6): the
	// base installer's InstallerReleaseEntry must be Active and each basic app's
	// FoundationAppEntry must be Active with the advertised tier before the
	// reseller re-serves the root's mirrored bytes.
	FetchInstallerReleaseEntry(ctx context.Context, addrB58 string) (installerHash [32]byte, status verify.AttestationStatus, err error)
	FetchFoundationAppEntry(ctx context.Context, addrB58 string) (appID [32]byte, tier uint8, status verify.ApprovalStatus, err error)
}

// compile-time assertion: the production client satisfies the interface.
var _ chainReader = (*verify.RPCClient)(nil)

// VerifyPublish is the trust gate for POST /publish. It is FAIL-CLOSED at every
// step: any mismatch, missing PDA, or genuine RPC error returns a non-nil error
// naming the failing check, and the caller MUST refuse to publish. None of the
// dev-only offline/skip escape hatches are reachable from here (spec §5 S7).
//
// Per FEDERATED-STORE-MVP §0 the store's receive-side checks protect the
// OPERATOR from bad publishers; the install still re-verifies the chain itself.
//
//	spk            — the raw Sandstorm package bytes (.spk) being published.
//	rel            — the publisher's CLAIMS (melusina-release-v1). Never trusted
//	                 on its own; every field used here is re-checked on-chain.
//	operatorPubkey — the sidecar's own receipt-signing ed25519 pubkey (32B). The
//	                 on-chain StoreOperatorAuthorization.store_authority MUST equal
//	                 this, proving this process is the authorized single writer.
//	foundationTier — optional FoundationApp tier mask for the app (0 = unknown /
//	                 not supplied; the mask coverage check is then skipped — see
//	                 residual: no per-app tier reader is wired yet).
func VerifyPublish(ctx context.Context, cr chainReader, cfg Config, spk []byte, rel ReleaseJSON, operatorPubkey [32]byte, foundationTier uint8) error {
	// (a)+(b) Re-hash the SPK, require it equals the claimed app_hash, and require
	// an Active on-chain ReleaseEntry (derived from masterNftMint+app_hash) pinning
	// that hash. This is the load-bearing "are these the attested bytes" core,
	// SHARED with the serve-time gate (VerifyServe) so both enforce it identically.
	sum := sha256.Sum256(spk)
	masterMint, _, err := verifyReleaseEntryHash(ctx, cr, hex.EncodeToString(sum[:]), rel)
	if err != nil {
		return err
	}

	// (c) Derive the StoreOperatorAuthorization PDA for THIS license+domain,
	// fetch it, and require: Active, its store_authority == our own operator
	// signing key (proving this process is the authorized single writer for this
	// store), and — if a FoundationApp tier is known — the allowed_tier_mask
	// covers it. This is the WRITE-authority half: it needs the operator identity
	// and is therefore NOT part of the serve-time (read-only) gate.
	storeDomainHash := primitives.StoreDomainHash(cfg.Domain)
	licenseMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.LicenseNFTMint))
	if err != nil {
		return fmt.Errorf("check=store_operator_authz: bad cfg.license_nft_mint: %w", err)
	}
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, storeDomainHash, programID)
	if err != nil {
		return fmt.Errorf("check=store_operator_authz: derive PDA: %w", err)
	}
	authzStatus, storeAuthority, allowedTierMask, _, _, err := cr.FetchStoreOperatorAuthz(ctx, authzPDA.Base58())
	if err != nil {
		return fmt.Errorf("check=store_operator_authz: fetch %s: %w", authzPDA.Base58(), err)
	}
	if err := authzStatus.RequireActive(); err != nil {
		return fmt.Errorf("check=store_operator_authz: status %s not Active: %w", authzStatus, err)
	}
	if storeAuthority != verify.Pubkey(operatorPubkey) {
		return fmt.Errorf("check=store_operator_authz: store_authority %x != sidecar operator %x", storeAuthority[:], operatorPubkey[:])
	}
	if foundationTier != 0 && (allowedTierMask&foundationTier) != foundationTier {
		return fmt.Errorf("check=store_operator_authz: allowed_tier_mask 0x%02x does not cover app tier 0x%02x", allowedTierMask, foundationTier)
	}

	// (d) Blacklist check. Neither the app master NFT mint nor the operator's own
	// license may be denied. present==true => REJECT; a genuine RPC/decode error
	// => REJECT (fail closed); a missing PDA is the common "clear" case.
	if err := verifyNotBlacklisted(ctx, cr, masterMint, "app"); err != nil {
		return err
	}
	if err := verifyNotBlacklisted(ctx, cr, licenseMint, "license"); err != nil {
		return err
	}
	return nil
}

// VerifyServeHash is the SERVE-TIME trust gate (canon §5b: "the store-sidecar's
// verifier refuses to serve any SPK lacking an Active ReleaseEntry whose AppHash
// matches — load-bearing AT SERVE TIME"). It is the chain-READ-ONLY subset of
// VerifyPublish: it needs ONLY the on-chain reader, never the operator signing
// identity — serve-time proves the SERVED BYTES are on-chain-attested, not who
// may write. The serve handler stream-hashes the file once while serving and
// passes that lowercase hex here, so the gate never re-buffers a 100 MiB SPK.
// FAIL-CLOSED at every step:
//
//	(a) spkSHA256Hex == rel.AppHash
//	(b) an Active on-chain ReleaseEntry (masterNftMint+appHash) pins that appHash
//	(d) the app's master NFT mint is not blacklisted
//
// It deliberately OMITS VerifyPublish's StoreOperatorAuthorization/operator check
// (c): that is a write-authority concern requiring the operator identity (the
// boot-identity ceremony, tracked separately as B1-02). cfg is accepted for
// signature parity with VerifyPublish and future per-store policy; it is not used
// by the read-only serve checks today.
func VerifyServeHash(ctx context.Context, cr chainReader, cfg Config, spkSHA256Hex string, rel ReleaseJSON) error {
	_ = cfg
	masterMint, _, err := verifyReleaseEntryHash(ctx, cr, spkSHA256Hex, rel)
	if err != nil {
		return err
	}
	return verifyNotBlacklisted(ctx, cr, masterMint, "app")
}

// VerifyServe is VerifyServeHash over raw bytes (it computes the sha256). Used by
// callers/tests holding the bytes; the serve hot path uses VerifyServeHash with a
// hash it already streamed.
func VerifyServe(ctx context.Context, cr chainReader, cfg Config, spk []byte, rel ReleaseJSON) error {
	sum := sha256.Sum256(spk)
	return VerifyServeHash(ctx, cr, cfg, hex.EncodeToString(sum[:]), rel)
}

// verifyReleaseEntryHash performs the serve-time load-bearing checks given the
// PRECOMPUTED sha256 hex of the bytes in hand: (a) it equals rel.AppHash, and
// (b) the on-chain ReleaseEntry derived from rel.masterNftMint+appHash exists,
// pins THIS app_hash, and is Active. Returns the app master NFT mint + the
// 32-byte app_hash for the caller's downstream (blacklist) checks. FAIL-CLOSED.
// (The author ed25519 sig was verified on-chain at register — §1; we confirm the
// entry, not the sig.)
func verifyReleaseEntryHash(ctx context.Context, cr chainReader, spkSHA256Hex string, rel ReleaseJSON) (pda.Pubkey, [32]byte, error) {
	var zeroMint pda.Pubkey
	var zeroHash [32]byte

	gotHash := strings.ToLower(strings.TrimSpace(spkSHA256Hex))
	wantHash := strings.ToLower(strings.TrimSpace(rel.AppHash))
	if gotHash != wantHash {
		return zeroMint, zeroHash, fmt.Errorf("check=spk_sha256: sha256(spk)=%s != release.appHash=%s", gotHash, wantHash)
	}
	appHashBytes, err := hash32FromHex(wantHash)
	if err != nil {
		return zeroMint, zeroHash, fmt.Errorf("check=spk_sha256: release.appHash not 32-byte hex: %w", err)
	}

	masterMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(rel.MasterNftMint))
	if err != nil {
		return zeroMint, zeroHash, fmt.Errorf("check=release_entry: bad release.masterNftMint: %w", err)
	}
	relPDA, _, err := pda.Release(masterMint, appHashBytes, programID)
	if err != nil {
		return zeroMint, zeroHash, fmt.Errorf("check=release_entry: derive PDA: %w", err)
	}
	onchainAppHash, relStatus, err := cr.FetchReleaseEntry(ctx, relPDA.Base58())
	if err != nil {
		return zeroMint, zeroHash, fmt.Errorf("check=release_entry: fetch %s: %w", relPDA.Base58(), err)
	}
	if onchainAppHash != appHashBytes {
		return zeroMint, zeroHash, fmt.Errorf("check=release_entry: on-chain app_hash %x != %x", onchainAppHash[:], appHashBytes[:])
	}
	if err := relStatus.RequireActive(); err != nil {
		return zeroMint, zeroHash, fmt.Errorf("check=release_entry: status %s not Active: %w", relStatus, err)
	}
	return masterMint, appHashBytes, nil
}

// verifyNotBlacklisted rejects when target has a BlacklistEntry PDA — its mere
// EXISTENCE is the deny signal (the struct carries no status); seeds=["blacklist",
// target]. A genuine RPC/decode error => REJECT (fail closed); a missing PDA is
// the common, expected "clear" case. label names the check in the error
// ("app" / "license").
func verifyNotBlacklisted(ctx context.Context, cr chainReader, target pda.Pubkey, label string) error {
	blPDA, _, err := pda.BlacklistEntry(target, programID)
	if err != nil {
		return fmt.Errorf("check=blacklist[%s]: derive PDA: %w", label, err)
	}
	present, entryType, err := cr.FetchBlacklistEntry(ctx, blPDA.Base58())
	if err != nil {
		return fmt.Errorf("check=blacklist[%s]: fetch %s: %w", label, blPDA.Base58(), err)
	}
	if present {
		return fmt.Errorf("check=blacklist[%s]: target %s is blacklisted (type=%s)", label, target.Base58(), entryType)
	}
	return nil
}

func hash32FromHex(h string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(h)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("want 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}
