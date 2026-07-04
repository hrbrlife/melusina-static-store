package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const defaultLicenseProgramID = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"

// programID is the license-registry program the federated store verifies
// against (FEDERATED-STORE-MVP §1). It defaults to the current devnet registry
// and is overwritten from validated operator config at process boot.
var programID = mustPubkey(defaultLicenseProgramID)

func mustPubkey(s string) pda.Pubkey {
	p, err := primitives.PubkeyFromBase58(s)
	if err != nil {
		panic("melusina-store-sidecar: bad programID: " + err.Error())
	}
	return p
}

func setProgramIDFromConfig(s string) {
	programID = mustPubkey(strings.TrimSpace(s))
}

// chainReader is the subset of *verify.RPCClient the /publish gate needs. It is
// an interface so the live RPC client satisfies it in production AND tests can
// inject a deterministic mock (devnet is unreliable — see memory
// melusina-devnet-rpc; we NEVER hit a live RPC in unit tests).
type chainReader interface {
	FetchReleaseEntry(ctx context.Context, addrB58 string) (appHash [32]byte, status verify.AttestationStatus, err error)
	FetchReleaseEntryMeta(ctx context.Context, addrB58 string) (releaseEntryMeta, error)
	FetchActiveReleaseEntriesByAppID(ctx context.Context, appID [32]byte) ([]releaseEntryMeta, error)
	// FetchReleaseEntryAppID reads the on-chain ReleaseEntry.app_id (the stable
	// per-application identity, distinct from app_hash). The publish gate derives
	// the FoundationAppEntry from THIS app_id — never from the untrusted
	// RELEASE.json — to enforce the operator tier ceiling (B1-05/B2-05).
	FetchReleaseEntryAppID(ctx context.Context, addrB58 string) (appID [32]byte, err error)
	FetchStoreOperatorAuthz(ctx context.Context, addrB58 string) (status verify.AuthorizationStatus, storeAuthority verify.Pubkey, allowedTierMask uint8, isRoot bool, storeDomainHash [32]byte, err error)
	FetchBlacklistEntry(ctx context.Context, addrB58 string) (present bool, entryType verify.BlacklistType, err error)
	// FetchInstallerReleaseEntry + FetchFoundationAppEntry are the reseller
	// ROOT-MIRROR worker's re-verification reads (FEDERATED-STORE-MVP §C2.6): the
	// base installer's InstallerReleaseEntry must be Active and each basic app's
	// FoundationAppEntry must be Active with the advertised tier before the
	// reseller re-serves the root's mirrored bytes. FetchFoundationAppEntry is
	// ALSO the publish-gate tier reader (B1-05/B2-05).
	FetchInstallerReleaseEntry(ctx context.Context, addrB58 string) (installerHash [32]byte, status verify.AttestationStatus, err error)
	FetchInstallerReleaseEntryMeta(ctx context.Context, addrB58 string) (installerReleaseMeta, error)
	FetchFoundationAppEntry(ctx context.Context, addrB58 string) (appID [32]byte, tier uint8, status verify.ApprovalStatus, err error)
	// FetchSidecarIdentity is the boot-identity ceremony's anchor read (B1-02):
	// the derived operator's signing/encryption keys, served domain, TLS cert, and
	// binary hash must all match the on-chain SidecarIdentityEntry before /publish
	// is enabled.
	FetchSidecarIdentity(ctx context.Context, addrB58 string) (verify.SidecarIdentity, error)
}

// compile-time assertion: the production wrapper satisfies the interface.
var _ chainReader = (*storeRPCReader)(nil)

// VerifyPublish is the trust gate for POST /publish. It is FAIL-CLOSED at every
// step: any mismatch, missing PDA, or genuine RPC error returns a non-nil error
// naming the failing check, and the caller MUST refuse to publish. None of the
// dev-only offline/skip escape hatches are reachable from here (spec §5 S7).
//
// Per FEDERATED-STORE-MVP §0 the store's receive-side checks protect the
// OPERATOR from bad publishers; the install still re-verifies the chain itself.
//
//	spk            — the raw Sandstorm package bytes (.spk) being published.
//	metadata       — the app's metadata.json bytes. Together with spk they form the
//	                 canonical staged tree the on-chain AppHash binds (the pearl
//	                 ceremony hashes exactly {app.spk, metadata.json}); transported
//	                 in the publish request so the gate can recompute that AppHash.
//	rel            — the publisher's CLAIMS (melusina-release-v1). Never trusted
//	                 on its own; every field used here is re-checked on-chain.
//	operatorPubkey — the sidecar's own receipt-signing ed25519 pubkey (32B). The
//	                 on-chain StoreOperatorAuthorization.store_authority MUST equal
//	                 this, proving this process is the authorized single writer.
//
// The FoundationApp tier ceiling (B1-05/B2-05) is resolved INTERNALLY from the
// on-chain ReleaseEntry.app_id → FoundationAppEntry — never from a caller-supplied
// tier or the untrusted RELEASE.json — so an operator cannot dodge the mask by
// omitting the tier.
func VerifyPublish(ctx context.Context, cr chainReader, cfg Config, spk []byte, metadata []byte, rel ReleaseJSON, operatorPubkey [32]byte) error {
	// (a)+(b) Recompute the on-chain AppHash — the TREE-HASH over the canonical
	// {app.spk, metadata.json} pair (apphash.Canonical), NOT sha256(spk) — require it
	// equals the claimed app_hash, and require an Active on-chain ReleaseEntry
	// (derived from masterNftMint+app_hash) pinning that hash. This is the
	// load-bearing "are these the attested bytes" core, SHARED with the serve-time
	// gate (VerifyServeHash) so both enforce it identically.
	appHash, err := apphash.Canonical(bytes.NewReader(spk), metadata)
	if err != nil {
		return fmt.Errorf("check=app_hash: compute app-hash: %w", err)
	}
	masterMint, _, relPDA, submittedMeta, err := verifyReleaseEntryHash(ctx, cr, appHash, rel)
	if err != nil {
		return err
	}

	// (a-time) STORE HYGIENE — attestation proximity. The publisher-supplied release
	// time (rel.SignedAtUnix, surfaced by the catalog as the app's "updated N ago")
	// must sit within +/-24h of the on-chain registered_at that WITNESSED this
	// ReleaseEntry. The chain-witnessed time (submittedMeta.RegisteredAt, just read
	// from the confirmed-Active entry) is the unforgeable anchor. FAIL-CLOSED.
	if err := verifyAttestationProximity(rel, submittedMeta); err != nil {
		return err
	}

	// (b2) Resolve the FoundationApp tier from the CHAIN (B1-05/B2-05). app_id is
	// read from the on-chain ReleaseEntry (just confirmed Active) — NOT from the
	// untrusted RELEASE.json — and the FoundationAppEntry is derived from it. A
	// non-Foundation app yields tier 0 (no ceiling); a Foundation app yields its
	// tier bit, which the StoreOperatorAuthorization.allowed_tier_mask MUST cover.
	foundationTier, err := resolveFoundationTier(ctx, cr, relPDA)
	if err != nil {
		return err
	}

	allowedTierMask, licenseMint, err := VerifyStoreOperator(ctx, cr, cfg, operatorPubkey, false /* requireRoot */)
	if err != nil {
		return err
	}
	// Tier ceiling (B1-05/B2-05): a Foundation app (tier != 0) must be covered by
	// the operator's allowed_tier_mask. foundationTier is the on-chain-resolved
	// tier BIT (1<<FoundationAppTier); 0 means the app is not a Foundation app and
	// no ceiling applies.
	if foundationTier != 0 && (allowedTierMask&foundationTier) != foundationTier {
		return fmt.Errorf("check=store_operator_authz: allowed_tier_mask 0x%02x does not cover Foundation app tier 0x%02x", allowedTierMask, foundationTier)
	}
	if err := verifyReleaseVersionForward(ctx, cr, submittedMeta); err != nil {
		return err
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

// VerifyStoreOperator is the WRITE-authority check shared by app publish and
// installer publish. It proves this process is the authorized single writer for
// cfg.Domain: an Active StoreOperatorAuthorization exists for cfg.LicenseNFTMint
// + store_domain_hash(cfg.Domain), and its store_authority equals the sidecar's
// derived operator signing pubkey. Installer/root artifacts additionally require
// is_root=true so reseller/tenant stores cannot originate fleet-wide artifacts.
func VerifyStoreOperator(ctx context.Context, cr chainReader, cfg Config, operatorPubkey [32]byte, requireRoot bool) (allowedTierMask uint8, licenseMint pda.Pubkey, err error) {
	storeDomainHash := primitives.StoreDomainHash(cfg.Domain)
	licenseMint, err = primitives.PubkeyFromBase58(strings.TrimSpace(cfg.LicenseNFTMint))
	if err != nil {
		return 0, pda.Pubkey{}, fmt.Errorf("check=store_operator_authz: bad cfg.license_nft_mint: %w", err)
	}
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, storeDomainHash, programID)
	if err != nil {
		return 0, pda.Pubkey{}, fmt.Errorf("check=store_operator_authz: derive PDA: %w", err)
	}
	authzStatus, storeAuthority, allowedTierMask, isRoot, onchainDomainHash, err := cr.FetchStoreOperatorAuthz(ctx, authzPDA.Base58())
	if err != nil {
		return 0, pda.Pubkey{}, fmt.Errorf("check=store_operator_authz: fetch %s: %w", authzPDA.Base58(), err)
	}
	if err := authzStatus.RequireActive(); err != nil {
		return 0, pda.Pubkey{}, fmt.Errorf("check=store_operator_authz: status %s not Active: %w", authzStatus, err)
	}
	if storeAuthority != verify.Pubkey(operatorPubkey) {
		return 0, pda.Pubkey{}, fmt.Errorf("check=store_operator_authz: store_authority %x != sidecar operator %x", storeAuthority[:], operatorPubkey[:])
	}
	if onchainDomainHash != storeDomainHash {
		return 0, pda.Pubkey{}, fmt.Errorf("check=store_operator_authz: store_domain_hash %x != cfg domain hash %x", onchainDomainHash[:], storeDomainHash[:])
	}
	if requireRoot && !isRoot {
		return 0, pda.Pubkey{}, fmt.Errorf("check=store_operator_authz: is_root=false; installer artifacts require root store authority")
	}
	return allowedTierMask, licenseMint, nil
}

// resolveFoundationTier reads the on-chain ReleaseEntry.app_id at relPDA, derives
// the FoundationAppEntry PDA (["foundation_app", app_id]), and returns the tier
// BIT (1<<FoundationAppTier) the operator's allowed_tier_mask must cover. It is
// FAIL-CLOSED: a genuine RPC/decode error rejects; a Foundation app whose status
// is not Active rejects (a revoked basic app must not be re-listed). The only
// non-error "no ceiling" outcome is a genuine PDA-absent FoundationAppEntry —
// i.e. a third-party (non-Foundation) app — which returns tier 0.
//
// app_id is taken from the CHAIN (the just-confirmed-Active ReleaseEntry), never
// from RELEASE.json: trusting a publisher-supplied app_id would let a Standard
// app borrow a Core app_id to dodge the mask (audit 2026-06-17 B1-05/B2-05).
func resolveFoundationTier(ctx context.Context, cr chainReader, relPDA pda.Pubkey) (uint8, error) {
	appID, err := cr.FetchReleaseEntryAppID(ctx, relPDA.Base58())
	if err != nil {
		return 0, fmt.Errorf("check=foundation_tier: fetch release app_id %s: %w", relPDA.Base58(), err)
	}
	faPDA, _, err := pda.FoundationApp(appID, programID)
	if err != nil {
		return 0, fmt.Errorf("check=foundation_tier: derive FoundationApp PDA: %w", err)
	}
	_, tier, status, err := cr.FetchFoundationAppEntry(ctx, faPDA.Base58())
	if err != nil {
		if errors.Is(err, verify.ErrPDANotFound) {
			return 0, nil // not a Foundation app — no tier ceiling applies
		}
		return 0, fmt.Errorf("check=foundation_tier: fetch %s: %w", faPDA.Base58(), err)
	}
	if err := status.RequireActive(); err != nil {
		return 0, fmt.Errorf("check=foundation_tier: FoundationAppEntry status %s not Active: %w", status, err)
	}
	// FoundationAppTier discriminant → allowed_tier_mask bit (Core=0→0x01,
	// Standard=1→0x02), matching TIER_MASK_CORE/STANDARD on-chain. A corrupt tier
	// byte > Standard is already rejected by the reader (fail-closed).
	return uint8(1) << tier, nil
}

// VerifyServeHash is the SERVE-TIME trust gate (canon §5b: "the store-sidecar's
// verifier refuses to serve any SPK lacking an Active ReleaseEntry whose AppHash
// matches — load-bearing AT SERVE TIME"). It is the chain-READ-ONLY subset of
// VerifyPublish: it needs ONLY the on-chain reader, never the operator signing
// identity — serve-time proves the SERVED BYTES are on-chain-attested, not who
// may write. The serve handler recomputes the on-chain AppHash (the tree-hash over
// the served {app.spk, metadata.json}) once while serving and passes that lowercase
// hex here, so the gate never re-buffers a 100 MiB SPK. FAIL-CLOSED at every step:
//
//	(a) appHashHex (the recomputed tree-hash) == rel.AppHash
//	(b) an Active on-chain ReleaseEntry (masterNftMint+appHash) pins that appHash
//	(d) the app's master NFT mint is not blacklisted
//
// It deliberately OMITS VerifyPublish's StoreOperatorAuthorization/operator check
// (c): that is a write-authority concern requiring the operator identity (the
// boot-identity ceremony, tracked separately as B1-02). cfg is accepted for
// signature parity with VerifyPublish and future per-store policy; it is not used
// by the read-only serve checks today.
func VerifyServeHash(ctx context.Context, cr chainReader, cfg Config, appHashHex string, rel ReleaseJSON) error {
	_ = cfg
	masterMint, _, _, _, err := verifyReleaseEntryHash(ctx, cr, appHashHex, rel)
	if err != nil {
		return err
	}
	return verifyNotBlacklisted(ctx, cr, masterMint, "app")
}

// errReleaseMasterMintRequired marks an operator configuration that has not
// declared the Master NFT mint used for InstallerReleaseEntry PDA derivation.
var errReleaseMasterMintRequired = errors.New("release_master_nft_mint is required")

// VerifyInstallerReleaseHash is the serve-time gate for whole-file artifacts
// under /releases/<class>/<name>. It verifies that sha256(file bytes) has an
// Active InstallerReleaseEntry under the configured Master NFT mint. This is the
// binary-artifact sibling of VerifyServeHash: app SPKs use ReleaseEntry over the
// canonical tree hash; shell bundles/sidecar binaries/venv bundles use
// InstallerReleaseEntry over the exact file sha256.
func VerifyInstallerReleaseHash(ctx context.Context, cr chainReader, cfg Config, installerHash [32]byte) error {
	meta, err := fetchInstallerReleaseMetaForHash(ctx, cr, cfg, installerHash)
	if err != nil {
		return err
	}
	if err := meta.Status.RequireActive(); err != nil {
		return fmt.Errorf("check=installer_release: status %s not Active: %w", meta.Status, err)
	}
	return nil
}

func fetchInstallerReleaseMetaForHash(ctx context.Context, cr chainReader, cfg Config, installerHash [32]byte) (installerReleaseMeta, error) {
	var zero installerReleaseMeta
	masterMintB58 := strings.TrimSpace(cfg.ReleaseMasterNftMint)
	if masterMintB58 == "" {
		masterMintB58 = strings.TrimSpace(cfg.Mirror.RootMasterNftMint)
	}
	if masterMintB58 == "" {
		return zero, fmt.Errorf("check=installer_release: %w", errReleaseMasterMintRequired)
	}
	masterMint, err := primitives.PubkeyFromBase58(masterMintB58)
	if err != nil {
		return zero, fmt.Errorf("check=installer_release: bad release_master_nft_mint: %w", err)
	}
	relPDA, _, err := pda.InstallerRelease(masterMint, installerHash, programID)
	if err != nil {
		return zero, fmt.Errorf("check=installer_release: derive PDA: %w", err)
	}
	meta, err := cr.FetchInstallerReleaseEntryMeta(ctx, relPDA.Base58())
	if err != nil {
		return zero, fmt.Errorf("check=installer_release: fetch %s: %w", relPDA.Base58(), err)
	}
	if meta.InstallerHash != installerHash {
		return zero, fmt.Errorf("check=installer_release: on-chain installer_hash %x != served sha256 %x",
			meta.InstallerHash[:], installerHash[:])
	}
	if meta.PDA == "" {
		meta.PDA = relPDA.Base58()
	}
	return meta, nil
}

// verifyReleaseEntryHash performs the load-bearing checks given the PRECOMPUTED
// app-hash hex of the bytes in hand (the tree-hash over {app.spk, metadata.json},
// per apphash.Canonical): (a) it equals rel.AppHash, and (b) the on-chain
// ReleaseEntry derived from rel.masterNftMint+appHash exists, pins THIS app_hash,
// and is Active. Returns the app master NFT mint + the 32-byte app_hash for the
// caller's downstream (blacklist) checks. FAIL-CLOSED. (The author ed25519 sig was
// verified on-chain at register — §1; we confirm the entry, not the sig.)
func verifyReleaseEntryHash(ctx context.Context, cr chainReader, appHashHex string, rel ReleaseJSON) (pda.Pubkey, [32]byte, pda.Pubkey, releaseEntryMeta, error) {
	var zeroMint pda.Pubkey
	var zeroHash [32]byte
	var zeroPDA pda.Pubkey
	var zeroMeta releaseEntryMeta

	gotHash := strings.ToLower(strings.TrimSpace(appHashHex))
	wantHash := strings.ToLower(strings.TrimSpace(rel.AppHash))
	if gotHash != wantHash {
		return zeroMint, zeroHash, zeroPDA, zeroMeta, fmt.Errorf("check=app_hash: apphash(spk,metadata)=%s != release.appHash=%s", gotHash, wantHash)
	}
	appHashBytes, err := hash32FromHex(wantHash)
	if err != nil {
		return zeroMint, zeroHash, zeroPDA, zeroMeta, fmt.Errorf("check=app_hash: release.appHash not 32-byte hex: %w", err)
	}

	masterMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(rel.MasterNftMint))
	if err != nil {
		return zeroMint, zeroHash, zeroPDA, zeroMeta, fmt.Errorf("check=release_entry: bad release.masterNftMint: %w", err)
	}
	relPDA, _, err := pda.Release(masterMint, appHashBytes, programID)
	if err != nil {
		return zeroMint, zeroHash, zeroPDA, zeroMeta, fmt.Errorf("check=release_entry: derive PDA: %w", err)
	}
	meta, err := cr.FetchReleaseEntryMeta(ctx, relPDA.Base58())
	if err != nil {
		return zeroMint, zeroHash, zeroPDA, zeroMeta, fmt.Errorf("check=release_entry: fetch %s: %w", relPDA.Base58(), err)
	}
	if meta.AppHash != appHashBytes {
		return zeroMint, zeroHash, zeroPDA, zeroMeta, fmt.Errorf("check=release_entry: on-chain app_hash %x != %x", meta.AppHash[:], appHashBytes[:])
	}
	if err := meta.Status.RequireActive(); err != nil {
		return zeroMint, zeroHash, zeroPDA, zeroMeta, fmt.Errorf("check=release_entry: status %s not Active: %w", meta.Status, err)
	}
	if meta.PDA == "" {
		meta.PDA = relPDA.Base58()
	}
	return masterMint, appHashBytes, relPDA, meta, nil
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
