package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// programID is the license-registry program the federated store verifies
// against (FEDERATED-STORE-MVP §1). The Store compiles no registry: which
// program an estate trusts is a fact of that estate. It is carried by the
// operator config (rendered from the owner-signed estate profile for an
// enrolled Store) and pinned once per process by setProgramIDFromConfig.
// Production code reads it only through licenseRegistryProgramID.
var programID pda.Pubkey

// licenseRegistryProgramID returns the registry program pinned from config.
// Reading it before a pin is a programming error, not a state to serve from:
// the zero key is the System Program, so a PDA derived from it, or an account
// owner compared with it, would silently trust the wrong program.
func licenseRegistryProgramID() pda.Pubkey {
	if programID == (pda.Pubkey{}) {
		panic("melusina-store-sidecar: license-registry program_id read before it was pinned from config")
	}
	return programID
}

// parseLicenseRegistryProgramID is the single validation of config.program_id,
// shared by LoadConfig and the process pin. There is no default to fall back
// to: a missing value is a named refusal.
func parseLicenseRegistryProgramID(raw string) (pda.Pubkey, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return pda.Pubkey{}, errors.New("config: program_id is required")
	}
	program, err := primitives.PubkeyFromBase58(value)
	if err != nil {
		return pda.Pubkey{}, fmt.Errorf("config: program_id is invalid: %w", err)
	}
	if program == (pda.Pubkey{}) {
		return pda.Pubkey{}, errors.New("config: program_id must not be the System Program")
	}
	return program, nil
}

// licenseRegistryPinnedLog is the startup line naming the one registry program
// this process trusts. It is emitted only by a successful config pin.
const licenseRegistryPinnedLog = "license registry: program %s pinned from config"

// setProgramIDFromConfig pins the registry program for this process. Every
// entry point calls it with the value LoadConfig has already validated, and
// refuses to continue when it fails.
func setProgramIDFromConfig(raw string) error {
	program, err := parseLicenseRegistryProgramID(raw)
	if err != nil {
		return err
	}
	programID = program
	log.Printf(licenseRegistryPinnedLog, program.Base58())
	return nil
}

// chainReader is the subset of *verify.RPCClient the /publish gate needs. It is
// an interface so the live RPC client satisfies it in production AND tests can
// inject a deterministic mock (devnet is unreliable — see memory
// melusina-devnet-rpc; we NEVER hit a live RPC in unit tests).
type chainReader interface {
	FetchReleaseEntry(ctx context.Context, addrB58 string) (appHash [32]byte, status verify.AttestationStatus, err error)
	FetchReleaseEntryMeta(ctx context.Context, addrB58 string) (releaseEntryMeta, error)
	// FetchStoreReleaseListingMeta reads the exact per-store projection that
	// authorizes this sidecar to serve one release. It is intentionally separate
	// from the legacy shared reader: the registry's new Delisted state is a
	// listing-only state and must not be decoded as generic authorization status.
	FetchStoreReleaseListingMeta(ctx context.Context, addrB58 string) (storeReleaseListingMeta, error)
	FetchActiveReleaseEntriesByAppID(ctx context.Context, appID [32]byte) ([]releaseEntryMeta, error)
	// FetchReleaseEntryAppID reads the on-chain ReleaseEntry.app_id (the stable
	// per-application identity, distinct from app_hash). The publish gate derives
	// the FoundationAppEntry from THIS app_id — never from the untrusted
	// RELEASE.json — to enforce the operator tier ceiling (B1-05/B2-05).
	FetchReleaseEntryAppID(ctx context.Context, addrB58 string) (appID [32]byte, err error)
	FetchStoreOperatorAuthz(ctx context.Context, addrB58 string) (status verify.AuthorizationStatus, storeAuthority verify.Pubkey, allowedTierMask uint8, isRoot bool, storeDomainHash [32]byte, err error)
	// FetchLicenseEntry and FetchResellerEntry are the own-licence rule's
	// reads (store_own_licence.go): the Store's LicenseEntry and the
	// ResellerEntry it names, each owned by the pinned program, carrying its
	// discriminator and decoded by the reader the approval cascade uses. An
	// absent account is verify.ErrPDANotFound.
	FetchLicenseEntry(ctx context.Context, addrB58 string) (licenseEntryHead, error)
	FetchResellerEntry(ctx context.Context, addrB58 string) (verify.ResellerEntry, error)
	// FetchBlacklistStatus reads one BlacklistStatusEntry with its owner
	// (blacklist_status.go). An absent account is verify.ErrPDANotFound, which
	// every caller refuses: absence is not a clearance statement.
	FetchBlacklistStatus(ctx context.Context, addrB58 string) (blacklistStatusEntry, error)
	// FetchInstallerReleaseEntryMeta is the one InstallerReleaseEntry read: the
	// whole account decoded exactly (internal/installerrelease), for the serve,
	// publish and generation gates and the reseller ROOT-MIRROR worker, each of
	// which admits it under the estate's installer-release trust.
	// FetchFoundationAppEntry is the ROOT-MIRROR worker's basic-app read
	// (FEDERATED-STORE-MVP §C2.6) and ALSO the publish-gate tier reader
	// (B1-05/B2-05).
	FetchInstallerReleaseEntryMeta(ctx context.Context, addrB58 string) (installerReleaseMeta, error)
	FetchFoundationAppEntry(ctx context.Context, addrB58 string) (appID [32]byte, tier uint8, status verify.ApprovalStatus, err error)
	// FetchSidecarIdentity is the boot-identity ceremony's anchor read (B1-02):
	// the derived operator's signing/encryption keys, served domain, TLS cert, and
	// binary hash must all match the on-chain SidecarIdentityEntry before /publish
	// is enabled.
	FetchSidecarIdentity(ctx context.Context, addrB58 string) (verify.SidecarIdentity, error)
}

// storeListingStatus is the frozen Borsh enum stored in
// StoreReleaseListing.status. It preserves the historical encoding
// Active=0/Revoked=1 and adds Delisted=2. Unknown bytes are refused.
type storeListingStatus uint8

const (
	storeListingStatusActive storeListingStatus = iota
	storeListingStatusRevoked
	storeListingStatusDelisted
)

func (s storeListingStatus) String() string {
	switch s {
	case storeListingStatusActive:
		return "Active"
	case storeListingStatusRevoked:
		return "Revoked"
	case storeListingStatusDelisted:
		return "Delisted"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// errStoreReleaseListingDelisted is deliberately typed so catalog projection
// can remove only a deliberately delisted target. Every other chain error,
// mismatch, or unknown state aborts the catalog response instead of silently
// hiding data or serving it unverified.
var errStoreReleaseListingDelisted = errors.New("store release listing is Delisted")

// errReleaseEntryRecalled is the second, and last, permitted catalog
// omission: the estate's owners explicitly recalled this exact release on
// chain (revoke_release_entry, a global recall the master-NFT custodian
// signs). It is typed for the same reason as errStoreReleaseListingDelisted:
// the catalog projection omits only this row and keeps serving the rest,
// while the package route, publish and promote still refuse it. Only
// releaseEntryExplicitRecall produces it.
var errReleaseEntryRecalled = errors.New("release-entry-recalled")

// releaseEntryExplicitRecall reports whether a non-Active ReleaseEntry is an
// explicit recall of this estate's release, the one non-Active state the
// catalog may omit instead of refusing. Every fact must hold:
//   - status Revoked with revoked_at set, the pair revoke_release_entry
//     writes together. Superseded, an unknown status, or Revoked without a
//     revocation time is not a recall;
//   - the estate master mint is configured (release_master_nft_mint, the
//     enrolled profile's anchors.masterMint) and the account's own
//     master_nft_mint field is it;
//   - readAt, the address the entry was read from (the caller derives it from
//     the row's RELEASE.json master mint), is the PDA derived from the estate
//     master mint and the row's app hash under the configured license-registry
//     program. So the row names the estate master mint too;
//   - the account's app_hash is the row's.
//
// A ReleaseEntry that cannot be read (RPC error, absent, malformed) never
// reaches this function: those stay fail-closed.
func releaseEntryExplicitRecall(cfg Config, appHash [32]byte, readAt pda.Pubkey, meta releaseEntryMeta) bool {
	if meta.Status != verify.AttestationStatusRevoked || meta.RevokedAt == nil {
		return false
	}
	estateMaster, err := rootStoreBootMasterMint(cfg)
	if err != nil {
		return false
	}
	if meta.MasterNFTMint != [32]byte(estateMaster) {
		return false
	}
	derived, _, err := pda.Release(estateMaster, appHash, licenseRegistryProgramID())
	if err != nil || derived != readAt {
		return false
	}
	return meta.AppHash == appHash
}

// revokedAtText renders ReleaseEntry.revoked_at for a refusal message.
func revokedAtText(at *int64) string {
	if at == nil {
		return "None"
	}
	return fmt.Sprintf("%d", *at)
}

func (s storeListingStatus) requireActive() error {
	switch s {
	case storeListingStatusActive:
		return nil
	case storeListingStatusDelisted:
		return errStoreReleaseListingDelisted
	case storeListingStatusRevoked:
		return errors.New("store release listing is Revoked")
	default:
		return fmt.Errorf("invalid store release listing status %d", uint8(s))
	}
}

// storeReleaseListingMeta is the sidecar's minimal, read-only decoding of the
// program's StoreReleaseListing account. Each field below participates in an
// exact target binding; omitting any one would let a listing for another
// app/domain/release authorize the current store.
type storeReleaseListingMeta struct {
	PDA                   string
	StoreAuthority        pda.Pubkey
	AppHash               [32]byte
	ReleaseEntry          pda.Pubkey
	StoreDomainHash       [32]byte
	OperatorAuthorization pda.Pubkey
	Status                storeListingStatus
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
	_, appHashBytes, relPDA, submittedMeta, err := verifyReleaseEntryHash(ctx, cr, cfg, appHash, rel)
	if err != nil {
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

	// (d) Clearance. The app (its decoded Sandstorm appId, bound to the
	// ReleaseEntry's app_id) and the operator's own licence must each have an
	// explicit Clear BlacklistStatusEntry. Blocked, an absent record, or a
	// genuine RPC/decode error each REJECT (blacklist_status.go).
	if err := verifyAppClear(ctx, cr, metadataAppID(metadata), &submittedMeta.AppID); err != nil {
		return err
	}
	if err := verifyLicenseClear(ctx, cr, licenseMint); err != nil {
		return err
	}

	// (e) Admission. The handler signs rel.ReleaseHash into the receipt and
	// the catalog pointer once this gate passes, and the tenant refuses both
	// unless the ReleaseEntry attests that release hash and this app. So the
	// entry must attest exactly this release (app_hash, app_id, release_hash,
	// version) and, on an enrolled Store, be admitted by the estate's
	// releaseTrust as mel-release admits it (admitReleaseEntryForPublish).
	if err := admitReleaseEntryForPublish(cfg, appHashBytes, submittedMeta, rel, metadataAppID(metadata)); err != nil {
		return err
	}

	// (a-time) STORE HYGIENE — attestation proximity. Runs LAST, after every
	// security-relevant on-chain refusal (authz, tier ceiling, version/supersede,
	// blacklist), so those take error precedence over this display-integrity check.
	// The publisher-supplied release time (rel.SignedAtUnix, surfaced by the catalog
	// as the app's "updated N ago") must sit within +/-24h of the on-chain
	// registered_at that WITNESSED this ReleaseEntry — the unforgeable anchor
	// (submittedMeta.RegisteredAt). FAIL-CLOSED.
	if err := verifyAttestationProximity(rel, submittedMeta); err != nil {
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
// Last, the licence the row is under must be one verify_license accepts, under
// this estate's master mint: its LicenseEntry Active and the ResellerEntry it
// names Active (verifyStoreOwnLicence). Revoking either leaves the row Active.
func VerifyStoreOperator(ctx context.Context, cr chainReader, cfg Config, operatorPubkey [32]byte, requireRoot bool) (allowedTierMask uint8, licenseMint pda.Pubkey, err error) {
	storeDomainHash := primitives.StoreDomainHash(cfg.Domain)
	licenseMint, err = primitives.PubkeyFromBase58(strings.TrimSpace(cfg.LicenseNFTMint))
	if err != nil {
		return 0, pda.Pubkey{}, fmt.Errorf("check=store_operator_authz: bad cfg.license_nft_mint: %w", err)
	}
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, storeDomainHash, licenseRegistryProgramID())
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
	if err := verifyStoreOwnLicence(ctx, cr, cfg, licenseMint); err != nil {
		return 0, pda.Pubkey{}, err
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
	faPDA, _, err := pda.FoundationApp(appID, licenseRegistryProgramID())
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
//	(d) the app is explicitly Clear: appID is the served release's Sandstorm
//	    appId text, SHA-256 of which must be the ReleaseEntry's app_id, and
//	    its decoded key's BlacklistStatusEntry must read Clear
//
// When StoreAuthority is explicitly configured, it also requires an Active
// exact StoreReleaseListing for this store. ReleaseEntry authenticity is
// global; visibility in an opted-in store is target-scoped. A Delisted listing
// refuses the package while leaving ReleaseEntry/history untouched for other
// stores. Before the separate listing bootstrap is governed and complete, an
// empty StoreAuthority deliberately retains the established ReleaseEntry-only
// policy rather than manufacturing a partial listing projection.
func VerifyServeHash(ctx context.Context, cr chainReader, cfg Config, appHashHex string, appID string, rel ReleaseJSON) error {
	_, appHash, releasePDA, meta, err := verifyReleaseEntryHashForServe(ctx, cr, cfg, appHashHex, rel)
	if err != nil {
		return err
	}
	if err := verifyAppClear(ctx, cr, appID, &meta.AppID); err != nil {
		return err
	}
	return verifyStoreReleaseListing(ctx, cr, cfg, appHash, releasePDA)
}

// verifyCurrentStoreReleaseListing re-checks the target-scoped visibility fact
// after a cached global ReleaseEntry verdict. A DELIST must take effect on the
// next package or catalog request; it must not inherit the (documented) bounded
// cache window used for global release revocation. The caller has already
// verified this exact release while populating that cache, but we still derive
// the ReleaseEntry PDA afresh from the supplied release to bind the listing to
// the same master mint + app hash.
func verifyCurrentStoreReleaseListing(ctx context.Context, cr chainReader, cfg Config, appHashHex string, rel ReleaseJSON) error {
	gotHash := strings.ToLower(strings.TrimSpace(appHashHex))
	wantHash := strings.ToLower(strings.TrimSpace(rel.AppHash))
	if gotHash != wantHash {
		return fmt.Errorf("check=app_hash: apphash(spk,metadata)=%s != release.appHash=%s", gotHash, wantHash)
	}
	appHash, err := hash32FromHex(wantHash)
	if err != nil {
		return fmt.Errorf("check=app_hash: release.appHash not 32-byte hex: %w", err)
	}
	masterMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(rel.MasterNftMint))
	if err != nil {
		return fmt.Errorf("check=release_entry: bad release.masterNftMint: %w", err)
	}
	releasePDA, _, err := pda.Release(masterMint, appHash, licenseRegistryProgramID())
	if err != nil {
		return fmt.Errorf("check=release_entry: derive PDA: %w", err)
	}
	// A fresh global verdict is allowed to cache status/clearance facts for its
	// bounded revoke window, but never lets a replacement RELEASE.json bypass
	// the shared publisher-vault check. The vault is immutable chain state, so
	// re-read and compare it on every cached serve path.
	meta, err := cr.FetchReleaseEntryMeta(ctx, releasePDA.Base58())
	if err != nil {
		return fmt.Errorf("check=release_entry: fetch %s: %w", releasePDA.Base58(), err)
	}
	if err := verifySharedSquadsAuthorityForServe(cfg, rel, meta); err != nil {
		return err
	}
	return verifyStoreReleaseListing(ctx, cr, cfg, appHash, releasePDA)
}

// verifyStoreReleaseListing proves that the globally active ReleaseEntry is
// intentionally projected by THIS store. The configuration pins one store
// authority; the active StoreOperatorAuthorization pins that authority to the
// configured license+domain; the licence is one verify_license accepts
// (verifyStoreOwnLicence); and the listing PDA pins that tuple to this exact
// app hash. A missing, malformed, mismatched, revoked, unknown, or RPC-unreadable
// listing always refuses service, and so does a Store whose licence or whose
// licence's reseller is revoked. Only an explicitly Delisted exact listing is
// distinguishable so the catalog projection can omit that one target.
func verifyStoreReleaseListing(ctx context.Context, cr chainReader, cfg Config, appHash [32]byte, releasePDA pda.Pubkey) error {
	if strings.TrimSpace(cfg.StoreAuthority) == "" {
		return nil
	}
	storeAuthority, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.StoreAuthority))
	if err != nil {
		return fmt.Errorf("check=store_release_listing: bad cfg.store_authority: %w", err)
	}
	licenseMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.LicenseNFTMint))
	if err != nil {
		return fmt.Errorf("check=store_release_listing: bad cfg.license_nft_mint: %w", err)
	}
	domainHash := primitives.StoreDomainHash(cfg.Domain)
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, domainHash, licenseRegistryProgramID())
	if err != nil {
		return fmt.Errorf("check=store_release_listing: derive store operator authorization: %w", err)
	}
	authzStatus, onchainStoreAuthority, _, _, onchainDomainHash, err := cr.FetchStoreOperatorAuthz(ctx, authzPDA.Base58())
	if err != nil {
		return fmt.Errorf("check=store_release_listing: fetch store operator authorization %s: %w", authzPDA.Base58(), err)
	}
	if err := authzStatus.RequireActive(); err != nil {
		return fmt.Errorf("check=store_release_listing: StoreOperatorAuthorization status %s not Active: %w", authzStatus, err)
	}
	if onchainStoreAuthority != verify.Pubkey(storeAuthority) {
		return fmt.Errorf("check=store_release_listing: StoreOperatorAuthorization store_authority %x != cfg.store_authority %x", onchainStoreAuthority[:], storeAuthority[:])
	}
	if onchainDomainHash != domainHash {
		return fmt.Errorf("check=store_release_listing: StoreOperatorAuthorization domain hash %x != cfg domain hash %x", onchainDomainHash[:], domainHash[:])
	}
	// A Store-wide verdict, checked before this row's listing so that no row
	// is omitted as Delisted by a Store whose own licence is invalid.
	if err := verifyStoreOwnLicence(ctx, cr, cfg, licenseMint); err != nil {
		return err
	}

	listingPDA, _, err := pda.StoreReleaseListing(storeAuthority, appHash, licenseRegistryProgramID())
	if err != nil {
		return fmt.Errorf("check=store_release_listing: derive listing PDA: %w", err)
	}
	listing, err := cr.FetchStoreReleaseListingMeta(ctx, listingPDA.Base58())
	if err != nil {
		return fmt.Errorf("check=store_release_listing: fetch %s: %w", listingPDA.Base58(), err)
	}
	if err := listing.Status.requireActive(); err != nil {
		return fmt.Errorf("check=store_release_listing: status %s not Active: %w", listing.Status, err)
	}
	if listing.StoreAuthority != storeAuthority {
		return fmt.Errorf("check=store_release_listing: listing store_authority %x != cfg.store_authority %x", listing.StoreAuthority[:], storeAuthority[:])
	}
	if listing.AppHash != appHash {
		return fmt.Errorf("check=store_release_listing: listing app_hash %x != served app_hash %x", listing.AppHash[:], appHash[:])
	}
	if listing.ReleaseEntry != releasePDA {
		return fmt.Errorf("check=store_release_listing: listing release_entry %s != derived ReleaseEntry %s", listing.ReleaseEntry.Base58(), releasePDA.Base58())
	}
	if listing.StoreDomainHash != domainHash {
		return fmt.Errorf("check=store_release_listing: listing domain hash %x != cfg domain hash %x", listing.StoreDomainHash[:], domainHash[:])
	}
	if listing.OperatorAuthorization != authzPDA {
		return fmt.Errorf("check=store_release_listing: listing operator_authorization %s != derived authorization %s", listing.OperatorAuthorization.Base58(), authzPDA.Base58())
	}
	return nil
}

// errReleaseMasterMintRequired marks an operator configuration that has not
// declared the Master NFT mint used for InstallerReleaseEntry PDA derivation.
var errReleaseMasterMintRequired = errors.New("release_master_nft_mint is required")

// VerifyInstallerReleaseHash is the serve-time gate for whole-file artifacts
// under /releases/<class>/<name>. It verifies that sha256(file bytes) has an
// InstallerReleaseEntry under the configured Master NFT mint that the estate's
// installer-release trust admits: Active, registered by the master NFT
// custodian (the enrolled profile's core vault), and carrying a publisher key
// the profile's releaseTrust names with that key's signature over the entry's
// own fields. A Store with no enrolled profile has no such trust and refuses
// (installer-release-trust-unconfigured). This is the binary-artifact sibling
// of VerifyServeHash: app SPKs use ReleaseEntry over the canonical tree hash;
// shell bundles/sidecar binaries/venv bundles use InstallerReleaseEntry over
// the exact file sha256.
func VerifyInstallerReleaseHash(ctx context.Context, cr chainReader, cfg Config, installerHash [32]byte) error {
	meta, err := fetchInstallerReleaseMetaForHash(ctx, cr, cfg, installerHash)
	if err != nil {
		return err
	}
	if err := cfg.installerReleaseTrust.Admit(meta.Entry, installerHash); err != nil {
		return fmt.Errorf("check=installer_release: %s: %w", meta.PDA, err)
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
	relPDA, _, err := pda.InstallerRelease(masterMint, installerHash, licenseRegistryProgramID())
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
// and is Active. Returns the app master NFT mint, the 32-byte app_hash, the
// ReleaseEntry PDA and its decoded account (whose app_id binds the caller's
// clearance check). FAIL-CLOSED. (The author ed25519 sig was verified
// on-chain at register — §1. Publish additionally admits the whole entry,
// release_hash and publisher included: admitReleaseEntryForPublish.)
func verifyReleaseEntryHash(ctx context.Context, cr chainReader, cfg Config, appHashHex string, rel ReleaseJSON) (pda.Pubkey, [32]byte, pda.Pubkey, releaseEntryMeta, error) {
	return verifyReleaseEntryHashWithAuthorityPolicy(ctx, cr, cfg, appHashHex, rel, false)
}

// verifyReleaseEntryHashForServe is the serve-time form of
// verifyReleaseEntryHash. It differs only for a RELEASE.json that carries no
// quorumPolicy claim at all, which it hands to
// servedReleaseWithoutQuorumClaimRefusal: the standard build admits such a
// historically attested release there, and the estate-bootstrap build refuses
// it by name. It never relaxes the chain-bound publisher vault check, and it is
// intentionally not used by either publish path.
func verifyReleaseEntryHashForServe(ctx context.Context, cr chainReader, cfg Config, appHashHex string, rel ReleaseJSON) (pda.Pubkey, [32]byte, pda.Pubkey, releaseEntryMeta, error) {
	return verifyReleaseEntryHashWithAuthorityPolicy(ctx, cr, cfg, appHashHex, rel, true)
}

func verifyReleaseEntryHashWithAuthorityPolicy(ctx context.Context, cr chainReader, cfg Config, appHashHex string, rel ReleaseJSON, serving bool) (pda.Pubkey, [32]byte, pda.Pubkey, releaseEntryMeta, error) {
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
	relPDA, _, err := pda.Release(masterMint, appHashBytes, licenseRegistryProgramID())
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
		statusErr := fmt.Errorf("check=release_entry: status %s not Active: %w", meta.Status, err)
		if !releaseEntryExplicitRecall(cfg, appHashBytes, relPDA, meta) {
			return zeroMint, zeroHash, zeroPDA, zeroMeta, statusErr
		}
		// An explicit recall of this estate's release is still held to the
		// same publisher custody as the release was: a row whose served claim
		// or on-chain vault is not this Store's refuses by that name, not as a
		// recall.
		if err := checkSharedSquadsAuthority(cfg, rel, meta, serving); err != nil {
			return zeroMint, zeroHash, zeroPDA, zeroMeta, err
		}
		return zeroMint, zeroHash, zeroPDA, zeroMeta, fmt.Errorf("%w: %w: ReleaseEntry %s under the estate master mint %s, revoked_at %v", statusErr, errReleaseEntryRecalled, relPDA.Base58(), masterMint.Base58(), revokedAtText(meta.RevokedAt))
	}
	if err := checkSharedSquadsAuthority(cfg, rel, meta, serving); err != nil {
		return zeroMint, zeroHash, zeroPDA, zeroMeta, err
	}
	if meta.PDA == "" {
		meta.PDA = relPDA.Base58()
	}
	return masterMint, appHashBytes, relPDA, meta, nil
}

// errReleaseQuorumClaimAbsent names a RELEASE.json with no quorumPolicy claim
// at all: no threshold, no member count and no multisig. No build publishes
// one. Only the standard build serves one, and only one attested before the
// claim existed (servedReleaseWithoutQuorumClaimRefusal).
var errReleaseQuorumClaimAbsent = errors.New("release-quorum-claim-absent: RELEASE.json carries no quorumPolicy claim")

// verifySharedSquadsAuthority binds both representations of publisher custody
// to the one catalog-level Squads authority. RELEASE.json is a served claim;
// ReleaseEntry.publisher_squads_vault is the chain-authenticated fact. Both
// must name the configured vault, and the served quorum claim must name the
// configured multisig and quorum. App SPK keys are intentionally not consulted
// here: they remain per-app signing keys and are verified by the package path
// separately.
func verifySharedSquadsAuthority(cfg Config, rel ReleaseJSON, meta releaseEntryMeta) error {
	return checkSharedSquadsAuthority(cfg, rel, meta, false)
}

// verifySharedSquadsAuthorityForServe is deliberately narrower than a publish
// exception. It differs from verifySharedSquadsAuthority only for a release
// with no quorum claim at all, and the build decides that case
// (servedReleaseWithoutQuorumClaimRefusal). Even where the standard build
// admits it, the absent claim adds no authority: the served vault claim and the
// active ReleaseEntry's publisher vault have already been compared exactly with
// the Store configuration. A partial claim is checked in full.
func verifySharedSquadsAuthorityForServe(cfg Config, rel ReleaseJSON, meta releaseEntryMeta) error {
	return checkSharedSquadsAuthority(cfg, rel, meta, true)
}

func checkSharedSquadsAuthority(cfg Config, rel ReleaseJSON, meta releaseEntryMeta, serving bool) error {
	want, err := cfg.sharedSquadsAuthority()
	if err != nil {
		return fmt.Errorf("check=publisher_squads_authority: %w", err)
	}
	claimedVault, err := canonicalSquadsPubkey("release.licenseSquadsVault", rel.LicenseSquadsVault)
	if err != nil {
		return fmt.Errorf("check=publisher_squads_authority: %w", err)
	}
	if claimedVault != want.Vault {
		return fmt.Errorf("check=publisher_squads_authority: release licenseSquadsVault %s != configured vault %s", claimedVault.Base58(), want.Vault.Base58())
	}
	if meta.PublisherSquadsVault != want.Vault {
		got := pda.Pubkey(meta.PublisherSquadsVault)
		return fmt.Errorf("check=publisher_squads_authority: on-chain publisher_squads_vault %s != configured vault %s", got.Base58(), want.Vault.Base58())
	}
	if rel.QuorumPolicy == (QuorumPolicy{}) {
		if serving {
			return servedReleaseWithoutQuorumClaimRefusal()
		}
		return fmt.Errorf("check=publisher_squads_authority: %w", errReleaseQuorumClaimAbsent)
	}
	claimedMultisig, err := canonicalSquadsPubkey("release.quorumPolicy.multisigPda", rel.QuorumPolicy.MultisigPda)
	if err != nil {
		return fmt.Errorf("check=publisher_squads_authority: %w", err)
	}
	if claimedMultisig != want.Multisig {
		return fmt.Errorf("check=publisher_squads_authority: release quorumPolicy multisigPda %s != configured multisig %s", claimedMultisig.Base58(), want.Multisig.Base58())
	}
	if rel.QuorumPolicy.Threshold != want.Threshold || rel.QuorumPolicy.MemberCount != want.MemberCount {
		return fmt.Errorf("check=publisher_squads_authority: release quorumPolicy %d/%d != configured quorum %d/%d", rel.QuorumPolicy.Threshold, rel.QuorumPolicy.MemberCount, want.Threshold, want.MemberCount)
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
