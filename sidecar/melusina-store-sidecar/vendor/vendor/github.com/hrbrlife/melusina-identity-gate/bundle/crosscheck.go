package bundle

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// Sentinel errors raised by CrossCheckOnChain. Callers branch on
// these via errors.Is to distinguish "bundle is wrong about TLS pin"
// from "global app approval has been revoked" without parsing
// strings.
var (
	// ErrTLSFingerprintMismatch means the bundle's
	// Install.TLSFingerprintSHA256 disagrees with the on-chain
	// LicenseEntry.tls_cert_fingerprint. Bundle is suspect — the
	// gate MUST refuse to load.
	ErrTLSFingerprintMismatch = errors.New("trust bundle TLS fingerprint does not match on-chain LicenseEntry")

	// ErrAppApprovalNotActive means the bundle authorizes an app
	// whose GlobalAppApproval is not status==Active on chain. Inv 2
	// requires the cascade head to be Active before any descendant
	// can be honoured.
	ErrAppApprovalNotActive = errors.New("trust bundle authorizes app whose GlobalAppApproval is not Active")

	// ErrAppHashMismatch means the bundle's authorized_app.app_hash
	// disagrees with the on-chain GlobalAppApproval.app_hash. Either
	// the bundle was authored against a different app revision, or
	// the on-chain pin was revoked + reissued — either way, fail
	// closed.
	ErrAppHashMismatch = errors.New("trust bundle app_hash does not match on-chain GlobalAppApproval")

	// ErrCrossCheckMissingField means the bundle is missing a field
	// the cross-check requires (license_entry_id, global_approval_id,
	// etc). Bundles authored without these cannot be verified
	// against chain — fail closed (Inv 5).
	ErrCrossCheckMissingField = errors.New("trust bundle missing field required for on-chain cross-check")

	// ErrTrustBundleURIMismatch means the URL the verifier fetched
	// the trust bundle from disagrees with the URI pinned on chain at
	// `LicenseEntry.trust_bundle_uri` (D20). Either the bundle was
	// served from an unauthorized mirror, or the on-chain pin was
	// rotated and the local URL is stale. Either way, fail closed
	// (Inv 5) — the verifier MUST refuse the bundle.
	//
	// Both values must be non-empty for this check to fire. An empty
	// `LicenseEntry.trust_bundle_uri` is a documented "deployer
	// hasn't pinned the URI yet" state and skips the comparison
	// (matches the same opt-in posture B11 takes for sandstorm_version).
	ErrTrustBundleURIMismatch = errors.New("fetched trust bundle URI does not match LicenseEntry.trust_bundle_uri on chain")
)

// CrossCheckOnChain re-validates the loaded trust bundle against
// authoritative on-chain state via the supplied RPCClient. Production
// loader paths MUST invoke this after LoadAndVerify — the local
// Ed25519 signature only proves the bundle was minted by the install
// admin, not that the install admin's claims still match what's
// committed on chain.
//
// Specifically:
//
//   - LicenseEntry[Install.LicenseEntryID].tls_cert_fingerprint must
//     equal hex-decoded Install.TLSFingerprintSHA256.
//   - GlobalAppApproval[AuthorizedApp.GlobalApprovalID].status must
//     be Active AND its app_hash must equal hex-decoded
//     AuthorizedApp.AppHash.
//
// Any mismatch returns one of the sentinel errors above wrapped with
// context. The bundle digest is logged so operators can correlate the
// failing bundle with the issuing install admin.
//
// Callers that load trust bundles in dev tooling (e.g. one-shot
// CLI inspection) MAY skip CrossCheckOnChain to avoid the round trip
// to a Solana RPC. Production sidecar / shell loaders MUST NOT.
func (l *Loaded) CrossCheckOnChain(ctx context.Context, rpc *verify.RPCClient) error {
	if rpc == nil {
		return errors.New("CrossCheckOnChain: nil rpc client")
	}
	b := &l.Bundle

	// — TLS fingerprint pin —
	if strings.TrimSpace(b.Install.LicenseEntryID) == "" {
		return fmt.Errorf("%w: install.license_entry_id", ErrCrossCheckMissingField)
	}
	if strings.TrimSpace(b.Install.TLSFingerprintSHA256) == "" {
		return fmt.Errorf("%w: install.tls_fingerprint_sha256", ErrCrossCheckMissingField)
	}
	wantFP, err := hex.DecodeString(strings.ToLower(b.Install.TLSFingerprintSHA256))
	if err != nil {
		return fmt.Errorf("install.tls_fingerprint_sha256: %w", err)
	}
	if len(wantFP) != 32 {
		return fmt.Errorf("install.tls_fingerprint_sha256: want 32 bytes, got %d", len(wantFP))
	}

	gotFP, err := rpc.FetchLicenseEntryTLSFingerprint(ctx, b.Install.LicenseEntryID)
	if err != nil {
		return fmt.Errorf("fetch LicenseEntry %s: %w", b.Install.LicenseEntryID, err)
	}
	for i := 0; i < 32; i++ {
		if wantFP[i] != gotFP[i] {
			return fmt.Errorf("%w: bundle=%s on_chain=%s LicenseEntry=%s",
				ErrTLSFingerprintMismatch,
				strings.ToLower(b.Install.TLSFingerprintSHA256),
				hex.EncodeToString(gotFP[:]),
				b.Install.LicenseEntryID)
		}
	}

	// — App approval cascade head —
	app := b.AuthorizedApp
	if strings.TrimSpace(app.GlobalApprovalID) == "" {
		return fmt.Errorf("%w: authorized_app.global_approval_id", ErrCrossCheckMissingField)
	}
	if strings.TrimSpace(app.AppHash) == "" {
		return fmt.Errorf("%w: authorized_app.app_hash", ErrCrossCheckMissingField)
	}
	wantHash, err := hex.DecodeString(strings.ToLower(app.AppHash))
	if err != nil {
		return fmt.Errorf("authorized_app.app_hash: %w", err)
	}
	if len(wantHash) != 32 {
		return fmt.Errorf("authorized_app.app_hash: want 32 bytes, got %d", len(wantHash))
	}

	status, err := rpc.FetchGlobalAppApprovalStatus(ctx, app.GlobalApprovalID)
	if err != nil {
		return fmt.Errorf("fetch GlobalAppApproval %s status: %w", app.GlobalApprovalID, err)
	}
	if status != verify.ApprovalStatusActive {
		return fmt.Errorf("%w: app_id=%s global_approval=%s status=%s",
			ErrAppApprovalNotActive, app.AppID, app.GlobalApprovalID, status)
	}

	gotHash, err := rpc.FetchGlobalAppApprovalAppHash(ctx, app.GlobalApprovalID)
	if err != nil {
		return fmt.Errorf("fetch GlobalAppApproval %s app_hash: %w", app.GlobalApprovalID, err)
	}
	for i := 0; i < 32; i++ {
		if wantHash[i] != gotHash[i] {
			return fmt.Errorf("%w: bundle=%s on_chain=%s global_approval=%s",
				ErrAppHashMismatch,
				strings.ToLower(app.AppHash),
				hex.EncodeToString(gotHash[:]),
				app.GlobalApprovalID)
		}
	}

	return nil
}

// CrossCheckTrustBundleURI fetches the on-chain `trust_bundle_uri`
// pin from the LicenseEntry referenced by Install.LicenseEntryID and
// compares it to fetchURI (the URL the verifier fetched the bundle
// from). Returns nil iff they match exactly (after TrimSpace) OR if
// the on-chain pin is empty (documented "deployer hasn't pinned
// yet" state). A populated on-chain pin that disagrees with fetchURI
// returns ErrTrustBundleURIMismatch — fail-closed (Inv 5).
//
// fetchURI MAY be empty — the cross-check skips (returns nil) in
// that case so verifiers loading bundles from disk (no fetch URL to
// compare against) don't trip the gate. Production verify-receipt
// flows that reach this code with both empty values get a clean
// pass — the field-pin is opt-in until deployer landing.
//
// Callers that need stricter semantics ("trust bundle MUST be
// fetched-from-URL, AND that URL MUST match the on-chain pin") wrap
// this with their own non-empty assertion before invoking.
func (l *Loaded) CrossCheckTrustBundleURI(ctx context.Context, rpc *verify.RPCClient, fetchURI string) error {
	if rpc == nil {
		return errors.New("CrossCheckTrustBundleURI: nil rpc client")
	}
	b := &l.Bundle
	if strings.TrimSpace(b.Install.LicenseEntryID) == "" {
		return fmt.Errorf("%w: install.license_entry_id", ErrCrossCheckMissingField)
	}
	want, err := rpc.FetchLicenseEntryTrustBundleURI(ctx, b.Install.LicenseEntryID)
	if err != nil {
		return fmt.Errorf("fetch LicenseEntry %s trust_bundle_uri: %w", b.Install.LicenseEntryID, err)
	}
	want = strings.TrimSpace(want)
	got := strings.TrimSpace(fetchURI)
	if want == "" || got == "" {
		return nil // opt-in skip — see godoc above
	}
	if want != got {
		return fmt.Errorf("%w: fetched=%s on_chain=%s LicenseEntry=%s",
			ErrTrustBundleURIMismatch, got, want, b.Install.LicenseEntryID)
	}
	return nil
}
