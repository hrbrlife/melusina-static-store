package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-identity-gate/bundle"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// rootTrustBundlePath is the single public trust-discovery endpoint for the
// default Bazaar. Reseller stores fetch this exact path before accepting any
// mirrored root bytes.
const rootTrustBundlePath = bundle.WellKnownPath

// newRootTrustBundleHandler builds the default Bazaar's signed trust-discovery
// handler. The bundle is assembled from the already-configured Store facts and
// signed by the boot-derived Store operator. It is deliberately unavailable
// unless each GET can still prove that operator is the active root authority on
// chain; a revoked or non-root Store must not keep serving a usable trust root.
func newRootTrustBundleHandler(cfg Config, operator *identity.Private, cr chainReader) (http.Handler, error) {
	if operator == nil {
		return nil, fmt.Errorf("root trust bundle: Store operator is unavailable")
	}
	if cr == nil {
		return nil, fmt.Errorf("root trust bundle: chain reader is unavailable")
	}

	loaded, detachedSignature, err := buildRootTrustBundle(cfg, operator)
	if err != nil {
		return nil, err
	}
	served := bundle.WellKnownHandler(loaded, detachedSignature)
	opPub, err := signPubkey32(operator.Public())
	if err != nil {
		return nil, fmt.Errorf("root trust bundle: operator signing key: %w", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Keep the well-known transport contract exact: its own handler owns
		// method rejection, so a non-GET never triggers an unnecessary chain read.
		if r.Method != http.MethodGet {
			served.ServeHTTP(w, r)
			return
		}
		if _, _, err := VerifyStoreOperator(r.Context(), cr, cfg, opPub, true /* requireRoot */); err != nil {
			// This endpoint is a root-of-trust discovery document, not an
			// authorization API. Do not serve a stale valid signature after the
			// authority is revoked or reseated; make the unavailable trust state
			// explicit without leaking chain internals to unauthenticated callers.
			http.Error(w, "root trust bundle unavailable", http.StatusServiceUnavailable)
			return
		}
		served.ServeHTTP(w, r)
	}), nil
}

// unavailableRootTrustBundleHandler reserves the exact discovery route even
// when local configuration cannot safely assemble a signed bundle. Leaving it
// to the catch-all static surface would turn a trust outage into an ambiguous
// 404 or SPA response.
func unavailableRootTrustBundleHandler(err error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.Error(w, "root trust bundle unavailable", http.StatusServiceUnavailable)
	})
}

// buildRootTrustBundle emits the canonical document used by the well-known
// transport. That transport intentionally strips bundle_signature from the
// canonical bytes and relies on its detached Ed25519 signature instead; this
// is the exact shape rootMirror verifies before parsing root claims.
func buildRootTrustBundle(cfg Config, operator *identity.Private) (*bundle.Loaded, []byte, error) {
	if operator == nil {
		return nil, nil, fmt.Errorf("root trust bundle: Store operator is unavailable")
	}
	installURL, installDomain, err := rootTrustBundleInstallLocation(cfg.PublicBaseURL)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(cfg.StoreID) == "" {
		return nil, nil, fmt.Errorf("root trust bundle: store_id is required")
	}
	if strings.TrimSpace(cfg.RPCURL) == "" {
		return nil, nil, fmt.Errorf("root trust bundle: rpc_url is required")
	}
	licenseMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.LicenseNFTMint))
	if err != nil {
		return nil, nil, fmt.Errorf("root trust bundle: license_nft_mint: %w", err)
	}
	licenseEntry, _, err := primitives.DeriveLicense(licenseMint, programID)
	if err != nil {
		return nil, nil, fmt.Errorf("root trust bundle: derive license entry: %w", err)
	}
	masterMint := strings.TrimSpace(cfg.ReleaseMasterNftMint)
	if _, err := primitives.PubkeyFromBase58(masterMint); err != nil {
		return nil, nil, fmt.Errorf("root trust bundle: release_master_nft_mint: %w", err)
	}
	tlsFingerprint, err := tlsCertFingerprint(bootIdentityTLSCertPath(cfg))
	if err != nil {
		return nil, nil, fmt.Errorf("root trust bundle: TLS certificate: %w", err)
	}

	operatorPublic := operator.Public()
	trust := bundle.TrustBundle{
		Tenant: cfg.StoreID,
		Melusina: bundle.MelusinaProvenance{
			RPCURL:                   cfg.RPCURL,
			LicenseRegistryProgramID: cfg.ProgramID,
		},
		Install: bundle.InstallAttestation{
			ID:                   cfg.StoreID,
			Verified:             true,
			LicenseNFTMint:       cfg.LicenseNFTMint,
			LicenseEntryID:       licenseEntry.Base58(),
			MasterNftMint:        masterMint,
			Domain:               installDomain,
			InstallURL:           installURL,
			AllowedHosts:         []string{installDomain},
			TLSFingerprintSHA256: hex.EncodeToString(tlsFingerprint[:]),
			BundleSigningPubkey:  operatorPublic.SignPubkeyB58,
		},
		// A Store is not a Sandstorm application, but the common bundle schema
		// requires an authorization shape. StoreID is the stable identity of
		// this root endpoint; no fictitious app hash or approval is emitted.
		AuthorizedApp: bundle.AppAuthorization{
			AppID:  cfg.StoreID,
			Active: true,
		},
		Signers: []bundle.BundleSigner{{
			Pubkey: operatorPublic.SignPubkeyB58,
			Role:   "install_admin",
			Label:  "default Bazaar Store operator",
		}},
	}

	raw, err := json.Marshal(trust)
	if err != nil {
		return nil, nil, fmt.Errorf("root trust bundle: marshal bundle: %w", err)
	}
	canonical, err := bundle.CanonicalizeForSigning(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("root trust bundle: canonicalize bundle: %w", err)
	}
	detachedSignature := operator.Sign(canonical)
	if !operatorPublic.Verify(canonical, detachedSignature) {
		return nil, nil, fmt.Errorf("root trust bundle: detached signature self-check failed")
	}

	return &bundle.Loaded{RawJSON: raw, Bundle: trust}, detachedSignature, nil
}

// rootTrustBundleInstallLocation accepts only a public HTTPS origin. The Store
// sidecar's cfg.Domain is intentionally an internal sidecar host, so it must
// never be substituted into a browser-facing or signed trust endpoint.
func rootTrustBundleInstallLocation(raw string) (installURL, installDomain string, err error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", fmt.Errorf("root trust bundle: public_base_url is required")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed == nil || parsed.Scheme != "https" || parsed.Host == "" {
		return "", "", fmt.Errorf("root trust bundle: public_base_url must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", "", fmt.Errorf("root trust bundle: public_base_url must be a clean HTTPS origin")
	}
	if parsed.Port() != "" {
		return "", "", fmt.Errorf("root trust bundle: public_base_url must not include a port")
	}
	domain := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if domain == "" {
		return "", "", fmt.Errorf("root trust bundle: public_base_url has no host")
	}
	return "https://" + domain, domain, nil
}
