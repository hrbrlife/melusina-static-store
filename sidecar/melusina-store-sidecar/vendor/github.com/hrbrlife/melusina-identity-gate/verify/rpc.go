package verify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RPCClient is a minimal Solana JSON-RPC client for the single call
// every verifier needs: getAccountInfo for a PDA. It intentionally
// does not wrap the full Solana JSON-RPC surface — that belongs in
// Anchor / web3.js clients; here we just need account bytes.
//
// Safe for concurrent use.
type RPCClient struct {
	Endpoint   string
	HTTPClient *http.Client
}

// NewRPCClient returns a client with a sane HTTP timeout. Override by
// replacing HTTPClient on the returned struct.
func NewRPCClient(endpoint string) *RPCClient {
	return &RPCClient{
		Endpoint: endpoint,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetAccountInfo fetches the account at addressBase58, returns the
// raw (non-discriminator-stripped) Borsh-encoded data bytes, and an
// error otherwise. A nil data slice with no error means the account
// does not exist on chain — callers MUST treat that as fail-closed
// (wrap as ErrPDANotFound).
func (c *RPCClient) GetAccountInfo(ctx context.Context, addressBase58 string) ([]byte, error) {
	req := rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "getAccountInfo",
		Params: []any{
			addressBase58,
			map[string]any{"encoding": "base64", "commitment": "confirmed"},
		},
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRPCUnreachable, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrRPCUnreachable, resp.StatusCode, string(raw))
	}

	var parsed rpcResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode rpc response: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	if parsed.Result.Value == nil {
		return nil, nil // account does not exist
	}
	if len(parsed.Result.Value.Data) < 2 {
		return nil, errors.New("unexpected getAccountInfo data shape")
	}
	if parsed.Result.Value.Data[1] != "base64" {
		return nil, fmt.Errorf("expected base64 encoding, got %q", parsed.Result.Value.Data[1])
	}
	decoded, err := base64.StdEncoding.DecodeString(parsed.Result.Value.Data[0])
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	return decoded, nil
}

// FetchStatus fetches an account and returns its ApprovalStatus byte
// at a fixed offset. Only safe for accounts with no variable-length
// fields before status — primarily LocalAppApproval
// (use LocalAppApprovalStatusOffset). For accounts with variable
// prefixes (InstallAdminEntry, OrganizationMemberEntry, Global /
// Reseller approvals, LocalSidecarApproval) use the PDA-specific
// Fetch* helpers below instead.
func (c *RPCClient) FetchStatus(ctx context.Context, addressBase58 string, statusOffset int) (ApprovalStatus, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return 0, err
	}
	if data == nil {
		return 0, ErrPDANotFound
	}
	return ReadStatusByte(data, statusOffset)
}

// FetchInstallAdminStatus fetches and walks an InstallAdminEntry PDA.
func (c *RPCClient) FetchInstallAdminStatus(ctx context.Context, addressBase58 string) (ApprovalStatus, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return 0, err
	}
	if data == nil {
		return 0, ErrPDANotFound
	}
	return ReadInstallAdminStatus(data)
}

// FetchOrganizationMemberStatus fetches and walks an
// OrganizationMemberEntry PDA.
func (c *RPCClient) FetchOrganizationMemberStatus(ctx context.Context, addressBase58 string) (ApprovalStatus, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return 0, err
	}
	if data == nil {
		return 0, ErrPDANotFound
	}
	return ReadOrganizationMemberStatus(data)
}

// FetchLocalAppApprovalStatus fetches a LocalAppApproval PDA (fixed
// offset layout).
func (c *RPCClient) FetchLocalAppApprovalStatus(ctx context.Context, addressBase58 string) (ApprovalStatus, error) {
	return c.FetchStatus(ctx, addressBase58, LocalAppApprovalStatusOffset)
}

// FetchGlobalAppApprovalStatus fetches a GlobalAppApproval PDA
// (variable-string layout).
func (c *RPCClient) FetchGlobalAppApprovalStatus(ctx context.Context, addressBase58 string) (ApprovalStatus, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return 0, err
	}
	if data == nil {
		return 0, ErrPDANotFound
	}
	return ReadGlobalAppApprovalStatus(data)
}

// FetchLocalSidecarStatus fetches a LocalSidecarApproval PDA and
// returns its status byte, walking past the variable-length
// sidecar_id String in the account data. Used by every Melusina
// sidecar on /tenant/join per §5.4 (ailagoon, creeper, opensanctions, …).
func (c *RPCClient) FetchLocalSidecarStatus(ctx context.Context, addressBase58 string) (ApprovalStatus, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return 0, err
	}
	if data == nil {
		return 0, ErrPDANotFound
	}
	return ReadSidecarApprovalStatusLocal(data)
}

// FetchResellerSidecarStatus fetches a ResellerSidecarApproval PDA.
// Used by the cascade-check path on /tenant/join when the daemon
// runs in direct-RPC mode (no authzsign UDS).
func (c *RPCClient) FetchResellerSidecarStatus(ctx context.Context, addressBase58 string) (ApprovalStatus, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return 0, err
	}
	if data == nil {
		return 0, ErrPDANotFound
	}
	return ReadSidecarApprovalStatusReseller(data)
}

// FetchResellerEntryStatus fetches the ResellerEntry authority-parent PDA.
// A reseller-sidecar approval is not independently sufficient: the deployed
// program rejects the whole child cascade once this parent is Revoked.
func (c *RPCClient) FetchResellerEntryStatus(ctx context.Context, addressBase58 string) (ResellerStatus, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return 0, err
	}
	if data == nil {
		return 0, ErrPDANotFound
	}
	return ReadResellerEntryStatus(data)
}

// FetchLicenseEntryTLSFingerprint fetches a LicenseEntry PDA and
// returns its [32]byte tls_cert_fingerprint. Used by the trust-bundle
// loader's CrossCheckOnChain helper (B8) to assert the bundle's
// tls_fingerprint_sha256 matches the on-chain pin.
func (c *RPCClient) FetchLicenseEntryTLSFingerprint(ctx context.Context, addressBase58 string) ([32]byte, error) {
	var fp [32]byte
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return fp, err
	}
	if data == nil {
		return fp, ErrPDANotFound
	}
	return ReadLicenseEntryTLSFingerprint(data)
}

// FetchLicenseEntrySandstormVersion fetches a LicenseEntry PDA and
// returns its `sandstorm_version` String pin (B10/B11). Empty string
// is the documented "not yet pinned" state — the launch-side helper
// at melusina-attest/binhash treats empty as warn-and-continue, but a
// populated pin that differs from the on-disk version is fail-closed
// (Inv 5). PDA-not-found is surfaced as ErrPDANotFound.
func (c *RPCClient) FetchLicenseEntrySandstormVersion(ctx context.Context, addressBase58 string) (string, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", ErrPDANotFound
	}
	return ReadLicenseEntrySandstormVersion(data)
}

// FetchLicenseEntryTrustBundleURI fetches a LicenseEntry PDA and
// returns its `trust_bundle_uri` String pin (D20). Empty string is
// the documented "not yet pinned" state — deployer pins the URI via
// a follow-up update once the well-known endpoint is live. A
// populated URI is the canonical address from which a verifier
// fetches the signed trust bundle via `bundle.FetchFromURL`.
// PDA-not-found is surfaced as ErrPDANotFound.
func (c *RPCClient) FetchLicenseEntryTrustBundleURI(ctx context.Context, addressBase58 string) (string, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", ErrPDANotFound
	}
	return ReadLicenseEntryTrustBundleURI(data)
}

// FetchLicenseEntrySummary fetches a LicenseEntry PDA and walks its
// full layout into a LicenseEntrySummary. Used by the launch-prep
// operator CLI (`melusina-installhealth`) to amortize one network
// round-trip across the License-Active / dev_permissive / authz pubkey
// / sandstorm_version / trust_bundle_uri / TLS fingerprint /
// squads_vault checks. PDA-not-found is surfaced as ErrPDANotFound
// (Inv 5: callers fail closed).
func (c *RPCClient) FetchLicenseEntrySummary(ctx context.Context, addressBase58 string) (LicenseEntrySummary, error) {
	var s LicenseEntrySummary
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return s, err
	}
	if data == nil {
		return s, ErrPDANotFound
	}
	return ReadLicenseEntrySummary(data)
}

// FetchGlobalAppApprovalAppHash fetches a GlobalAppApproval PDA and
// returns its [32]byte app_hash. Used by the trust-bundle loader's
// CrossCheckOnChain helper (B8).
func (c *RPCClient) FetchGlobalAppApprovalAppHash(ctx context.Context, addressBase58 string) ([32]byte, error) {
	var hash [32]byte
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return hash, err
	}
	if data == nil {
		return hash, ErrPDANotFound
	}
	return ReadGlobalAppApprovalAppHash(data)
}

// FetchGlobalSidecarStatus fetches a GlobalSidecarApproval PDA.
// Same direct-RPC path as the reseller fetch above; the Global
// approval sits at the top of the cascade.
func (c *RPCClient) FetchGlobalSidecarStatus(ctx context.Context, addressBase58 string) (ApprovalStatus, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return 0, err
	}
	if data == nil {
		return 0, ErrPDANotFound
	}
	return ReadSidecarApprovalStatusGlobal(data)
}

// FetchGlobalSidecarBinaryHash fetches a GlobalSidecarApproval PDA and
// returns its [32]byte binary_hash. Used by the B11 hash-attestation
// gate at sidecar boot — the Foundation pin is the cascade root that
// every install inherits when LocalSidecarApproval.binary_hash is None.
func (c *RPCClient) FetchGlobalSidecarBinaryHash(ctx context.Context, addressBase58 string) ([32]byte, error) {
	var zero [32]byte
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return zero, err
	}
	if data == nil {
		return zero, ErrPDANotFound
	}
	return ReadGlobalSidecarBinaryHash(data)
}

// FetchLocalSidecarBinaryHash fetches a LocalSidecarApproval PDA and
// returns its Option<[u8;32]> binary_hash field. The boolean is true
// when the install has pinned a specific build (Some), false when the
// field is None (in which case callers must fall back to the Global
// pin). PDA-not-found is surfaced as ErrPDANotFound.
func (c *RPCClient) FetchLocalSidecarBinaryHash(ctx context.Context, addressBase58 string) ([32]byte, bool, error) {
	var zero [32]byte
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return zero, false, err
	}
	if data == nil {
		return zero, false, ErrPDANotFound
	}
	return ReadLocalSidecarBinaryHash(data)
}

// ── Federated-store fetches (FEDERATED-STORE-MVP §C1/§C4) ─────────────────

// FetchReleaseEntry fetches a ReleaseEntry PDA (seeds
// ["release_v2", master_nft_mint, app_hash]) and returns its app_hash +
// status. Used by C2.3's /publish gate: re-hash the SPK, assert it ==
// app_hash, then assert status == Active. PDA-not-found is surfaced as
// ErrPDANotFound (Inv 5: callers fail closed).
func (c *RPCClient) FetchReleaseEntry(ctx context.Context, addressBase58 string) (appHash [32]byte, status AttestationStatus, err error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return appHash, 0, err
	}
	if data == nil {
		return appHash, 0, ErrPDANotFound
	}
	return ReadReleaseEntry(data)
}

// FetchReleaseEntryAppID fetches a ReleaseEntry PDA and returns ONLY its
// on-chain `app_id` (the stable per-application identity, distinct from the
// per-release app_hash). The store-sidecar's /publish gate uses it to derive
// the FoundationAppEntry PDA and enforce the operator tier ceiling
// (audit 2026-06-17 B1-05/B2-05) — app_id is taken from the chain, never from
// the untrusted RELEASE.json. PDA-not-found is surfaced as ErrPDANotFound.
func (c *RPCClient) FetchReleaseEntryAppID(ctx context.Context, addressBase58 string) (appID [32]byte, err error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return appID, err
	}
	if data == nil {
		return appID, ErrPDANotFound
	}
	return ReadReleaseEntryAppID(data)
}

// FetchSidecarIdentity fetches a SidecarIdentityEntry PDA (seeds
// ["sidecar_identity", license_nft_mint, sidecar_id, key_version_le]) and
// returns the binary_hash, domain_hash, tls_cert_fingerprint, signing/encryption
// pubkeys, key_version, and status. Used by the store-sidecar's boot-identity
// ceremony (audit 2026-06-17 B1-02) to bind its derived operator identity to the
// on-chain attestation before enabling the gated /publish path. PDA-not-found is
// surfaced as ErrPDANotFound (Inv 5: the boot gate fails closed).
func (c *RPCClient) FetchSidecarIdentity(ctx context.Context, addressBase58 string) (SidecarIdentity, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return SidecarIdentity{}, err
	}
	if data == nil {
		return SidecarIdentity{}, ErrPDANotFound
	}
	return ReadSidecarIdentity(data)
}

// FetchStoreOperatorAuthz fetches a StoreOperatorAuthorization PDA (seeds
// ["store_operator", license_nft_mint, store_domain_hash]) and returns the
// fields the store-operate gate (§C1) + cascade store stage (§C4) need:
// status, store_authority, allowed_tier_mask, is_root, store_domain_hash.
// PDA-not-found is surfaced as ErrPDANotFound.
func (c *RPCClient) FetchStoreOperatorAuthz(ctx context.Context, addressBase58 string) (status AuthorizationStatus, storeAuthority Pubkey, allowedTierMask uint8, isRoot bool, storeDomainHash [32]byte, err error) {
	data, gerr := c.GetAccountInfo(ctx, addressBase58)
	if gerr != nil {
		return 0, Pubkey{}, 0, false, [32]byte{}, gerr
	}
	if data == nil {
		return 0, Pubkey{}, 0, false, [32]byte{}, ErrPDANotFound
	}
	a, derr := ReadStoreOperatorAuthz(data)
	if derr != nil {
		return 0, Pubkey{}, 0, false, [32]byte{}, derr
	}
	return a.Status, a.StoreAuthority, a.AllowedTierMask, a.IsRoot, a.StoreDomainHash, nil
}

// FetchStoreReleaseListing fetches a StoreReleaseListing PDA (seeds
// ["store_release_listing", store_authority, app_hash]) and returns the C1
// fields the cascade store stage (§C4) needs: app_hash, store_domain_hash,
// operator_authorization, status. PDA-not-found is surfaced as
// ErrPDANotFound.
func (c *RPCClient) FetchStoreReleaseListing(ctx context.Context, addressBase58 string) (appHash [32]byte, storeDomainHash [32]byte, operatorAuthorization Pubkey, status AuthorizationStatus, err error) {
	data, gerr := c.GetAccountInfo(ctx, addressBase58)
	if gerr != nil {
		return [32]byte{}, [32]byte{}, Pubkey{}, 0, gerr
	}
	if data == nil {
		return [32]byte{}, [32]byte{}, Pubkey{}, 0, ErrPDANotFound
	}
	l, derr := ReadStoreReleaseListing(data)
	if derr != nil {
		return [32]byte{}, [32]byte{}, Pubkey{}, 0, derr
	}
	return l.AppHash, l.StoreDomainHash, l.OperatorAuthorization, l.Status, nil
}

// FetchInstallerReleaseEntry fetches an InstallerReleaseEntry PDA (seeds
// ["installer_release", master_nft_mint, installer_hash]) and returns its
// installer_hash + status. Used by the reseller store-sidecar's ROOT-MIRROR
// worker (§C2.6): when re-serving the base Melusina installer mirrored from
// the root, the worker re-derives this PDA and asserts status == Active before
// serving the bytes. PDA-not-found is surfaced as ErrPDANotFound (Inv 5:
// callers fail closed).
func (c *RPCClient) FetchInstallerReleaseEntry(ctx context.Context, addressBase58 string) (installerHash [32]byte, status AttestationStatus, err error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return installerHash, 0, err
	}
	if data == nil {
		return installerHash, 0, ErrPDANotFound
	}
	return ReadInstallerReleaseEntry(data)
}

// FetchFoundationAppEntry fetches a FoundationAppEntry PDA (seeds
// ["foundation_app", app_id]) and returns its app_id, tier (Core=0/Standard=1),
// and status. Used by the reseller store-sidecar's ROOT-MIRROR worker (§C2.6):
// for each basic app mirrored from the root, re-derive this PDA and assert
// status == Active AND tier matches the root's advertised tier before
// re-serving the root's bytes. PDA-not-found is surfaced as ErrPDANotFound.
func (c *RPCClient) FetchFoundationAppEntry(ctx context.Context, addressBase58 string) (appID [32]byte, tier uint8, status ApprovalStatus, err error) {
	data, gerr := c.GetAccountInfo(ctx, addressBase58)
	if gerr != nil {
		return [32]byte{}, 0, 0, gerr
	}
	if data == nil {
		return [32]byte{}, 0, 0, ErrPDANotFound
	}
	e, derr := ReadFoundationAppEntry(data)
	if derr != nil {
		return [32]byte{}, 0, 0, derr
	}
	return e.AppID, uint8(e.Tier), e.Status, nil
}

// FetchBlacklistEntry fetches a BlacklistEntry PDA (seeds ["blacklist",
// target]; state/app_approval.rs:109 — the struct IS deployed on-chain) and
// returns (present, entry_type). The struct carries NO status field: the
// PDA's mere existence is the deny signal (§C4), so present=true means
// blacklisted. A non-existent account is NOT an error here — it is the
// common, expected "not blacklisted" case — so this returns
// (false, 0, nil) rather than ErrPDANotFound. Genuine RPC / decode errors
// are still surfaced so the caller fails closed (Inv 5).
func (c *RPCClient) FetchBlacklistEntry(ctx context.Context, addressBase58 string) (present bool, entryType BlacklistType, err error) {
	data, gerr := c.GetAccountInfo(ctx, addressBase58)
	if gerr != nil {
		return false, 0, gerr
	}
	if data == nil {
		return false, 0, nil // not blacklisted
	}
	t, derr := ReadBlacklistEntryType(data)
	if derr != nil {
		return true, 0, derr
	}
	return true, t, nil
}

// ── RPC wire types ───────────────────────────────────────────────────────

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResponse struct {
	JSONRPC string       `json:"jsonrpc"`
	ID      int          `json:"id"`
	Result  rpcResult    `json:"result"`
	Error   *rpcErrorObj `json:"error,omitempty"`
}

type rpcResult struct {
	Context rpcContext     `json:"context"`
	Value   *rpcAccountVal `json:"value"`
}

type rpcContext struct {
	Slot uint64 `json:"slot"`
}

type rpcAccountVal struct {
	Lamports   uint64    `json:"lamports"`
	Data       [2]string `json:"data"` // [base64Content, "base64"]
	Owner      string    `json:"owner"`
	Executable bool      `json:"executable"`
	RentEpoch  uint64    `json:"rentEpoch"`
}

type rpcErrorObj struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
