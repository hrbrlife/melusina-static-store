package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// cascade_gate.go — the apply-time chain gate that MIRRORS the deployed
// license-registry program's require_active_sidecar_cascade (attestation.rs).
// The controller must NOT accept a sidecar_identity component on the strength of
// the 3-PDA SidecarIdentityEntry alone: reseller/global/local/license revocation
// must be caught. Every PDA is derived LOCALLY from the pinned program/master/
// license; the on-chain account owner must equal the pinned program; the 8-byte
// Anchor account discriminator must match; status must be Active; and the
// artifact hash must bind Global (and Local, when Local carries a hash). A
// sidecar_cascade (keyless) component is gated on this cascade alone, and for it
// the Local hash is required, not optional.

// rawAccountReader is the raw getAccountInfo capability the cascade needs
// (data + owner). The production *storeRPCReader implements it; test mocks
// implement it too so the cascade is ALWAYS enforced (never skippable).
type rawAccountReader interface {
	fetchRawAccount(ctx context.Context, addrB58 string) (data []byte, owner string, err error)
}

// fetchRawAccount performs a getAccountInfo and returns both the account data and
// its owner program. A nil data with nil error means the account does not exist.
func (c *storeRPCReader) fetchRawAccount(ctx context.Context, addrB58 string) ([]byte, string, error) {
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
		"params": []any{addrB58, map[string]any{"encoding": "base64", "commitment": "confirmed"}},
	})
	if err != nil {
		return nil, "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.RPCClient.Endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.RPCClient.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", verify.ErrRPCUnreachable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("%w: read getAccountInfo response: %v", verify.ErrRPCUnreachable, err)
	}
	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("%w: getAccountInfo HTTP %d: %s", verify.ErrRPCUnreachable, resp.StatusCode, string(raw))
	}
	var parsed struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
		Result struct {
			Value *struct {
				Data  [2]string `json:"data"`
				Owner string    `json:"owner"`
			} `json:"value"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, "", fmt.Errorf("decode getAccountInfo: %w", err)
	}
	if parsed.Error != nil {
		return nil, "", fmt.Errorf("rpc error: %s", parsed.Error.Message)
	}
	if parsed.Result.Value == nil {
		return nil, "", nil // absent
	}
	if parsed.Result.Value.Data[1] != "base64" {
		return nil, "", fmt.Errorf("unexpected encoding %q", parsed.Result.Value.Data[1])
	}
	dec, err := base64.StdEncoding.DecodeString(parsed.Result.Value.Data[0])
	if err != nil {
		return nil, "", fmt.Errorf("base64 decode: %w", err)
	}
	return dec, parsed.Result.Value.Owner, nil
}

// accountDiscriminator is Anchor's account discriminator: sha256("account:"+Name)[:8].
func accountDiscriminator(name string) []byte {
	sum := sha256.Sum256([]byte("account:" + name))
	return sum[:8]
}

// borshCursor is a minimal sequential Borsh reader for the cascade layouts.
type borshCursor struct {
	b   []byte
	off int
	err error
}

func (c *borshCursor) fail(msg string) {
	if c.err == nil {
		c.err = errors.New(msg)
	}
}
func (c *borshCursor) need(n int) bool {
	if c.err != nil {
		return false
	}
	if c.off+n > len(c.b) {
		c.fail("cascade account truncated")
		return false
	}
	return true
}
func (c *borshCursor) skip(n int) {
	if c.need(n) {
		c.off += n
	}
}
func (c *borshCursor) u8() byte {
	if !c.need(1) {
		return 0
	}
	v := c.b[c.off]
	c.off++
	return v
}
func (c *borshCursor) u32() int {
	if !c.need(4) {
		return 0
	}
	v := int(c.b[c.off]) | int(c.b[c.off+1])<<8 | int(c.b[c.off+2])<<16 | int(c.b[c.off+3])<<24
	c.off += 4
	return v
}
func (c *borshCursor) skipU64()    { c.skip(8) }
func (c *borshCursor) skipPubkey() { c.skip(32) }

// skipOptionPubkey skips Borsh Option<Pubkey>.  The tag alone is not the
// whole field when the live license is Squads-custodied: tag=Some is followed
// by the 32-byte vault/multisig key.  Treat an unknown tag as malformed rather
// than risking a later field (such as status) being read at the wrong offset.
func (c *borshCursor) skipOptionPubkey() {
	switch c.u8() {
	case 0: // None
	case 1: // Some(pubkey)
		c.skipPubkey()
	default:
		c.fail("cascade option pubkey has invalid tag")
	}
}

// skipString skips a borsh string (u32 length prefix + bytes).
func (c *borshCursor) skipString() {
	_ = c.readString()
}

// skipVecStrings skips a borsh Vec<String>.
func (c *borshCursor) skipVecStrings() {
	_ = c.readVecStrings()
}

// readString reads a Borsh string without trusting its length prefix.  Cascade
// account data is chain-controlled input, so a malformed length must fail the
// gate rather than let a later field be interpreted at the wrong offset.
func (c *borshCursor) readString() string {
	n := c.u32()
	if c.err != nil {
		return ""
	}
	if n < 0 || n > len(c.b)-c.off {
		c.fail("cascade string length out of range")
		return ""
	}
	v := string(c.b[c.off : c.off+n])
	c.off += n
	return v
}

// readVecStrings reads a Borsh Vec<String>. Each element has at least its
// four-byte length prefix, which bounds the count before allocating. This keeps
// an adversarial on-chain blob from creating an unbounded allocation or loop.
func (c *borshCursor) readVecStrings() []string {
	n := c.u32()
	if c.err != nil {
		return nil
	}
	if n < 0 || n > (len(c.b)-c.off)/4 {
		c.fail("cascade string vector length out of range")
		return nil
	}
	values := make([]string, 0, n)
	for i := 0; i < n; i++ {
		values = append(values, c.readString())
	}
	return values
}

// readOptionHash reads a borsh Option<[32]byte>: 1-byte flag, then 32 bytes if 1.
func (c *borshCursor) readOptionHash() (has bool, hash [32]byte) {
	flag := c.u8()
	if flag == 1 {
		if c.need(32) {
			copy(hash[:], c.b[c.off:c.off+32])
			c.off += 32
		}
		return true, hash
	}
	return false, hash
}

// Refusal names of the sidecar approval cascade. They are the names the
// sidecars' own boot gate gives for the same facts (Melusina
// shared/melusina-attest/binhash, the Refusal* constants), so one revoked or
// foreign account is refused by one name wherever it is read: at promote, at
// serve, at this Store's own start, and at a sidecar's boot.
// root_store_boot_cascade_test.go compares each spelling with the committed
// binhash.go. A refusal reads "<name>:<Account>[.<field>]: <detail>".
var (
	// errCascadeAccountOwner: the account is not owned by the pinned
	// license-registry program.
	errCascadeAccountOwner = errors.New("cascade-account-owner")
	// errCascadeAccountDiscriminator: the account's first 8 bytes are not the
	// Anchor discriminator of the account the address is derived for.
	errCascadeAccountDiscriminator = errors.New("cascade-account-discriminator")
	// errCascadeAccountMalformed: the account does not decode in the program's
	// layout.
	errCascadeAccountMalformed = errors.New("cascade-account-malformed")
	// errCascadeNotActive: the account's status is not Active (Revoked, or a
	// RevokingCascadeInProgress approval).
	errCascadeNotActive = errors.New("cascade-not-active")
	// errCascadeBindingMismatch: the account names another estate, licence,
	// reseller or sidecar than the one its address was derived for.
	errCascadeBindingMismatch = errors.New("cascade-binding-mismatch")
	// errCascadeScopeMismatch: the Global SAN list names no single tier, or the
	// Local approval's scope is not that tier.
	errCascadeScopeMismatch = errors.New("cascade-scope-mismatch")
)

// cascadeRefusal spells one named cascade refusal: "<name>:<subject>: detail".
// subject is the Anchor account, or "<Account>.<field>" for a binding.
func cascadeRefusal(name error, subject, format string, args ...any) error {
	return fmt.Errorf("%w:%s: %s", name, subject, fmt.Sprintf(format, args...))
}

// requireDiscAndOwner checks the account owner, then the 8-byte discriminator,
// in the order the sidecar boot gate checks them: nothing is decoded from an
// account the pinned program did not write.
func requireDiscAndOwner(name string, data []byte, owner string) error {
	if pinned := licenseRegistryProgramID().Base58(); owner != pinned {
		return cascadeRefusal(errCascadeAccountOwner, name, "account owner %s != pinned program %s", owner, pinned)
	}
	if len(data) < 8 {
		return cascadeRefusal(errCascadeAccountDiscriminator, name, "account too short for discriminator")
	}
	if !bytes.Equal(data[:8], accountDiscriminator(name)) {
		return cascadeRefusal(errCascadeAccountDiscriminator, name, "wrong account discriminator")
	}
	return nil
}

// cascadeBind requires the pubkey an account names to be want, the key its
// address was derived from.
func cascadeBind(account, field string, got, want primitives.Pubkey, what, sidecarID, pdaB58 string) error {
	if got == want {
		return nil
	}
	return cascadeRefusal(errCascadeBindingMismatch, account+"."+field, "the account names %s, not %s %s, sidecar_id=%s, pda=%s", got.Base58(), what, want.Base58(), sidecarID, pdaB58)
}

// cascadeBindSidecar requires the sidecar id an approval names to be the one
// its address was derived from.
func cascadeBindSidecar(account, got, sidecarID, pdaB58 string) error {
	if got == sidecarID {
		return nil
	}
	return cascadeRefusal(errCascadeBindingMismatch, account+".sidecar_id", "the account names sidecar %q, not %q, pda=%s", got, sidecarID, pdaB58)
}

// cascadeNotActive spells a status refusal as the boot gate does.
func cascadeNotActive(account, status, sidecarID, pdaB58 string) error {
	return cascadeRefusal(errCascadeNotActive, account, "status %s, not Active, sidecar_id=%s, pda=%s", status, sidecarID, pdaB58)
}

// decodeApprovalStatus reads a sidecar approval's status byte as the program's
// ApprovalStatus (Active, Revoked, RevokingCascadeInProgress). Any other byte
// is a layout the program cannot have written, refused as malformed, as the
// boot gate's decoder refuses it.
func decodeApprovalStatus(account string, b byte) (verify.ApprovalStatus, error) {
	if b > byte(verify.ApprovalStatusRevokingCascadeInProgress) {
		return 0, cascadeRefusal(errCascadeAccountMalformed, account, "unknown ApprovalStatus byte: %d", b)
	}
	return verify.ApprovalStatus(b), nil
}

// licenseStatusName names a LicenseStatus byte (state/license.rs: Active,
// Revoked), as the boot gate names it.
func licenseStatusName(status byte) string {
	switch status {
	case 0:
		return "Active"
	case 1:
		return "Revoked"
	default:
		return fmt.Sprintf("Unknown(%d)", status)
	}
}

// Sidecar scopes are part of the on-chain authority contract. A Global
// approval names its intended plane through SANs, while a Local approval names
// the plane through this numeric enum. A host controller must never infer
// host-tier authority merely because both approvals are Active.
const (
	sidecarScopeHost byte = iota
	sidecarScopeHypervisor
	sidecarScopeLocal
	sidecarScopeRemote
)

// sidecarSANTier maps one canonical GlobalSidecarApproval SAN to its local
// scope enum. It mirrors SidecarScope::from_san() in the deployed registry:
// DNS names are case-insensitive, while the canonical sidecar suffix and a
// non-empty prefix remain mandatory.
func sidecarSANTier(san string) (byte, error) {
	canonical := strings.ToLower(san)
	for _, candidate := range []struct {
		suffix string
		scope  byte
	}{
		{".sidecar.host.shared", sidecarScopeHost},
		{".sidecar.host", sidecarScopeHost},
		{".sidecar.hypervisor.shared", sidecarScopeHypervisor},
		{".sidecar.hypervisor", sidecarScopeHypervisor},
		{".sidecar.local.shared", sidecarScopeLocal},
		{".sidecar.local", sidecarScopeLocal},
		{".sidecar.remote.shared", sidecarScopeRemote},
		{".sidecar.remote", sidecarScopeRemote},
	} {
		if strings.HasSuffix(canonical, candidate.suffix) && len(canonical) > len(candidate.suffix) {
			return candidate.scope, nil
		}
	}
	return 0, fmt.Errorf("unrecognized sidecar SAN %q", san)
}

// uniformGlobalSANTier rejects an empty, unknown, or cross-plane SAN vector.
// A cross-plane Global approval is ambiguous for a component that will be
// applied by one concrete controller plane, so it is not an authorization.
func uniformGlobalSANTier(sans []string) (byte, error) {
	if len(sans) == 0 {
		return 0, errors.New("GlobalSidecarApproval SAN list is empty")
	}
	var tier byte
	for i, san := range sans {
		got, err := sidecarSANTier(san)
		if err != nil {
			return 0, fmt.Errorf("GlobalSidecarApproval SAN[%d]: %w", i, err)
		}
		if i == 0 {
			tier = got
			continue
		}
		if got != tier {
			return 0, fmt.Errorf("GlobalSidecarApproval SANs span multiple scope tiers (%d and %d)", tier, got)
		}
	}
	return tier, nil
}

// requireGlobalSANTierMatchesLocalScope requires the Local approval's scope to
// be the Global SAN tier, worded as the sidecar boot gate words it. An unknown
// scope byte names no tier, so it never matches.
func requireGlobalSANTierMatchesLocalScope(globalTier, localScope byte) error {
	if localScope > sidecarScopeRemote || globalTier != localScope {
		return fmt.Errorf("the Local scope %s is not the Global SAN tier %s", verify.SidecarScope(localScope), verify.SidecarScope(globalTier))
	}
	return nil
}

// verifyFiveFactCascade mirrors require_active_sidecar_cascade: License Active,
// GlobalSidecarApproval Active + binary_hash==artifact, LocalSidecarApproval
// Active (+ optional hash==artifact; required for a keyless view), ResellerSidecarApproval Active, and
// ResellerEntry Active. All PDAs derived locally; owner+discriminator checked.
func (s *publishService) verifyFiveFactCascade(ctx context.Context, c componentReleaseChainView, artifact [32]byte) error {
	rr, ok := s.cr.(rawAccountReader)
	if !ok {
		return errors.New("chain reader does not support the raw cascade reads required by require_active_sidecar_cascade")
	}
	return checkSidecarCascade(ctx, rr, c, artifact)
}

// checkSidecarCascade is the one five-fact cascade comparison in this
// repository. Promote and serve run it for a component's sidecar
// (verifyFiveFactCascade); this Store runs it for its own sidecar id and
// licence at every start (verifyRootStoreBootCascade). Each account is read at
// the address the Store derives, must be owned by the pinned program and carry
// its Anchor discriminator, must name what its address was derived from, and
// must be Active; the artifact must equal the Global pin and a Some Local pin.
// The order and the refusal names are those of the sidecar boot gate
// (binhash checkApprovals).
func checkSidecarCascade(ctx context.Context, rr rawAccountReader, c componentReleaseChainView, artifact [32]byte) error {
	sidecarID := c.sidecarID
	licenseMint := c.licenseMint
	pinMaster := c.keyless || c.pinMaster
	if pinMaster && c.masterMint == (primitives.Pubkey{}) {
		return errors.New("cascade master mint pin is the zero key; the master mint comes from the signed component or the enrolled estate profile, never a default")
	}

	// 1. LicenseEntry Active — and extract reseller + master mints from it.
	licPDA, _, err := primitives.DeriveLicense(licenseMint, licenseRegistryProgramID())
	if err != nil {
		return fmt.Errorf("derive LicenseEntry PDA: %w", err)
	}
	licData, licOwner, err := rr.fetchRawAccount(ctx, licPDA.Base58())
	if err != nil {
		return fmt.Errorf("fetch LicenseEntry: %w", err)
	}
	if licData == nil {
		return errors.New("LicenseEntry absent")
	}
	if err := requireDiscAndOwner("LicenseEntry", licData, licOwner); err != nil {
		return err
	}
	licence, err := decodeLicenseEntryHead(licData)
	if err != nil {
		return cascadeRefusal(errCascadeAccountMalformed, "LicenseEntry", "%v", err)
	}
	named, reseller, master, licStatus := licence.LicenseNFTMint, licence.ResellerNFTMint, licence.MasterNFTMint, licence.Status
	if licStatus != 0 {
		return cascadeNotActive("LicenseEntry", licenseStatusName(licStatus), sidecarID, licPDA.Base58())
	}
	if err := cascadeBind("LicenseEntry", "license_nft_mint", named, licenseMint, "the license NFT", sidecarID, licPDA.Base58()); err != nil {
		return err
	}
	if pinMaster && master != c.masterMint {
		if c.keyless {
			return fmt.Errorf("%w:LicenseEntry.master_nft_mint: %w: LicenseEntry names %s, the component %s", errCascadeBindingMismatch, errKeylessSidecarMasterMismatch, master.Base58(), c.masterMint.Base58())
		}
		if err := cascadeBind("LicenseEntry", "master_nft_mint", master, c.masterMint, "the estate's master mint", sidecarID, licPDA.Base58()); err != nil {
			return err
		}
	}

	// 2. GlobalSidecarApproval Active + binary_hash == artifact.
	globalPDA, _, err := primitives.DeriveGlobalSidecar(master, sidecarID, licenseRegistryProgramID())
	if err != nil {
		return fmt.Errorf("derive GlobalSidecarApproval PDA: %w", err)
	}
	gData, gOwner, err := rr.fetchRawAccount(ctx, globalPDA.Base58())
	if err != nil {
		return fmt.Errorf("fetch GlobalSidecarApproval: %w", err)
	}
	if gData == nil {
		return errors.New("GlobalSidecarApproval absent")
	}
	if err := requireDiscAndOwner("GlobalSidecarApproval", gData, gOwner); err != nil {
		return err
	}
	gc := &borshCursor{b: gData, off: 8}
	globalSidecarID := gc.readString() // sidecar_id
	var globalHash [32]byte
	if gc.need(32) {
		copy(globalHash[:], gc.b[gc.off:gc.off+32])
		gc.off += 32
	}
	gc.skipString()                   // version
	globalSANs := gc.readVecStrings() // san_list
	gc.skipU64()                      // required_permissions
	gc.skipPubkey()                   // author
	var globalMaster primitives.Pubkey
	if gc.need(32) {
		copy(globalMaster[:], gc.b[gc.off:gc.off+32])
		gc.off += 32
	}
	gc.skipPubkey() // approved_by
	gStatus := gc.u8()
	if gc.err != nil {
		return cascadeRefusal(errCascadeAccountMalformed, "GlobalSidecarApproval", "parse GlobalSidecarApproval: %v", gc.err)
	}
	globalStatus, err := decodeApprovalStatus("GlobalSidecarApproval", gStatus)
	if err != nil {
		return err
	}
	if err := cascadeBindSidecar("GlobalSidecarApproval", globalSidecarID, sidecarID, globalPDA.Base58()); err != nil {
		return err
	}
	if err := cascadeBind("GlobalSidecarApproval", "master_nft_mint", globalMaster, master, "the estate's master mint", sidecarID, globalPDA.Base58()); err != nil {
		return err
	}
	globalSANTier, err := uniformGlobalSANTier(globalSANs)
	if err != nil {
		return cascadeRefusal(errCascadeScopeMismatch, "GlobalSidecarApproval.san_list", "%v", err)
	}
	if globalStatus != verify.ApprovalStatusActive {
		return cascadeNotActive("GlobalSidecarApproval", globalStatus.String(), sidecarID, globalPDA.Base58())
	}
	if globalHash != artifact {
		return fmt.Errorf("GlobalSidecarApproval binary_hash %x != served artifact %x", globalHash[:], artifact[:])
	}

	// 3. LocalSidecarApproval Active (+ optional hash == artifact).
	localPDA, _, err := primitives.DeriveLocalSidecar(licenseMint, sidecarID, licenseRegistryProgramID())
	if err != nil {
		return fmt.Errorf("derive LocalSidecarApproval PDA: %w", err)
	}
	lData, lOwner, err := rr.fetchRawAccount(ctx, localPDA.Base58())
	if err != nil {
		return fmt.Errorf("fetch LocalSidecarApproval: %w", err)
	}
	if lData == nil {
		return errors.New("LocalSidecarApproval absent")
	}
	if err := requireDiscAndOwner("LocalSidecarApproval", lData, lOwner); err != nil {
		return err
	}
	lcl := &borshCursor{b: lData, off: 8}
	localSidecarID := lcl.readString() // sidecar_id
	var localLicense primitives.Pubkey
	if lcl.need(32) {
		copy(localLicense[:], lcl.b[lcl.off:lcl.off+32])
		lcl.off += 32
	}
	hasHash, localHash := lcl.readOptionHash()
	localScope := lcl.u8() // scope
	lcl.skipPubkey()       // approved_by
	lStatus := lcl.u8()
	if lcl.err != nil {
		return cascadeRefusal(errCascadeAccountMalformed, "LocalSidecarApproval", "parse LocalSidecarApproval: %v", lcl.err)
	}
	localStatus, err := decodeApprovalStatus("LocalSidecarApproval", lStatus)
	if err != nil {
		return err
	}
	if err := cascadeBindSidecar("LocalSidecarApproval", localSidecarID, sidecarID, localPDA.Base58()); err != nil {
		return err
	}
	if err := cascadeBind("LocalSidecarApproval", "license_nft_mint", localLicense, licenseMint, "the license NFT", sidecarID, localPDA.Base58()); err != nil {
		return err
	}
	if err := requireGlobalSANTierMatchesLocalScope(globalSANTier, localScope); err != nil {
		return cascadeRefusal(errCascadeScopeMismatch, "LocalSidecarApproval.scope", "%v, sidecar_id=%s, pda=%s", err, sidecarID, localPDA.Base58())
	}
	if localStatus != verify.ApprovalStatusActive {
		return cascadeNotActive("LocalSidecarApproval", localStatus.String(), sidecarID, localPDA.Base58())
	}
	if c.keyless && !hasHash {
		return fmt.Errorf("%w (served artifact %x)", errKeylessSidecarLocalPinAbsent, artifact[:])
	}
	if hasHash && localHash != artifact {
		return fmt.Errorf("LocalSidecarApproval optional hash %x != served artifact %x", localHash[:], artifact[:])
	}

	// 4. ResellerSidecarApproval Active.
	resApprovalPDA, _, err := primitives.DeriveResellerSidecar(reseller, sidecarID, licenseRegistryProgramID())
	if err != nil {
		return fmt.Errorf("derive ResellerSidecarApproval PDA: %w", err)
	}
	raData, raOwner, err := rr.fetchRawAccount(ctx, resApprovalPDA.Base58())
	if err != nil {
		return fmt.Errorf("fetch ResellerSidecarApproval: %w", err)
	}
	if raData == nil {
		return errors.New("ResellerSidecarApproval absent")
	}
	if err := requireDiscAndOwner("ResellerSidecarApproval", raData, raOwner); err != nil {
		return err
	}
	rac := &borshCursor{b: raData, off: 8}
	resellerSidecarID := rac.readString() // sidecar_id
	var approvalReseller primitives.Pubkey
	if rac.need(32) {
		copy(approvalReseller[:], rac.b[rac.off:rac.off+32])
		rac.off += 32
	}
	rac.skipPubkey() // approved_by
	raStatus := rac.u8()
	if rac.err != nil {
		return cascadeRefusal(errCascadeAccountMalformed, "ResellerSidecarApproval", "parse ResellerSidecarApproval: %v", rac.err)
	}
	resellerApprovalStatus, err := decodeApprovalStatus("ResellerSidecarApproval", raStatus)
	if err != nil {
		return err
	}
	if err := cascadeBindSidecar("ResellerSidecarApproval", resellerSidecarID, sidecarID, resApprovalPDA.Base58()); err != nil {
		return err
	}
	if err := cascadeBind("ResellerSidecarApproval", "reseller_nft_mint", approvalReseller, reseller, "the license's reseller", sidecarID, resApprovalPDA.Base58()); err != nil {
		return err
	}
	if resellerApprovalStatus != verify.ApprovalStatusActive {
		return cascadeNotActive("ResellerSidecarApproval", resellerApprovalStatus.String(), sidecarID, resApprovalPDA.Base58())
	}

	// 5. ResellerEntry Active (PDA seeds ["reseller", reseller_mint]).
	parentPDA, _, err := primitives.FindProgramAddress([][]byte{[]byte("reseller"), reseller[:]}, licenseRegistryProgramID(), nil)
	if err != nil {
		return fmt.Errorf("derive ResellerEntry PDA: %w", err)
	}
	reData, reOwner, err := rr.fetchRawAccount(ctx, parentPDA.Base58())
	if err != nil {
		return fmt.Errorf("fetch ResellerEntry: %w", err)
	}
	if reData == nil {
		return errors.New("ResellerEntry absent")
	}
	if err := requireDiscAndOwner("ResellerEntry", reData, reOwner); err != nil {
		return err
	}
	// The status byte follows two Options whose payloads are on chain whenever
	// they are Some: parent_reseller (Option<Pubkey>, Some for every
	// sub-reseller) and category (Option<String>, Some when the estate profile
	// names a reseller category). Decode with the vendored reader the tenant
	// update controller uses (cmd/melusina-update-controller/chaingate.go), so the
	// Store and the tenant cannot read the same account differently. It walks
	// every preceding field and refuses an Option tag other than 0 or 1,
	// truncation, and a status byte that is neither Active nor Revoked.
	reStatus, err := verify.ReadResellerEntryStatus(reData)
	if err != nil {
		return cascadeRefusal(errCascadeAccountMalformed, "ResellerEntry", "parse ResellerEntry: %v", err)
	}
	var entryReseller primitives.Pubkey
	copy(entryReseller[:], reData[8:8+32]) // ReadResellerEntryStatus walked past it
	if err := cascadeBind("ResellerEntry", "reseller_nft_mint", entryReseller, reseller, "the license's reseller", sidecarID, parentPDA.Base58()); err != nil {
		return err
	}
	if reStatus != verify.ResellerStatusActive {
		return cascadeNotActive("ResellerEntry", reStatus.String(), sidecarID, parentPDA.Base58())
	}

	return nil
}

// licenseEntryHead is the part of a LicenseEntry (state/license.rs) every
// licence gate in this Store reads: the three mints and the status byte
// (LicenseStatus: Active=0, Revoked=1).
type licenseEntryHead struct {
	LicenseNFTMint  primitives.Pubkey
	ResellerNFTMint primitives.Pubkey
	MasterNFTMint   primitives.Pubkey
	Status          byte
}

// decodeLicenseEntryHead is the LicenseEntry walk the approval cascade
// (checkSidecarCascade, and so the Store's boot cascade) and the own-licence
// rule (verifyStoreOwnLicence) share, so the Store's own licence reads the
// same at start and at every gate. The caller has checked the account's owner
// and discriminator. It walks every field before status as the program lays it
// out, both Squads Options with their payloads when they are Some, so status
// is read where the program wrote it; truncation, a string longer than the
// account and an Option tag other than 0 or 1 are errors.
func decodeLicenseEntryHead(data []byte) (licenseEntryHead, error) {
	var head licenseEntryHead
	// layout: disc(8) license(32) reseller(32) master(32) ... status(after 2 strings)
	if len(data) < 8+96 {
		return licenseEntryHead{}, errors.New("LicenseEntry too short")
	}
	copy(head.LicenseNFTMint[:], data[8:8+32])
	copy(head.ResellerNFTMint[:], data[8+32:8+64])
	copy(head.MasterNFTMint[:], data[8+64:8+96])
	lc := &borshCursor{b: data, off: 8}
	lc.skipPubkey()       // license
	lc.skipPubkey()       // reseller
	lc.skipPubkey()       // master
	lc.skipU64()          // edition_number
	lc.skipString()       // homeserver_domain
	lc.skipString()       // install_url
	lc.skip(32)           // tls_cert_fingerprint
	lc.skip(3)            // threshold + keyholder counters
	lc.skipPubkey()       // owner
	lc.skip(1)            // custody_mode
	lc.skipOptionPubkey() // squads_vault Option<Pubkey>
	lc.skipOptionPubkey() // squads_multisig Option<Pubkey>
	head.Status = lc.u8()
	if lc.err != nil {
		return licenseEntryHead{}, fmt.Errorf("parse LicenseEntry: %v", lc.err)
	}
	return head, nil
}

// componentReleaseChainView is the minimal view of a sidecar the cascade needs.
type componentReleaseChainView struct {
	sidecarID   string
	licenseMint primitives.Pubkey
	// keyless is set for a sidecar_cascade component. It changes two things,
	// both stricter: the LocalSidecarApproval must pin the artifact (Some ==
	// artifact; None is refused with errKeylessSidecarLocalPinAbsent), and the
	// LicenseEntry's master must be masterMint, the one the signed component
	// names. A key-bearing component keeps the identity's binary_hash as its
	// second pin, so for it the Local pin stays optional.
	keyless bool
	// pinMaster requires the LicenseEntry to name masterMint as its
	// master_nft_mint (cascade-binding-mismatch:LicenseEntry.master_nft_mint)
	// without the keyless Local-pin rule. This Store's own boot cascade sets it
	// with the enrolled profile's anchors.masterMint, the pin the sidecar boot
	// gate takes from its estate anchors. A keyless view implies it.
	pinMaster  bool
	masterMint primitives.Pubkey
}

// errKeylessSidecarLocalPinAbsent: a keyless sidecar's LocalSidecarApproval has
// binary_hash None. With no SidecarIdentityEntry, the Local pin is the second
// pin on the served bytes, so None is not "inherit the Global pin" here.
var errKeylessSidecarLocalPinAbsent = errors.New("keyless-sidecar-local-pin-absent: a keyless (sidecar_cascade) sidecar's LocalSidecarApproval must pin the served artifact, and its binary_hash is None")

// errKeylessSidecarMasterMismatch: a keyless sidecar names a masterNftMint that
// is not the one its LicenseEntry names.
var errKeylessSidecarMasterMismatch = errors.New("keyless-sidecar-master-mismatch: the component's masterNftMint is not the LicenseEntry's master_nft_mint")
