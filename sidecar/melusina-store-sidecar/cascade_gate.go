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

// requireDiscAndOwner checks the 8-byte discriminator and the account owner.
func requireDiscAndOwner(name string, data []byte, owner string) error {
	if len(data) < 8 {
		return fmt.Errorf("%s: account too short for discriminator", name)
	}
	if !bytes.Equal(data[:8], accountDiscriminator(name)) {
		return fmt.Errorf("%s: wrong account discriminator", name)
	}
	if pinned := licenseRegistryProgramID().Base58(); owner != pinned {
		return fmt.Errorf("%s: account owner %s != pinned program %s", name, owner, pinned)
	}
	return nil
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

func requireGlobalSANTierMatchesLocalScope(globalTier, localScope byte) error {
	if localScope > sidecarScopeRemote {
		return fmt.Errorf("LocalSidecarApproval scope %d is unknown", localScope)
	}
	if globalTier != localScope {
		return fmt.Errorf("GlobalSidecarApproval SAN tier %d != LocalSidecarApproval scope %d", globalTier, localScope)
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
	sidecarID := c.sidecarID
	licenseMint := c.licenseMint

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
	// layout: disc(8) license(32) reseller(32) master(32) ... status(after 2 strings)
	if len(licData) < 8+96 {
		return errors.New("LicenseEntry too short")
	}
	var reseller, master primitives.Pubkey
	copy(reseller[:], licData[8+32:8+64])
	copy(master[:], licData[8+64:8+96])
	if c.keyless && master != c.masterMint {
		return fmt.Errorf("%w: LicenseEntry names %s, the component %s", errKeylessSidecarMasterMismatch, master.Base58(), c.masterMint.Base58())
	}
	lc := &borshCursor{b: licData, off: 8}
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
	licStatus := lc.u8()
	if lc.err != nil {
		return fmt.Errorf("parse LicenseEntry: %w", lc.err)
	}
	if licStatus != 0 {
		return fmt.Errorf("LicenseEntry status %d not Active", licStatus)
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
	gc.skipString() // sidecar_id
	var globalHash [32]byte
	if gc.need(32) {
		copy(globalHash[:], gc.b[gc.off:gc.off+32])
		gc.off += 32
	}
	gc.skipString()                   // version
	globalSANs := gc.readVecStrings() // san_list
	gc.skipU64()                      // required_permissions
	gc.skipPubkey()                   // author
	gc.skipPubkey()                   // master
	gc.skipPubkey()                   // approved_by
	gStatus := gc.u8()
	if gc.err != nil {
		return fmt.Errorf("parse GlobalSidecarApproval: %w", gc.err)
	}
	globalSANTier, err := uniformGlobalSANTier(globalSANs)
	if err != nil {
		return err
	}
	if gStatus != 0 {
		return fmt.Errorf("GlobalSidecarApproval status %d not Active", gStatus)
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
	lcl.skipString() // sidecar_id
	lcl.skipPubkey() // license
	hasHash, localHash := lcl.readOptionHash()
	localScope := lcl.u8() // scope
	lcl.skipPubkey()       // approved_by
	lStatus := lcl.u8()
	if lcl.err != nil {
		return fmt.Errorf("parse LocalSidecarApproval: %w", lcl.err)
	}
	if err := requireGlobalSANTierMatchesLocalScope(globalSANTier, localScope); err != nil {
		return err
	}
	if lStatus != 0 {
		return fmt.Errorf("LocalSidecarApproval status %d not Active", lStatus)
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
	rac.skipString() // sidecar_id
	rac.skipPubkey() // reseller
	rac.skipPubkey() // approved_by
	raStatus := rac.u8()
	if rac.err != nil {
		return fmt.Errorf("parse ResellerSidecarApproval: %w", rac.err)
	}
	if raStatus != 0 {
		return fmt.Errorf("ResellerSidecarApproval status %d not Active", raStatus)
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
		return fmt.Errorf("parse ResellerEntry: %w", err)
	}
	if reStatus != verify.ResellerStatusActive {
		return fmt.Errorf("ResellerEntry status %d (%s) not Active", uint8(reStatus), reStatus)
	}

	return nil
}

// componentReleaseChainView is the minimal view of a component the cascade needs.
type componentReleaseChainView struct {
	sidecarID   string
	licenseMint primitives.Pubkey
	// keyless is set for a sidecar_cascade component. It changes two things,
	// both stricter: the LocalSidecarApproval must pin the artifact (Some ==
	// artifact; None is refused with errKeylessSidecarLocalPinAbsent), and the
	// LicenseEntry's master must be masterMint, the one the signed component
	// names. A key-bearing component keeps the identity's binary_hash as its
	// second pin, so for it the Local pin stays optional.
	keyless    bool
	masterMint primitives.Pubkey
}

// errKeylessSidecarLocalPinAbsent: a keyless sidecar's LocalSidecarApproval has
// binary_hash None. With no SidecarIdentityEntry, the Local pin is the second
// pin on the served bytes, so None is not "inherit the Global pin" here.
var errKeylessSidecarLocalPinAbsent = errors.New("keyless-sidecar-local-pin-absent: a keyless (sidecar_cascade) sidecar's LocalSidecarApproval must pin the served artifact, and its binary_hash is None")

// errKeylessSidecarMasterMismatch: a keyless sidecar names a masterNftMint that
// is not the one its LicenseEntry names.
var errKeylessSidecarMasterMismatch = errors.New("keyless-sidecar-master-mismatch: the component's masterNftMint is not the LicenseEntry's master_nft_mint")
