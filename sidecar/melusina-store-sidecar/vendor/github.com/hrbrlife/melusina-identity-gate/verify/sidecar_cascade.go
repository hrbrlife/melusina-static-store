package verify

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

// The sidecar approval cascade: the five accounts the license-registry
// program's require_active_sidecar_cascade (instructions/attestation.rs) and
// handler_verify_local_sidecar (instructions/sidecar_approval.rs) require, and
// the Store's verifyFiveFactCascade mirrors. The decoders below read every
// field up to and including status, in the order the program writes them
// (state/license.rs, state/sidecar_approval.rs, state/reseller.rs). Like every
// reader in this package they start after the 8-byte Anchor discriminator and
// do not interpret it: a caller that authorizes from an account checks its
// owner program and AnchorAccountDiscriminator first.

// Anchor account names of the sidecar approval cascade. An account's
// discriminator is AnchorAccountDiscriminator(name).
const (
	AccountLicenseEntry            = "LicenseEntry"
	AccountGlobalSidecarApproval   = "GlobalSidecarApproval"
	AccountLocalSidecarApproval    = "LocalSidecarApproval"
	AccountResellerSidecarApproval = "ResellerSidecarApproval"
	AccountResellerEntry           = "ResellerEntry"
)

// AnchorAccountDiscriminator is the first 8 bytes of every account an Anchor
// program writes for the struct named name: sha256("account:" + name)[:8].
func AnchorAccountDiscriminator(name string) [AccountDiscriminatorLen]byte {
	sum := sha256.Sum256([]byte("account:" + name))
	var disc [AccountDiscriminatorLen]byte
	copy(disc[:], sum[:AccountDiscriminatorLen])
	return disc
}

// SidecarScope mirrors the Anchor enum SidecarScope (state/sidecar_approval.rs):
// the placement tier a LocalSidecarApproval declares, which the program
// requires to equal the tier of the Global approval's SAN list (B13).
type SidecarScope uint8

const (
	SidecarScopeHost       SidecarScope = 0
	SidecarScopeHypervisor SidecarScope = 1
	SidecarScopeLocal      SidecarScope = 2
	SidecarScopeRemote     SidecarScope = 3
)

func (s SidecarScope) String() string {
	switch s {
	case SidecarScopeHost:
		return "Host"
	case SidecarScopeHypervisor:
		return "Hypervisor"
	case SidecarScopeLocal:
		return "Local"
	case SidecarScopeRemote:
		return "Remote"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(s))
	}
}

// SidecarScopeFromSAN is SidecarScope::from_san: the tier of one
// `<name>.sidecar.<host|hypervisor|local|remote>[.shared]` SAN, compared after
// ASCII lowercasing (Rust to_ascii_lowercase, not Unicode folding), with a
// non-empty leading name. Any other name has no tier.
func SidecarScopeFromSAN(san string) (SidecarScope, bool) {
	lower := asciiLower(san)
	trimmed := strings.TrimSuffix(lower, ".shared")
	for _, tier := range []struct {
		suffix string
		scope  SidecarScope
	}{
		{".sidecar.host", SidecarScopeHost},
		{".sidecar.hypervisor", SidecarScopeHypervisor},
		{".sidecar.local", SidecarScopeLocal},
		{".sidecar.remote", SidecarScopeRemote},
	} {
		if stripped, ok := strings.CutSuffix(trimmed, tier.suffix); ok && stripped != "" {
			return tier.scope, true
		}
	}
	return 0, false
}

// SidecarScopeFromSANList is SidecarScope::from_san_list: the one tier every
// SAN names. An empty list, a SAN without a tier, or SANs of two tiers has
// none.
func SidecarScopeFromSANList(sans []string) (SidecarScope, bool) {
	if len(sans) == 0 {
		return 0, false
	}
	want, ok := SidecarScopeFromSAN(sans[0])
	if !ok {
		return 0, false
	}
	for _, san := range sans[1:] {
		if got, ok := SidecarScopeFromSAN(san); !ok || got != want {
			return 0, false
		}
	}
	return want, true
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// GlobalSidecarApproval is the Foundation-level approval
// ["global_sidecar", master_nft_mint, sidecar_id], decoded through status.
type GlobalSidecarApproval struct {
	SidecarID           string
	BinaryHash          [32]byte
	Version             string
	SANList             []string
	RequiredPermissions uint64
	Author              Pubkey
	MasterNftMint       Pubkey
	ApprovedBy          Pubkey
	Status              ApprovalStatus
}

// DecodeGlobalSidecarApproval walks a GlobalSidecarApproval account:
//
//	discriminator | sidecar_id (String) | binary_hash ([u8;32])
//	  | version (String) | san_list (Vec<String>)
//	  | required_permissions (u64) | author (Pubkey)
//	  | master_nft_mint (Pubkey) | approved_by (Pubkey)
//	  | status (u8) | ...
func DecodeGlobalSidecarApproval(data []byte) (GlobalSidecarApproval, error) {
	var a GlobalSidecarApproval
	r := borshReader{data: data, offset: AccountDiscriminatorLen, account: "global_sidecar"}
	a.SidecarID = r.string("sidecar_id")
	a.BinaryHash = r.bytes32("binary_hash")
	a.Version = r.string("version")
	a.SANList = r.stringVec("san_list")
	a.RequiredPermissions = r.u64("required_permissions")
	a.Author = r.bytes32("author")
	a.MasterNftMint = r.bytes32("MasterNftMint")
	a.ApprovedBy = r.bytes32("approved_by")
	if r.err != nil {
		return a, r.err
	}
	var err error
	a.Status, err = ReadStatusByte(data, r.offset)
	return a, err
}

// LocalSidecarApproval is the install-level approval
// ["local_sidecar", license_nft_mint, sidecar_id], decoded through status.
type LocalSidecarApproval struct {
	SidecarID      string
	LicenseNFTMint Pubkey
	// HasBinaryHash is true when the install pinned a build (Some); None
	// inherits the Global pin.
	HasBinaryHash bool
	BinaryHash    [32]byte
	// Scope is the byte as written, not checked against the enum here (the
	// status readers never did); a caller compares it with the Global SAN
	// tier, which is always a known SidecarScope, so an unknown byte never
	// matches.
	Scope      SidecarScope
	ApprovedBy Pubkey
	Status     ApprovalStatus
}

// DecodeLocalSidecarApproval walks a LocalSidecarApproval account:
//
//	discriminator | sidecar_id (String) | license_nft_mint (Pubkey)
//	  | binary_hash (Option<[u8;32]>) | scope (SidecarScope u8)
//	  | approved_by (Pubkey) | status (u8) | ...
func DecodeLocalSidecarApproval(data []byte) (LocalSidecarApproval, error) {
	var a LocalSidecarApproval
	r := borshReader{data: data, offset: AccountDiscriminatorLen, account: "local_sidecar"}
	a.SidecarID = r.string("sidecar_id")
	a.LicenseNFTMint = r.bytes32("license_nft_mint")
	if r.optionTag("binary_hash") {
		a.HasBinaryHash = true
		a.BinaryHash = r.bytes32("binary_hash")
	}
	a.Scope = SidecarScope(r.u8("scope"))
	a.ApprovedBy = r.bytes32("approved_by")
	if r.err != nil {
		return a, r.err
	}
	var err error
	a.Status, err = ReadStatusByte(data, r.offset)
	return a, err
}

// ResellerSidecarApproval is the reseller-level approval
// ["reseller_sidecar", reseller_nft_mint, sidecar_id], decoded through status.
type ResellerSidecarApproval struct {
	SidecarID       string
	ResellerNFTMint Pubkey
	ApprovedBy      Pubkey
	Status          ApprovalStatus
}

// DecodeResellerSidecarApproval walks a ResellerSidecarApproval account:
//
//	discriminator | sidecar_id (String) | reseller_nft_mint (Pubkey)
//	  | approved_by (Pubkey) | status (u8) | ...
func DecodeResellerSidecarApproval(data []byte) (ResellerSidecarApproval, error) {
	var a ResellerSidecarApproval
	r := borshReader{data: data, offset: AccountDiscriminatorLen, account: "reseller_sidecar"}
	a.SidecarID = r.string("sidecar_id")
	a.ResellerNFTMint = r.bytes32("reseller_nft_mint")
	a.ApprovedBy = r.bytes32("approved_by")
	if r.err != nil {
		return a, r.err
	}
	var err error
	a.Status, err = ReadStatusByte(data, r.offset)
	return a, err
}

// ResellerEntry is the reseller entity ["reseller", reseller_nft_mint],
// decoded through status.
type ResellerEntry struct {
	ResellerNFTMint    Pubkey
	MasterNftMint      Pubkey
	EditionNumber      uint64
	Owner              Pubkey
	Name               string
	Territory          string
	IssuanceLimit      uint32
	LicensesIssued     uint32
	HasParentReseller  bool
	ParentReseller     Pubkey
	TotalSubResellers  uint32
	ActiveSubResellers uint32
	HasCategory        bool
	Category           string
	Status             ResellerStatus
}

// DecodeResellerEntry walks a ResellerEntry account (state/reseller.rs):
//
//	discriminator | reseller_nft_mint | master_nft_mint | edition_number
//	  | owner | name (String) | territory (String) | issuance_limit (u32)
//	  | licenses_issued (u32) | parent_reseller (Option<Pubkey>)
//	  | total_sub_resellers (u32) | active_sub_resellers (u32)
//	  | category (Option<String>) | status (u8) | ...
//
// Both Options are read as the program writes them: a Some parent_reseller is
// followed by its 32-byte key and a Some category by its String, so status is
// found after them, never at the offset a None would put it.
func DecodeResellerEntry(data []byte) (ResellerEntry, error) {
	var e ResellerEntry
	r := borshReader{data: data, offset: AccountDiscriminatorLen, account: "reseller"}
	e.ResellerNFTMint = r.bytes32("reseller_nft_mint")
	e.MasterNftMint = r.bytes32("master_nft_mint")
	e.EditionNumber = r.u64("edition_number")
	e.Owner = r.bytes32("owner")
	e.Name = r.string("name")
	e.Territory = r.string("territory")
	e.IssuanceLimit = r.u32("issuance_limit")
	e.LicensesIssued = r.u32("licenses_issued")
	if r.optionTag("parent_reseller") {
		e.HasParentReseller = true
		e.ParentReseller = r.bytes32("parent_reseller")
	}
	e.TotalSubResellers = r.u32("total_sub_resellers")
	e.ActiveSubResellers = r.u32("active_sub_resellers")
	if r.optionTag("category") {
		e.HasCategory = true
		e.Category = r.string("category")
	}
	if r.err != nil {
		return e, r.err
	}
	if r.offset >= len(data) {
		return e, errors.New("reseller: buffer too short for status")
	}
	e.Status = ResellerStatus(data[r.offset])
	if e.Status != ResellerStatusActive && e.Status != ResellerStatusRevoked {
		return e, fmt.Errorf("reseller: unknown ResellerStatus byte: %d", data[r.offset])
	}
	return e, nil
}

// borshReader reads Borsh fields in order and keeps the first error, named
// "<account>: <field>: <cause>" as the other readers in this package name
// theirs. Every length is checked against the bytes that remain before
// anything is read or allocated: account data is chain input.
type borshReader struct {
	data    []byte
	offset  int
	account string
	err     error
}

func (r *borshReader) fail(field string, err error) {
	if r.err == nil {
		r.err = fmt.Errorf("%s: %s: %w", r.account, field, err)
	}
}

func (r *borshReader) take(field string, n int) []byte {
	if r.err != nil {
		return nil
	}
	next, err := skip(r.data, r.offset, n)
	if err != nil {
		r.fail(field, err)
		return nil
	}
	out := r.data[r.offset:next]
	r.offset = next
	return out
}

func (r *borshReader) u8(field string) uint8 {
	b := r.take(field, 1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *borshReader) u32(field string) uint32 {
	b := r.take(field, 4)
	if b == nil {
		return 0
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func (r *borshReader) u64(field string) uint64 {
	b := r.take(field, 8)
	if b == nil {
		return 0
	}
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func (r *borshReader) bytes32(field string) [32]byte {
	var out [32]byte
	if b := r.take(field, 32); b != nil {
		copy(out[:], b)
	}
	return out
}

func (r *borshReader) string(field string) string {
	if r.err != nil {
		return ""
	}
	n := r.u32(field)
	if r.err != nil {
		return ""
	}
	if uint64(n) > uint64(len(r.data)-r.offset) {
		r.fail(field, errors.New("buffer too short for Borsh string contents"))
		return ""
	}
	return string(r.take(field, int(n)))
}

// stringVec reads a Vec<String>. Each element carries at least its 4-byte
// length prefix, which bounds the count before anything is allocated.
func (r *borshReader) stringVec(field string) []string {
	if r.err != nil {
		return nil
	}
	n := r.u32(field)
	if r.err != nil {
		return nil
	}
	if uint64(n) > uint64(len(r.data)-r.offset)/4 {
		r.fail(field, errors.New("Vec<String> length exceeds the account"))
		return nil
	}
	out := make([]string, 0, n)
	for i := uint32(0); i < n && r.err == nil; i++ {
		out = append(out, r.string(fmt.Sprintf("%s[%d]", field, i)))
	}
	return out
}

// optionTag reads a Borsh Option tag: false for None, true for Some. Any other
// tag is an error.
func (r *borshReader) optionTag(field string) bool {
	tag := r.u8(field)
	if r.err != nil {
		return false
	}
	switch tag {
	case 0:
		return false
	case 1:
		return true
	default:
		r.fail(field, fmt.Errorf("invalid Option tag: %d", tag))
		return false
	}
}
