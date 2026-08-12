package verify

// attest_records.go — the two decoders PROVENANCE_CONTRACTS.md §7.4 names as
// "MUST BE WRITTEN", plus the block-time read the GrainCert slot binding needs.
//
// Why they were missing, stated plainly so nobody re-derives it: this file's
// siblings decode SidecarIdentity (approvals.go:1257), LicenseEntry (:657),
// ReleaseEntry (:1153), StoreOperatorAuthz (:1349) and BlacklistEntry (:1493).
// There was NO decoder for PearlIdentityEntry or DomainClaim. The PDA DERIVERS
// exist (melusina-attest/pda.go); the PARSERS did not — you could compute the
// address and nothing could parse the account. So no GrainCert check could read
// chain, and there was no way to ask the only question that resists a captured
// trust root: "which license owns this domain?" (§7.3.1).
//
// FAIL-CLOSED, mirroring ReadSidecarIdentity field-for-field: a short buffer, a
// garbled Option tag or an unknown status byte returns an error. A caller that
// cannot decode an authority record must reject, never assume (Inv 5).
//
// This module has NO dependencies on purpose (Pubkey is a local [32]byte alias,
// approvals.go:1101-1107, precisely so melusina-solana-primitives stays out of
// it). These decoders keep that property: they return raw [32]byte and leave
// base58 encoding and PDA derivation to the attest-side adapter.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// ---------------------------------------------------------------------------
// DomainClaim — the forward-resolution root (§7.3.1)
// ---------------------------------------------------------------------------

// DomainClaim mirrors state/license.rs:134-138 field-for-field.
//
// It is the ONLY on-chain anti-squat control and the root of FORWARD resolution:
// the verifier asks "which license owns this domain?" (domain → license) rather
// than "does the license this cert points at claim this domain?" (license →
// domain). The direction is the whole security property — see ReadDomainClaim.
type DomainClaim struct {
	DomainHash     [32]byte
	LicenseNFTMint Pubkey
}

// ReadDomainClaim decodes a DomainClaim account.
//
// PDA seeds are [b"domain_claim", domain_hash] — the 32-BYTE HASH, VERIFIED AT
// SOURCE (instructions/licenses.rs:399, :759; instructions/purchase.rs:400,
// :472; instructions/domain.rs:44; state/license.rs:132's own comment says
// [b"domain_claim", &sha256(normalized_domain)]).
//
// TRAP, VERIFIED AT SOURCE — do NOT derive this PDA from the RAW DOMAIN STRING
// (FindProgramAddress{SeedDomainClaim, []byte(domain)}). The program seeds the
// HASH; the two derive DIFFERENT addresses, so string seeding can never find a
// real account.
//
// primitives exported exactly that mistake as `DeriveDomainClaim` for the whole
// life of this comment. It is now DELETED: a helper whose NAME says DomainClaim
// and whose CODE derives a PDA the program never writes is a comment asserting a
// control, in a function signature — and four such comments could not disarm it.
// Seed the hash directly, as ReadDomainClaim below does.
//
// Layout:
//
//	discriminator (8) | domain_hash ([u8;32]) | license_nft_mint (Pubkey)
//	  | bump (u8)
//
// Every field before bump is fixed-size, so this is a straight fixed-offset
// walk — no String or Option prefix.
func ReadDomainClaim(data []byte) (DomainClaim, error) {
	var d DomainClaim
	offset := AccountDiscriminatorLen
	var err error
	if offset, err = readAttest32(data, offset, "domain_claim", "domain_hash", &d.DomainHash); err != nil {
		return DomainClaim{}, err
	}
	if _, err = readAttest32(data, offset, "domain_claim", "license_nft_mint", &d.LicenseNFTMint); err != nil {
		return DomainClaim{}, err
	}
	return d, nil
}

// FetchDomainClaim fetches the DomainClaim at addressBase58. PDA-not-found is
// surfaced as ErrPDANotFound: an unclaimed domain is NOT a pass — the verifier
// rejects (R-13a / R-43). Absence is the clear case for a BLACKLIST entry only;
// here it means nobody has proven they own this domain.
func (c *RPCClient) FetchDomainClaim(ctx context.Context, addressBase58 string) (DomainClaim, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return DomainClaim{}, err
	}
	if data == nil {
		return DomainClaim{}, ErrPDANotFound
	}
	return ReadDomainClaim(data)
}

// ---------------------------------------------------------------------------
// PearlIdentityEntry — the grain binding
// ---------------------------------------------------------------------------

// PearlIdentity mirrors state/attestation.rs:88-107 field-for-field.
//
// Fields are returned raw ([32]byte, not base58) to keep this module
// dependency-free; the attest-side adapter encodes.
//
// KeyVersion / Supersedes / Status / RevokedAt are DEAD STATE on the program we
// run and this decoder does not pretend otherwise: the pearl_identity PDA seed
// is [b"pearl_identity", license_nft_mint, grain_id_hash] (attestation.rs:976 —
// NO key_version) and the account is `init`, so re-registration is impossible;
// lib.rs exposes only register_pearl_identity — no revoke, no supersede, no
// update. So status can only ever be Active (attestation.rs:230) and revoked_at
// only ever None (:231). They are decoded anyway, honestly, because the fields
// are on chain and the verifier must bind what it reads — the day the program
// gains those instructions this decoder is already right. Reading a field that
// can only hold one value is not the same as trusting it to.
type PearlIdentity struct {
	LicenseNFTMint   Pubkey
	GrainIDHash      [32]byte
	PublicIDHash     [32]byte
	OwnerUserHash    [32]byte
	OwnerWallet      Pubkey
	AppHash          [32]byte
	AppID            [32]byte
	ReleaseEntry     Pubkey
	SigningPubkey    [32]byte
	EncryptionPubkey [32]byte
	DomainHash       [32]byte
	KeyVersion       uint32

	// HasSupersedes distinguishes None from a zero-valued Some, exactly as
	// LicenseEntrySummary.HasSquadsVault / HasRevokedAt do.
	HasSupersedes bool
	Supersedes    Pubkey

	RegisteredBy Pubkey
	RegisteredAt int64
	Status       AttestationStatus
	HasRevokedAt bool
	RevokedAt    int64
}

// ReadPearlIdentity decodes a PearlIdentityEntry account (seeds
// ["pearl_identity", license_nft_mint, grain_id_hash]; state/attestation.rs:88).
//
// FAIL-CLOSED: a short/garbled buffer, a bad Option tag or an unknown status
// byte returns an error.
//
// Layout — pinned to state/attestation.rs:88-107. Any future reorder there has
// to land in this function in the same commit (Inv 5: better fail-closed than
// silently mis-decode; a decoder that walks a stale layout reports the WRONG
// pubkey as the grain's authority, which is worse than not reading at all):
//
//	discriminator (8) | license_nft_mint (Pubkey) | grain_id_hash ([u8;32])
//	  | public_id_hash ([u8;32]) | owner_user_hash ([u8;32])
//	  | owner_wallet (Pubkey) | app_hash ([u8;32]) | app_id ([u8;32])
//	  | release_entry (Pubkey) | signing_pubkey ([u8;32])
//	  | encryption_pubkey ([u8;32]) | domain_hash ([u8;32])
//	  | key_version (u32 LE) | supersedes (Option<Pubkey>)
//	  | registered_by (Pubkey) | registered_at (i64)
//	  | status (AttestationStatus u8) | revoked_at (Option<i64>) | bump (u8)
//
// The Option<Pubkey> sits BEFORE status, so the walk past it is mandatory — a
// fixed-offset read of status would land on registered_by's first byte whenever
// supersedes is Some. That is exactly the class of bug that makes a decoder
// report Active for a revoked record.
func ReadPearlIdentity(data []byte) (PearlIdentity, error) {
	var p PearlIdentity
	const rec = "pearl_identity"
	offset := AccountDiscriminatorLen
	var err error

	for _, f := range []struct {
		name string
		dst  *[32]byte
	}{
		{"license_nft_mint", &p.LicenseNFTMint},
		{"grain_id_hash", &p.GrainIDHash},
		{"public_id_hash", &p.PublicIDHash},
		{"owner_user_hash", &p.OwnerUserHash},
		{"owner_wallet", &p.OwnerWallet},
		{"app_hash", &p.AppHash},
		{"app_id", &p.AppID},
		{"release_entry", &p.ReleaseEntry},
		{"signing_pubkey", &p.SigningPubkey},
		{"encryption_pubkey", &p.EncryptionPubkey},
		{"domain_hash", &p.DomainHash},
	} {
		if offset, err = readAttest32(data, offset, rec, f.name, f.dst); err != nil {
			return PearlIdentity{}, err
		}
	}

	if p.KeyVersion, offset, err = readAttestU32LE(data, offset, rec, "key_version"); err != nil {
		return PearlIdentity{}, err
	}
	if p.HasSupersedes, p.Supersedes, offset, err = readAttestOptionPubkey(data, offset, rec, "supersedes"); err != nil {
		return PearlIdentity{}, err
	}
	if offset, err = readAttest32(data, offset, rec, "registered_by", &p.RegisteredBy); err != nil {
		return PearlIdentity{}, err
	}
	if p.RegisteredAt, offset, err = readAttestI64LE(data, offset, rec, "registered_at"); err != nil {
		return PearlIdentity{}, err
	}

	status, err := ReadAttestationStatusByte(data, offset)
	if err != nil {
		return PearlIdentity{}, fmt.Errorf("%s: status: %w", rec, err)
	}
	p.Status = status
	offset++

	if p.HasRevokedAt, p.RevokedAt, _, err = readAttestOptionI64(data, offset, rec, "revoked_at"); err != nil {
		return PearlIdentity{}, err
	}
	return p, nil
}

// FetchPearlIdentity fetches the PearlIdentityEntry at addressBase58.
// PDA-not-found is surfaced as ErrPDANotFound — an unregistered grain is a
// REJECTION (R-09d / R-43), never an unattested pass.
func (c *RPCClient) FetchPearlIdentity(ctx context.Context, addressBase58 string) (PearlIdentity, error) {
	data, err := c.GetAccountInfo(ctx, addressBase58)
	if err != nil {
		return PearlIdentity{}, err
	}
	if data == nil {
		return PearlIdentity{}, ErrPDANotFound
	}
	return ReadPearlIdentity(data)
}

// ---------------------------------------------------------------------------
// Block time
// ---------------------------------------------------------------------------

// GetBlockTimeMs returns the cluster block time of slot, in unix MILLISECONDS.
//
// The Solana getBlockTime RPC returns unix SECONDS; the conversion happens here,
// once, rather than at each callsite — a unit mismatch between a slot time and a
// millisecond cert window silently widens or voids the window instead of failing.
//
// A null result means the node has no block time for that slot (pruned, or the
// slot is not yet confirmed). That is NOT a zero timestamp and must never be
// treated as one: it returns ErrPDANotFound-free, explicit failure so the caller
// rejects rather than binding a cert to the epoch.
func (c *RPCClient) GetBlockTimeMs(ctx context.Context, slot uint64) (int64, error) {
	raw, err := c.rpcCall(ctx, "getBlockTime", []any{slot})
	if err != nil {
		return 0, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return 0, fmt.Errorf("getBlockTime: no block time for slot %d (pruned or unconfirmed)", slot)
	}
	var secs int64
	if err := json.Unmarshal(raw, &secs); err != nil {
		return 0, fmt.Errorf("getBlockTime: decode slot %d: %w", slot, err)
	}
	return secs * 1000, nil
}

// rpcCall issues a JSON-RPC call and returns the raw `result` bytes. It mirrors
// GetAccountInfo's transport handling exactly — same ErrRPCUnreachable wrapping,
// same HTTP-status and rpc-error treatment — rather than opening a second,
// divergent transport path with its own error semantics.
func (c *RPCClient) rpcCall(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	client := c.HTTPClient
	if client == nil {
		return nil, errors.New("rpc: nil HTTPClient")
	}
	resp, err := client.Do(httpReq)
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
	var parsed struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcErrorObj    `json:"error"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode rpc response: %w", err)
	}
	if parsed.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", parsed.Error.Code, parsed.Error.Message)
	}
	return parsed.Result, nil
}

// ---------------------------------------------------------------------------
// Borsh helpers — named per-record so an error names the field that failed
// ---------------------------------------------------------------------------

// readAttest32 copies a fixed 32-byte field, naming record+field on a short
// buffer. (readFixed32 exists but hard-codes a "sidecar_identity:" prefix in its
// error, which would misattribute every pearl/domain failure.)
func readAttest32(data []byte, offset int, rec, field string, dst *[32]byte) (int, error) {
	if offset < 0 || offset+32 > len(data) {
		return 0, fmt.Errorf("%s: %s: buffer too short (need 32 at %d, have %d)", rec, field, offset, len(data)-offset)
	}
	copy(dst[:], data[offset:offset+32])
	return offset + 32, nil
}

func readAttestU32LE(data []byte, offset int, rec, field string) (uint32, int, error) {
	if offset < 0 || offset+4 > len(data) {
		return 0, 0, fmt.Errorf("%s: %s: buffer too short for u32", rec, field)
	}
	v := uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
	return v, offset + 4, nil
}

func readAttestI64LE(data []byte, offset int, rec, field string) (int64, int, error) {
	if offset < 0 || offset+8 > len(data) {
		return 0, 0, fmt.Errorf("%s: %s: buffer too short for i64", rec, field)
	}
	var v uint64
	for i := 7; i >= 0; i-- {
		v = v<<8 | uint64(data[offset+i])
	}
	return int64(v), offset + 8, nil
}

// readAttestOptionTag reads a Borsh Option discriminant. Borsh defines exactly
// two values, 0 (None) and 1 (Some); ANY OTHER BYTE IS A REJECTION rather than a
// truthy "some". A decoder that treats a garbled tag as Some walks the remaining
// fields at a shifted offset and reports confident nonsense.
func readAttestOptionTag(data []byte, offset int, rec, field string) (bool, int, error) {
	if offset < 0 || offset+1 > len(data) {
		return false, 0, fmt.Errorf("%s: %s: buffer too short for Option tag", rec, field)
	}
	switch data[offset] {
	case 0:
		return false, offset + 1, nil
	case 1:
		return true, offset + 1, nil
	default:
		return false, 0, fmt.Errorf("%s: %s: invalid Borsh Option tag %d (want 0 or 1)", rec, field, data[offset])
	}
}

func readAttestOptionPubkey(data []byte, offset int, rec, field string) (bool, Pubkey, int, error) {
	var pk Pubkey
	some, offset, err := readAttestOptionTag(data, offset, rec, field)
	if err != nil {
		return false, pk, 0, err
	}
	if !some {
		return false, pk, offset, nil
	}
	offset, err = readAttest32(data, offset, rec, field, &pk)
	if err != nil {
		return false, pk, 0, err
	}
	return true, pk, offset, nil
}

func readAttestOptionI64(data []byte, offset int, rec, field string) (bool, int64, int, error) {
	some, offset, err := readAttestOptionTag(data, offset, rec, field)
	if err != nil {
		return false, 0, 0, err
	}
	if !some {
		return false, 0, offset, nil
	}
	v, offset, err := readAttestI64LE(data, offset, rec, field)
	if err != nil {
		return false, 0, 0, err
	}
	return true, v, offset, nil
}
