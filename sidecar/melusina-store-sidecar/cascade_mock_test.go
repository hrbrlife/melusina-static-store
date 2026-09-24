package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// fetchRawAccount is the mock's implementation of the cascade raw-read
// capability. A test may override an owner for a purpose-specific foreign
// program account (such as a Squads multisig); otherwise seeded accounts are
// owned by the pinned registry program.
func (m *mockChainReader) fetchRawAccount(_ context.Context, addr string) ([]byte, string, error) {
	if m.rawAccounts == nil {
		return nil, "", nil
	}
	data, ok := m.rawAccounts[addr]
	if !ok {
		return nil, "", nil // absent
	}
	owner := programID.Base58()
	if m.rawAccountOwners != nil && m.rawAccountOwners[addr] != "" {
		owner = m.rawAccountOwners[addr]
	}
	return data, owner, nil
}

func (m *mockChainReader) fetchFinalizedHostApplyTransaction(_ context.Context, signature string) (hostApplyFinalizedTransaction, error) {
	if m.hostApplyErr != nil {
		return hostApplyFinalizedTransaction{}, m.hostApplyErr
	}
	tx, ok := m.hostApplyTransactions[signature]
	if !ok {
		return hostApplyFinalizedTransaction{}, verify.ErrPDANotFound
	}
	return tx, nil
}

func (m *mockChainReader) fetchFinalizedHostApplyAccounts(_ context.Context, addresses []string, minContextSlot uint64) (hostApplyFinalizedAccountCohort, error) {
	if m.hostApplyErr != nil {
		return hostApplyFinalizedAccountCohort{}, m.hostApplyErr
	}
	if m.hostApplyContextSlot < minContextSlot {
		return hostApplyFinalizedAccountCohort{}, verify.ErrPDANotFound
	}
	out := hostApplyFinalizedAccountCohort{ContextSlot: m.hostApplyContextSlot, Accounts: make([]hostApplyFinalizedAccount, len(addresses))}
	for i, address := range addresses {
		data, ok := m.rawAccounts[address]
		if !ok {
			return hostApplyFinalizedAccountCohort{}, verify.ErrPDANotFound
		}
		owner := programID.Base58()
		if m.rawAccountOwners != nil && m.rawAccountOwners[address] != "" {
			owner = m.rawAccountOwners[address]
		}
		out.Accounts[i] = hostApplyFinalizedAccount{Address: address, Owner: owner, Data: data}
	}
	return out, nil
}

// ── cascade account layout builders (mirror the deployed Anchor layouts) ──────

func mkPutU32(dst []byte, n uint32) []byte {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], n)
	return append(dst, raw[:]...)
}
func mkPutU64(dst []byte, n uint64) []byte {
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], n)
	return append(dst, raw[:]...)
}
func mkPutString(dst []byte, s string) []byte {
	dst = mkPutU32(dst, uint32(len(s)))
	return append(dst, []byte(s)...)
}
func mkPutVecStrings(dst []byte, values ...string) []byte {
	dst = mkPutU32(dst, uint32(len(values)))
	for _, v := range values {
		dst = mkPutString(dst, v)
	}
	return dst
}

func mkLicenseAccount(license, reseller, master primitives.Pubkey) []byte {
	b := accountDiscriminator("LicenseEntry")
	b = append(b, license[:]...)
	b = append(b, reseller[:]...)
	b = append(b, master[:]...)
	b = mkPutU64(b, 1) // edition_number
	b = mkPutString(b, "acceptance.example")
	b = mkPutString(b, "https://acceptance.example/install")
	b = append(b, make([]byte, 32)...) // tls_cert_fingerprint
	b = append(b, 1, 1, 1)             // threshold/keyholder counters
	b = append(b, make([]byte, 32)...) // owner
	b = append(b, 1)                   // custody_mode
	// Live pilot licenses are Squads-custodied. Keeping both options Some here
	// prevents a decoder that skips only the tags from falsely reading the first
	// vault byte as the status field.
	var vault, multisig [32]byte
	vault[0], multisig[0] = 0xf8, 0x42 // nonzero proves we skip each full Pubkey
	b = append(b, 1)                   // squads_vault=Some
	b = append(b, vault[:]...)
	b = append(b, 1) // squads_multisig=Some
	b = append(b, multisig[:]...)
	b = append(b, 0)                   // status = Active
	b = mkPutU64(b, 1)                 // activated_at
	b = append(b, 0)                   // revoked_at=None
	b = mkPutU32(b, 0)                 // total_shares
	b = mkPutU32(b, 0)                 // active_shares
	b = append(b, 0, 0)                // signer counters
	b = append(b, make([]byte, 32)...) // authz_identity_pubkey
	b = append(b, 0)                   // dev_permissive
	b = mkPutString(b, "")             // sandstorm_version
	b = mkPutString(b, "")             // trust_bundle_uri
	b = mkPutU32(b, 0)                 // accepted_stores
	b = append(b, make([]byte, 32)...) // root_store_domain_hash
	b = mkPutU64(b, 0)                 // enabled_features
	b = append(b, 1)                   // bump
	return b
}

func mkLocalAccountWithScope(sidecarID string, license primitives.Pubkey, scope byte) []byte {
	b := accountDiscriminator("LocalSidecarApproval")
	b = mkPutString(b, sidecarID)
	b = append(b, license[:]...)
	b = append(b, 0)                   // optional hash = None
	b = append(b, scope)               // scope
	b = append(b, make([]byte, 32)...) // approved_by
	b = append(b, 0)                   // status = Active
	b = mkPutU64(b, 1)
	b = append(b, 0, 1) // revoked_at=None, bump
	return b
}

func mkLocalAccount(sidecarID string, license primitives.Pubkey) []byte {
	return mkLocalAccountWithScope(sidecarID, license, sidecarScopeHost)
}

func mkResellerApprovalAccount(sidecarID string, reseller primitives.Pubkey) []byte {
	b := accountDiscriminator("ResellerSidecarApproval")
	b = mkPutString(b, sidecarID)
	b = append(b, reseller[:]...)
	b = append(b, make([]byte, 32)...) // approved_by
	b = append(b, 0)                   // status = Active
	b = mkPutU64(b, 1)
	b = append(b, 0, 1)
	return b
}

// resellerEntryFields are the ResellerEntry fields a cascade test varies. A nil
// parent or category is encoded as None; otherwise as Some with its payload.
type resellerEntryFields struct {
	parent   *primitives.Pubkey
	category *string
	status   byte
}

// seedResellerParent and seedResellerCategory are the seed cascade's
// ResellerEntry options. Both are Some, as the contracts foundation writes them
// for a sub-reseller and for an estate profile that names a reseller category.
// Every byte of the parent key is nonzero, so a decoder that skips only an
// Option tag reads a nonzero status and refuses the seed instead of passing by
// luck; TestResellerEntryFixtureDefeatsTagOnlyDecoder holds that property.
var (
	seedResellerParent   = primitives.Pubkey(bytes.Repeat([]byte{0x5c}, 32))
	seedResellerCategory = "x"
)

// mkResellerEntryAccountWith encodes a ResellerEntry in the contracts Borsh
// layout (melusina-os-smartcontract programs/license-registry/src/state/
// reseller.rs, re-read at contracts main 655c5f8): every field in order,
// including the fields after status.
func mkResellerEntryAccountWith(reseller, master primitives.Pubkey, f resellerEntryFields) []byte {
	b := accountDiscriminator("ResellerEntry")
	b = append(b, reseller[:]...)             // reseller_nft_mint
	b = append(b, master[:]...)               // master_nft_mint
	b = mkPutU64(b, 1)                        // edition_number
	b = append(b, make([]byte, 32)...)        // owner
	b = mkPutString(b, "acceptance reseller") // name
	b = mkPutString(b, "test")                // territory
	b = mkPutU32(b, 100)                      // issuance_limit
	b = mkPutU32(b, 1)                        // licenses_issued
	if f.parent == nil {                      // parent_reseller: Option<Pubkey>
		b = append(b, 0)
	} else {
		b = append(b, 1)
		b = append(b, f.parent[:]...)
	}
	b = mkPutU32(b, 0)     // total_sub_resellers
	b = mkPutU32(b, 0)     // active_sub_resellers
	if f.category == nil { // category: Option<String>
		b = append(b, 0)
	} else {
		b = append(b, 1)
		b = mkPutString(b, *f.category)
	}
	b = append(b, f.status) // status: ResellerStatus
	b = mkPutU64(b, 1)      // activated_at
	b = append(b, 0, 1)     // revoked_at=None, bump
	b = mkPutU64(b, 0)      // license_price_lamports
	b = append(b, 0)        // base_domain=None
	return b
}

// mkResellerEntryAccount is the seed cascade's Active ResellerEntry, with
// parent_reseller and category both Some.
func mkResellerEntryAccount(reseller, master primitives.Pubkey) []byte {
	parent, category := seedResellerParent, seedResellerCategory
	return mkResellerEntryAccountWith(reseller, master, resellerEntryFields{parent: &parent, category: &category})
}

func mkGlobalAccountWithSANs(sidecarID string, master primitives.Pubkey, hash [32]byte, sans ...string) []byte {
	b := accountDiscriminator("GlobalSidecarApproval")
	b = mkPutString(b, sidecarID)
	b = append(b, hash[:]...)
	b = mkPutString(b, "probe-v1")
	b = mkPutVecStrings(b, sans...)
	b = mkPutU64(b, 0)                 // required_permissions
	b = append(b, make([]byte, 32)...) // author
	b = append(b, master[:]...)
	b = append(b, make([]byte, 32)...) // approved_by
	b = append(b, 0)                   // status = Active
	b = mkPutU64(b, 1)
	b = append(b, 0, 0, 1) // revoked_at=None, revoke_reason=None, bump
	return b
}

func mkGlobalAccount(sidecarID string, master primitives.Pubkey, hash [32]byte) []byte {
	return mkGlobalAccountWithSANs(sidecarID, master, hash, sidecarID+".sidecar.host")
}

// seedValidCascade populates the mock with an all-Active 5-fact cascade for the
// given license/sidecar/artifact, so a mock-driven sidecar_identity re-verify
// passes the full require_active_sidecar_cascade mirror.
func seedValidCascade(t *testing.T, m *mockChainReader, license primitives.Pubkey, sidecarID string, artifact [32]byte) {
	t.Helper()
	// Deterministic reseller + master mints for the mock cascade.
	var reseller, master primitives.Pubkey
	reseller[0], reseller[1] = 0xAA, 0x01
	master[0], master[1] = 0xBB, 0x02

	licPDA, _, err := primitives.DeriveLicense(license, programID)
	if err != nil {
		t.Fatal(err)
	}
	globalPDA, _, err := primitives.DeriveGlobalSidecar(master, sidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	localPDA, _, err := primitives.DeriveLocalSidecar(license, sidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	resApprovalPDA, _, err := primitives.DeriveResellerSidecar(reseller, sidecarID, programID)
	if err != nil {
		t.Fatal(err)
	}
	parentPDA, _, err := primitives.FindProgramAddress([][]byte{[]byte("reseller"), reseller[:]}, programID, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.rawAccounts[licPDA.Base58()] = mkLicenseAccount(license, reseller, master)
	m.rawAccounts[globalPDA.Base58()] = mkGlobalAccount(sidecarID, master, artifact)
	m.rawAccounts[localPDA.Base58()] = mkLocalAccount(sidecarID, license)
	m.rawAccounts[resApprovalPDA.Base58()] = mkResellerApprovalAccount(sidecarID, reseller)
	m.rawAccounts[parentPDA.Base58()] = mkResellerEntryAccount(reseller, master)
}

func TestVerifyFiveFactCascadeRejectsAmbiguousOrMismatchedSANTier(t *testing.T) {
	license, err := primitives.PubkeyFromBase58(testLicenseMint)
	if err != nil {
		t.Fatal(err)
	}
	const sidecarID = "fineract-v2"
	artifact := [32]byte{0x42}

	for _, tc := range []struct {
		name       string
		sans       []string
		localScope byte
		want       string
	}{
		{
			name: "host_shared_and_unshared_sans_are_one_host_tier",
			sans: []string{sidecarID + ".sidecar.host", sidecarID + ".sidecar.host.shared"},
		},
		{
			name: "case_and_multilabel_global_san_match_registry_grammar",
			sans: []string{"Fineract.Production." + sidecarID + ".SIDEcar.HOST.Shared"},
		},
		{
			name: "global_hypervisor_cannot_authorize_host_local_scope",
			sans: []string{sidecarID + ".sidecar.hypervisor"},
			want: "SAN tier",
		},
		{
			name: "empty_global_san_vector_is_not_an_authorization",
			sans: nil,
			want: "SAN list is empty",
		},
		{
			name: "mixed_global_san_scopes_are_not_an_authorization",
			sans: []string{sidecarID + ".sidecar.host", sidecarID + ".sidecar.hypervisor"},
			want: "span multiple scope tiers",
		},
		{
			name: "unknown_global_san_scope_is_not_an_authorization",
			sans: []string{sidecarID + ".sidecar.edge"},
			want: "unrecognized sidecar SAN",
		},
		{
			name:       "unknown_local_scope_is_not_an_authorization",
			sans:       []string{sidecarID + ".sidecar.host"},
			localScope: 0xff,
			want:       "cascade-scope-mismatch:LocalSidecarApproval.scope: the Local scope Unknown(255) is not the Global SAN tier Host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMockChainReader()
			seedValidCascade(t, m, license, sidecarID, artifact)

			var master primitives.Pubkey
			master[0], master[1] = 0xBB, 0x02
			globalPDA, _, err := primitives.DeriveGlobalSidecar(master, sidecarID, programID)
			if err != nil {
				t.Fatal(err)
			}
			m.rawAccounts[globalPDA.Base58()] = mkGlobalAccountWithSANs(sidecarID, master, artifact, tc.sans...)
			if tc.localScope != 0 {
				localPDA, _, err := primitives.DeriveLocalSidecar(license, sidecarID, programID)
				if err != nil {
					t.Fatal(err)
				}
				m.rawAccounts[localPDA.Base58()] = mkLocalAccountWithScope(sidecarID, license, tc.localScope)
			}

			svc := &publishService{cr: m}
			err = svc.verifyFiveFactCascade(context.Background(), componentReleaseChainView{sidecarID: sidecarID, licenseMint: license}, artifact)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("cascade rejected valid host SAN/scope binding: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("cascade accepted invalid SAN/scope binding, err=%v", err)
			}
		})
	}
}

// resellerEntryParentTagOffset is where the fixture's parent_reseller Option
// tag sits: discriminator, three keys and edition_number, the name and
// territory strings, then issuance_limit and licenses_issued.
const resellerEntryParentTagOffset = 8 + 32 + 32 + 8 + 32 + (4 + len("acceptance reseller")) + (4 + len("test")) + 4 + 4

// resellerEntryTailLen is the fixture's bytes after status: activated_at,
// revoked_at=None, bump, license_price_lamports and base_domain=None.
const resellerEntryTailLen = 8 + 1 + 1 + 8 + 1

// TestVerifyFiveFactCascadeDecodesResellerEntryOptions runs the Store's
// sidecar cascade over ResellerEntry accounts in the contracts layout with
// parent_reseller and category each None or Some. The contracts foundation
// writes category=Some when the estate profile names a reseller category, and
// every sub-reseller has parent_reseller=Some; a Store that read either Option
// as its tag byte alone refused every sidecar promote and download for such an
// estate (seam audit round 2, finding 0). Malformed tags, a category length past
// the account end, truncation and an unknown status byte must be refused.
func TestVerifyFiveFactCascadeDecodesResellerEntryOptions(t *testing.T) {
	license, err := primitives.PubkeyFromBase58(testLicenseMint)
	if err != nil {
		t.Fatal(err)
	}
	const sidecarID = "fineract-v2"
	artifact := [32]byte{0x42}
	var reseller, master primitives.Pubkey
	reseller[0], reseller[1] = 0xAA, 0x01 // seedValidCascade's reseller
	master[0], master[1] = 0xBB, 0x02
	resellerPDA, _, err := primitives.FindProgramAddress([][]byte{[]byte("reseller"), reseller[:]}, programID, nil)
	if err != nil {
		t.Fatal(err)
	}

	parent := seedResellerParent
	str := func(s string) *string { return &s }
	fields := func(p *primitives.Pubkey, c *string, status byte) resellerEntryFields {
		return resellerEntryFields{parent: p, category: c, status: status}
	}
	// withByte builds the fixture and overwrites one byte, after checking the
	// byte it replaces, so a fixture layout change fails here by name instead
	// of corrupting an unrelated field.
	withByte := func(t *testing.T, f resellerEntryFields, off func([]byte) int, was, now byte) []byte {
		t.Helper()
		data := mkResellerEntryAccountWith(reseller, master, f)
		i := off(data)
		if data[i] != was {
			t.Fatalf("fixture byte %d is %d, want %d: the ResellerEntry fixture layout moved", i, data[i], was)
		}
		data[i] = now
		return data
	}
	categoryTagOffset := func(parentSome bool) func([]byte) int {
		return func([]byte) int {
			off := resellerEntryParentTagOffset + 1 + 4 + 4
			if parentSome {
				off += 32
			}
			return off
		}
	}
	statusOffset := func(data []byte) int { return len(data) - resellerEntryTailLen - 1 }

	for _, tc := range []struct {
		name string
		data func(t *testing.T) []byte
		want string // empty: the cascade must accept
	}{
		{
			name: "root_reseller_parent_none_category_none",
			data: func(*testing.T) []byte { return mkResellerEntryAccountWith(reseller, master, fields(nil, nil, 0)) },
		},
		{
			name: "sub_reseller_parent_some",
			data: func(*testing.T) []byte { return mkResellerEntryAccountWith(reseller, master, fields(&parent, nil, 0)) },
		},
		{
			name: "category_some_x",
			data: func(*testing.T) []byte { return mkResellerEntryAccountWith(reseller, master, fields(nil, str("x"), 0)) },
		},
		{
			name: "category_some_msb",
			data: func(*testing.T) []byte {
				return mkResellerEntryAccountWith(reseller, master, fields(nil, str("msb"), 0))
			},
		},
		{
			name: "category_at_contracts_max_len_32",
			data: func(*testing.T) []byte {
				return mkResellerEntryAccountWith(reseller, master, fields(nil, str(strings.Repeat("c", 32)), 0))
			},
		},
		{
			name: "sub_reseller_parent_some_category_some",
			data: func(*testing.T) []byte {
				return mkResellerEntryAccountWith(reseller, master, fields(&parent, str("x"), 0))
			},
		},
		{
			name: "revoked_with_parent_some_category_some",
			data: func(*testing.T) []byte {
				return mkResellerEntryAccountWith(reseller, master, fields(&parent, str("x"), 1))
			},
			want: "cascade-not-active:ResellerEntry: status Revoked, not Active",
		},
		{
			name: "unknown_status_byte_with_parent_some_category_some",
			data: func(*testing.T) []byte {
				return mkResellerEntryAccountWith(reseller, master, fields(&parent, str("x"), 2))
			},
			want: "unknown ResellerStatus byte: 2",
		},
		{
			name: "parent_option_tag_2_is_malformed",
			data: func(t *testing.T) []byte {
				return withByte(t, fields(&parent, str("x"), 0), func([]byte) int { return resellerEntryParentTagOffset }, 1, 2)
			},
			want: "parent_reseller: invalid Option tag: 2",
		},
		{
			name: "category_option_tag_2_is_malformed",
			data: func(t *testing.T) []byte {
				return withByte(t, fields(&parent, str("x"), 0), categoryTagOffset(true), 1, 2)
			},
			want: "category: invalid Option tag: 2",
		},
		{
			name: "category_length_past_account_end",
			data: func(t *testing.T) []byte {
				// The length prefix's high byte follows the tag by four bytes.
				return withByte(t, fields(&parent, str("x"), 0), func(d []byte) int { return categoryTagOffset(true)(d) + 4 }, 0, 0x7f)
			},
			want: "category: buffer too short for Borsh string contents",
		},
		{
			name: "truncated_before_status",
			data: func(t *testing.T) []byte {
				data := mkResellerEntryAccountWith(reseller, master, fields(&parent, str("x"), 0))
				return data[:statusOffset(data)]
			},
			want: "buffer too short for status",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMockChainReader()
			seedValidCascade(t, m, license, sidecarID, artifact)
			m.rawAccounts[resellerPDA.Base58()] = tc.data(t)

			svc := &publishService{cr: m}
			err := svc.verifyFiveFactCascade(context.Background(), componentReleaseChainView{sidecarID: sidecarID, licenseMint: license}, artifact)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("cascade refused an Active ResellerEntry in the contracts layout: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("cascade error = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// tagOnlyResellerStatus is the ResellerEntry decoder the Store shipped before
// seam audit round 2 finding 0: it skipped each Option's tag byte and never its
// Some payload. It is kept only as the known-bad reference that
// TestResellerEntryFixtureDefeatsTagOnlyDecoder measures the fixtures against.
func tagOnlyResellerStatus(data []byte) (byte, error) {
	c := &borshCursor{b: data, off: 8}
	c.skipPubkey()
	c.skipPubkey()
	c.skipU64()
	c.skipPubkey()
	c.skipString()
	c.skipString()
	c.skip(4)
	c.skip(4)
	c.skip(1) // parent_reseller tag only
	c.skip(4)
	c.skip(4)
	c.skip(1) // category tag only
	status := c.u8()
	return status, c.err
}

// TestResellerEntryFixtureDefeatsTagOnlyDecoder is the positive control for the
// Some fixtures: each Active ResellerEntry with a Some option must read as
// something other than Active under the tag-only decoder. If a fixture stopped
// encoding its Some payload, or its payload bytes happened to decode as Active,
// the cascade tests above could pass against the old decoder, and this test
// fails by name instead.
func TestResellerEntryFixtureDefeatsTagOnlyDecoder(t *testing.T) {
	var reseller, master primitives.Pubkey
	reseller[0], master[0] = 0xAA, 0xBB
	parent := seedResellerParent
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"seed_cascade_reseller_entry", mkResellerEntryAccount(reseller, master)},
		{"parent_some", mkResellerEntryAccountWith(reseller, master, resellerEntryFields{parent: &parent})},
		{"category_some_x", mkResellerEntryAccountWith(reseller, master, resellerEntryFields{category: &seedResellerCategory})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := verify.ReadResellerEntryStatus(tc.data)
			if err != nil || got != verify.ResellerStatusActive {
				t.Fatalf("contracts-layout reader: status=%v err=%v, want Active", got, err)
			}
			if old, err := tagOnlyResellerStatus(tc.data); err == nil && old == 0 {
				t.Fatalf("tag-only decoder also reads Active (%d): this fixture cannot catch a decoder that skips only the Option tag", old)
			}
		})
	}
}
