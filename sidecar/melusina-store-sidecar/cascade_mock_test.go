package main

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// fetchRawAccount is the mock's implementation of the cascade raw-read
// capability. Seeded accounts are always owned by the pinned program.
func (m *mockChainReader) fetchRawAccount(_ context.Context, addr string) ([]byte, string, error) {
	if m.rawAccounts == nil {
		return nil, "", nil
	}
	data, ok := m.rawAccounts[addr]
	if !ok {
		return nil, "", nil // absent
	}
	return data, programID.Base58(), nil
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

func mkResellerEntryAccount(reseller, master primitives.Pubkey) []byte {
	b := accountDiscriminator("ResellerEntry")
	b = append(b, reseller[:]...)
	b = append(b, master[:]...)
	b = mkPutU64(b, 1)
	b = append(b, make([]byte, 32)...) // owner
	b = mkPutString(b, "acceptance reseller")
	b = mkPutString(b, "test")
	b = mkPutU32(b, 100)
	b = mkPutU32(b, 1)
	b = append(b, 0) // parent_reseller=None
	b = mkPutU32(b, 0)
	b = mkPutU32(b, 0)
	b = append(b, 0) // category=None
	b = append(b, 0) // status = Active
	b = mkPutU64(b, 1)
	b = append(b, 0, 1)
	b = mkPutU64(b, 0)
	b = append(b, 0) // base_domain=None
	return b
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
			want:       "scope 255 is unknown",
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
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("cascade accepted invalid SAN/scope binding, err=%v", err)
			}
		})
	}
}
