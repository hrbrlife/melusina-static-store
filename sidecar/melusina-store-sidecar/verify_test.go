package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// TestVerifyPublish_Accept asserts the gate ACCEPTs a self-consistent
// (spk, release, authz) bundle: sha256(spk)==appHash, Active ReleaseEntry
// pinning that hash, Active StoreOperatorAuthorization whose store_authority is
// the sidecar's own operator key, and a clear blacklist.
func TestVerifyPublish_Accept(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)
	f := buildValidFixture(t, cfg, master)

	m := newMockChainReader()
	f.pinAccept(m, operatorPub)

	if err := VerifyPublish(context.Background(), m, cfg, f.spk, f.rel, operatorPub, 0); err != nil {
		t.Fatalf("expected ACCEPT, got: %v", err)
	}
}

func TestVerifyPublish_Reject(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)

	cases := []struct {
		name      string
		mutate    func(m *mockChainReader, f *publishFixture)
		wantCheck string
	}{
		{
			name: "sha256_mismatch",
			mutate: func(m *mockChainReader, f *publishFixture) {
				// Corrupt the SPK so its hash no longer equals release.appHash.
				f.spk = append(append([]byte{}, f.spk...), 0xFF)
			},
			wantCheck: "check=spk_sha256",
		},
		{
			name: "release_entry_not_active",
			mutate: func(m *mockChainReader, f *publishFixture) {
				appSum := sha256.Sum256(f.spk)
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: appSum, status: verify.AttestationStatusRevoked}
			},
			wantCheck: "check=release_entry",
		},
		{
			name: "release_entry_apphash_mismatch",
			mutate: func(m *mockChainReader, f *publishFixture) {
				var other [32]byte
				other[0] = 0x99
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: other, status: verify.AttestationStatusActive}
			},
			wantCheck: "check=release_entry",
		},
		{
			name: "release_entry_not_found",
			mutate: func(m *mockChainReader, f *publishFixture) {
				delete(m.releaseEntry, f.relPDA)
			},
			wantCheck: "check=release_entry",
		},
		{
			name: "store_authority_mismatch",
			mutate: func(m *mockChainReader, f *publishFixture) {
				var wrong [32]byte
				wrong[0] = 0x07
				a := m.storeAuthz[f.authzPDA]
				a.authority = verify.Pubkey(wrong)
				m.storeAuthz[f.authzPDA] = a
			},
			wantCheck: "check=store_operator_authz",
		},
		{
			name: "store_authz_not_active",
			mutate: func(m *mockChainReader, f *publishFixture) {
				a := m.storeAuthz[f.authzPDA]
				a.status = verify.AuthorizationStatusRevoked
				m.storeAuthz[f.authzPDA] = a
			},
			wantCheck: "check=store_operator_authz",
		},
		{
			name: "blacklist_app_present",
			mutate: func(m *mockChainReader, f *publishFixture) {
				m.blacklist[f.blAppPDA] = mockBlacklist{present: true, entryType: verify.BlacklistTypeApp}
			},
			wantCheck: "check=blacklist[app]",
		},
		{
			name: "blacklist_license_present",
			mutate: func(m *mockChainReader, f *publishFixture) {
				m.blacklist[f.blLicPDA] = mockBlacklist{present: true, entryType: verify.BlacklistTypeLicense}
			},
			wantCheck: "check=blacklist[license]",
		},
		{
			name: "rpc_error_release",
			mutate: func(m *mockChainReader, f *publishFixture) {
				m.releaseErr = errors.New("RPC unreachable")
			},
			wantCheck: "check=release_entry",
		},
		{
			name: "rpc_error_blacklist",
			mutate: func(m *mockChainReader, f *publishFixture) {
				m.blacklistErr = errors.New("RPC unreachable")
			},
			wantCheck: "check=blacklist",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := buildValidFixture(t, cfg, master)
			m := newMockChainReader()
			f.pinAccept(m, operatorPub)
			tc.mutate(m, &f)

			err := VerifyPublish(context.Background(), m, cfg, f.spk, f.rel, operatorPub, 0)
			if err == nil {
				t.Fatalf("expected REJECT, got ACCEPT")
			}
			if !strings.Contains(err.Error(), tc.wantCheck) {
				t.Fatalf("error %q does not name failing check %q", err.Error(), tc.wantCheck)
			}
		})
	}
}

// TestVerifyPublish_TierMaskCoverage asserts the optional FoundationApp tier
// gate: a non-zero tier not covered by allowed_tier_mask is REJECTed; the same
// tier when covered is ACCEPTed.
func TestVerifyPublish_TierMaskCoverage(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)

	f := buildValidFixture(t, cfg, master)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	// Narrow the mask to Core only (0x01) and require an admin tier (0x04).
	a := m.storeAuthz[f.authzPDA]
	a.tierMask = 0x01
	m.storeAuthz[f.authzPDA] = a

	if err := VerifyPublish(context.Background(), m, cfg, f.spk, f.rel, operatorPub, 0x04); err == nil {
		t.Fatal("expected REJECT for uncovered tier")
	} else if !strings.Contains(err.Error(), "check=store_operator_authz") {
		t.Fatalf("tier reject did not name store_operator_authz: %v", err)
	}

	// Covered tier (Core) is accepted.
	if err := VerifyPublish(context.Background(), m, cfg, f.spk, f.rel, operatorPub, 0x01); err != nil {
		t.Fatalf("expected ACCEPT for covered tier, got: %v", err)
	}
}
