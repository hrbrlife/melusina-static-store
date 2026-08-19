package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// TestVerifyPublish_Accept asserts the gate ACCEPTs a self-consistent
// (spk, metadata, release, authz) bundle: canonicalAppHash(spk,metadata)==appHash,
// Active ReleaseEntry pinning that hash, Active StoreOperatorAuthorization whose
// store_authority is the sidecar's own operator key, and a clear blacklist.
func TestVerifyPublish_Accept(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)
	f := buildValidFixture(t, cfg, master)

	m := newMockChainReader()
	f.pinAccept(m, operatorPub)

	if err := VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, operatorPub); err != nil {
		t.Fatalf("expected ACCEPT, got: %v", err)
	}
}

func TestVerifyServeHash_LegacyStoreSkipsListingUntilAuthorityConfigured(t *testing.T) {
	cfg, _ := testConfig(t)
	configuredAuthority := cfg.StoreAuthority
	operator := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, operator)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	delete(m.storeListing, f.listingPDA)

	cfg.StoreAuthority = ""
	if err := VerifyServeHash(context.Background(), m, cfg, f.rel.AppHash, f.rel); err != nil {
		t.Fatalf("legacy release gate rejected before listing bootstrap: %v", err)
	}

	cfg.StoreAuthority = configuredAuthority
	if err := VerifyServeHash(context.Background(), m, cfg, f.rel.AppHash, f.rel); err == nil || !strings.Contains(err.Error(), "check=store_release_listing") {
		t.Fatalf("explicit listing policy accepted missing listing: %v", err)
	}
}

func TestVerifyPublish_RejectsAnyPublisherSquadsOverride(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)

	cases := []struct {
		name   string
		mutate func(*mockChainReader, *publishFixture, *Config)
	}{
		{
			name: "release_vault_override",
			mutate: func(_ *mockChainReader, f *publishFixture, _ *Config) {
				f.rel.LicenseSquadsVault = randPubkeyB58(t)
			},
		},
		{
			name: "release_multisig_override",
			mutate: func(_ *mockChainReader, f *publishFixture, _ *Config) {
				f.rel.QuorumPolicy.MultisigPda = randPubkeyB58(t)
			},
		},
		{
			name: "release_threshold_override",
			mutate: func(_ *mockChainReader, f *publishFixture, _ *Config) {
				f.rel.QuorumPolicy.Threshold = 2
			},
		},
		{
			name: "release_member_count_override",
			mutate: func(_ *mockChainReader, f *publishFixture, _ *Config) {
				f.rel.QuorumPolicy.MemberCount = 3
			},
		},
		{
			name: "onchain_vault_override",
			mutate: func(m *mockChainReader, f *publishFixture, _ *Config) {
				entry := m.releaseEntry[f.relPDA]
				entry.publisherSquadsVault = mustPubkey(randPubkeyB58(t))
				m.releaseEntry[f.relPDA] = entry
			},
		},
		{
			name: "catalog_authority_override",
			mutate: func(_ *mockChainReader, _ *publishFixture, c *Config) {
				c.ReleaseSquadsAuthority.Vault = randPubkeyB58(t)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cfg
			f := buildValidFixture(t, candidate, randPubkeyB58(t))
			m := newMockChainReader()
			f.pinAccept(m, operatorPub)
			tc.mutate(m, &f, &candidate)
			if err := VerifyPublish(context.Background(), m, candidate, f.spk, f.metadata, f.rel, operatorPub); err == nil || !strings.Contains(err.Error(), "check=publisher_squads_authority") {
				t.Fatalf("publisher Squads override accepted or unnamed: %v", err)
			}
		})
	}
}

func TestVerifyCurrentStoreReleaseListing_RechecksSharedPublisherAuthority(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	m := newMockChainReader()
	f.pinAccept(m, operatorSignPub32(t, op))
	cfg.StoreAuthority = "" // isolate the cache-path publisher check from listing policy.
	if err := VerifyServeHash(context.Background(), m, cfg, f.rel.AppHash, f.rel); err != nil {
		t.Fatalf("initial serve verification: %v", err)
	}
	f.rel.LicenseSquadsVault = randPubkeyB58(t)
	if err := verifyCurrentStoreReleaseListing(context.Background(), m, cfg, f.rel.AppHash, f.rel); err == nil || !strings.Contains(err.Error(), "check=publisher_squads_authority") {
		t.Fatalf("cached serve path accepted changed publisher vault: %v", err)
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
			name: "apphash_mismatch",
			mutate: func(m *mockChainReader, f *publishFixture) {
				// Corrupt the SPK so the recomputed tree-hash no longer equals
				// release.appHash.
				f.spk = append(append([]byte{}, f.spk...), 0xFF)
			},
			wantCheck: "check=app_hash",
		},
		{
			name: "release_entry_not_active",
			mutate: func(m *mockChainReader, f *publishFixture) {
				m.releaseEntry[f.relPDA] = mockReleaseEntry{appHash: f.appHashBytes, status: verify.AttestationStatusRevoked}
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
		{
			name: "foundation_app_not_active",
			mutate: func(m *mockChainReader, f *publishFixture) {
				// A Foundation app whose entry is Revoked must not be re-listable.
				f.pinFoundationApp(m, 0, verify.ApprovalStatusRevoked)
			},
			wantCheck: "check=foundation_tier",
		},
		{
			name: "foundation_app_rpc_error",
			mutate: func(m *mockChainReader, f *publishFixture) {
				m.foundationErr = errors.New("RPC unreachable")
			},
			wantCheck: "check=foundation_tier",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := buildValidFixture(t, cfg, master)
			m := newMockChainReader()
			f.pinAccept(m, operatorPub)
			tc.mutate(m, &f)

			err := VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, operatorPub)
			if err == nil {
				t.Fatalf("expected REJECT, got ACCEPT")
			}
			if !strings.Contains(err.Error(), tc.wantCheck) {
				t.Fatalf("error %q does not name failing check %q", err.Error(), tc.wantCheck)
			}
		})
	}
}

// TestVerifyPublish_TierMaskCoverage asserts the FoundationApp tier ceiling
// (B1-05/B2-05) is resolved FROM CHAIN (not a caller param) and is unbypassable:
// a Standard-tier Foundation app published by a Core-only operator is REJECTed;
// the same app is ACCEPTed once the operator mask covers Standard.
func TestVerifyPublish_TierMaskCoverage(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)

	f := buildValidFixture(t, cfg, master)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	// The app IS a Foundation app of Standard tier (discriminant 1 → bit 0x02).
	f.pinFoundationApp(m, uint8(verify.FoundationAppTierStandard), verify.ApprovalStatusActive)
	// Narrow the operator mask to Core only (0x01) — it does NOT cover Standard.
	a := m.storeAuthz[f.authzPDA]
	a.tierMask = 0x01
	m.storeAuthz[f.authzPDA] = a

	if err := VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, operatorPub); err == nil {
		t.Fatal("expected REJECT for uncovered Standard tier")
	} else if !strings.Contains(err.Error(), "check=store_operator_authz") {
		t.Fatalf("tier reject did not name store_operator_authz: %v", err)
	}

	// Widen the mask to Core|Standard (0x03) — now the Standard app is accepted.
	a = m.storeAuthz[f.authzPDA]
	a.tierMask = 0x03
	m.storeAuthz[f.authzPDA] = a
	if err := VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, operatorPub); err != nil {
		t.Fatalf("expected ACCEPT once mask covers Standard, got: %v", err)
	}
}
