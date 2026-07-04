package main

import (
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// ── check (a): attestation proximity ──────────────────────────────────────────

// TestVerifyAttestationProximity exercises the +/-24h proximity rule against the
// on-chain registered_at anchor: within tolerance (incl. the exact boundary)
// accepts; beyond it (either direction), an unset claim, or an unset anchor rejects
// with check=release_attestation_proximity.
func TestVerifyAttestationProximity(t *testing.T) {
	const base = int64(1_700_000_000)
	const tol = releaseAttestationToleranceSeconds

	cases := []struct {
		name       string
		signedAt   int64
		registered int64
		wantErr    bool
	}{
		{"equal", base, base, false},
		{"plus_23h", base + 23*3600, base, false},
		{"minus_23h", base - 23*3600, base, false},
		{"plus_exactly_24h", base + tol, base, false},
		{"minus_exactly_24h", base - tol, base, false},
		{"plus_over_24h", base + tol + 1, base, true},
		{"minus_over_24h", base - tol - 1, base, true},
		{"signed_unset", 0, base, true},
		{"registered_unset", base, 0, true},
		{"registered_negative", base, -1, true},
		// Overflow bypass guard: signedAtUnix crafted so signedAtUnix-registeredAt ==
		// math.MinInt64 (whose negation stays negative) must NOT slip past the window.
		{"minint64_overflow_bypass", math.MinInt64 + base, base, true},
		// signedAtUnix at the int64 extremes must reject (far outside +/-24h).
		{"max_int64", math.MaxInt64, base, true},
		{"min_int64", math.MinInt64, base, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rel := ReleaseJSON{SignedAtUnix: tc.signedAt}
			meta := releaseEntryMeta{RegisteredAt: tc.registered}
			err := verifyAttestationProximity(rel, meta)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected REJECT, got ACCEPT")
				}
				if !strings.Contains(err.Error(), "check=release_attestation_proximity") {
					t.Fatalf("error %q does not name check=release_attestation_proximity", err.Error())
				}
			} else if err != nil {
				t.Fatalf("expected ACCEPT, got: %v", err)
			}
		})
	}
}

// ── check (b): monotonic release timestamp ────────────────────────────────────

// writeServedReleaseClaim writes a minimal RELEASE.json into the served attest tree
// at the appId slot so currentPublishedSignedAt can read it.
func writeServedReleaseClaim(t *testing.T, distDir, appID string, signedAt int64) {
	t.Helper()
	dir := filepath.Join(distDir, "attest", appID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rel := ReleaseJSON{
		Schema:        "melusina-release-v1",
		AppHash:       strings.Repeat("a", 64), // readReleaseClaim only checks 64-char length
		ReleaseHash:   strings.Repeat("b", 64),
		Version:       "1.0.0",
		SignedAtUnix:  signedAt,
		MasterNftMint: "MASTERmintAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	if err := os.WriteFile(filepath.Join(dir, "RELEASE.json"), mustJSON(t, rel), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyReleaseTimestampForward(t *testing.T) {
	const appID = "appslot0000000000000000000000000000000000000000000000"

	t.Run("first_publish_no_served_slot", func(t *testing.T) {
		dist := t.TempDir()
		if err := verifyReleaseTimestampForward(dist, appID, ReleaseJSON{SignedAtUnix: 2000}); err != nil {
			t.Fatalf("first publish must pass, got: %v", err)
		}
	})

	t.Run("strictly_greater_accepts", func(t *testing.T) {
		dist := t.TempDir()
		writeServedReleaseClaim(t, dist, appID, 1000)
		if err := verifyReleaseTimestampForward(dist, appID, ReleaseJSON{SignedAtUnix: 2000}); err != nil {
			t.Fatalf("strictly-greater must pass, got: %v", err)
		}
	})

	t.Run("equal_rejects", func(t *testing.T) {
		dist := t.TempDir()
		writeServedReleaseClaim(t, dist, appID, 2000)
		err := verifyReleaseTimestampForward(dist, appID, ReleaseJSON{SignedAtUnix: 2000})
		if err == nil || !strings.Contains(err.Error(), "check=release_timestamp_monotonic") {
			t.Fatalf("equal timestamp must reject with monotonic check, got: %v", err)
		}
	})

	t.Run("older_rejects", func(t *testing.T) {
		dist := t.TempDir()
		writeServedReleaseClaim(t, dist, appID, 3000)
		err := verifyReleaseTimestampForward(dist, appID, ReleaseJSON{SignedAtUnix: 2000})
		if err == nil || !strings.Contains(err.Error(), "check=release_timestamp_monotonic") {
			t.Fatalf("older timestamp must reject with monotonic check, got: %v", err)
		}
	})

	t.Run("same_apphash_idempotent_passes", func(t *testing.T) {
		dist := t.TempDir()
		// The served descriptor IS this exact release (same app_hash) — an idempotent
		// re-publish or a pre-staged copy of THIS publish. It must NOT be treated as a
		// prior to advance past, even with an equal timestamp.
		writeServedReleaseClaim(t, dist, appID, 2000) // writes appHash = "aaaa...a" (64)
		rel := ReleaseJSON{AppHash: strings.Repeat("a", 64), SignedAtUnix: 2000}
		if err := verifyReleaseTimestampForward(dist, appID, rel); err != nil {
			t.Fatalf("same-app_hash idempotent re-publish must pass, got: %v", err)
		}
	})

	t.Run("different_slot_no_bar", func(t *testing.T) {
		dist := t.TempDir()
		// A served release under a DIFFERENT appId slot must not bar this app's
		// publish, even with a much higher timestamp.
		writeServedReleaseClaim(t, dist, "otherslot00000000000000000000000000000000000000000000", 9000)
		if err := verifyReleaseTimestampForward(dist, appID, ReleaseJSON{SignedAtUnix: 2000}); err != nil {
			t.Fatalf("different-slot prior must not bar, got: %v", err)
		}
	})

	t.Run("empty_appid_skips", func(t *testing.T) {
		dist := t.TempDir()
		writeServedReleaseClaim(t, dist, appID, 9000)
		// No served-slot identity to anchor the bar; the on-chain gate still governs.
		if err := verifyReleaseTimestampForward(dist, "", ReleaseJSON{SignedAtUnix: 1}); err != nil {
			t.Fatalf("empty appId must skip, got: %v", err)
		}
	})

	t.Run("traversal_appid_skips", func(t *testing.T) {
		dist := t.TempDir()
		// A traversal appId must never be joined into the dist path; it is rejected
		// as unsafe and the check skips (defense-in-depth).
		if err := verifyReleaseTimestampForward(dist, "../../etc", ReleaseJSON{SignedAtUnix: 1}); err != nil {
			t.Fatalf("unsafe appId must skip, got: %v", err)
		}
	})
}

func TestMetadataAppID(t *testing.T) {
	if got := metadataAppID([]byte(`{"appId":"abc123","name":"X"}`)); got != "abc123" {
		t.Fatalf("appId parse: got %q want abc123", got)
	}
	if got := metadataAppID([]byte(`{"name":"no appid here"}`)); got != "" {
		t.Fatalf("missing appId: got %q want empty", got)
	}
	if got := metadataAppID([]byte(`{not json`)); got != "" {
		t.Fatalf("malformed metadata: got %q want empty", got)
	}
}

// ── handler-level integration (both refusals on the real /publish path) ────────

// TestHandlePublish_AttestationProximityReject drives the full /publish gate: a
// publish whose on-chain registered_at sits 48h from the claimed signedAtUnix is
// refused 403 check=release_attestation_proximity (everything else valid).
func TestHandlePublish_AttestationProximityReject(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)
	f := buildValidFixture(t, cfg, master)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	// Override the on-chain registered_at to sit 48h from the claimed signedAtUnix.
	m.releaseEntry[f.relPDA] = mockReleaseEntry{
		appHash:      f.appHashBytes,
		appID:        f.appID,
		version:      f.rel.Version,
		status:       verify.AttestationStatusActive,
		registeredAt: f.rel.SignedAtUnix + 48*3600,
	}
	svc := newTestService(t, cfg, m, op)
	svc.cfg.Policy.AcceptPublishers = []string{f.rel.ReleaseEntryPda}

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=release_attestation_proximity") {
		t.Fatalf("body %q does not name check=release_attestation_proximity", w.Body.String())
	}
}

// TestHandlePublish_MonotonicTimestampReject drives the full /publish gate: an
// on-chain-valid publish whose claimed signedAtUnix is NOT greater than the
// currently-served version of the same app is refused 409
// check=release_timestamp_monotonic.
func TestHandlePublish_MonotonicTimestampReject(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)
	f := buildValidFixture(t, cfg, master) // rel.SignedAtUnix=1700000000, rel.MasterNftMint=master
	m := newMockChainReader()
	f.pinAccept(m, operatorPub) // registeredAt = signedAtUnix -> proximity passes
	// Serve a prior version of THIS app's slot (same appId) with an EQUAL claim.
	writeServedReleaseClaim(t, cfg.DistDir, metadataAppID(f.metadata), f.rel.SignedAtUnix)
	svc := newTestService(t, cfg, m, op)
	svc.cfg.Policy.AcceptPublishers = []string{f.rel.ReleaseEntryPda}

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
	if w.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "check=release_timestamp_monotonic") {
		t.Fatalf("body %q does not name check=release_timestamp_monotonic", w.Body.String())
	}
}

// TestHandlePublish_MonotonicTimestampAccept proves the same setup ACCEPTS (200)
// once the claimed signedAtUnix strictly advances past the served prior — the
// non-destructive rule gates only regressions, not legitimate bumps.
func TestHandlePublish_MonotonicTimestampAccept(t *testing.T) {
	cfg, _ := testConfig(t)
	cfg.DistDir = t.TempDir()
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	operatorPub := operatorSignPub32(t, op)
	master := randPubkeyB58(t)
	f := buildValidFixture(t, cfg, master)
	m := newMockChainReader()
	f.pinAccept(m, operatorPub)
	// Served prior claims an OLDER time -> the submitted publish strictly advances.
	writeServedReleaseClaim(t, cfg.DistDir, metadataAppID(f.metadata), f.rel.SignedAtUnix-1000)
	svc := newTestService(t, cfg, m, op)
	svc.cfg.Policy.AcceptPublishers = []string{f.rel.ReleaseEntryPda}

	release := mustJSON(t, f.rel)
	pub := newTestIdentity(t, "publisher", randPubkeyB58(t), "publisher.example.org")
	sig := signPublish(t, pub, op.Public(), f.spk, release)

	w := doPublish(t, svc, jsonPublishBody(t, sig, release, f.spk, f.metadata))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", w.Code, w.Body.String())
	}
}
