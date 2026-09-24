//go:build !estatebootstrap

package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
)

// TestUnenrolledStandardStoreAdmitsOnTheTrustFreeSubset: the standard build's
// unenrolled Store has no estate profile, so no publisher keys to judge an
// entry's publisher by. Its /publish admission still refuses a release its
// ReleaseEntry does not attest (release_hash, version; app_id in
// TestPublishAdmissionBindsTheAppID). An enrolled Store that reached the
// admission without its trust is refused by name.
func TestUnenrolledStandardStoreAdmitsOnTheTrustFreeSubset(t *testing.T) {
	cfg, _ := testConfig(t)
	if cfg.EstateEnrollmentStatePath != "" || cfg.appReleaseTrust != nil {
		t.Fatal("the standard fixture is not an unenrolled Store")
	}
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	opPub := operatorSignPub32(t, op)
	setup := func() (*mockChainReader, publishFixture) {
		f := buildValidFixture(t, cfg, randPubkeyB58(t))
		m := newMockChainReader()
		f.pinAccept(m, opPub)
		return m, f
	}
	m, f := setup()
	if err := VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, opPub); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	// No profile names a publisher, so none is refused here; an enrolled
	// Store refuses this one (TestPublishAdmissionRefusesAReleaseItsEntryDoesNotAttest).
	entry := m.releaseEntry[f.relPDA]
	entry.publisher = admissionOtherPublisher()
	m.releaseEntry[f.relPDA] = entry
	if err := VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, opPub); err != nil {
		t.Fatalf("the unenrolled Store judged a publisher it has no trust for: %v", err)
	}

	m, f = setup()
	f.rel.ReleaseHash = flipHex32(t, f.rel.ReleaseHash)
	requireAdmissionRefusal(t, VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, opPub), releaseentry.ErrReleaseHashMismatch)

	m, f = setup()
	entry = m.releaseEntry[f.relPDA]
	entry.version = "1.0.1"
	m.releaseEntry[f.relPDA] = entry
	requireAdmissionRefusal(t, VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, opPub), releaseentry.ErrVersionMismatch)

	m, f = setup()
	enrolled := cfg
	enrolled.EstateEnrollmentStatePath = filepath.Join(t.TempDir(), "estate-enrollment.json")
	requireAdmissionRefusal(t, VerifyPublish(context.Background(), m, enrolled, f.spk, f.metadata, f.rel, opPub), releaseentry.ErrTrustUnconfigured)
}
