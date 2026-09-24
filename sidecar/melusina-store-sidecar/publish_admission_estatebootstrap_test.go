//go:build estatebootstrap

package main

import (
	"context"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/releaseentry"
)

// TestEstateBootstrapAdmitsNoAppReleaseWithoutTheEstateTrust: a bootstrap
// component's Store always starts enrolled and binds its estate's app-release
// trust. A Config that reaches the /publish admission without one refuses
// even a release its entry attests exactly, by name; with the trust bound the
// same release is admitted.
func TestEstateBootstrapAdmitsNoAppReleaseWithoutTheEstateTrust(t *testing.T) {
	cfg, _ := testConfig(t)
	op := newTestIdentity(t, "store-operator", cfg.LicenseNFTMint, cfg.Domain)
	opPub := operatorSignPub32(t, op)
	f := buildValidFixture(t, cfg, randPubkeyB58(t))
	m := newMockChainReader()
	f.pinAccept(m, opPub)
	if cfg.appReleaseTrust != nil {
		t.Fatal("the fixture config already carries a trust")
	}
	requireAdmissionRefusal(t, VerifyPublish(context.Background(), m, cfg, f.spk, f.metadata, f.rel, opPub), releaseentry.ErrTrustUnconfigured)
	if err := VerifyPublish(context.Background(), m, withReleaseTrust(cfg, m), f.spk, f.metadata, f.rel, opPub); err != nil {
		t.Fatalf("positive control: the enrolled estate's trust must admit the attested release: %v", err)
	}
}
