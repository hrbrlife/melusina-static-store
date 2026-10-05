package main

import (
	"context"
	"strings"
	"testing"
)

// This test lives outside the byte-pinned C3-D41 boot helper. It exercises the
// same production boot path with an Active cascade and each on-chain recall.
func TestH0947RootStoreBootNamesRevokedCascade(t *testing.T) {
	const control = "4.7::title-claim"
	f := newRootStoreBootCeremony(t)
	if verified, err := deriveVerifiedBootIdentity(context.Background(), f.cfg, f.chain); err != nil || verified == nil {
		t.Fatalf("%s: active root Store cascade refused: %v", control, err)
	}
	for _, tc := range []struct {
		name   string
		recall func(*rootStoreBootCascade)
		want   string
	}{
		{"licence", func(c *rootStoreBootCascade) { c.licStatus = 1 }, "LicenseEntry: status Revoked"},
		{"global", func(c *rootStoreBootCascade) { c.globalStatus = 1 }, "GlobalSidecarApproval: status Revoked"},
		{"local", func(c *rootStoreBootCascade) { c.localStatus = 1 }, "LocalSidecarApproval: status Revoked"},
		{"reseller-approval", func(c *rootStoreBootCascade) { c.approvalStatus = 1 }, "ResellerSidecarApproval: status Revoked"},
		{"reseller-entry", func(c *rootStoreBootCascade) { c.entry.status = 1 }, "ResellerEntry: status Revoked"},
		{"global-revoking", func(c *rootStoreBootCascade) { c.globalStatus = 2 }, "GlobalSidecarApproval: status RevokingCascadeInProgress"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRootStoreBootCeremony(t)
			tc.recall(f.cascade)
			f.reseed(t)
			_, err := deriveVerifiedBootIdentity(context.Background(), f.cfg, f.chain)
			if err == nil || !strings.HasPrefix(err.Error(), control+": check=sidecar_cascade: cascade-not-active:"+tc.want) {
				t.Fatalf("%s: revoked cascade was accepted or lost its refusal name: %v", control, err)
			}
		})
	}
}
