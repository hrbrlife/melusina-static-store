package main

import (
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/installerpublish"
)

// The member ceiling submit-installer and the deployer's generation-one
// tooling refuse above is derived from this handler's body ceiling. If the
// handler's limit moves, the derived ceiling must move with it, or a member
// signed under the old ceiling is refused as an oversized body on the Store
// host after its envelope exists.
func TestInstallerArtifactCeilingFitsThePublishBody(t *testing.T) {
	if installerpublish.MaxPublishBodyBytes != maxInstallerPublishBody {
		t.Fatalf("STORE_INSTALLER_BODY_CEILING_DRIFT: installerpublish %d, handler %d",
			installerpublish.MaxPublishBodyBytes, maxInstallerPublishBody)
	}
	if installerpublish.MaxArtifactBytes+installerpublish.PublishBodyHeadroomBytes != maxInstallerPublishBody ||
		installerpublish.PublishBodyHeadroomBytes < 2*(64<<10) {
		t.Fatalf("STORE_INSTALLER_MEMBER_CEILING_HEADROOM: member %d + headroom %d != body %d (headroom must cover a 64 KiB envelope and the multipart framing)",
			installerpublish.MaxArtifactBytes, installerpublish.PublishBodyHeadroomBytes, maxInstallerPublishBody)
	}
}
