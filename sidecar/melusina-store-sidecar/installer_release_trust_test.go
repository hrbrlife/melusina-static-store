package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease/releasetest"
)

// Startup projects the enrolled profile's installer-release trust onto the
// Store config, and only a profile consistent with the config's own release
// master mint and the enrolled pin.
func TestBindInstallerReleaseTrustProjectsOnlyTheEnrolledEstate(t *testing.T) {
	p := releasetest.LoadProfileVector(t, testEstateProfileVectors, releasetest.NewEstateVector)
	state := &storeEnrollmentState{Profile: p.Profile, ProfilePin: estateprofile.Pin{ProfileSHA256: p.SHA256}}

	cfg := Config{ReleaseMasterNftMint: p.Profile.Anchors.MasterMint}
	if err := bindInstallerReleaseTrust(&cfg, state); err != nil || cfg.installerReleaseTrust == nil {
		t.Fatalf("enrolled estate not bound: %v", err)
	}
	var hash [32]byte
	hash[0] = 7
	if err := cfg.installerReleaseTrust.Admit(releasetest.Entry(t, p.Profile, hash, "1.0.0", releasetest.TrustedPublisher()), hash); err != nil {
		t.Fatalf("bound trust refused the estate's publisher: %v", err)
	}

	// No enrolled state: no trust, and a stale one is cleared.
	if err := bindInstallerReleaseTrust(&cfg, nil); err != nil || cfg.installerReleaseTrust != nil {
		t.Fatalf("unenrolled Store kept a trust: %v", err)
	}
	if err := cfg.installerReleaseTrust.Admit(releasetest.Entry(t, p.Profile, hash, "1.0.0", releasetest.TrustedPublisher()), hash); !errors.Is(err, installerrelease.ErrTrustUnconfigured) {
		t.Fatalf("unenrolled Store admitted an entry: %v", err)
	}

	// A config whose release master is another estate's.
	other := Config{ReleaseMasterNftMint: randPubkeyB58(t)}
	if err := bindInstallerReleaseTrust(&other, state); !errors.Is(err, installerrelease.ErrEstateMismatch) || !strings.Contains(err.Error(), "masterNftMint") || other.installerReleaseTrust != nil {
		t.Fatalf("foreign master mint: %v", err)
	}
	// A state whose pin is not its profile's digest.
	pinned := &storeEnrollmentState{Profile: p.Profile, ProfilePin: estateprofile.Pin{ProfileSHA256: strings.Repeat("0", 64)}}
	if err := bindInstallerReleaseTrust(&Config{ReleaseMasterNftMint: p.Profile.Anchors.MasterMint}, pinned); !errors.Is(err, installerrelease.ErrProfile) {
		t.Fatalf("pin mismatch: %v", err)
	}
}

// The Store's reader decodes the K3 account exactly and refuses the pre-K3
// layout by size rather than reading its prefix.
func TestReadInstallerReleaseEntryMetaDecodesOnlyTheK3Layout(t *testing.T) {
	p := releasetest.LoadProfileVector(t, testEstateProfileVectors, releasetest.NewEstateVector)
	var hash [32]byte
	hash[0] = 9
	e := releasetest.Entry(t, p.Profile, hash, "1.0.64", releasetest.TrustedPublisher())
	account := releasetest.Encode(e)
	meta, err := readInstallerReleaseEntryMeta(account)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(releasetest.Encode(meta.Entry), account) || meta.InstallerHash != hash || meta.Version != "1.0.64" {
		t.Fatalf("decoded %+v", meta.Entry)
	}
	legacy := append([]byte(nil), account[:8+32+32+4+len(e.Version)+32+32+8+1]...)
	legacy = append(legacy, 0, e.Bump)
	legacy = append(legacy, make([]byte, 191-len(legacy))...)
	if _, err := readInstallerReleaseEntryMeta(legacy); err == nil || !strings.Contains(err.Error(), "installer-release-entry-malformed:size") {
		t.Fatalf("pre-K3 account: %v", err)
	}
}
