package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func signedLegacyManifest(t *testing.T, build int64, private ed25519.PrivateKey) legacyManifest {
	t.Helper()
	m := legacyManifest{Build: build, BundleURL: "https://bazaar.example/releases/shell/sandstorm.tar.xz", Channel: "dev", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Size: 1, Tarball: "sandstorm.tar.xz", Version: "build-84"}
	canonical, err := legacyManifestCanonical(m)
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(private, canonical))
	return m
}

func TestLegacyManifestReplacementOnlyRepairsInvalidEqualBuild(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	next := signedLegacyManifest(t, 84, private)
	valid, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	if legacyManifestReplacementAllowed(valid, next, public) {
		t.Fatal("a valid equal-build projection must remain immutable")
	}
	unsigned := next
	unsigned.Signature = ""
	invalid, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	if !legacyManifestReplacementAllowed(invalid, next, public) {
		t.Fatal("an unsigned equal-build projection must be repairable")
	}
	higher := signedLegacyManifest(t, 85, private)
	higher.Signature = ""
	higherBytes, err := json.Marshal(higher)
	if err != nil {
		t.Fatal(err)
	}
	if legacyManifestReplacementAllowed(higherBytes, next, public) {
		t.Fatal("an invalid higher-build projection must not be rolled back")
	}
}
