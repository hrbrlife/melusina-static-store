package dossierretention

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestDossierRetentionAnotherAppKeyPinRefused(t *testing.T) {
	s, source, scope, encrypted := fixture(t)
	if err := s.Put(source, scope, encrypted); err != nil {
		t.Fatal("positive source authority refused:", err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.ccash = other
	if err := s.Put(source, scope, encrypted); err == nil || !strings.Contains(err.Error(), "dossier-ccash-attestation-invalid") {
		t.Fatalf("other app key survived: %v", err)
	}
}
