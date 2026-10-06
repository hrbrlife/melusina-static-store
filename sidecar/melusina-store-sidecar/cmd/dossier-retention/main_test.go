package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDossierRetentionKeyCustodyAndPinnedAuthority(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	keyPath, pinPath := filepath.Join(root, "test-only.key"), filepath.Join(root, "test-only.pub")
	if err := os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(private)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte(base64.RawURLEncoding.EncodeToString(public)), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readIdentity(keyPath, pinPath)
	if err != nil || !bytes.Equal(got, private) {
		t.Fatal("positive pinned identity refused", err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, []byte(base64.RawURLEncoding.EncodeToString(otherPublic)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentity(keyPath, pinPath); err == nil || !strings.Contains(err.Error(), "dossier-retention-key-pin-mismatch") {
		t.Fatalf("substituted pin survived: %v", err)
	}
	if err := os.Chmod(keyPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentity(keyPath, pinPath); err == nil || !strings.Contains(err.Error(), "dossier-retention-key-custody-invalid") {
		t.Fatalf("readable key survived: %v", err)
	}
}
