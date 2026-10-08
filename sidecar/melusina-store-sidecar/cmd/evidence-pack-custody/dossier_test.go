package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/dossierretention"
)

func TestBuiltCustodyDossierRequiresEnrolledStorageSource(t *testing.T) {
	root := filepath.Join(t.TempDir(), "custody")
	dossierRoot := filepath.Join(root, "dossier-retention")
	if err := os.MkdirAll(dossierRoot, 0700); err != nil {
		t.Fatal(err)
	}
	pearl := t.TempDir()
	_, storage, id, err := dossierretention.LoadOrCreateIdentity(dossierRoot, "member")
	if err != nil {
		t.Fatal(err)
	}
	ccash, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	due, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pins := map[string]ed25519.PublicKey{"ccash/source": ccash, "dueprocess/station": due, "storage/" + id: storage}
	if _, err := openDossier(root, pearl, pins); err != nil {
		t.Fatalf("signed source roster refused: %v", err)
	}
	foreign, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pins["storage/"+id] = foreign
	if _, err := openDossier(root, pearl, pins); err == nil || !strings.Contains(err.Error(), "evidence-pack-dossier-signed-roster-drift") {
		t.Fatalf("foreign enrolled storage source admitted: %v", err)
	}
	pins["storage/"+id] = storage
	pins["ccash/foreign"] = foreign
	if _, err := openDossier(root, pearl, pins); err == nil || !strings.Contains(err.Error(), "evidence-pack-dossier-pin-ambiguous") {
		t.Fatalf("competing Ccash source admitted: %v", err)
	}
}
