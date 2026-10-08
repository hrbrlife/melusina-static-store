package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/dossierretention"
)

func TestBuiltCustodySetupPublishesOnlyDurablePublicKeys(t *testing.T) {
	root := filepath.Join(t.TempDir(), "custody")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	var first, second bytes.Buffer
	if err := writeDossierSetupPublic(root, &first); err != nil {
		t.Fatal(err)
	}
	if err := writeDossierSetupPublic(root, &second); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("Store public signer setup changed after first writer")
	}
	var setup struct {
		Schema string `json:"schema"`
		Keys   []struct {
			Purpose string `json:"purpose"`
			KeyID   string `json:"key_id"`
			Public  string `json:"public_key"`
		} `json:"keys"`
	}
	if json.Unmarshal(first.Bytes(), &setup) != nil || setup.Schema != "storage-evidence-pack-setup-keys-v1" ||
		len(setup.Keys) != 2 || setup.Keys[0].Purpose != "native" || setup.Keys[1].Purpose != "member" ||
		setup.Keys[0].Public == setup.Keys[1].Public || bytes.Contains(first.Bytes(), []byte("private")) {
		t.Fatalf("Store setup did not return only two distinct public signers: %s", first.String())
	}
	if err := os.Chmod(filepath.Join(root, "dossier-retention", "evidence-pack-member-key"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeDossierSetupPublic(root, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "custody-invalid") {
		t.Fatalf("broad Store member signer admitted by setup producer: %v", err)
	}
	if err := os.Chmod(filepath.Join(root, "dossier-retention", "evidence-pack-member-key"), 0600); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(t.TempDir(), "foreign")
	if err := os.Symlink(root, foreign); err != nil {
		t.Fatal(err)
	}
	if err := writeDossierSetupPublic(foreign, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "setup-root-invalid") {
		t.Fatalf("symlinked Store setup root admitted: %v", err)
	}
}

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
