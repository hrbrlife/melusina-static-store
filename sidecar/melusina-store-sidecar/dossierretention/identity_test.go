package dossierretention

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStorageSourceIdentitiesPersistAndRefuseBroadCustody(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	native, nativePublic, nativeID, err := LoadOrCreateIdentity(dir, "native")
	if err != nil {
		t.Fatal(err)
	}
	member, memberPublic, memberID, err := LoadOrCreateIdentity(dir, "member")
	if err != nil || bytes.Equal(nativePublic, memberPublic) || nativeID == memberID {
		t.Fatalf("storage source signers not distinct: %v", err)
	}
	again, againPublic, againID, err := LoadOrCreateIdentity(dir, "member")
	if err != nil || !bytes.Equal(member, again) || !bytes.Equal(memberPublic, againPublic) || memberID != againID {
		t.Fatalf("storage member identity changed: %v", err)
	}
	t.Setenv("STORAGE_EVIDENCE_PACK_EXPORT_KEY_PATH", filepath.Join(dir, "foreign"))
	after, _, _, err := LoadOrCreateIdentity(dir, "native")
	if err != nil || !bytes.Equal(native, after) {
		t.Fatalf("ambient key substituted storage native identity: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "evidence-pack-member-key"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadOrCreateIdentity(dir, "member"); err == nil || !strings.Contains(err.Error(), "custody-invalid") {
		t.Fatalf("broad storage member identity admitted: %v", err)
	}
	if _, _, _, err := LoadOrCreateIdentity(dir, "other"); err == nil || !strings.Contains(err.Error(), "purpose-invalid") {
		t.Fatalf("foreign signer purpose admitted: %v", err)
	}
}

func TestStorageSourceIdentityRequiresPrivateDirectory(t *testing.T) {
	base := t.TempDir()
	broad := filepath.Join(base, "broad")
	if err := os.Mkdir(broad, 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadOrCreateIdentity(broad, "member"); err == nil || !strings.Contains(err.Error(), "custody-invalid") {
		t.Fatalf("STORAGE_MEMBER_BROAD_DIRECTORY_MUTATION_CONTROL: %v", err)
	}
	private := filepath.Join(base, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadOrCreateIdentity(private, "member"); err != nil {
		t.Fatalf("STORAGE_MEMBER_PRIVATE_DIRECTORY_POSITIVE: %v", err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(private, alias); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadOrCreateIdentity(alias, "member"); err == nil || !strings.Contains(err.Error(), "custody-invalid") {
		t.Fatalf("STORAGE_MEMBER_SYMLINK_DIRECTORY_REFUSED: %v", err)
	}
}
