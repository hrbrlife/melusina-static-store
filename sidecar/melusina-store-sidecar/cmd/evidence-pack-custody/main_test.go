package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPinsRequiresExactInstallerDigest(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"keys":{"dueprocess/test":"` + base64.StdEncoding.EncodeToString(public) + `"}}`)
	path := filepath.Join(t.TempDir(), "pins.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	pins, err := loadPins(path, hex.EncodeToString(sum[:]))
	if err != nil || string(pins["dueprocess/test"]) != string(public) {
		t.Fatalf("installer roster positive: %v", err)
	}
	if _, err := loadPins(path, strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "pins-drift") {
		t.Fatalf("evidence-pack-custody-pins-drift: changed roster digest admitted: %v", err)
	}
}

func TestPackCustodySocketRequiresInstallerGrainGroup(t *testing.T) {
	if got, err := socketGroupID("", os.Getgid()); err != nil || got != os.Getgid() {
		t.Fatalf("installer numeric grain group positive: gid=%d err=%v", got, err)
	}
	if _, err := socketGroupID("", -1); err == nil || !strings.Contains(err.Error(), "socket-group-missing") {
		t.Fatalf("evidence-pack-custody-socket-group-missing: absent group admitted: %v", err)
	}
	if _, err := socketGroupID("root", -1); err == nil || !strings.Contains(err.Error(), "socket-group-invalid") {
		t.Fatalf("evidence-pack-custody-socket-group-invalid: alternate service group admitted: %v", err)
	}
	if _, err := socketGroupID("melusina", os.Getgid()); err == nil || !strings.Contains(err.Error(), "socket-group-invalid") {
		t.Fatalf("evidence-pack-custody-socket-group-invalid: conflicting group authorities admitted: %v", err)
	}
	path := filepath.Join(t.TempDir(), "pack.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := setSocketAccess(path, -1); err == nil || !strings.Contains(err.Error(), "socket-group-missing") {
		t.Fatalf("evidence-pack-custody-socket-group-missing: unset installer group admitted: %v", err)
	}
	if err := setSocketAccess(path, os.Getgid()); err != nil {
		t.Fatalf("grain socket access positive: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0660 {
		t.Fatalf("grain socket mode != 0660: %v %v", info, err)
	}
}
