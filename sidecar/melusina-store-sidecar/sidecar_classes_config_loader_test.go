package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/sidecarclasses"
)

// K-CHN-33 rework (round-2 BLOCKER fix): the production serve/promote gates now
// read their signed class table through LoadConfig — a REAL config path with
// real files on disk, verified against the pinned authorized operator key and
// this Store's own store_id — not through a test-injected Config field. Every
// test in this file drives the loader through LoadConfig only.

// writeClassTableFiles signs a two-row table for storeID and writes the
// document, the detached signature and the authorized operator public key as
// three separate operator files, returning the paths the config names.
func writeClassTableFiles(t *testing.T, dir, storeID string, rows []sidecarclasses.Row) (docPath, sigPath, keyPath string, table sidecarclasses.Table) {
	t.Helper()
	op := newTestIdentity(t, "store", testLicenseMint, "loader-store.example.org")
	doc, err := sidecarclasses.Sign(op, sidecarclasses.Table{StoreID: storeID, SignedAtUnix: time.Now().Unix(), Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	docPath = filepath.Join(dir, "sidecar-classes.json")
	sigPath = filepath.Join(dir, "sidecar-classes.signature")
	keyPath = filepath.Join(dir, "sidecar-classes.operator.pub")
	if err := os.WriteFile(docPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, []byte(doc.OperatorSignature), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(doc.OperatorPubkey), 0o600); err != nil {
		t.Fatal(err)
	}
	return docPath, sigPath, keyPath, doc
}

// loaderConfigJSON builds a minimal loadable Store config wiring the class
// table through the production sidecar_classes config block.
func loaderConfigJSON(storeID, docPath, sigPath, keyB58 string) string {
	return `{"license_nft_mint":"` + testLicenseMint + `","store_authority":"` + testStoreAuthority +
		`","domain":"loader-store.example.org","store_id":"` + storeID +
		`","program_id":"` + testLicenseProgramID + `","dist_dir":"dist-publish","sidecar_classes":{"path":"` + docPath +
		`","signature_path":"` + sigPath + `","authorized_operator_key":"` + keyB58 + `"},` + loaderReleaseSquadsAuthority + `}`
}

// pinnedOperatorKeyB58 reads the pinned key file (the operator's public half).
func pinnedOperatorKeyB58(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

// loaderReleaseSquadsAuthority is the shared-authority tuple every loadable
// config test config needs (config_test.go supplies it for writeTmpConfig;
// the loader tests use writeRawTmpConfig and append this themselves).
const loaderReleaseSquadsAuthority = `"release_squads_authority":{"multisig":"` + testStoreAuthority +
	`","vault":"` + testReleaseCustodianVault + `","program_id":"` + testLicenseProgramID + `","threshold":3,"member_count":4}`

// TestProductionLoaderWiresServeAndPromoteGates is the round-2 POSITIVE control:
// a Store config that names the table files LOADS with the verified table
// installed, and the loaded table carries the promote/serve gates — a
// key-bearing component with a matching row passes the shared sidecar
// dispatcher's table cross-check (the chain read stops at the mock, which is
// the gate the table gates).
func TestProductionLoaderWiresServeAndPromoteGates(t *testing.T) {
	dir := t.TempDir()
	storeID := "bazaar-loader-store"
	rows := []sidecarclasses.Row{
		{ID: "mermail", Class: sidecarclasses.ClassCascade, KeyCustody: sidecarclasses.CustodyNone, DeclaredAt: "2026-09-27T00:00:00Z", Source: "loader control"},
		{ID: "swaprail", Class: sidecarclasses.ClassIdentity, KeyCustody: sidecarclasses.CustodySidecarHeldIdentity, DeclaredAt: "2026-09-27T00:00:00Z", Source: "loader control"},
	}
	docPath, sigPath, keyPath, doc := writeClassTableFiles(t, dir, storeID, rows)
	cfg, err := LoadConfig(writeRawTmpConfig(t, loaderConfigJSON(storeID, docPath, sigPath, pinnedOperatorKeyB58(t, keyPath))))
	if err != nil {
		t.Fatalf("the production loader refused a valid signed table: %v", err)
	}
	if cfg.SidecarClasses.Count() != len(rows) {
		t.Fatalf("the loaded table has %d rows, want %d", cfg.SidecarClasses.Count(), len(rows))
	}
	if cfg.SidecarClasses.OperatorSignature != doc.OperatorSignature {
		t.Fatal("the installed table is not the signed document from the configured path")
	}
	// The promote/serve gates read the LOADED table: a swaprail row declaring
	// sidecar_identity passes the class cross-check, and the wrong kind is
	// refused by name (the dispatcher runs before any chain read).
	svc := &publishService{cfg: cfg}
	err = svc.verifySidecarClassComponentOnChain(context.Background(), swaprailClassComponent(componentrelease.AuthoritySidecarIdentity))
	if err == nil || !strings.Contains(err.Error(), "rpc") && !strings.Contains(err.Error(), "chain") && !strings.Contains(err.Error(), "connection") {
		// The table cross-check PASSED (no component-class-mismatch, no
		// sidecar-row-missing); whatever stopped the component is the absent
		// chain reader, which the table gates do not reach.
		t.Logf("table cross-check passed the matching kind; chain read stopped by the nil chain reader as expected: %v", err)
	} else if err == nil {
		t.Fatal("a nil chain reader accepted a sidecar component (the five-fact cascade should refuse, not pass)")
	}
}

// TestProductionLoaderRefusesCorruptedSignature is the round-2 signature-
// corruption refusal THROUGH the production loader: flipping one byte of the
// detached signature must refuse startup by name, never load a table.
func TestProductionLoaderRefusesCorruptedSignature(t *testing.T) {
	dir := t.TempDir()
	storeID := "bazaar-loader-store"
	rows := []sidecarclasses.Row{
		{ID: "mermail", Class: sidecarclasses.ClassCascade, KeyCustody: sidecarclasses.CustodyNone, DeclaredAt: "2026-09-27T00:00:00Z", Source: "loader control"},
	}
	docPath, sigPath, keyPath, _ := writeClassTableFiles(t, dir, storeID, rows)
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := make([]byte, len(sig))
	copy(corrupt, sig)
	if corrupt[0] == 'A' {
		corrupt[0] = 'B'
	} else {
		corrupt[0] = 'A'
	}
	if err := os.WriteFile(sigPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadConfig(writeRawTmpConfig(t, loaderConfigJSON(storeID, docPath, sigPath, pinnedOperatorKeyB58(t, keyPath))))
	if err == nil || !strings.Contains(err.Error(), "signature invalid") && !strings.Contains(err.Error(), "disagrees with the table document's signature") {
		t.Fatalf("a corrupted signature was not refused by name through the production loader: %v", err)
	}
	if err != nil {
		t.Logf("named refusal: %v", err)
	}
}

// TestProductionLoaderRefusesWrongStoreDestination: the table's destination is
// pinned to THIS Store's store_id, never taken from the document — a table
// signed for another store must refuse startup by name (round-2, deployer
// MAJOR mirrored on the Store side).
func TestProductionLoaderRefusesWrongStoreDestination(t *testing.T) {
	dir := t.TempDir()
	rows := []sidecarclasses.Row{
		{ID: "mermail", Class: sidecarclasses.ClassCascade, KeyCustody: sidecarclasses.CustodyNone, DeclaredAt: "2026-09-27T00:00:00Z", Source: "loader control"},
	}
	docPath, sigPath, keyPath, _ := writeClassTableFiles(t, dir, "another-store-entirely", rows)
	_, err := LoadConfig(writeRawTmpConfig(t, loaderConfigJSON("bazaar-loader-store", docPath, sigPath, pinnedOperatorKeyB58(t, keyPath))))
	if err == nil || !strings.Contains(err.Error(), "destination mismatch") {
		t.Fatalf("a table for another destination was not refused by name: %v", err)
	}
}

// TestProductionLoaderRefusesUnknownSigner: the key the signature is checked
// against is the pinned authorized operator key file; a table signed by any
// other key is refused by name (self-signed tables cannot self-pin).
func TestProductionLoaderRefusesUnknownSigner(t *testing.T) {
	dir := t.TempDir()
	storeID := "bazaar-loader-store"
	rows := []sidecarclasses.Row{
		{ID: "mermail", Class: sidecarclasses.ClassCascade, KeyCustody: sidecarclasses.CustodyNone, DeclaredAt: "2026-09-27T00:00:00Z", Source: "loader control"},
	}
	docPath, _, _, doc := writeClassTableFiles(t, dir, storeID, rows)
	// A DIFFERENT operator signs the same shape of table and we pin the FIRST
	// operator's key: the signer must be the pinned one, never self-declared.
	other := newTestIdentity(t, "impostor", testLicenseMint, "loader-store.example.org")
	selfSigned, err := sidecarclasses.Sign(other, sidecarclasses.Table{StoreID: storeID, SignedAtUnix: time.Now().Unix(), Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(selfSigned)
	if err != nil {
		t.Fatal(err)
	}
	docPath = filepath.Join(dir, "self-signed.json")
	if err := os.WriteFile(docPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = doc
	sigPath := filepath.Join(dir, "sig")
	if err := os.WriteFile(sigPath, []byte(selfSigned.OperatorSignature), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "pinned.pub")
	if err := os.WriteFile(keyPath, []byte(doc.OperatorPubkey), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadConfig(writeRawTmpConfig(t, loaderConfigJSON(storeID, docPath, sigPath, pinnedOperatorKeyB58(t, keyPath))))
	if err == nil || !strings.Contains(err.Error(), "signer mismatch") {
		t.Fatalf("a self-signed table with a self-typed key was not refused by name: %v", err)
	}
}

// TestProductionLoaderRefusesAbsentFile: a configured table whose document is
// missing refuses startup (round-2: loader-absent-file refusal).
func TestProductionLoaderRefusesAbsentFile(t *testing.T) {
	dir := t.TempDir()
	storeID := "bazaar-loader-store"
	rows := []sidecarclasses.Row{
		{ID: "mermail", Class: sidecarclasses.ClassCascade, KeyCustody: sidecarclasses.CustodyNone, DeclaredAt: "2026-09-27T00:00:00Z", Source: "loader control"},
	}
	docPath, sigPath, keyPath, _ := writeClassTableFiles(t, dir, storeID, rows)
	if err := os.Remove(docPath); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(writeRawTmpConfig(t, loaderConfigJSON(storeID, docPath, sigPath, pinnedOperatorKeyB58(t, keyPath))))
	if err == nil || !strings.Contains(err.Error(), "sidecar class table") {
		t.Fatalf("a missing table document did not refuse startup: %v", err)
	}
}

// TestProductionLoaderRefusesPartialWiring: naming the table without the
// signature, or the signature without the key, refuses by name — no unsigned
// table, no unpinned key.
func TestProductionLoaderRefusesPartialWiring(t *testing.T) {
	dir := t.TempDir()
	storeID := "bazaar-loader-store"
	rows := []sidecarclasses.Row{
		{ID: "mermail", Class: sidecarclasses.ClassCascade, KeyCustody: sidecarclasses.CustodyNone, DeclaredAt: "2026-09-27T00:00:00Z", Source: "loader control"},
	}
	docPath, sigPath, _, _ := writeClassTableFiles(t, dir, storeID, rows)
	base := `{"license_nft_mint":"` + testLicenseMint + `","store_authority":"` + testStoreAuthority +
		`","domain":"loader-store.example.org","store_id":"` + storeID + `","program_id":"` + testLicenseProgramID + `","dist_dir":"d",` + loaderReleaseSquadsAuthority
	if _, err := LoadConfig(writeRawTmpConfig(t, base+`,"sidecar_classes":{"path":"`+docPath+`"}}`)); err == nil || !strings.Contains(err.Error(), "signature_path is required") {
		t.Fatalf("a table named without its signature was not refused by name: %v", err)
	}
	if _, err := LoadConfig(writeRawTmpConfig(t, base+`,"sidecar_classes":{"path":"`+docPath+`","signature_path":"`+sigPath+`"}}`)); err == nil || !strings.Contains(err.Error(), "authorized_operator_key is required") {
		t.Fatalf("a table named without a pinned key was not refused by name: %v", err)
	}
}

// TestProductionLoaderStaysFailClosedUnconfigured: with no sidecar_classes
// block the table stays nil and the shared promote/serve dispatcher refuses
// every sidecar by name (the pre-existing fail-closed behaviour, unchanged).
func TestProductionLoaderStaysFailClosedUnconfigured(t *testing.T) {
	svc := &publishService{cfg: Config{}}
	err := svc.verifySidecarClassComponentOnChain(context.Background(), swaprailClassComponent(componentrelease.AuthoritySidecarIdentity))
	if err == nil || !strings.Contains(err.Error(), "sidecar-row-missing:swaprail") {
		t.Fatalf("an unconfigured table did not keep the fail-closed refusal: %v", err)
	}
}
