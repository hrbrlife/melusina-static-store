package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type testFixture struct {
	opts       options
	args       []string
	policy     securityPolicy
	migrations string
	receipts   string
}

func TestPrepareCatalogV104CreatesDurableAuthorizationAndIsIdempotent(t *testing.T) {
	f := newTestFixture(t)
	var out bytes.Buffer
	if err := run(f.args, &out, f.policy); err != nil {
		t.Fatalf("first run: %v", err)
	}
	var got result
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.State != "seeded" || !isCanonicalHex(got.LedgerID, 32) {
		t.Fatalf("unexpected result: %+v", got)
	}
	if got.ChainReceiptVerification != "strict-schema-and-archive-hash-binding" {
		t.Fatalf("receipt trust seam not explicit: %+v", got)
	}

	assertMode(t, f.migrations, 0700)
	assertMode(t, f.receipts, 0700)
	assertMode(t, filepath.Join(f.migrations, writerLockName), 0600)
	assertMode(t, filepath.Join(f.migrations, catalogStateName), 0600)
	assertMode(t, filepath.Join(f.receipts, catalogStateName), 0600)

	var state migrationState
	readTestJSON(t, filepath.Join(f.migrations, catalogStateName), &state)
	if state.State != "authorized" || state.LedgerID != got.LedgerID || state.FromVersion != fromVersion || state.ToVersion != toVersion {
		t.Fatalf("unexpected migration state: %+v", state)
	}

	var second bytes.Buffer
	if err := run(f.args, &second, f.policy); err != nil {
		t.Fatalf("idempotent run: %v", err)
	}
	var again result
	if err := json.Unmarshal(second.Bytes(), &again); err != nil {
		t.Fatal(err)
	}
	if again.LedgerID != got.LedgerID {
		t.Fatalf("idempotent run changed ledger ID: %s != %s", again.LedgerID, got.LedgerID)
	}
}

func TestPrepareCatalogV104ResumesOnlyMatchingSeeding(t *testing.T) {
	f := newTestFixture(t)
	crashCount := 0
	f.policy.afterWriterLock = func() error {
		crashCount++
		if crashCount == 1 {
			return errors.New("injected crash")
		}
		return nil
	}
	if _, err := prepareCatalogV104(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "injected crash") {
		t.Fatalf("expected injected failure, got %v", err)
	}
	var seeding applyReceipt
	readTestJSON(t, filepath.Join(f.receipts, catalogStateName), &seeding)
	if seeding.State != "seeding" {
		t.Fatalf("state after crash = %q, want seeding", seeding.State)
	}
	if _, err := os.Stat(filepath.Join(f.migrations, catalogStateName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("migration state created before injected crash: %v", err)
	}

	res, err := prepareCatalogV104(f.opts, f.policy)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if res.LedgerID != seeding.LedgerID || res.State != "seeded" {
		t.Fatalf("resume did not preserve seeding identity: %+v vs %+v", res, seeding)
	}
}

func TestSeededMissingMigrationRefusesWithoutReseed(t *testing.T) {
	f := newTestFixture(t)
	if _, err := prepareCatalogV104(f.opts, f.policy); err != nil {
		t.Fatal(err)
	}
	migrationPath := filepath.Join(f.migrations, catalogStateName)
	if err := os.Remove(migrationPath); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCatalogV104(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "refusing reseed") {
		t.Fatalf("seeded missing migration was not refused: %v", err)
	}
	if _, err := os.Stat(migrationPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing migration was recreated: %v", err)
	}
}

func TestExistingReceiptMismatchRefuses(t *testing.T) {
	f := newTestFixture(t)
	if _, err := prepareCatalogV104(f.opts, f.policy); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(f.opts.newELF), "other-new-elf")
	if err := os.WriteFile(other, []byte("different 1.0.4 binary"), 0755); err != nil {
		t.Fatal(err)
	}
	f.opts.newELF = other
	f.opts.newELFSHA256 = fileSHA256(t, other)
	if _, err := prepareCatalogV104(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "existing apply receipt mismatch") {
		t.Fatalf("mismatched reapply was accepted: %v", err)
	}
}

func TestInputSymlinkAndUnknownForceFlagRefuse(t *testing.T) {
	f := newTestFixture(t)
	linked := filepath.Join(filepath.Dir(f.opts.archive), "archive-link")
	if err := os.Symlink(f.opts.archive, linked); err != nil {
		t.Fatal(err)
	}
	f.opts.archive = linked
	if _, err := prepareCatalogV104(f.opts, f.policy); err == nil {
		t.Fatal("symlink archive was accepted")
	}

	args := append(append([]string{}, f.args...), "--force")
	if _, err := parseOptions(args); err == nil {
		t.Fatal("unsupported --force flag was accepted")
	}
}

func TestChainReceiptIsStrictAndArchiveBound(t *testing.T) {
	f := newTestFixture(t)
	var receipt map[string]any
	raw, err := os.ReadFile(f.opts.chainReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt["unexpected"] = true
	writeTestJSON(t, f.opts.chainReceipt, receipt, 0600)
	if _, err := prepareCatalogV104(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown receipt field accepted: %v", err)
	}

	delete(receipt, "unexpected")
	receipt["installerSha256"] = strings.Repeat("0", 64)
	writeTestJSON(t, f.opts.chainReceipt, receipt, 0600)
	if _, err := prepareCatalogV104(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("unbound chain receipt accepted: %v", err)
	}
}

func TestPersistentModeMismatchRefuses(t *testing.T) {
	f := newTestFixture(t)
	if err := os.Mkdir(f.migrations, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCatalogV104(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "want 0700") {
		t.Fatalf("unsafe persistent directory mode accepted: %v", err)
	}
}

func newTestFixture(t *testing.T) testFixture {
	t.Helper()
	root := t.TempDir()
	archive := filepath.Join(root, "store-1.0.4.tar.xz")
	oldELF := filepath.Join(root, "installed-1.0.3")
	newELF := filepath.Join(root, "melusina-store-sidecar")
	for path, contents := range map[string]string{
		archive: "governed store archive", oldELF: "installed 1.0.3 binary", newELF: "deterministic 1.0.4 binary",
	} {
		if err := os.WriteFile(path, []byte(contents), 0755); err != nil {
			t.Fatal(err)
		}
	}
	archiveHash := fileSHA256(t, archive)
	chainPath := filepath.Join(root, "verified-InstallerReleaseEntry-receipt.json")
	writeTestJSON(t, chainPath, chainVerificationReceipt{
		Schema: chainReceiptSchema, InstallerSHA256: archiveHash,
		InstallerReleasePDA: "installer-release-pda", ProgramID: "program-id", MasterNFTMint: "master-mint",
		Status: "active", VerifiedSlot: 12345, VerifiedAtUnix: 1_700_000_000,
	}, 0600)
	persist := filepath.Join(root, "persist")
	if err := os.Mkdir(persist, 0700); err != nil {
		t.Fatal(err)
	}
	migrations := filepath.Join(persist, "migrations")
	receipts := filepath.Join(persist, "update-receipts")
	opts := options{
		archive: archive, archiveSHA256: archiveHash, chainReceipt: chainPath,
		installedELF: oldELF, expectedOldELFSHA256: fileSHA256(t, oldELF),
		newELF: newELF, newELFSHA256: fileSHA256(t, newELF),
		migrationStateDir: migrations, updateReceiptDir: receipts,
	}
	args := []string{
		prepareCatalogV104Command,
		"--archive", opts.archive, "--archive-sha256", opts.archiveSHA256,
		"--chain-receipt", opts.chainReceipt,
		"--installed-elf", opts.installedELF, "--expected-old-elf-sha256", opts.expectedOldELFSHA256,
		"--new-elf", opts.newELF, "--new-elf-sha256", opts.newELFSHA256,
		"--migration-state-dir", opts.migrationStateDir, "--update-receipt-dir", opts.updateReceiptDir,
	}
	return testFixture{
		opts: opts, args: args, migrations: migrations, receipts: receipts,
		policy: securityPolicy{expectedUID: uint32(os.Geteuid())},
	}
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func writeTestJSON(t *testing.T, path string, value any, mode os.FileMode) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), mode); err != nil {
		t.Fatal(err)
	}
}

func readTestJSON(t *testing.T, path string, dst any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatal(err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %04o, want %04o", path, info.Mode().Perm(), want)
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	if st.Uid != uint32(os.Geteuid()) {
		t.Fatalf("%s uid = %d, want %d", path, st.Uid, os.Geteuid())
	}
}
