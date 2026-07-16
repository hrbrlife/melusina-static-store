package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

type testFixture struct {
	opts       options
	args       []string
	policy     securityPolicy
	migrations string
	receipts   string
	chain      *mockInstallerVerifier
}

type mockInstallerVerifier struct {
	hash    [32]byte
	status  verify.AttestationStatus
	err     error
	wantPDA string
	calls   int
}

func (m *mockInstallerVerifier) FetchInstallerReleaseEntry(_ context.Context, got string) ([32]byte, verify.AttestationStatus, error) {
	m.calls++
	if m.wantPDA != "" && got != m.wantPDA {
		return [32]byte{}, 0, errors.New("unexpected derived PDA: " + got)
	}
	return m.hash, m.status, m.err
}

func TestPrepareStoreUpdateCreatesDurableAuthorizationAndIsIdempotent(t *testing.T) {
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
	if got.ChainReceiptVerification != "independent-active-pda-fetch-and-strict-receipt-binding" {
		t.Fatalf("receipt trust seam not explicit: %+v", got)
	}

	assertMode(t, f.migrations, 0700)
	assertMode(t, f.receipts, 0700)
	assertMode(t, filepath.Join(f.migrations, writerLockName), 0600)
	assertMode(t, filepath.Join(f.receipts, applyReceiptName), 0600)

	var receipt applyReceipt
	readTestJSON(t, filepath.Join(f.receipts, applyReceiptName), &receipt)
	if receipt.State != "seeded" || receipt.LedgerID != got.LedgerID ||
		receipt.FromVersion != fromVersion || receipt.ToVersion != toVersion {
		t.Fatalf("unexpected apply receipt: %+v", receipt)
	}
	if receipt.FromVersion != "1.0.5" || receipt.ToVersion != "1.0.6" {
		t.Fatalf("apply receipt does not stamp the governed 1.0.5->1.0.6 transition: %+v", receipt)
	}

	// The 1.0.5->1.0.6 hop is a pure binary swap: it carries no catalog
	// migration. The store reads the pre-existing committed
	// migrations/catalog-v104.json record at boot, so this helper must never
	// create, touch, or supersede anything in the migration-state directory
	// other than the writer lock it owns.
	assertMigrationDirHoldsOnlyWriterLock(t, f.migrations)

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
	if f.chain.calls != 2 {
		t.Fatalf("independent chain fetch calls = %d, want 2", f.chain.calls)
	}
}

func TestPrepareStoreUpdateLocksBeforeCreatingPersistentState(t *testing.T) {
	f := newTestFixture(t)
	crashCount := 0
	f.policy.afterWriterLock = func() error {
		crashCount++
		if crashCount == 1 {
			return errors.New("injected crash")
		}
		return nil
	}
	if _, err := prepareStoreUpdate(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "injected crash") {
		t.Fatalf("expected injected failure, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.receipts, applyReceiptName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("apply receipt created before writer ownership: %v", err)
	}
	assertMigrationDirHoldsOnlyWriterLock(t, f.migrations)

	res, err := prepareStoreUpdate(f.opts, f.policy)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if res.State != "seeded" || res.LedgerID == "" {
		t.Fatalf("retry did not seed a fresh identity: %+v", res)
	}
}

func TestPrepareStoreUpdateRefusesHeldWriterLockWithoutStateMutation(t *testing.T) {
	f := newTestFixture(t)
	lockPath := filepath.Join(f.migrations, writerLockName)
	if err := ensureSecureDir(f.migrations, f.policy.expectedUID); err != nil {
		t.Fatal(err)
	}
	if err := createOrValidateWriterLock(lockPath, f.policy.expectedUID, f.policy.expectedGID); err != nil {
		t.Fatal(err)
	}
	held, err := acquireWriterLock(lockPath, f.policy.expectedUID, f.policy.expectedGID)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if _, err := prepareStoreUpdate(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "writer lock ownership") {
		t.Fatalf("helper entered while writer lock held: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.receipts, applyReceiptName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("persistent state changed while lock held: %v", err)
	}
	assertMigrationDirHoldsOnlyWriterLock(t, f.migrations)
}

func TestPrepareStoreUpdateRejectsWriterLockGIDMismatch(t *testing.T) {
	f := newTestFixture(t)
	f.policy.expectedGID++
	if _, err := prepareStoreUpdate(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "uid:gid") {
		t.Fatalf("helper accepted writer.lock GID mismatch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.receipts, applyReceiptName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("receipt created despite writer.lock GID mismatch: %v", err)
	}
}

// A crash between the durable "seeding" receipt write and the advance to
// "seeded" must resume onto the same governed identity rather than mint a new
// ledger ID.
func TestSeedingReceiptResumesOntoTheSameIdentity(t *testing.T) {
	f := newTestFixture(t)
	if _, err := prepareStoreUpdate(f.opts, f.policy); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(f.receipts, applyReceiptName)
	var receipt applyReceipt
	readTestJSON(t, receiptPath, &receipt)
	receipt.State = "seeding"
	if err := replaceJSONDurable(receiptPath, receipt, f.policy.expectedUID); err != nil {
		t.Fatal(err)
	}
	got, err := prepareStoreUpdate(f.opts, f.policy)
	if err != nil {
		t.Fatalf("resume seeding receipt: %v", err)
	}
	if got.State != "seeded" || got.LedgerID != receipt.LedgerID {
		t.Fatalf("resume changed identity: %+v", got)
	}
	assertMigrationDirHoldsOnlyWriterLock(t, f.migrations)
}

func TestExistingReceiptMismatchRefuses(t *testing.T) {
	f := newTestFixture(t)
	if _, err := prepareStoreUpdate(f.opts, f.policy); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(f.opts.installedELF), "other-old-elf")
	if err := os.WriteFile(other, []byte("different installed 1.0.3 binary"), 0755); err != nil {
		t.Fatal(err)
	}
	f.opts.installedELF = other
	f.opts.expectedOldELFSHA256 = fileSHA256(t, other)
	if _, err := prepareStoreUpdate(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "existing apply receipt mismatch") {
		t.Fatalf("mismatched reapply was accepted: %v", err)
	}
}

func TestIndependentChainVerificationRefusesWrongHashOrInactive(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*mockInstallerVerifier)
		want   string
	}{
		{"wrong hash", func(m *mockInstallerVerifier) { m.hash[0] ^= 0xff }, "on-chain installer hash"},
		{"revoked", func(m *mockInstallerVerifier) { m.status = verify.AttestationStatusRevoked }, "on-chain status Revoked"},
		{"rpc failure", func(m *mockInstallerVerifier) { m.err = errors.New("rpc unavailable") }, "independent fetch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestFixture(t)
			tc.mutate(f.chain)
			if _, err := prepareStoreUpdate(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("untrusted chain state accepted: %v", err)
			}
		})
	}
}

func TestArchiveELFBindingRefusesMissingDuplicateAndTraversal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []tarEntry
		want    string
	}{
		{"missing", []tarEntry{{"bin/other", "elf"}}, "not found"},
		{"duplicate", []tarEntry{{"bin/melusina-store-sidecar", "deterministic 1.0.6 binary"}, {"bin/melusina-store-sidecar", "deterministic 1.0.6 binary"}}, "duplicate member"},
		{"traversal", []tarEntry{{"../escape", "bad"}, {"bin/melusina-store-sidecar", "deterministic 1.0.6 binary"}}, "unsafe member"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTestFixture(t)
			writeTarXZ(t, f.opts.archive, tc.entries)
			if _, err := hashXZTarMember(f.opts.archive, f.opts.newELFMember); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unsafe archive accepted: %v", err)
			}
		})
	}
}

func TestInputSymlinkAndUnknownForceFlagRefuse(t *testing.T) {
	f := newTestFixture(t)
	linked := filepath.Join(filepath.Dir(f.opts.archive), "archive-link")
	if err := os.Symlink(f.opts.archive, linked); err != nil {
		t.Fatal(err)
	}
	f.opts.archive = linked
	if _, err := prepareStoreUpdate(f.opts, f.policy); err == nil {
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
	if _, err := prepareStoreUpdate(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown receipt field accepted: %v", err)
	}

	delete(receipt, "unexpected")
	receipt["installerSha256"] = strings.Repeat("0", 64)
	writeTestJSON(t, f.opts.chainReceipt, receipt, 0600)
	if _, err := prepareStoreUpdate(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("unbound chain receipt accepted: %v", err)
	}
}

func TestPersistentModeMismatchRefuses(t *testing.T) {
	f := newTestFixture(t)
	if err := os.Mkdir(f.migrations, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareStoreUpdate(f.opts, f.policy); err == nil || !strings.Contains(err.Error(), "want 0700") {
		t.Fatalf("unsafe persistent directory mode accepted: %v", err)
	}
}

func newTestFixture(t *testing.T) testFixture {
	t.Helper()
	root := t.TempDir()
	archive := filepath.Join(root, "store-1.0.6.tar.xz")
	oldELF := filepath.Join(root, "installed-1.0.5")
	newELF := filepath.Join(root, "melusina-store-sidecar")
	for path, contents := range map[string]string{
		oldELF: "installed 1.0.5 binary", newELF: "deterministic 1.0.6 binary",
	} {
		if err := os.WriteFile(path, []byte(contents), 0755); err != nil {
			t.Fatal(err)
		}
	}
	member := "bin/melusina-store-sidecar"
	writeTarXZ(t, archive, []tarEntry{{member, "deterministic 1.0.6 binary"}})
	archiveHash := fileSHA256(t, archive)
	archiveHashBytes := mustHash32(t, archiveHash)
	masterMint, err := primitives.PubkeyFromBase58(canonicalLicenseProgramID)
	if err != nil {
		t.Fatal(err)
	}
	programID, err := primitives.PubkeyFromBase58(canonicalLicenseProgramID)
	if err != nil {
		t.Fatal(err)
	}
	releasePDA, _, err := pda.InstallerRelease(masterMint, archiveHashBytes, programID)
	if err != nil {
		t.Fatal(err)
	}
	chainPath := filepath.Join(root, "verified-InstallerReleaseEntry-receipt.json")
	writeTestJSON(t, chainPath, chainVerificationReceipt{
		Schema: chainReceiptSchema, InstallerSHA256: archiveHash,
		InstallerReleasePDA: releasePDA.Base58(), ProgramID: canonicalLicenseProgramID, MasterNFTMint: masterMint.Base58(),
		Status: "Active", VerifiedSlot: 12345, VerifiedAtUnix: 1_700_000_000,
	}, 0600)
	persist := filepath.Join(root, "persist")
	if err := os.Mkdir(persist, 0700); err != nil {
		t.Fatal(err)
	}
	migrations := filepath.Join(persist, "migrations")
	receipts := filepath.Join(persist, "update-receipts")
	opts := options{
		archive: archive, archiveSHA256: archiveHash, chainReceipt: chainPath,
		rpcURL: "https://rpc.example.invalid", masterNFTMint: masterMint.Base58(),
		installedELF: oldELF, expectedOldELFSHA256: fileSHA256(t, oldELF),
		newELF: newELF, newELFMember: member, newELFSHA256: fileSHA256(t, newELF),
		migrationStateDir: migrations, updateReceiptDir: receipts,
	}
	args := []string{
		prepareStoreUpdateCommand,
		"--archive", opts.archive, "--archive-sha256", opts.archiveSHA256,
		"--chain-receipt", opts.chainReceipt,
		"--rpc-url", opts.rpcURL, "--master-nft-mint", opts.masterNFTMint,
		"--installed-elf", opts.installedELF, "--expected-old-elf-sha256", opts.expectedOldELFSHA256,
		"--new-elf", opts.newELF, "--new-elf-member", opts.newELFMember, "--new-elf-sha256", opts.newELFSHA256,
		"--migration-state-dir", opts.migrationStateDir, "--update-receipt-dir", opts.updateReceiptDir,
	}
	mock := &mockInstallerVerifier{hash: archiveHashBytes, status: verify.AttestationStatusActive, wantPDA: releasePDA.Base58()}
	return testFixture{
		opts: opts, args: args, migrations: migrations, receipts: receipts,
		chain:  mock,
		policy: securityPolicy{expectedUID: uint32(os.Geteuid()), expectedGID: uint32(os.Getegid()), newChainVerifier: func(string) installerReleaseVerifier { return mock }},
	}
}

type tarEntry struct{ name, contents string }

func writeTarXZ(t *testing.T, dst string, entries []tarEntry) {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, entry := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0755, Size: int64(len(entry.contents)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(entry.contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(xzExecutable, "--compress", "--stdout")
	cmd.Stdin = bytes.NewReader(raw.Bytes())
	compressed, err := cmd.Output()
	if err != nil {
		t.Fatalf("create xz fixture: %v", err)
	}
	if err := os.WriteFile(dst, compressed, 0600); err != nil {
		t.Fatal(err)
	}
}

func mustHash32(t *testing.T, value string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad test hash %q: %v", value, err)
	}
	var out [32]byte
	copy(out[:], raw)
	return out
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

// assertMigrationDirHoldsOnlyWriterLock pins the 1.0.5->1.0.6 invariant that
// this helper emits no migration state at all. The store's own boot path still
// reads the pre-existing committed migrations/catalog-v104.json record, so any
// file this helper writes there beyond the writer lock it owns would be a
// regression against a live install.
func assertMigrationDirHoldsOnlyWriterLock(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != writerLockName {
			t.Fatalf("migration-state directory holds unexpected entry %q; the helper must not write migration state", entry.Name())
		}
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
