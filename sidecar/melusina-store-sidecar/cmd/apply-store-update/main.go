// Command apply-store-update performs narrowly-scoped, fail-closed host-side
// preparation for governed store updates. It is intentionally not a generic
// migration/reset utility.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	prepareCatalogV104Command = "prepare-catalog-v104"
	chainReceiptSchema        = "melusina-installer-release-chain-verification-v1"
	applyReceiptSchema        = "melusina-store-update-apply-v1"
	migrationStateSchema      = "melusina-catalog-v104-migration-v1"
	fromVersion               = "1.0.3"
	toVersion                 = "1.0.4"
	catalogStateName          = "catalog-v104.json"
	writerLockName            = "writer.lock"
	maxChainReceiptBytes      = 64 << 10
	maxPersistentJSONBytes    = 64 << 10
	maxArchiveBytes           = int64(8 << 30)
	maxELFBytes               = int64(1 << 30)
)

type options struct {
	archive              string
	archiveSHA256        string
	chainReceipt         string
	installedELF         string
	expectedOldELFSHA256 string
	newELF               string
	newELFSHA256         string
	migrationStateDir    string
	updateReceiptDir     string
}

// chainVerificationReceipt is a bounded handoff from the governed pull/chain
// verification step. This command validates its exact schema, Active verdict,
// slot, and archive-hash binding. There is currently no shared cryptographic
// verifier for this receipt in the repository; callers must treat the receipt
// file as root-controlled evidence produced by that earlier verification step.
type chainVerificationReceipt struct {
	Schema              string `json:"schema"`
	InstallerSHA256     string `json:"installerSha256"`
	InstallerReleasePDA string `json:"installerReleasePda"`
	ProgramID           string `json:"programId"`
	MasterNFTMint       string `json:"masterNftMint"`
	Status              string `json:"status"`
	VerifiedSlot        uint64 `json:"verifiedSlot"`
	VerifiedAtUnix      int64  `json:"verifiedAtUnix"`
}

type applyReceipt struct {
	Schema                     string `json:"schema"`
	State                      string `json:"state"`
	FromVersion                string `json:"fromVersion"`
	ToVersion                  string `json:"toVersion"`
	ArchiveSHA256              string `json:"archiveSha256"`
	ChainReceiptSHA256         string `json:"chainReceiptSha256"`
	InstallerReleasePDA        string `json:"installerReleasePda"`
	ChainVerifiedSlot          uint64 `json:"chainVerifiedSlot"`
	ExpectedInstalledELFSHA256 string `json:"expectedInstalledElfSha256"`
	NewELFSHA256               string `json:"newElfSha256"`
	LedgerID                   string `json:"ledgerId"`
}

type migrationState struct {
	Schema                     string `json:"schema"`
	State                      string `json:"state"`
	FromVersion                string `json:"fromVersion"`
	ToVersion                  string `json:"toVersion"`
	SourceChainReceiptSHA256   string `json:"sourceChainReceiptSha256"`
	SourceInstallerReleasePDA  string `json:"sourceInstallerReleasePda"`
	ArchiveSHA256              string `json:"archiveSha256"`
	ExpectedInstalledELFSHA256 string `json:"expectedInstalledElfSha256"`
	NewELFSHA256               string `json:"newElfSha256"`
	LedgerID                   string `json:"ledgerId"`
}

type result struct {
	Schema                   string `json:"schema"`
	State                    string `json:"state"`
	LedgerID                 string `json:"ledgerId"`
	ChainReceiptVerification string `json:"chainReceiptVerification"`
}

type securityPolicy struct {
	expectedUID          uint32
	requireEffectiveRoot bool
	afterWriterLock      func() error
}

func productionSecurityPolicy() securityPolicy {
	return securityPolicy{expectedUID: 0, requireEffectiveRoot: true}
}

func main() {
	if err := run(os.Args[1:], os.Stdout, productionSecurityPolicy()); err != nil {
		fmt.Fprintf(os.Stderr, "apply-store-update: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer, policy securityPolicy) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	res, err := prepareCatalogV104(opts, policy)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

func parseOptions(args []string) (options, error) {
	if len(args) == 0 || args[0] != prepareCatalogV104Command {
		return options{}, fmt.Errorf("exact subcommand %q is required", prepareCatalogV104Command)
	}
	var opts options
	fs := flag.NewFlagSet("apply-store-update "+prepareCatalogV104Command, flag.ContinueOnError)
	fs.StringVar(&opts.archive, "archive", "", "pulled store 1.0.4 archive")
	fs.StringVar(&opts.archiveSHA256, "archive-sha256", "", "verified archive sha256")
	fs.StringVar(&opts.chainReceipt, "chain-receipt", "", "bounded InstallerReleaseEntry verification receipt")
	fs.StringVar(&opts.installedELF, "installed-elf", "", "installed 1.0.3 store ELF")
	fs.StringVar(&opts.expectedOldELFSHA256, "expected-old-elf-sha256", "", "expected installed 1.0.3 ELF sha256")
	fs.StringVar(&opts.newELF, "new-elf", "", "pulled 1.0.4 store ELF")
	fs.StringVar(&opts.newELFSHA256, "new-elf-sha256", "", "verified 1.0.4 ELF sha256")
	fs.StringVar(&opts.migrationStateDir, "migration-state-dir", "", "persistent migration-state directory")
	fs.StringVar(&opts.updateReceiptDir, "update-receipt-dir", "", "persistent update-receipt directory")
	if err := fs.Parse(args[1:]); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional args: %v", fs.Args())
	}
	for name, value := range map[string]string{
		"--archive": opts.archive, "--archive-sha256": opts.archiveSHA256,
		"--chain-receipt": opts.chainReceipt, "--installed-elf": opts.installedELF,
		"--expected-old-elf-sha256": opts.expectedOldELFSHA256,
		"--new-elf":                 opts.newELF, "--new-elf-sha256": opts.newELFSHA256,
		"--migration-state-dir": opts.migrationStateDir, "--update-receipt-dir": opts.updateReceiptDir,
	} {
		if strings.TrimSpace(value) == "" {
			return options{}, fmt.Errorf("%s is required", name)
		}
	}
	var err error
	if opts.archiveSHA256, err = canonicalSHA256(opts.archiveSHA256); err != nil {
		return options{}, fmt.Errorf("--archive-sha256: %w", err)
	}
	if opts.expectedOldELFSHA256, err = canonicalSHA256(opts.expectedOldELFSHA256); err != nil {
		return options{}, fmt.Errorf("--expected-old-elf-sha256: %w", err)
	}
	if opts.newELFSHA256, err = canonicalSHA256(opts.newELFSHA256); err != nil {
		return options{}, fmt.Errorf("--new-elf-sha256: %w", err)
	}
	if !filepath.IsAbs(opts.migrationStateDir) || filepath.Clean(opts.migrationStateDir) != opts.migrationStateDir {
		return options{}, errors.New("--migration-state-dir must be an absolute clean path")
	}
	if !filepath.IsAbs(opts.updateReceiptDir) || filepath.Clean(opts.updateReceiptDir) != opts.updateReceiptDir {
		return options{}, errors.New("--update-receipt-dir must be an absolute clean path")
	}
	if opts.migrationStateDir == opts.updateReceiptDir || filepath.Dir(opts.migrationStateDir) != filepath.Dir(opts.updateReceiptDir) {
		return options{}, errors.New("migration-state and update-receipt directories must be distinct siblings")
	}
	return opts, nil
}

func prepareCatalogV104(opts options, policy securityPolicy) (result, error) {
	if policy.requireEffectiveRoot && os.Geteuid() != 0 {
		return result{}, errors.New("must run as root")
	}
	archiveHash, err := hashRegularNoFollow(opts.archive, maxArchiveBytes)
	if err != nil {
		return result{}, fmt.Errorf("archive: %w", err)
	}
	if archiveHash != opts.archiveSHA256 {
		return result{}, fmt.Errorf("archive sha256 mismatch: got %s want %s", archiveHash, opts.archiveSHA256)
	}
	oldHash, err := hashRegularNoFollow(opts.installedELF, maxELFBytes)
	if err != nil {
		return result{}, fmt.Errorf("installed ELF: %w", err)
	}
	if oldHash != opts.expectedOldELFSHA256 {
		return result{}, fmt.Errorf("installed ELF sha256 mismatch: got %s want %s", oldHash, opts.expectedOldELFSHA256)
	}
	newHash, err := hashRegularNoFollow(opts.newELF, maxELFBytes)
	if err != nil {
		return result{}, fmt.Errorf("new ELF: %w", err)
	}
	if newHash != opts.newELFSHA256 {
		return result{}, fmt.Errorf("new ELF sha256 mismatch: got %s want %s", newHash, opts.newELFSHA256)
	}

	chainRaw, err := readRegularNoFollow(opts.chainReceipt, maxChainReceiptBytes)
	if err != nil {
		return result{}, fmt.Errorf("chain receipt: %w", err)
	}
	var chain chainVerificationReceipt
	if err := decodeStrictJSON(chainRaw, &chain); err != nil {
		return result{}, fmt.Errorf("chain receipt: %w", err)
	}
	if err := validateChainReceipt(chain, opts.archiveSHA256); err != nil {
		return result{}, fmt.Errorf("chain receipt: %w", err)
	}
	chainHashBytes := sha256.Sum256(chainRaw)
	chainHash := hex.EncodeToString(chainHashBytes[:])

	if err := ensureSecureDir(opts.migrationStateDir, policy.expectedUID); err != nil {
		return result{}, fmt.Errorf("migration-state directory: %w", err)
	}
	if err := ensureSecureDir(opts.updateReceiptDir, policy.expectedUID); err != nil {
		return result{}, fmt.Errorf("update-receipt directory: %w", err)
	}

	receiptPath := filepath.Join(opts.updateReceiptDir, catalogStateName)
	migrationPath := filepath.Join(opts.migrationStateDir, catalogStateName)
	lockPath := filepath.Join(opts.migrationStateDir, writerLockName)

	var receipt applyReceipt
	receiptExists, err := readSecureJSONIfExists(receiptPath, policy.expectedUID, &receipt)
	if err != nil {
		return result{}, fmt.Errorf("apply receipt: %w", err)
	}
	if !receiptExists {
		ledgerID, err := randomHex(32)
		if err != nil {
			return result{}, fmt.Errorf("generate ledger ID: %w", err)
		}
		receipt = desiredApplyReceipt("seeding", opts, chainHash, chain, ledgerID)
		if err := writeExclusiveJSON(receiptPath, receipt, policy.expectedUID); err != nil {
			return result{}, fmt.Errorf("create seeding apply receipt: %w", err)
		}
		if err := fsyncDir(opts.updateReceiptDir); err != nil {
			return result{}, fmt.Errorf("fsync update-receipt directory: %w", err)
		}
	} else if err := validateApplyReceipt(receipt, opts, chainHash, chain); err != nil {
		return result{}, fmt.Errorf("existing apply receipt mismatch: %w", err)
	}

	if receipt.State == "seeded" {
		if err := validateWriterLock(lockPath, policy.expectedUID); err != nil {
			return result{}, fmt.Errorf("seeded receipt has invalid writer lock: %w", err)
		}
		var migration migrationState
		exists, err := readSecureJSONIfExists(migrationPath, policy.expectedUID, &migration)
		if err != nil {
			return result{}, fmt.Errorf("seeded receipt migration state: %w", err)
		}
		if !exists {
			return result{}, errors.New("seeded receipt exists but migration state is missing; refusing reseed")
		}
		if err := validateMigrationState(migration, receipt, true); err != nil {
			return result{}, fmt.Errorf("seeded receipt migration state mismatch: %w", err)
		}
		return preparedResult(receipt), nil
	}
	if receipt.State != "seeding" {
		return result{}, fmt.Errorf("unsupported apply receipt state %q", receipt.State)
	}

	if err := createOrValidateWriterLock(lockPath, policy.expectedUID); err != nil {
		return result{}, fmt.Errorf("writer lock: %w", err)
	}
	if policy.afterWriterLock != nil {
		if err := policy.afterWriterLock(); err != nil {
			return result{}, err
		}
	}

	desiredMigration := desiredMigrationState(receipt)
	var migration migrationState
	migrationExists, err := readSecureJSONIfExists(migrationPath, policy.expectedUID, &migration)
	if err != nil {
		return result{}, fmt.Errorf("migration state: %w", err)
	}
	if !migrationExists {
		if err := writeExclusiveJSON(migrationPath, desiredMigration, policy.expectedUID); err != nil {
			return result{}, fmt.Errorf("create authorized migration state: %w", err)
		}
		if err := fsyncDir(opts.migrationStateDir); err != nil {
			return result{}, fmt.Errorf("fsync migration-state directory: %w", err)
		}
	} else if err := validateMigrationState(migration, receipt, false); err != nil {
		return result{}, fmt.Errorf("seeding migration state mismatch: %w", err)
	}

	seeded := receipt
	seeded.State = "seeded"
	if err := replaceJSONDurable(receiptPath, seeded, policy.expectedUID); err != nil {
		return result{}, fmt.Errorf("advance apply receipt to seeded: %w", err)
	}
	return preparedResult(seeded), nil
}

func preparedResult(receipt applyReceipt) result {
	return result{
		Schema: applyReceiptSchema, State: receipt.State, LedgerID: receipt.LedgerID,
		ChainReceiptVerification: "strict-schema-and-archive-hash-binding",
	}
}

func desiredApplyReceipt(state string, opts options, chainHash string, chain chainVerificationReceipt, ledgerID string) applyReceipt {
	return applyReceipt{
		Schema: applyReceiptSchema, State: state, FromVersion: fromVersion, ToVersion: toVersion,
		ArchiveSHA256: opts.archiveSHA256, ChainReceiptSHA256: chainHash,
		InstallerReleasePDA: chain.InstallerReleasePDA, ChainVerifiedSlot: chain.VerifiedSlot,
		ExpectedInstalledELFSHA256: opts.expectedOldELFSHA256, NewELFSHA256: opts.newELFSHA256,
		LedgerID: ledgerID,
	}
}

func desiredMigrationState(receipt applyReceipt) migrationState {
	return migrationState{
		Schema: migrationStateSchema, State: "authorized", FromVersion: receipt.FromVersion, ToVersion: receipt.ToVersion,
		SourceChainReceiptSHA256: receipt.ChainReceiptSHA256, SourceInstallerReleasePDA: receipt.InstallerReleasePDA,
		ArchiveSHA256: receipt.ArchiveSHA256, ExpectedInstalledELFSHA256: receipt.ExpectedInstalledELFSHA256,
		NewELFSHA256: receipt.NewELFSHA256, LedgerID: receipt.LedgerID,
	}
}

func validateChainReceipt(receipt chainVerificationReceipt, archiveHash string) error {
	if receipt.Schema != chainReceiptSchema {
		return fmt.Errorf("schema %q is not %q", receipt.Schema, chainReceiptSchema)
	}
	h, err := canonicalSHA256(receipt.InstallerSHA256)
	if err != nil || h != receipt.InstallerSHA256 {
		return errors.New("installerSha256 must be canonical lowercase sha256")
	}
	if h != archiveHash {
		return errors.New("installerSha256 does not bind the verified archive")
	}
	if strings.TrimSpace(receipt.InstallerReleasePDA) == "" || strings.TrimSpace(receipt.ProgramID) == "" || strings.TrimSpace(receipt.MasterNFTMint) == "" {
		return errors.New("installerReleasePda, programId and masterNftMint are required")
	}
	if receipt.Status != "active" {
		return fmt.Errorf("status %q is not active", receipt.Status)
	}
	if receipt.VerifiedSlot == 0 || receipt.VerifiedAtUnix <= 0 {
		return errors.New("verifiedSlot and verifiedAtUnix must be positive")
	}
	return nil
}

func validateApplyReceipt(receipt applyReceipt, opts options, chainHash string, chain chainVerificationReceipt) error {
	if receipt.Schema != applyReceiptSchema || receipt.FromVersion != fromVersion || receipt.ToVersion != toVersion {
		return errors.New("schema or version transition differs")
	}
	if receipt.ArchiveSHA256 != opts.archiveSHA256 || receipt.ChainReceiptSHA256 != chainHash ||
		receipt.InstallerReleasePDA != chain.InstallerReleasePDA || receipt.ChainVerifiedSlot != chain.VerifiedSlot ||
		receipt.ExpectedInstalledELFSHA256 != opts.expectedOldELFSHA256 || receipt.NewELFSHA256 != opts.newELFSHA256 {
		return errors.New("source/archive/ELF binding differs")
	}
	if !isCanonicalHex(receipt.LedgerID, 32) {
		return errors.New("ledgerId is invalid")
	}
	return nil
}

func validateMigrationState(state migrationState, receipt applyReceipt, allowProgressed bool) error {
	desired := desiredMigrationState(receipt)
	if state.Schema != desired.Schema || state.FromVersion != desired.FromVersion || state.ToVersion != desired.ToVersion ||
		state.SourceChainReceiptSHA256 != desired.SourceChainReceiptSHA256 || state.SourceInstallerReleasePDA != desired.SourceInstallerReleasePDA ||
		state.ArchiveSHA256 != desired.ArchiveSHA256 || state.ExpectedInstalledELFSHA256 != desired.ExpectedInstalledELFSHA256 ||
		state.NewELFSHA256 != desired.NewELFSHA256 || state.LedgerID != desired.LedgerID {
		return errors.New("schema, transition, source, archive, ELF, or ledger binding differs")
	}
	if state.State == "authorized" {
		return nil
	}
	if allowProgressed && (state.State == "initializing" || state.State == "committed") {
		return nil
	}
	return fmt.Errorf("state %q is not valid for this apply phase", state.State)
}

func canonicalSHA256(value string) (string, error) {
	if !isCanonicalHex(value, sha256.Size) {
		return "", errors.New("must be exactly 64 lowercase hexadecimal characters")
	}
	return value, nil
}

func isCanonicalHex(value string, byteLen int) bool {
	if len(value) != byteLen*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == byteLen
}

func hashRegularNoFollow(path string, maxBytes int64) (string, error) {
	f, size, err := openRegularNoFollow(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if size > maxBytes {
		return "", fmt.Errorf("file exceeds %d-byte bound", maxBytes)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxBytes {
		return "", fmt.Errorf("file exceeds %d-byte bound", maxBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readRegularNoFollow(path string, maxBytes int64) ([]byte, error) {
	f, size, err := openRegularNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if size > maxBytes {
		return nil, fmt.Errorf("file exceeds %d-byte bound", maxBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d-byte bound", maxBytes)
	}
	return raw, nil
}

func openRegularNoFollow(path string) (*os.File, int64, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, 0, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		f.Close()
		return nil, 0, errors.New("not a regular no-follow file")
	}
	if st.Size < 0 {
		f.Close()
		return nil, 0, errors.New("negative file size")
	}
	return f, st.Size, nil
}

func ensureSecureDir(path string, expectedUID uint32) error {
	if err := syscall.Mkdir(path, 0700); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return errors.New("not a no-follow directory")
	}
	if st.Uid != expectedUID {
		return fmt.Errorf("uid %d, want %d", st.Uid, expectedUID)
	}
	if st.Mode&07777 != 0700 {
		return fmt.Errorf("mode %04o, want 0700", st.Mode&07777)
	}
	return nil
}

func readSecureJSONIfExists(path string, expectedUID uint32, dst any) (bool, error) {
	raw, err := readSecureFile(path, expectedUID, maxPersistentJSONBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := decodeStrictJSON(raw, dst); err != nil {
		return false, err
	}
	return true, nil
}

func readSecureFile(path string, expectedUID uint32, maxBytes int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != 0600 || st.Uid != expectedUID {
		return nil, fmt.Errorf("must be uid %d mode-0600 regular no-follow file", expectedUID)
	}
	if st.Size < 0 || st.Size > maxBytes {
		return nil, fmt.Errorf("file exceeds %d-byte bound", maxBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d-byte bound", maxBytes)
	}
	return raw, nil
}

func writeExclusiveJSON(path string, value any, expectedUID uint32) error {
	raw, err := encodeBoundedJSON(value)
	if err != nil {
		return err
	}
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	if err := writeAllAndSync(f, raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return validateSecureFile(path, expectedUID, false)
}

func replaceJSONDurable(path string, value any, expectedUID uint32) error {
	raw, err := encodeBoundedJSON(value)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmpID, err := randomHex(16)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+"."+tmpID+".tmp")
	fd, err := syscall.Open(tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), tmp)
	ok := false
	defer func() {
		if !ok {
			f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := writeAllAndSync(f, raw); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if err := fsyncDir(dir); err != nil {
		return err
	}
	return validateSecureFile(path, expectedUID, false)
}

func encodeBoundedJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > maxPersistentJSONBytes {
		return nil, errors.New("persistent JSON exceeds bound")
	}
	return raw, nil
}

func writeAllAndSync(f *os.File, raw []byte) error {
	for len(raw) > 0 {
		n, err := f.Write(raw)
		if err != nil {
			return err
		}
		raw = raw[n:]
	}
	return f.Sync()
}

func createOrValidateWriterLock(path string, expectedUID uint32) error {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err == nil {
		f := os.NewFile(uintptr(fd), path)
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if err := fsyncDir(filepath.Dir(path)); err != nil {
			return err
		}
		return validateWriterLock(path, expectedUID)
	}
	if !errors.Is(err, syscall.EEXIST) {
		return err
	}
	return validateWriterLock(path, expectedUID)
}

func validateWriterLock(path string, expectedUID uint32) error {
	return validateSecureFile(path, expectedUID, true)
}

func validateSecureFile(path string, expectedUID uint32, requireEmpty bool) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != 0600 || st.Uid != expectedUID {
		return fmt.Errorf("must be uid %d mode-0600 regular no-follow file", expectedUID)
	}
	if requireEmpty && st.Size != 0 {
		return errors.New("writer lock must be empty")
	}
	return nil
}

func fsyncDir(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Fsync(fd)
}

func decodeStrictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func randomHex(bytesLen int) (string, error) {
	raw := make([]byte, bytesLen)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
