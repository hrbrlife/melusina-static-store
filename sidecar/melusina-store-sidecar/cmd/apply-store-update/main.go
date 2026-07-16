// Command apply-store-update performs narrowly-scoped, fail-closed host-side
// preparation for governed store updates. It is intentionally not a generic
// migration/reset utility.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	prepareStoreUpdateCommand = "prepare-store-update"
	chainReceiptSchema        = "melusina-installer-release-chain-verification-v1"
	applyReceiptSchema        = "melusina-store-update-apply-v1"
	fromVersion               = "1.0.5"
	toVersion                 = "1.0.6"
	applyReceiptName          = "store-1.0.6.json"
	writerLockName            = "writer.lock"
	legacyLicenseProgramID    = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	xzExecutable              = "/usr/bin/xz"
	maxChainReceiptBytes      = 64 << 10
	maxPersistentJSONBytes    = 64 << 10
	maxArchiveBytes           = int64(8 << 30)
	maxELFBytes               = int64(1 << 30)
	maxArchiveExpandedBytes   = int64(16 << 30)
	chainVerificationTimeout  = 15 * time.Second
)

type options struct {
	archive              string
	archiveSHA256        string
	chainReceipt         string
	rpcURL               string
	programID            string
	clusterGenesisHash   string
	masterNFTMint        string
	installedELF         string
	expectedOldELFSHA256 string
	newELF               string
	newELFMember         string
	newELFSHA256         string
	migrationStateDir    string
	updateReceiptDir     string
}

// chainVerificationReceipt is bounded audit evidence from the governed pull
// step. It is never authority: this command independently derives and fetches
// the InstallerReleaseEntry before matching every receipt identity field.
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
	ProgramID                  string `json:"programId"`
	ClusterGenesisHash         string `json:"clusterGenesisHash"`
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
	expectedGID          uint32
	requireEffectiveRoot bool
	afterWriterLock      func() error
	newChainVerifier     func(string) installerReleaseVerifier
	verifyGenesis        func(context.Context, string, string) error
}

type installerReleaseVerifier interface {
	FetchInstallerReleaseEntry(context.Context, string) ([32]byte, verify.AttestationStatus, error)
}

func productionSecurityPolicy() securityPolicy {
	return securityPolicy{
		expectedUID:          0,
		expectedGID:          0,
		requireEffectiveRoot: true,
		newChainVerifier: func(endpoint string) installerReleaseVerifier {
			return verify.NewRPCClient(endpoint)
		},
		verifyGenesis: verifyRPCGenesis,
	}
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
	res, err := prepareStoreUpdate(opts, policy)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

func parseOptions(args []string) (options, error) {
	if len(args) == 0 || args[0] != prepareStoreUpdateCommand {
		return options{}, fmt.Errorf("exact subcommand %q is required", prepareStoreUpdateCommand)
	}
	var opts options
	fs := flag.NewFlagSet("apply-store-update "+prepareStoreUpdateCommand, flag.ContinueOnError)
	fs.StringVar(&opts.archive, "archive", "", "pulled store 1.0.6 archive")
	fs.StringVar(&opts.archiveSHA256, "archive-sha256", "", "verified archive sha256")
	fs.StringVar(&opts.chainReceipt, "chain-receipt", "", "bounded InstallerReleaseEntry verification receipt")
	fs.StringVar(&opts.rpcURL, "rpc-url", "", "Solana JSON-RPC URL used for an independent InstallerReleaseEntry fetch")
	fs.StringVar(&opts.programID, "program-id", "", "exact freshly deployed license-registry program id (required; legacy refused)")
	fs.StringVar(&opts.clusterGenesisHash, "cluster-genesis-hash", "", "exact getGenesisHash result for --rpc-url (required)")
	fs.StringVar(&opts.masterNFTMint, "master-nft-mint", "", "Master NFT mint used to derive the InstallerReleaseEntry PDA")
	fs.StringVar(&opts.installedELF, "installed-elf", "", "installed 1.0.5 store ELF")
	fs.StringVar(&opts.expectedOldELFSHA256, "expected-old-elf-sha256", "", "expected installed 1.0.5 ELF sha256")
	fs.StringVar(&opts.newELF, "new-elf", "", "pulled 1.0.6 store ELF")
	fs.StringVar(&opts.newELFMember, "new-elf-member", "", "exact clean tar member containing the 1.0.6 store ELF")
	fs.StringVar(&opts.newELFSHA256, "new-elf-sha256", "", "verified 1.0.6 ELF sha256")
	fs.StringVar(&opts.migrationStateDir, "migration-state-dir", "", "persistent migration-state directory holding the writer lock")
	fs.StringVar(&opts.updateReceiptDir, "update-receipt-dir", "", "persistent update-receipt directory")
	if err := fs.Parse(args[1:]); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional args: %v", fs.Args())
	}
	for name, value := range map[string]string{
		"--archive": opts.archive, "--archive-sha256": opts.archiveSHA256,
		"--chain-receipt": opts.chainReceipt, "--rpc-url": opts.rpcURL,
		"--program-id": opts.programID, "--cluster-genesis-hash": opts.clusterGenesisHash,
		"--master-nft-mint": opts.masterNFTMint, "--installed-elf": opts.installedELF,
		"--expected-old-elf-sha256": opts.expectedOldELFSHA256,
		"--new-elf":                 opts.newELF, "--new-elf-member": opts.newELFMember,
		"--new-elf-sha256":      opts.newELFSHA256,
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
	parsedRPC, err := url.Parse(opts.rpcURL)
	if err != nil || (parsedRPC.Scheme != "http" && parsedRPC.Scheme != "https") || parsedRPC.Host == "" || parsedRPC.User != nil {
		return options{}, errors.New("--rpc-url must be an absolute http(s) URL without userinfo")
	}
	masterMint, err := primitives.PubkeyFromBase58(opts.masterNFTMint)
	if err != nil || masterMint.Base58() != opts.masterNFTMint {
		return options{}, errors.New("--master-nft-mint must be a canonical base58 Solana pubkey")
	}
	if err := validateArchiveMemberName(opts.newELFMember); err != nil {
		return options{}, fmt.Errorf("--new-elf-member: %w", err)
	}
	programID, err := primitives.PubkeyFromBase58(opts.programID)
	if err != nil || programID.Base58() != opts.programID {
		return options{}, errors.New("--program-id must be a canonical base58 Solana pubkey")
	}
	if opts.programID == legacyLicenseProgramID {
		return options{}, errors.New("legacy --program-id is refused")
	}
	genesis, err := primitives.PubkeyFromBase58(opts.clusterGenesisHash)
	if err != nil || genesis.Base58() != opts.clusterGenesisHash {
		return options{}, errors.New("--cluster-genesis-hash must be a canonical base58 32-byte hash")
	}
	return opts, nil
}

func prepareStoreUpdate(opts options, policy securityPolicy) (result, error) {
	if policy.requireEffectiveRoot && os.Geteuid() != 0 {
		return result{}, errors.New("must run as root")
	}
	if policy.verifyGenesis == nil {
		return result{}, errors.New("cluster genesis verifier is unavailable")
	}
	genesisCtx, genesisCancel := context.WithTimeout(context.Background(), chainVerificationTimeout)
	genesisErr := policy.verifyGenesis(genesisCtx, opts.rpcURL, opts.clusterGenesisHash)
	genesisCancel()
	if genesisErr != nil {
		return result{}, fmt.Errorf("cluster genesis: %w", genesisErr)
	}
	archiveHash, memberHash, err := hashArchiveAndXZTarMember(opts.archive, opts.newELFMember)
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
	if memberHash != opts.newELFSHA256 {
		return result{}, fmt.Errorf("archive member %q sha256 mismatch: got %s want %s", opts.newELFMember, memberHash, opts.newELFSHA256)
	}

	chainRaw, err := readRegularNoFollow(opts.chainReceipt, maxChainReceiptBytes)
	if err != nil {
		return result{}, fmt.Errorf("chain receipt: %w", err)
	}
	var chain chainVerificationReceipt
	if err := decodeStrictJSON(chainRaw, &chain); err != nil {
		return result{}, fmt.Errorf("chain receipt: %w", err)
	}
	if err := verifyChainAndReceipt(opts, policy, chain); err != nil {
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

	receiptPath := filepath.Join(opts.updateReceiptDir, applyReceiptName)
	lockPath := filepath.Join(opts.migrationStateDir, writerLockName)
	if err := createOrValidateWriterLock(lockPath, policy.expectedUID, policy.expectedGID); err != nil {
		return result{}, fmt.Errorf("writer lock: %w", err)
	}
	writerLock, err := acquireWriterLock(lockPath, policy.expectedUID, policy.expectedGID)
	if err != nil {
		return result{}, fmt.Errorf("writer lock ownership: %w", err)
	}
	defer writerLock.Close()
	if policy.afterWriterLock != nil {
		if err := policy.afterWriterLock(); err != nil {
			return result{}, err
		}
	}

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
		if err := validateWriterLock(lockPath, policy.expectedUID, policy.expectedGID); err != nil {
			return result{}, fmt.Errorf("seeded receipt has invalid writer lock: %w", err)
		}
		return preparedResult(receipt), nil
	}
	if receipt.State != "seeding" {
		return result{}, fmt.Errorf("unsupported apply receipt state %q", receipt.State)
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
		ChainReceiptVerification: "independent-active-pda-fetch-and-strict-receipt-binding",
	}
}

func desiredApplyReceipt(state string, opts options, chainHash string, chain chainVerificationReceipt, ledgerID string) applyReceipt {
	return applyReceipt{
		Schema: applyReceiptSchema, State: state, FromVersion: fromVersion, ToVersion: toVersion,
		ArchiveSHA256: opts.archiveSHA256, ChainReceiptSHA256: chainHash,
		InstallerReleasePDA: chain.InstallerReleasePDA, ChainVerifiedSlot: chain.VerifiedSlot,
		ProgramID: opts.programID, ClusterGenesisHash: opts.clusterGenesisHash,
		ExpectedInstalledELFSHA256: opts.expectedOldELFSHA256, NewELFSHA256: opts.newELFSHA256,
		LedgerID: ledgerID,
	}
}

func verifyChainAndReceipt(opts options, policy securityPolicy, receipt chainVerificationReceipt) error {
	if receipt.Schema != chainReceiptSchema {
		return fmt.Errorf("schema %q is not %q", receipt.Schema, chainReceiptSchema)
	}
	h, err := canonicalSHA256(receipt.InstallerSHA256)
	if err != nil || h != receipt.InstallerSHA256 {
		return errors.New("installerSha256 must be canonical lowercase sha256")
	}
	if h != opts.archiveSHA256 {
		return errors.New("installerSha256 does not bind the verified archive")
	}
	programID, err := primitives.PubkeyFromBase58(opts.programID)
	if err != nil {
		return fmt.Errorf("internal canonical program id: %w", err)
	}
	masterMint, err := primitives.PubkeyFromBase58(opts.masterNFTMint)
	if err != nil {
		return fmt.Errorf("master NFT mint: %w", err)
	}
	var archiveHash [32]byte
	decodedHash, err := hex.DecodeString(opts.archiveSHA256)
	if err != nil || len(decodedHash) != len(archiveHash) {
		return errors.New("internal archive sha256 is invalid")
	}
	copy(archiveHash[:], decodedHash)
	releasePDA, _, err := pda.InstallerRelease(masterMint, archiveHash, programID)
	if err != nil {
		return fmt.Errorf("derive InstallerReleaseEntry PDA: %w", err)
	}
	if receipt.ProgramID != opts.programID || receipt.MasterNFTMint != opts.masterNFTMint || receipt.InstallerReleasePDA != releasePDA.Base58() {
		return errors.New("programId, masterNftMint, or installerReleasePda does not match independently derived identity")
	}
	if receipt.Status != verify.AttestationStatusActive.String() {
		return fmt.Errorf("status %q is not canonical Active", receipt.Status)
	}
	if receipt.VerifiedSlot == 0 || receipt.VerifiedAtUnix <= 0 {
		return errors.New("verifiedSlot and verifiedAtUnix must be positive")
	}
	if policy.newChainVerifier == nil {
		return errors.New("independent chain verifier is unavailable")
	}
	verifier := policy.newChainVerifier(opts.rpcURL)
	if verifier == nil {
		return errors.New("independent chain verifier is nil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), chainVerificationTimeout)
	defer cancel()
	onChainHash, status, err := verifier.FetchInstallerReleaseEntry(ctx, releasePDA.Base58())
	if err != nil {
		return fmt.Errorf("independent fetch %s: %w", releasePDA.Base58(), err)
	}
	if onChainHash != archiveHash {
		return fmt.Errorf("on-chain installer hash %x does not match archive sha256 %x", onChainHash, archiveHash)
	}
	if err := status.RequireActive(); err != nil {
		return fmt.Errorf("on-chain status %s is not Active: %w", status, err)
	}
	if receipt.Status != status.String() {
		return fmt.Errorf("receipt status %q does not match independently fetched status %q", receipt.Status, status.String())
	}
	return nil
}

func validateApplyReceipt(receipt applyReceipt, opts options, chainHash string, chain chainVerificationReceipt) error {
	if receipt.Schema != applyReceiptSchema || receipt.FromVersion != fromVersion || receipt.ToVersion != toVersion {
		return errors.New("schema or version transition differs")
	}
	if receipt.ArchiveSHA256 != opts.archiveSHA256 || receipt.ChainReceiptSHA256 != chainHash ||
		receipt.InstallerReleasePDA != chain.InstallerReleasePDA || receipt.ChainVerifiedSlot != chain.VerifiedSlot ||
		receipt.ProgramID != opts.programID || receipt.ClusterGenesisHash != opts.clusterGenesisHash ||
		receipt.ExpectedInstalledELFSHA256 != opts.expectedOldELFSHA256 || receipt.NewELFSHA256 != opts.newELFSHA256 {
		return errors.New("source/archive/ELF binding differs")
	}
	if !isCanonicalHex(receipt.LedgerID, 32) {
		return errors.New("ledgerId is invalid")
	}
	return nil
}

func verifyRPCGenesis(ctx context.Context, rpcURL, expected string) error {
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"getGenesisHash"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("getGenesisHash HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return err
	}
	var result struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return err
	}
	if result.Error != nil {
		return fmt.Errorf("getGenesisHash RPC error %d: %s", result.Error.Code, result.Error.Message)
	}
	if strings.TrimSpace(result.Result) != expected {
		return fmt.Errorf("RPC=%q expected=%q", result.Result, expected)
	}
	return nil
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

func validateArchiveMemberName(name string) error {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") {
		return errors.New("must be a non-empty relative POSIX path")
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != name {
		return errors.New("must be an exact clean non-traversing POSIX path")
	}
	return nil
}

// hashArchiveAndXZTarMember computes both bindings from one O_NOFOLLOW-opened
// inode, preventing a path swap between the governed outer hash and member hash.
func hashArchiveAndXZTarMember(archivePath, wanted string) (string, string, error) {
	if err := validateArchiveMemberName(wanted); err != nil {
		return "", "", err
	}
	f, size, err := openRegularNoFollow(archivePath)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	if size > maxArchiveBytes {
		return "", "", fmt.Errorf("archive exceeds %d-byte bound", maxArchiveBytes)
	}
	outer := sha256.New()
	n, err := io.Copy(outer, io.LimitReader(f, maxArchiveBytes+1))
	if err != nil {
		return "", "", err
	}
	if n != size || n > maxArchiveBytes {
		return "", "", fmt.Errorf("archive size changed or exceeds %d-byte bound", maxArchiveBytes)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", "", fmt.Errorf("rewind archive: %w", err)
	}
	memberHash, err := hashXZTarMemberFromFile(f, wanted)
	if err != nil {
		return "", "", fmt.Errorf("new ELF member: %w", err)
	}
	return hex.EncodeToString(outer.Sum(nil)), memberHash, nil
}

func hashXZTarMember(archivePath, wanted string) (string, error) {
	_, memberHash, err := hashArchiveAndXZTarMember(archivePath, wanted)
	return memberHash, err
}

func hashXZTarMemberFromFile(f *os.File, wanted string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, xzExecutable, "--decompress", "--stdout")
	cmd.Stdin = f
	var stderr boundedBuffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start xz: %w", err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	limited := &io.LimitedReader{R: stdout, N: maxArchiveExpandedBytes + 1}
	tr := tar.NewReader(limited)
	found := false
	memberHash := ""
	for {
		hdr, nextErr := tr.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return "", fmt.Errorf("read tar: %w", nextErr)
		}
		entryName := strings.TrimSuffix(hdr.Name, "/")
		if err := validateArchiveMemberName(entryName); err != nil {
			return "", fmt.Errorf("unsafe member %q: %w", hdr.Name, err)
		}
		if hdr.Name != wanted {
			continue
		}
		if found {
			return "", fmt.Errorf("duplicate member %q", wanted)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return "", fmt.Errorf("member %q is not a regular file", wanted)
		}
		if hdr.Size < 0 || hdr.Size > maxELFBytes {
			return "", fmt.Errorf("member %q exceeds %d-byte bound", wanted, maxELFBytes)
		}
		h := sha256.New()
		n, copyErr := io.Copy(h, io.LimitReader(tr, maxELFBytes+1))
		if copyErr != nil {
			return "", fmt.Errorf("hash member %q: %w", wanted, copyErr)
		}
		if n != hdr.Size || n > maxELFBytes {
			return "", fmt.Errorf("member %q size mismatch or overflow", wanted)
		}
		memberHash = hex.EncodeToString(h.Sum(nil))
		found = true
	}
	// A valid tar may have zero padding after its end markers, but another
	// concatenated payload is ambiguous and therefore refused.
	var trailing zeroOnlyWriter
	if _, err := io.Copy(&trailing, limited); err != nil {
		return "", fmt.Errorf("drain xz output: %w", err)
	}
	if maxArchiveExpandedBytes+1-limited.N > maxArchiveExpandedBytes {
		return "", fmt.Errorf("expanded archive exceeds %d-byte bound", maxArchiveExpandedBytes)
	}
	if trailing.nonZero {
		return "", errors.New("non-zero data follows tar end markers")
	}
	if err := cmd.Wait(); err != nil {
		waited = true
		return "", fmt.Errorf("xz failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	waited = true
	if !found {
		return "", fmt.Errorf("member %q not found", wanted)
	}
	return memberHash, nil
}

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	want := len(p)
	if b.Len() < 4096 {
		keep := 4096 - b.Len()
		if keep > len(p) {
			keep = len(p)
		}
		_, _ = b.Buffer.Write(p[:keep])
	}
	return want, nil
}

type zeroOnlyWriter struct{ nonZero bool }

func (w *zeroOnlyWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b != 0 {
			w.nonZero = true
			break
		}
	}
	return len(p), nil
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

func createOrValidateWriterLock(path string, expectedUID, expectedGID uint32) error {
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
		return validateWriterLock(path, expectedUID, expectedGID)
	}
	if !errors.Is(err, syscall.EEXIST) {
		return err
	}
	return validateWriterLock(path, expectedUID, expectedGID)
}

func validateWriterLock(path string, expectedUID, expectedGID uint32) error {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != 0600 ||
		st.Uid != expectedUID || st.Gid != expectedGID || st.Size != 0 {
		return fmt.Errorf("must be uid:gid %d:%d mode-0600 empty regular no-follow file", expectedUID, expectedGID)
	}
	return nil
}

func acquireWriterLock(path string, expectedUID, expectedGID uint32) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = f.Close()
		}
	}()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != 0600 ||
		st.Uid != expectedUID || st.Gid != expectedGID || st.Size != 0 {
		return nil, fmt.Errorf("must be uid:gid %d:%d mode-0600 empty regular no-follow file", expectedUID, expectedGID)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, err
	}
	closeOnError = false
	return f, nil
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
