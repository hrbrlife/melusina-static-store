package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/finalizationinput"
)

const (
	firstMaster    = "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe"
	firstRegistry  = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	firstCore      = "4sPNmdcSzQRxtBq66R5TTbokUgQj3Betb765dtK7bq4V"
	firstVault     = "3jfN9rcSMRkEm6NJQ744YJTbwCkfzZZ3iRkKRgf4J2L3"
	firstPublisher = "ARX39MQQR1c7cT8L9ARbeg7AWw975gPGr9EE9oygKv1P"
)

// This checks the actual original author's public output using the same strict
// decoder consumed by the production preparation/finalization boundary. It
// creates only provisional staging material, with no chain or Store operation.
func firstAuthorRelease(raw []byte, appHash, runtimeHash string) (finalizationinput.CeremonyState, []byte, error) {
	s, err := finalizationinput.DecodePreparedCeremony(raw)
	if err != nil {
		return s, nil, err
	}
	if s.AppID != firstID || s.Version != "0.1.0" || s.AppHash != appHash || s.MasterNftMint != firstMaster || s.ProgramID != firstRegistry || s.MultisigPDA != firstCore || s.LicenseSquadsVault != firstVault || s.PublisherEd25519Pubkey != firstPublisher || s.QuorumPolicy.Threshold != 3 || s.QuorumPolicy.MemberCount != 4 {
		return s, nil, errors.New("author preparation differs from exact first Bazaar candidate or original Core authority")
	}
	r := finalizationinput.ReleaseClaims{Schema: "melusina-release-v1", AppHash: s.AppHash, ReleaseHash: s.ReleaseHash, Version: s.Version, SignedAtUnix: s.CreatedAtUnix, MasterNftMint: s.MasterNftMint, LicenseSquadsVault: s.LicenseSquadsVault, ReleaseEntryPDA: s.ReleaseEntryPDA, AuthorSig: s.AuthorSig, QuorumPolicy: s.QuorumPolicy, ReleaseNonce: s.ReleaseNonce, RuntimeContractSHA256: runtimeHash, RuntimeContractSchema: "melusina-app-runtime-contract-v1"}
	out, err := json.Marshal(r)
	if err != nil {
		return s, nil, err
	}
	if _, err := finalizationinput.DecodeReleaseDescriptor(out); err != nil {
		return s, nil, err
	}
	return s, out, nil
}

func readPublicPreparation(path string, max int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > max || s.Nlink != 1 || s.Uid != uint32(os.Getuid()) || st.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("bounded private original preparation file required")
	}
	return io.ReadAll(io.LimitReader(f, max+1))
}

func verifyFirstAuthor(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("canonical absolute preparation directory required")
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != dir {
		return errors.New("preparation directory must not traverse symlinks")
	}
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || s.Uid != uint32(os.Getuid()) || st.Mode().Perm() != 0o700 {
		return errors.New("original private preparation directory required")
	}
	for _, name := range []string{"RELEASE.provisional.json", "author-verification.json"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			return errors.New("author verification outputs must be new; prior evidence is retained")
		}
	}
	spk, err := readPackage(filepath.Join(dir, "app", "app.spk"))
	if err != nil {
		return err
	}
	meta, err := readPublicPreparation(filepath.Join(dir, "app", "metadata.json"), 1<<20)
	if err != nil {
		return err
	}
	if !bytes.Equal(meta, metadata()) {
		return errors.New("first Bazaar metadata differs from closed source selection")
	}
	appHash, err := apphash.Canonical(bytes.NewReader(spk), meta)
	if err != nil {
		return err
	}
	runtime, err := readPublicPreparation(filepath.Join(dir, "RUNTIME-CONTRACT.json"), 1<<20)
	if err != nil {
		return err
	}
	wantRuntime, err := json.MarshalIndent(contract(appHash), "", "  ")
	if err != nil {
		return err
	}
	if !bytes.Equal(runtime, append(wantRuntime, '\n')) {
		return errors.New("first Bazaar runtime differs from original disconnected bootstrap contract")
	}
	raw, err := readPublicPreparation(filepath.Join(dir, "author-ceremony.json"), 128<<10)
	if err != nil {
		return err
	}
	state, release, err := firstAuthorRelease(raw, appHash, digest(runtime))
	if err != nil {
		return err
	}
	report := map[string]any{"schema": "melusina-first-bazaar-author-verification.v1", "verifiedAt": time.Now().UTC(), "sourceSelection": selection(), "appHash": appHash, "releaseHash": state.ReleaseHash, "authorStateSHA256": digest(raw), "provisionalReleaseSHA256": digest(release), "runtimeContractSHA256": digest(runtime), "publisher": state.PublisherEd25519Pubkey, "releaseEntryPda": state.ReleaseEntryPDA, "transactionIndex": state.TransactionIndex, "transactionPda": state.TransactionPDA, "proposalPda": state.ProposalPDA, "verified": []string{"exact original package and source-bound metadata", "exact original runtime contract", "canonical author signature and signed payload", "independently derived original Core vault, Master ATA, transaction, proposal and ReleaseEntry", "exact register instruction and account privileges", "exact outer Ed25519 precompile"}, "proposalIndexReserved": false, "proposalCreated": false, "coreApprovalsCreated": false, "storeStaged": false, "publicationPerformed": false, "installed": false, "nextRequirement": "Actual browser ceremony must freshly verify the original Store authority and Core index, privately stage and independently accept the original Store receipt, then obtain original Core 3-of-4 approval/execution. Provisional signedAtUnix is author preparation time; final release must use independently observed ReleaseEntry registration time."}
	reportRaw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNew(dir, "RELEASE.provisional.json", release); err != nil {
		return err
	}
	if err := writeNew(dir, "author-verification.json", append(reportRaw, '\n')); err != nil {
		return err
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return err
	}
	fmt.Printf("VERIFIED_PREPARATION_ONLY first Bazaar releaseHash=%s; no proposal, Store request or execution\n", state.ReleaseHash)
	return nil
}
