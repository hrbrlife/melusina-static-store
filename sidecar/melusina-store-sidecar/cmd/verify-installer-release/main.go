// Command verify-installer-release proves, independently and without mutating
// anything, that a controller artifact on disk is cryptographically authorized
// to be installed on this host.
//
// docs/CONTROLLER_INSTALL_SURFACE.md makes the controller install a separately
// authorized custody ceremony, and requires that ceremony to "record and
// independently verify: the exact controller artifact hash and source revision,
// its active InstallerReleaseEntry, the pinned operator/store/origin/chain
// configuration". Nothing shipped could do the chain half from a script, so the
// ceremony was performed by hand -- and hand-installing 1.0.44 outside the rail
// is exactly what stranded this host's generation cursor (F-237).
//
// This command is that missing evidence step, and only that step. It never
// writes, installs, restarts, or touches the chain with a transaction. It reads
// the controller's OWN root-owned config for its pins, so the ceremony cannot be
// pointed at a different program, mint, or RPC than the controller itself
// trusts, and emits one bounded JSON evidence object on success.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// controllerPins is the strict subset of the controller config this ceremony
// needs. It is decoded leniently on purpose: the controller itself is the strict
// decoder of its own config, and duplicating that here would fail the ceremony
// for fields it has no business judging.
type controllerPins struct {
	MasterNftMint string `json:"masterNftMint"`
	ProgramID     string `json:"programId"`
	SolanaRPCURL  string `json:"solanaRpcUrl"`
}

type evidence struct {
	Schema           string `json:"schema"`
	ArtifactPath     string `json:"artifactPath"`
	ArtifactSHA256   string `json:"artifactSha256"`
	ArtifactSize     int64  `json:"artifactSize"`
	MasterNftMint    string `json:"masterNftMint"`
	ProgramID        string `json:"programId"`
	InstallerRelease string `json:"installerReleaseEntryPda"`
	Status           string `json:"status"`
	VerifiedAtUnix   int64  `json:"verifiedAtUnix"`
}

func main() {
	configPath := flag.String("config", "/etc/melusina/update-controller/config.json", "root-owned controller config supplying the chain pins")
	artifact := flag.String("artifact", "", "absolute path to the controller artifact to verify")
	flag.Parse()
	if err := run(*configPath, *artifact); err != nil {
		fmt.Fprintf(os.Stderr, "verify-installer-release: %v\n", err)
		os.Exit(1)
	}
}

func run(configPath, artifact string) error {
	if !filepath.IsAbs(configPath) || !filepath.IsAbs(artifact) {
		return fmt.Errorf("both -config and -artifact must be absolute paths")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var pins controllerPins
	if err := json.Unmarshal(raw, &pins); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	if pins.MasterNftMint == "" || pins.ProgramID == "" || pins.SolanaRPCURL == "" {
		return fmt.Errorf("config is missing masterNftMint, programId or solanaRpcUrl")
	}

	sum, size, err := hashNoFollow(artifact)
	if err != nil {
		return err
	}
	master, err := primitives.PubkeyFromBase58(pins.MasterNftMint)
	if err != nil {
		return fmt.Errorf("masterNftMint: %w", err)
	}
	program, err := primitives.PubkeyFromBase58(pins.ProgramID)
	if err != nil {
		return fmt.Errorf("programId: %w", err)
	}
	pda, _, err := primitives.DeriveInstallerRelease(master, sum, program)
	if err != nil {
		return fmt.Errorf("derive InstallerReleaseEntry PDA: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	onChainHash, status, err := verify.NewRPCClient(pins.SolanaRPCURL).FetchInstallerReleaseEntry(ctx, pda.Base58())
	if err != nil {
		return fmt.Errorf("fetch InstallerReleaseEntry %s: %w", pda.Base58(), err)
	}
	if err := status.RequireActive(); err != nil {
		return fmt.Errorf("installer release for %s is not Active: %w", hex.EncodeToString(sum[:]), err)
	}
	// Belt and braces: the PDA is derived FROM the artifact hash, so a mismatch
	// here should be unreachable. Assert it anyway -- an unreachable check that
	// costs nothing is the one that catches a future seed change.
	if onChainHash != sum {
		return fmt.Errorf("installer_hash %s != artifact %s", hex.EncodeToString(onChainHash[:]), hex.EncodeToString(sum[:]))
	}

	out, err := json.MarshalIndent(evidence{
		Schema:           "melusina-installer-release-verification-v1",
		ArtifactPath:     artifact,
		ArtifactSHA256:   hex.EncodeToString(sum[:]),
		ArtifactSize:     size,
		MasterNftMint:    pins.MasterNftMint,
		ProgramID:        pins.ProgramID,
		InstallerRelease: pda.Base58(),
		Status:           "Active",
		VerifiedAtUnix:   time.Now().UTC().Unix(),
	}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

// hashNoFollow hashes a REGULAR file opened with O_NOFOLLOW. The install target
// is a root-owned system binary path; following a symlink there would let the
// ceremony attest to bytes other than the ones that get installed.
func hashNoFollow(path string) ([32]byte, int64, error) {
	var zero [32]byte
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return zero, 0, fmt.Errorf("open artifact: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return zero, 0, err
	}
	if !info.Mode().IsRegular() {
		return zero, 0, fmt.Errorf("artifact is not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return zero, 0, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, info.Size(), nil
}
