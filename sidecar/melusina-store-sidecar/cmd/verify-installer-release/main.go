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
// its program, mint and profile pins from a root-owned controller-shaped
// config, and its chain endpoint ONLY from the owner-signed Store-host facts
// that config names (rpc_trust.go): https, TLS pinned to the owner-signed SPKI
// keys (never the system CA pool), the profile's genesis, and an
// InstallerReleaseEntry owned by the pinned program. It emits one bounded JSON
// evidence object on success.
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
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// controllerPins is the strict subset of the controller config this ceremony
// needs. It is decoded leniently on purpose: the controller itself is the strict
// decoder of its own config, and duplicating that here would fail the ceremony
// for fields it has no business judging. The estate profile pin is among them:
// the ceremony admits an entry by exactly the rule the controller's gate does
// (internal/installerrelease), under the same pinned profile.
//
// StoreHostFactsPath names the owner-signed Store-host facts, the only source
// of the RPC endpoint and its TLS pins. SolanaRPCURL is not a source: when the
// config carries one it must be the signed endpoint exactly, or the ceremony
// refuses by name (check=rpc_endpoint_unsigned).
type controllerPins struct {
	MasterNftMint       string `json:"masterNftMint"`
	ProgramID           string `json:"programId"`
	SolanaRPCURL        string `json:"solanaRpcUrl"`
	EstateProfilePath   string `json:"estateProfilePath"`
	EstateProfileSha256 string `json:"estateProfileSha256"`
	StoreHostFactsPath  string `json:"storeHostFactsPath"`
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
	Version          string `json:"version"`
	EstateProfile    string `json:"estateProfileSha256"`
	PublisherKey     string `json:"publisherEd25519PublicKey"`
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
		return fmt.Errorf("%w: both -config and -artifact must be absolute paths", errConfig)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("%w: read config: %v", errConfig, err)
	}
	var pins controllerPins
	if err := json.Unmarshal(raw, &pins); err != nil {
		return fmt.Errorf("%w: decode config: %v", errConfig, err)
	}
	if pins.MasterNftMint == "" || pins.ProgramID == "" {
		return fmt.Errorf("%w: config is missing masterNftMint or programId", errConfig)
	}
	if pins.EstateProfilePath == "" || pins.EstateProfileSha256 == "" {
		return fmt.Errorf("%w: config is missing estateProfilePath or estateProfileSha256", errConfig)
	}
	if pins.StoreHostFactsPath == "" {
		return fmt.Errorf("%w: config is missing storeHostFactsPath, the owner-signed source of the RPC endpoint", errRPCTrustAbsent)
	}

	sum, size, err := hashNoFollow(artifact)
	if err != nil {
		return err
	}
	master, err := primitives.PubkeyFromBase58(pins.MasterNftMint)
	if err != nil {
		return fmt.Errorf("%w: masterNftMint: %v", errConfig, err)
	}
	program, err := primitives.PubkeyFromBase58(pins.ProgramID)
	if err != nil {
		return fmt.Errorf("%w: programId: %v", errConfig, err)
	}
	trust, profile, err := installerrelease.LoadBoundProfileTrust(pins.EstateProfilePath, pins.EstateProfileSha256, program, master)
	if err != nil {
		return fmt.Errorf("estate profile: %w", err)
	}
	rpcTrust, err := loadSignedRPCTrust(pins.StoreHostFactsPath, profile, pins.EstateProfileSha256, program.Base58())
	if err != nil {
		return err
	}
	if pins.SolanaRPCURL != "" && pins.SolanaRPCURL != rpcTrust.endpoint.String() {
		return fmt.Errorf("%w: config solanaRpcUrl %q is not the owner-signed endpoint", errRPCEndpointUnsigned, pins.SolanaRPCURL)
	}
	pda, _, err := primitives.DeriveInstallerRelease(master, sum, program)
	if err != nil {
		return fmt.Errorf("derive InstallerReleaseEntry PDA: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	rpc := newPinnedRPC(rpcTrust, time.Now)
	if err := requireProfileGenesis(ctx, rpc, profile); err != nil {
		return err
	}
	reader := &verify.RPCClient{Endpoint: rpc.endpoint, HTTPClient: rpc.client}
	account, err := reader.GetAccount(ctx, pda.Base58())
	if err != nil {
		return rpc.classify(fmt.Errorf("fetch InstallerReleaseEntry %s: %w", pda.Base58(), err))
	}
	if account == nil {
		return fmt.Errorf("fetch InstallerReleaseEntry %s: %w", pda.Base58(), verify.ErrPDANotFound)
	}
	// Only the pinned program can have written an account it owns; bytes at
	// the derived address owned by anything else are not an entry.
	if account.Owner != program.Base58() {
		return fmt.Errorf("%w: InstallerReleaseEntry %s is owned by %q, not the pinned program %s", errAccountOwner,
			pda.Base58(), account.Owner, program.Base58())
	}
	entry, err := installerrelease.Decode(account.Data)
	if err != nil {
		return fmt.Errorf("decode InstallerReleaseEntry %s: %w", pda.Base58(), err)
	}
	// Admit re-checks the installer hash even though the PDA is derived FROM
	// it: an unreachable check that costs nothing is the one that catches a
	// future seed change.
	if err := trust.Admit(entry, sum); err != nil {
		return fmt.Errorf("InstallerReleaseEntry %s for %s refused: %w", pda.Base58(), hex.EncodeToString(sum[:]), err)
	}

	out, err := json.MarshalIndent(evidence{
		Schema:           "melusina-installer-release-verification-v1",
		ArtifactPath:     artifact,
		ArtifactSHA256:   hex.EncodeToString(sum[:]),
		ArtifactSize:     size,
		MasterNftMint:    pins.MasterNftMint,
		ProgramID:        pins.ProgramID,
		InstallerRelease: pda.Base58(),
		Status:           entry.Status.String(),
		Version:          entry.Version,
		EstateProfile:    pins.EstateProfileSha256,
		PublisherKey:     hex.EncodeToString(entry.PublisherEd25519Pubkey[:]),
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
