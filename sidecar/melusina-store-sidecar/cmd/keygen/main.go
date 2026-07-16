// Command keygen materializes the two identity JSON files the sealed-v3
// self-publish path (cmd/submit) needs and which, until now, existed nowhere
// on disk:
//
//	publisher <solana-keypair.json> > publisher.key.json
//	    Derives an attest identity.Private for --publisher-key from an
//	    EXISTING Solana ed25519 keypair file (the standard 64-byte
//	    [seed(32)||pubkey(32)] array format, e.g.
//	    test-wallets/core-app-team/publisher.json). The resulting
//	    sign_pubkey_b58 is byte-identical to the Solana keypair's own
//	    pubkey (both are raw ed25519), so an already-allowlisted
//	    accept_publishers entry (a Solana pubkey) keeps working unchanged.
//	    A fresh x25519 box seed is generated (envelope encryption is not
//	    exercised by /publish; the seed only needs to be well-formed).
//
//	store-pubkey > store-pubkey.json
//	    Reconstructs the store operator's identity.Public (the envelope
//	    DESTINATION for --store-pubkey) byte-for-byte from already-public
//	    on-chain-registered facts (no secret material involved) — the
//	    same Ref shape boot_identity.go's sidecarIdentityRef() builds
//	    server-side, so identity.Public.Digest() matches what the running
//	    sidecar computes for itself.
//
// Both subcommands print the finished JSON to stdout; write it to disk with
// shell redirection so this tool never needs a --out flag or write access.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const legacyProgramID = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: keygen publisher <solana-keypair.json> | keygen store-pubkey")
	}
	switch args[0] {
	case "publisher":
		fs := flag.NewFlagSet("publisher", flag.ContinueOnError)
		licenseMint := fs.String("license-mint", "", "identity.Ref.LicenseMint (required)")
		domain := fs.String("domain", "", "identity.Ref.Domain (required; store serving domain)")
		programID := fs.String("program-id", "", "fresh license-registry program id (required; legacy refused)")
		clusterGenesisHash := fs.String("cluster-genesis-hash", "", "exact target-cluster getGenesisHash result (required)")
		chainID := fs.String("chain-id", "solana:devnet", "identity.Ref.ChainID")
		pearlIDHash := fs.String("pearl-id-hash", "", "identity.Ref.PearlIDHash (required for Kind=pearl; defaults to sha256(label) if empty)")
		label := fs.String("label", "core-app-team-publisher", "human label hashed into the default pearl-id-hash when -pearl-id-hash is empty")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: keygen publisher <solana-keypair.json>")
		}
		if strings.TrimSpace(*licenseMint) == "" || strings.TrimSpace(*domain) == "" {
			return errors.New("--license-mint and --domain are required")
		}
		if err := validateFreshChain(*programID, *clusterGenesisHash); err != nil {
			return err
		}
		return doPublisher(fs.Arg(0), *licenseMint, *domain, *programID, *clusterGenesisHash, *chainID, *pearlIDHash, *label, stdout)
	case "store-pubkey":
		fs := flag.NewFlagSet("store-pubkey", flag.ContinueOnError)
		signPubkeyB58 := fs.String("sign-pubkey-b58", "", "store operator signing_pubkey_b58 (required)")
		boxPubkeyB58 := fs.String("box-pubkey-b58", "", "store operator encryption_pubkey_b58 (required)")
		licenseMint := fs.String("license-mint", "", "store operator license_nft_mint (required)")
		domain := fs.String("domain", "", "store serving domain (required)")
		programID := fs.String("program-id", "", "fresh license-registry program id (required; legacy refused)")
		clusterGenesisHash := fs.String("cluster-genesis-hash", "", "exact target-cluster getGenesisHash result (required)")
		chainID := fs.String("chain-id", "solana:devnet", "chain id")
		pdaFlag := fs.String("pda", "", "exact derived SidecarIdentityEntry PDA base58 (required)")
		sidecarID := fs.String("sidecar-id", "", "store sidecar_id (required)")
		keyVersion := fs.Uint("key-version", 1, "SidecarIdentityEntry key_version")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		for name, value := range map[string]string{
			"--sign-pubkey-b58": *signPubkeyB58, "--box-pubkey-b58": *boxPubkeyB58,
			"--license-mint": *licenseMint, "--domain": *domain, "--pda": *pdaFlag,
			"--sidecar-id": *sidecarID,
		} {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s is required", name)
			}
		}
		if err := validateFreshChain(*programID, *clusterGenesisHash); err != nil {
			return err
		}
		if *keyVersion == 0 || *keyVersion > uint(^uint32(0)) {
			return errors.New("--key-version must fit uint32 and be non-zero")
		}
		program, _ := primitives.PubkeyFromBase58(*programID)
		license, err := primitives.PubkeyFromBase58(*licenseMint)
		if err != nil {
			return fmt.Errorf("--license-mint: %w", err)
		}
		if err := primitives.ValidateSidecarID(*sidecarID); err != nil {
			return fmt.Errorf("--sidecar-id: %w", err)
		}
		expectedPDA, _, err := pda.SidecarIdentity(license, *sidecarID, uint32(*keyVersion), program)
		if err != nil {
			return fmt.Errorf("derive SidecarIdentity PDA: %w", err)
		}
		if *pdaFlag != expectedPDA.Base58() {
			return fmt.Errorf("--pda %s != derived fresh-program PDA %s", *pdaFlag, expectedPDA.Base58())
		}
		pub := identity.Public{
			Version: identity.CurrentVersion,
			Ref: identity.Ref{
				Kind:        identity.KindSidecar,
				ChainID:     *chainID,
				ProgramID:   *programID,
				LicenseMint: *licenseMint,
				Domain:      *domain,
				PDA:         *pdaFlag,
				SidecarID:   *sidecarID,
				KeyVersion:  uint32(*keyVersion),
			},
			SignPubkeyB58: *signPubkeyB58,
			BoxPubkeyB58:  *boxPubkeyB58,
		}
		if err := pub.Validate(); err != nil {
			return fmt.Errorf("constructed store identity.Public failed Validate(): %w", err)
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(pub); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "cluster_genesis_hash = %s\n", *clusterGenesisHash)
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q (want publisher | store-pubkey)", args[0])
	}
}

// solanaKeypairFile is the standard Solana CLI keypair JSON: a 64-byte array
// [ed25519 seed(32) || ed25519 pubkey(32)].
func loadSolanaSeed(path string) ([32]byte, ed25519.PublicKey, error) {
	var seed [32]byte
	raw, err := os.ReadFile(path)
	if err != nil {
		return seed, nil, err
	}
	var arr []byte
	if err := json.Unmarshal(raw, &arr); err != nil {
		return seed, nil, fmt.Errorf("parse %s as a JSON byte array: %w", path, err)
	}
	if len(arr) != 64 {
		return seed, nil, fmt.Errorf("%s: want a 64-byte Solana keypair array, got %d bytes", path, len(arr))
	}
	copy(seed[:], arr[:32])
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	// sanity: the file's own trailing 32 bytes should equal the derived pubkey.
	if !bytesEqual(arr[32:], pub) {
		return seed, nil, fmt.Errorf("%s: trailing 32 bytes do not match ed25519.NewKeyFromSeed(seed).Public() — not a standard Solana keypair file", path)
	}
	return seed, pub, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// publisherKeyFile mirrors cmd/submit's private (unexported) type — the JSON
// shape --publisher-key reads: {ref, sign_seed_hex, box_seed_hex}.
type publisherKeyFile struct {
	Ref                identity.Ref `json:"ref"`
	ClusterGenesisHash string       `json:"cluster_genesis_hash"`
	SignSeed           string       `json:"sign_seed_hex"`
	BoxSeed            string       `json:"box_seed_hex"`
}

func doPublisher(keypairPath, licenseMint, domain, programID, clusterGenesisHash, chainID, pearlIDHash, label string, stdout io.Writer) error {
	seed, pub, err := loadSolanaSeed(keypairPath)
	if err != nil {
		return err
	}
	if pearlIDHash == "" {
		sum := sha256.Sum256([]byte(label))
		pearlIDHash = hex.EncodeToString(sum[:])
	}
	pubB58 := primitives.EncodeBase58(pub)
	ref := identity.Ref{
		Kind:        identity.KindPearl,
		ChainID:     chainID,
		ProgramID:   programID,
		LicenseMint: licenseMint,
		Domain:      domain,
		PDA:         pubB58,
		PearlIDHash: pearlIDHash,
		KeyVersion:  1,
	}
	var boxSeed [32]byte
	if _, err := rand.Read(boxSeed[:]); err != nil {
		return fmt.Errorf("generate box seed: %w", err)
	}
	// Round-trip through NewPrivate to fail fast if the Ref is malformed
	// (Validate() runs inside), before ever writing anything out.
	priv, err := identity.NewPrivate(ref, seed, boxSeed)
	if err != nil {
		return fmt.Errorf("construct identity.Private: %w", err)
	}
	derivedPub := priv.Public()
	if derivedPub.SignPubkeyB58 != pubB58 {
		return fmt.Errorf("internal: derived sign_pubkey_b58 %s != solana keypair pubkey %s", derivedPub.SignPubkeyB58, pubB58)
	}
	out := publisherKeyFile{
		Ref: ref, ClusterGenesisHash: clusterGenesisHash,
		SignSeed: hex.EncodeToString(seed[:]), BoxSeed: hex.EncodeToString(boxSeed[:]),
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func validateFreshChain(programID, clusterGenesisHash string) error {
	if strings.TrimSpace(programID) == "" || strings.TrimSpace(clusterGenesisHash) == "" {
		return errors.New("--program-id and --cluster-genesis-hash are required")
	}
	if programID == legacyProgramID {
		return errors.New("legacy --program-id is refused")
	}
	program, err := primitives.PubkeyFromBase58(programID)
	if err != nil || program.Base58() != programID {
		return errors.New("--program-id must be a canonical base58 32-byte key")
	}
	genesis, err := primitives.PubkeyFromBase58(clusterGenesisHash)
	if err != nil || genesis.Base58() != clusterGenesisHash {
		return errors.New("--cluster-genesis-hash must be a canonical base58 32-byte hash")
	}
	return nil
}
