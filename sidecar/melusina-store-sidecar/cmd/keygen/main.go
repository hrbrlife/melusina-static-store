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

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

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
		licenseMint := fs.String("license-mint", "B7Bby1ZRUzWydLkch6cVA1sqHLGUTjKr9oEQ3GZBbYMe", "identity.Ref.LicenseMint (the release master-NFT mint; matches pearl-app-ceremony.sh MELUSINA_MASTER_NFT_MINT)")
		domain := fs.String("domain", "bazaar.melusina-os.org", "identity.Ref.Domain (must equal the envelope Payload.Domain the sidecar expects — the store's serving domain)")
		programID := fs.String("program-id", "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb", "identity.Ref.ProgramID (the license-registry program)")
		chainID := fs.String("chain-id", "solana:devnet", "identity.Ref.ChainID")
		pearlIDHash := fs.String("pearl-id-hash", "", "identity.Ref.PearlIDHash (required for Kind=pearl; defaults to sha256(label) if empty)")
		label := fs.String("label", "core-app-team-publisher", "human label hashed into the default pearl-id-hash when -pearl-id-hash is empty")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: keygen publisher <solana-keypair.json>")
		}
		return doPublisher(fs.Arg(0), *licenseMint, *domain, *programID, *chainID, *pearlIDHash, *label, stdout)
	case "store-pubkey":
		fs := flag.NewFlagSet("store-pubkey", flag.ContinueOnError)
		// The production Bazaar operator is the v2 boot identity under the
		// melusina-os.org license. Keep these defaults aligned with the active
		// on-chain SidecarIdentityEntry so a normal publish cannot seal to the
		// retired dev.paype.cc identity.
		signPubkeyB58 := fs.String("sign-pubkey-b58", "4J2hbufiTKmvgfxjGVNqhoQXiKVDsYwaor6hcaDKjzZV", "store operator signing_pubkey_b58 (from the active on-chain SidecarIdentityEntry)")
		boxPubkeyB58 := fs.String("box-pubkey-b58", "D62iWtghh4s6majv1xm5bbeTnLmzrkycF1tA9bgcnKJ5", "store operator encryption_pubkey_b58")
		licenseMint := fs.String("license-mint", "9yfmmcTG8BBiSPHf6kZC77tUzm46VMnfyrLzd3E2ii9J", "store operator license_nft_mint")
		domain := fs.String("domain", "bazaar.melusina-os.org", "store serving domain")
		programID := fs.String("program-id", "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb", "license-registry program id")
		chainID := fs.String("chain-id", "solana:devnet", "chain id")
		pda := fs.String("pda", "7eESnZ9hvVAVTDCwSq73FGygqhp9bQZ5jF672NZsSKr6", "active SidecarIdentityEntry PDA base58")
		sidecarID := fs.String("sidecar-id", "melusina-os-root-store-v2", "active store sidecar_id")
		keyVersion := fs.Uint("key-version", 1, "SidecarIdentityEntry key_version")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		pub := identity.Public{
			Version: identity.CurrentVersion,
			Ref: identity.Ref{
				Kind:        identity.KindSidecar,
				ChainID:     *chainID,
				ProgramID:   *programID,
				LicenseMint: *licenseMint,
				Domain:      *domain,
				PDA:         *pda,
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
		return enc.Encode(pub)
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
	Ref      identity.Ref `json:"ref"`
	SignSeed string       `json:"sign_seed_hex"`
	BoxSeed  string       `json:"box_seed_hex"`
}

func doPublisher(keypairPath, licenseMint, domain, programID, chainID, pearlIDHash, label string, stdout io.Writer) error {
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
		Ref:      ref,
		SignSeed: hex.EncodeToString(seed[:]),
		BoxSeed:  hex.EncodeToString(boxSeed[:]),
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
