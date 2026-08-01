// Command boot-identity-prep prepares the store-sidecar B1-02 boot identity
// ceremony without broadcasting any on-chain transaction.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	defaultProgramID = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	defaultChainID   = "solana:devnet"
)

type options struct {
	shardsDir          string
	licenseMint        string
	domain             string
	sidecarID          string
	chainID            string
	programID          string
	keyVersion         uint
	operatorKeyVersion uint
	operatorDomain     string
	binaryPath         string
	tlsCertPath        string
	caChainPath        string
}

type shardReport struct {
	Dir     string            `json:"dir"`
	Created bool              `json:"created"`
	Files   map[string]string `json:"files"`
}

type ceremonyReport struct {
	Warning              string          `json:"warning"`
	Shards               shardReport     `json:"shards"`
	IdentityRef          identity.Ref    `json:"identity_ref"`
	OperatorIdentityRef  identity.Ref    `json:"operator_identity_ref"`
	SidecarIdentityPDA   string          `json:"sidecar_identity_pda"`
	SidecarIdentityBump  uint8           `json:"sidecar_identity_bump"`
	RegisterSidecarInput registerSidecar `json:"register_sidecar_identity"`
	ConfigBootIdentity   configSnippet   `json:"config_boot_identity"`
}

type registerSidecar struct {
	ProgramID              string `json:"program_id"`
	LicenseNFTMint         string `json:"license_nft_mint"`
	SidecarID              string `json:"sidecar_id"`
	KeyVersion             uint32 `json:"key_version"`
	BinaryHashHex          string `json:"binary_hash_hex"`
	DomainHashHex          string `json:"domain_hash_hex"`
	TLSCertFingerprintHex  string `json:"tls_cert_fingerprint_hex"`
	CAChainHashHex         string `json:"ca_chain_hash_hex"`
	SigningPubkeyHex       string `json:"signing_pubkey_hex"`
	SigningPubkeyBase58    string `json:"signing_pubkey_b58"`
	EncryptionPubkeyHex    string `json:"encryption_pubkey_hex"`
	EncryptionPubkeyBase58 string `json:"encryption_pubkey_b58"`
}

type configSnippet struct {
	ShardsDir          string `json:"shards_dir"`
	SidecarID          string `json:"sidecar_id"`
	ChainID            string `json:"chain_id"`
	KeyVersion         uint32 `json:"key_version"`
	OperatorKeyVersion uint32 `json:"operator_key_version,omitempty"`
	OperatorDomain     string `json:"operator_domain,omitempty"`
	TLSCertPath        string `json:"tls_cert_path,omitempty"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "boot-identity-prep: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	report, err := prepare(opts)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func parseOptions(args []string) (options, error) {
	var opts options
	fs := flag.NewFlagSet("boot-identity-prep", flag.ContinueOnError)
	fs.StringVar(&opts.shardsDir, "shards-dir", "", "directory for author.shard, host-observation.shard, release.shard")
	fs.StringVar(&opts.licenseMint, "license-mint", "", "store operator License NFT mint")
	fs.StringVar(&opts.domain, "domain", "", "store domain used for store_domain_hash")
	fs.StringVar(&opts.sidecarID, "sidecar-id", "store", "sidecar_id seed for SidecarIdentityEntry")
	fs.StringVar(&opts.chainID, "chain-id", defaultChainID, "attest identity chain id")
	fs.StringVar(&opts.programID, "program-id", defaultProgramID, "license registry program id")
	fs.UintVar(&opts.keyVersion, "key-version", 1, "SidecarIdentityEntry key_version seed")
	fs.UintVar(&opts.operatorKeyVersion, "operator-key-version", 0, "stable operator identity key_version; 0 uses -key-version")
	fs.StringVar(&opts.operatorDomain, "operator-domain", "", "stable operator identity domain; empty uses -domain")
	fs.StringVar(&opts.binaryPath, "binary", "", "exact sidecar binary whose sha256 becomes binary_hash")
	fs.StringVar(&opts.tlsCertPath, "tls-cert", "", "PEM certificate/fullchain; first cert sha256(DER) becomes tls_cert_fingerprint")
	fs.StringVar(&opts.caChainPath, "ca-chain", "", "optional PEM CA/intermediate bundle; if omitted, hashes tls-cert certs after the leaf")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional args: %v", fs.Args())
	}
	return opts, validateOptions(opts)
}

func validateOptions(opts options) error {
	missing := []string{}
	for name, value := range map[string]string{
		"-shards-dir":   opts.shardsDir,
		"-license-mint": opts.licenseMint,
		"-domain":       opts.domain,
		"-sidecar-id":   opts.sidecarID,
		"-chain-id":     opts.chainID,
		"-program-id":   opts.programID,
		"-binary":       opts.binaryPath,
		"-tls-cert":     opts.tlsCertPath,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
	}
	if opts.keyVersion == 0 || opts.keyVersion > uint(^uint32(0)) {
		return fmt.Errorf("-key-version must fit uint32 and be non-zero")
	}
	if opts.operatorKeyVersion > uint(^uint32(0)) {
		return fmt.Errorf("-operator-key-version must fit uint32")
	}
	if err := primitives.ValidateSidecarID(opts.sidecarID); err != nil {
		return fmt.Errorf("-sidecar-id: %w", err)
	}
	if _, err := primitives.PubkeyFromBase58(opts.licenseMint); err != nil {
		return fmt.Errorf("-license-mint: %w", err)
	}
	if _, err := primitives.PubkeyFromBase58(opts.programID); err != nil {
		return fmt.Errorf("-program-id: %w", err)
	}
	return nil
}

func prepare(opts options) (ceremonyReport, error) {
	keyVersion := uint32(opts.keyVersion)
	licenseMint, _ := primitives.PubkeyFromBase58(opts.licenseMint)
	programID, _ := primitives.PubkeyFromBase58(opts.programID)
	sidecarPDA, bump, err := pda.SidecarIdentity(licenseMint, opts.sidecarID, keyVersion, programID)
	if err != nil {
		return ceremonyReport{}, fmt.Errorf("derive sidecar identity PDA: %w", err)
	}

	shards, shardsCreated, err := ensureShards(opts.shardsDir)
	if err != nil {
		return ceremonyReport{}, err
	}
	ref := identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     strings.TrimSpace(opts.chainID),
		ProgramID:   programID.Base58(),
		LicenseMint: licenseMint.Base58(),
		Domain:      strings.TrimSpace(opts.domain),
		PDA:         sidecarPDA.Base58(),
		SidecarID:   strings.TrimSpace(opts.sidecarID),
		KeyVersion:  keyVersion,
	}
	operatorVersion := uint32(opts.operatorKeyVersion)
	if operatorVersion == 0 {
		operatorVersion = keyVersion
	}
	operatorDomain := strings.TrimSpace(opts.operatorDomain)
	if operatorDomain == "" {
		operatorDomain = strings.TrimSpace(opts.domain)
	}
	operatorPDA, _, err := pda.SidecarIdentity(licenseMint, opts.sidecarID, operatorVersion, programID)
	if err != nil {
		return ceremonyReport{}, fmt.Errorf("derive operator identity PDA: %w", err)
	}
	operatorRef := identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     strings.TrimSpace(opts.chainID),
		ProgramID:   programID.Base58(),
		LicenseMint: licenseMint.Base58(),
		Domain:      operatorDomain,
		PDA:         operatorPDA.Base58(),
		SidecarID:   strings.TrimSpace(opts.sidecarID),
		KeyVersion:  operatorVersion,
	}
	operator, err := derive.DeriveSidecar(operatorRef, shards)
	if err != nil {
		return ceremonyReport{}, fmt.Errorf("derive sidecar operator: %w", err)
	}
	pub := operator.Public()
	signingPubkey, err := pub.SignPublicKey()
	if err != nil {
		return ceremonyReport{}, err
	}
	encryptionPubkey, err := pub.BoxPublicKey()
	if err != nil {
		return ceremonyReport{}, err
	}

	binaryHash, err := sha256OfFile(opts.binaryPath)
	if err != nil {
		return ceremonyReport{}, fmt.Errorf("binary_hash: %w", err)
	}
	tlsFingerprint, caHash, err := certHashes(opts.tlsCertPath, opts.caChainPath)
	if err != nil {
		return ceremonyReport{}, err
	}
	domainHash := primitives.StoreDomainHash(opts.domain)

	return ceremonyReport{
		Warning: "secret shard values are intentionally omitted; protect the shard files mode 0600 and never commit them",
		Shards: shardReport{
			Dir:     opts.shardsDir,
			Created: shardsCreated,
			Files: map[string]string{
				"author":           filepath.Join(opts.shardsDir, "author.shard"),
				"host_observation": filepath.Join(opts.shardsDir, "host-observation.shard"),
				"release":          filepath.Join(opts.shardsDir, "release.shard"),
			},
		},
		IdentityRef:         ref,
		OperatorIdentityRef: operatorRef,
		SidecarIdentityPDA:  sidecarPDA.Base58(),
		SidecarIdentityBump: bump,
		RegisterSidecarInput: registerSidecar{
			ProgramID:              programID.Base58(),
			LicenseNFTMint:         licenseMint.Base58(),
			SidecarID:              opts.sidecarID,
			KeyVersion:             keyVersion,
			BinaryHashHex:          hex32(binaryHash),
			DomainHashHex:          hex32(domainHash),
			TLSCertFingerprintHex:  hex32(tlsFingerprint),
			CAChainHashHex:         hex32(caHash),
			SigningPubkeyHex:       hex.EncodeToString(signingPubkey),
			SigningPubkeyBase58:    primitives.EncodeBase58(signingPubkey),
			EncryptionPubkeyHex:    hex.EncodeToString(encryptionPubkey.Bytes()),
			EncryptionPubkeyBase58: pub.BoxPubkeyB58,
		},
		ConfigBootIdentity: configSnippet{
			ShardsDir:          opts.shardsDir,
			SidecarID:          opts.sidecarID,
			ChainID:            opts.chainID,
			KeyVersion:         keyVersion,
			OperatorKeyVersion: uint32(opts.operatorKeyVersion),
			OperatorDomain:     strings.TrimSpace(opts.operatorDomain),
			TLSCertPath:        opts.tlsCertPath,
		},
	}, nil
}

func ensureShards(dir string) (derive.SidecarShards, bool, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return derive.SidecarShards{}, false, fmt.Errorf("create shards dir: %w", err)
	}
	names := []string{"author.shard", "host-observation.shard", "release.shard"}
	exists := 0
	for _, name := range names {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			exists++
		} else if !errors.Is(err, os.ErrNotExist) {
			return derive.SidecarShards{}, false, fmt.Errorf("stat %s: %w", name, err)
		}
	}
	if exists != 0 && exists != len(names) {
		return derive.SidecarShards{}, false, fmt.Errorf("partial shard set in %s; refusing to mix old and new shards", dir)
	}
	created := exists == 0
	if created {
		for _, name := range names {
			var shard [32]byte
			if _, err := rand.Read(shard[:]); err != nil {
				return derive.SidecarShards{}, false, fmt.Errorf("generate %s: %w", name, err)
			}
			if err := writeShard(filepath.Join(dir, name), shard); err != nil {
				return derive.SidecarShards{}, false, err
			}
		}
	}
	shards, err := loadShards(dir)
	if err != nil {
		return derive.SidecarShards{}, false, err
	}
	return shards, created, nil
}

func writeShard(path string, shard [32]byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("write shard %s: %w", path, err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s\n", hex.EncodeToString(shard[:])); err != nil {
		return fmt.Errorf("write shard %s: %w", path, err)
	}
	return nil
}

func loadShards(dir string) (derive.SidecarShards, error) {
	var shards derive.SidecarShards
	for _, file := range []struct {
		name string
		dst  *[32]byte
	}{
		{"author.shard", &shards.AuthorShard},
		{"host-observation.shard", &shards.HostObservationShard},
		{"release.shard", &shards.ReleaseShard},
	} {
		path := filepath.Join(dir, file.name)
		info, err := os.Stat(path)
		if err != nil {
			return shards, fmt.Errorf("stat %s: %w", path, err)
		}
		if info.Mode().Perm()&0077 != 0 {
			return shards, fmt.Errorf("%s permissions %04o are too broad; want no group/other bits", path, info.Mode().Perm())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return shards, fmt.Errorf("read %s: %w", path, err)
		}
		val, err := parseShard32(raw)
		if err != nil {
			return shards, fmt.Errorf("%s: %w", path, err)
		}
		*file.dst = val
	}
	return shards, nil
}

func parseShard32(raw []byte) ([32]byte, error) {
	var out [32]byte
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 64 {
		decoded, err := hex.DecodeString(trimmed)
		if err != nil {
			return out, fmt.Errorf("not valid 32-byte hex: %w", err)
		}
		copy(out[:], decoded)
		return out, nil
	}
	if len(raw) == 32 {
		copy(out[:], raw)
		return out, nil
	}
	return out, fmt.Errorf("want 64 hex chars or 32 raw bytes, got %d bytes", len(raw))
}

func certHashes(tlsCertPath, caChainPath string) ([32]byte, [32]byte, error) {
	leafAndMaybeChain, err := readPEMCerts(tlsCertPath)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("tls cert: %w", err)
	}
	leafFingerprint := sha256.Sum256(leafAndMaybeChain[0])
	caCerts := leafAndMaybeChain[1:]
	if strings.TrimSpace(caChainPath) != "" {
		caCerts, err = readPEMCerts(caChainPath)
		if err != nil {
			return [32]byte{}, [32]byte{}, fmt.Errorf("ca chain: %w", err)
		}
	}
	return leafFingerprint, sha256Concat(caCerts), nil
}

func readPEMCerts(path string) ([][]byte, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs [][]byte
	for rest := pemBytes; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert := make([]byte, len(block.Bytes))
			copy(cert, block.Bytes)
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s: no CERTIFICATE PEM block", path)
	}
	return certs, nil
}

func sha256Concat(parts [][]byte) [32]byte {
	if len(parts) == 0 {
		return [32]byte{}
	}
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func sha256OfFile(path string) ([32]byte, error) {
	var out [32]byte
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return out, err
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

func hex32(v [32]byte) string {
	return hex.EncodeToString(v[:])
}
