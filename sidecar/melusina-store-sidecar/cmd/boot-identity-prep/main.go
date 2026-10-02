// Command boot-identity-prep prepares the store-sidecar B1-02 boot identity
// ceremony without broadcasting any on-chain transaction.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-store-sidecar/internal/estateprofile"
	"github.com/hrbrlife/melusina-store-sidecar/internal/rootstore"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// The license-registry program has no default: it is a fact of the estate
// whose Store is being prepared, and the derived operator key is salted by it.
//
// Nor has the chain id. The operator key is derived under it, so a default
// becomes permanent: it once was the retiring estate's cluster, and a Store
// prepared on any other network without -chain-id silently inherited it
// (K-TEN-03). It is either stated (-chain-id) or taken
// from the owner-signed estate profile (-profile); with neither, the preparer
// refuses by name before it touches the shard directory.
const (
	RefusalChainIDRequired           = "boot-identity-chain-id-required"
	RefusalChainIDDiffersFromProfile = "boot-identity-chain-id-differs-from-profile"
	RefusalProfileUnusable           = "boot-identity-profile-unusable"
	RefusalProfileLabelNotChainRef   = "boot-identity-profile-label-not-a-chain-reference"
	// RefusalProgramDiffersFromProfile: with -profile, the licence-registry
	// programme the key is salted by must be the verified profile's own, so a
	// verified profile never lends its chain to another estate's programme.
	RefusalProgramDiffersFromProfile = "boot-identity-program-differs-from-profile"
	// RefusalIdentityLeafSelfSignatureInvalid: the first -tls-cert certificate
	// is the boot identity leaf; it must be self-signed, so a mutated or
	// externally signed leaf is refused rather than fingerprinted into the
	// ceremony report.
	RefusalIdentityLeafSelfSignatureInvalid = "identity-leaf-self-signature-invalid"
)

// chainReferencePattern is a CAIP-2 chain reference ([-_a-zA-Z0-9]{1,32}).
// An estate profile's network.label is a looser pattern (up to 64 characters,
// dots allowed); a label that is not a valid chain reference is refused rather
// than truncated or rewritten.
var chainReferencePattern = regexp.MustCompile(`^[-_a-zA-Z0-9]{1,32}$`)

// maxProfileBytes bounds the -profile read at the estateprofile package's own
// bound for one profile document.
const maxProfileBytes = estateprofile.MaxProfileJSONBytes

type options struct {
	shardsDir          string
	licenseMint        string
	domain             string
	sidecarID          string
	chainID            string
	profilePath        string
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
	fs.StringVar(&opts.sidecarID, "sidecar-id", rootstore.SidecarID, "sidecar_id seed for SidecarIdentityEntry (the root Store's protocol constant; an estate-enrolled Store refuses any other)")
	fs.StringVar(&opts.chainID, "chain-id", "", "attest identity chain id, solana:<network name>; required unless -profile is given (there is no default chain)")
	fs.StringVar(&opts.profilePath, "profile", "", "owner-signed EstateProfileV1 JSON; the chain id is solana:<network.label> of the verified profile, and a -chain-id that differs is refused")
	fs.StringVar(&opts.programID, "program-id", "", "the estate's license-registry program id (required)")
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
	chainID, err := resolveChainID(opts.chainID, opts.profilePath, opts.programID)
	if err != nil {
		return options{}, err
	}
	opts.chainID = chainID
	return opts, validateOptions(opts)
}

// resolveChainID returns the chain the operator key is derived under: the
// verified profile's solana:<network.label> when -profile is given (and
// -chain-id, if also given, must equal it), else the stated -chain-id. With
// neither it refuses by name: there is no default chain.
func resolveChainID(stated, profilePath, programID string) (string, error) {
	stated = strings.TrimSpace(stated)
	if strings.TrimSpace(profilePath) == "" {
		if stated == "" {
			return "", fmt.Errorf("%s: state -chain-id solana:<network name> or pass the owner-signed estate profile with -profile; there is no default chain", RefusalChainIDRequired)
		}
		return stated, nil
	}
	derived, profileProgram, err := chainIDFromProfile(profilePath)
	if err != nil {
		return "", err
	}
	if programID = strings.TrimSpace(programID); programID != "" && programID != profileProgram {
		return "", fmt.Errorf("%s: -program-id %q, estate profile license-registry programme is %q", RefusalProgramDiffersFromProfile, programID, profileProgram)
	}
	if stated != "" && stated != derived {
		return "", fmt.Errorf("%s: -chain-id %q, estate profile network is %q", RefusalChainIDDiffersFromProfile, stated, derived)
	}
	return derived, nil
}

// chainIDFromProfile reads and verifies an owner-signed EstateProfileV1 and
// returns solana:<network.label>. The label is the network name the owners
// signed; it is the same convention the estate runbook states for -chain-id
// ("solana:<your network name>"), and the retiring estate's profile yields
// exactly the chain id its Store was prepared under.
func chainIDFromProfile(path string) (string, string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", "", fmt.Errorf("%s: %v", RefusalProfileUnusable, err)
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("%s: -profile must be a regular file, not a symlink or device", RefusalProfileUnusable)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("%s: %v", RefusalProfileUnusable, err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(maxProfileBytes)+1))
	if err != nil {
		return "", "", fmt.Errorf("%s: %v", RefusalProfileUnusable, err)
	}
	if len(raw) > maxProfileBytes {
		return "", "", fmt.Errorf("%s: -profile exceeds %d bytes", RefusalProfileUnusable, maxProfileBytes)
	}
	profile, err := estateprofile.DecodeProfile(raw)
	if err != nil {
		return "", "", fmt.Errorf("%s: %v", RefusalProfileUnusable, err)
	}
	if _, err := estateprofile.VerifyProfile(profile); err != nil {
		return "", "", fmt.Errorf("%s: %v", RefusalProfileUnusable, err)
	}
	if !chainReferencePattern.MatchString(profile.Network.Label) {
		return "", "", fmt.Errorf("%s: network.label %q", RefusalProfileLabelNotChainRef, profile.Network.Label)
	}
	program := ""
	for _, entry := range profile.Programs {
		if entry.Role == estateprofile.ProgramRoleLicenseRegistry {
			program = entry.ProgramID
		}
	}
	return "solana:" + profile.Network.Label, program, nil
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
	leafDER := leafAndMaybeChain[0]
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%s: parse tls identity leaf: %v", RefusalIdentityLeafSelfSignatureInvalid, err)
	}
	if !bytes.Equal(leaf.RawSubject, leaf.RawIssuer) {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%s: issuer differs from subject", RefusalIdentityLeafSelfSignatureInvalid)
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		return [32]byte{}, [32]byte{}, fmt.Errorf("%s: %v", RefusalIdentityLeafSelfSignatureInvalid, err)
	}
	leafFingerprint := sha256.Sum256(leafDER)
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
