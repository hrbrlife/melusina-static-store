package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
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

// ── BOOT-IDENTITY ceremony (B1-02; gated /publish operator) ───────────────────
//
// Until this ran, main.go hard-coded `operator = nil`, so EVERY /publish 503'd —
// the only on-chain trust gate (VerifyPublish) was unreachable. This ceremony
// makes the operator real, fail-closed:
//
//  1. If boot_identity.shards_dir is UNSET, the store is deliberately read-only:
//     operator stays nil, /publish 503s, read+serve are unaffected. (returns nil,nil)
//  2. If it is SET, the store is publish-provisioned and EVERYTHING from here
//     fails CLOSED (Inv 5): a missing shard, an unreadable TLS cert, a missing /
//     mismatched on-chain SidecarIdentityEntry, or an RPC error → a non-nil error
//     that main.go turns into log.Fatalf (refuse to start a publish-provisioned
//     store with an unverified identity).
//
// The derived operator is bound to an on-chain SidecarIdentityEntry (registered
// by the deployer via register_sidecar_identity) — its signing_pubkey,
// encryption_pubkey, domain_hash, tls_cert_fingerprint, and binary_hash must ALL
// match the locally-derived/observed values. So the three secret shards alone are
// not enough: an attacker who guessed them would still have to match this store's
// domain, TLS cert, and running binary against the Foundation-cascade-gated chain
// entry. (This is the store-sidecar analogue of the fleet B11 self-hash gate that
// binhash.AttestSelfHashWith performs against GlobalSidecarApproval.)

// shardExeProc is the kernel's view of the running binary; sha256 over it is the
// binary_hash the SidecarIdentityEntry pins. Overridable in tests.
const shardExeProc = "/proc/self/exe"

// deriveOperatorIdentity runs the boot-identity ceremony and returns the gated
// /publish operator, or (nil, nil) when no operator is provisioned (read-only
// store). A non-nil error is FATAL at the call site (Inv 5 fail-closed).
func deriveOperatorIdentity(ctx context.Context, cfg Config, cr chainReader) (*identity.Private, error) {
	bi := cfg.BootIdentity
	if strings.TrimSpace(bi.ShardsDir) == "" {
		// Deliberately read-only: no publish operator provisioned.
		return nil, nil
	}

	// Publish-provisioned boot. From here everything fails CLOSED.
	if cr == nil {
		return nil, errors.New("boot_identity.shards_dir is set but rpc_url is not — cannot bind the operator on-chain (refusing to enable /publish unverified)")
	}
	if strings.TrimSpace(bootIdentityTLSCertPath(cfg)) == "" {
		return nil, errors.New("boot_identity.shards_dir is set but neither boot_identity.tls_cert_path nor tls.cert_path is set — a publish-provisioned store MUST bind a TLS cert to the on-chain SidecarIdentityEntry.tls_cert_fingerprint")
	}
	sidecarID := strings.TrimSpace(bi.SidecarID)
	if sidecarID == "" {
		return nil, errors.New("boot_identity.sidecar_id is required when shards_dir is set")
	}
	if err := primitives.ValidateSidecarID(sidecarID); err != nil {
		return nil, fmt.Errorf("boot_identity.sidecar_id %q invalid: %w", sidecarID, err)
	}
	if strings.TrimSpace(bi.ChainID) == "" {
		return nil, errors.New("boot_identity.chain_id is required when shards_dir is set")
	}
	keyVersion := bi.KeyVersion
	if keyVersion == 0 {
		keyVersion = 1
	}

	licenseMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.LicenseNFTMint))
	if err != nil {
		return nil, fmt.Errorf("boot_identity: bad license_nft_mint: %w", err)
	}
	sidecarPDA, _, err := pda.SidecarIdentity(licenseMint, sidecarID, keyVersion, programID)
	if err != nil {
		return nil, fmt.Errorf("boot_identity: derive SidecarIdentityEntry PDA: %w", err)
	}

	// Derive the operator from the three deploy-provisioned shards.
	shards, err := loadSidecarShards(bi.ShardsDir)
	if err != nil {
		return nil, fmt.Errorf("boot_identity: load shards: %w", err)
	}
	operatorRef, err := operatorIdentityRef(cfg, licenseMint, sidecarID, keyVersion)
	if err != nil {
		return nil, fmt.Errorf("boot_identity: derive operator identity Ref: %w", err)
	}
	operator, err := derive.DeriveSidecar(operatorRef, shards)
	if err != nil {
		return nil, fmt.Errorf("boot_identity: derive operator: %w", err)
	}

	// Compute the locally-observed bindings the on-chain entry must match.
	in, err := bootIdentityInputs(cfg, operator)
	if err != nil {
		return nil, fmt.Errorf("boot_identity: %w", err)
	}
	// Bind to the on-chain SidecarIdentityEntry (fail-closed).
	if err := verifySidecarIdentity(ctx, cr, sidecarPDA.Base58(), in); err != nil {
		return nil, err
	}
	return operator, nil
}

// sidecarIdentityRef builds the attest identity ref the operator key is derived
// under. Shared by deriveOperatorIdentity and its tests so the two can never
// drift (a drifted ref derives a different key, which then fails the on-chain
// signing_pubkey check — fail-closed, but the helper removes the footgun).
func sidecarIdentityRef(cfg Config, sidecarID string, keyVersion uint32, sidecarPDAB58 string) identity.Ref {
	return identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     strings.TrimSpace(cfg.BootIdentity.ChainID),
		ProgramID:   programID.Base58(),
		LicenseMint: cfg.LicenseNFTMint,
		Domain:      cfg.Domain,
		PDA:         sidecarPDAB58,
		SidecarID:   sidecarID,
		KeyVersion:  keyVersion,
	}
}

// operatorIdentityRef resolves the stable key-derivation Ref independently of
// the rotatable SidecarIdentityEntry selected by BootIdentity.KeyVersion.
// With no overrides it is byte-for-byte the legacy Ref.
func operatorIdentityRef(cfg Config, licenseMint primitives.Pubkey, sidecarID string, bindingVersion uint32) (identity.Ref, error) {
	operatorVersion := cfg.BootIdentity.OperatorKeyVersion
	if operatorVersion == 0 {
		operatorVersion = bindingVersion
	}
	operatorDomain := strings.TrimSpace(cfg.BootIdentity.OperatorDomain)
	if operatorDomain == "" {
		operatorDomain = cfg.Domain
	}
	operatorPDA, _, err := pda.SidecarIdentity(licenseMint, sidecarID, operatorVersion, programID)
	if err != nil {
		return identity.Ref{}, err
	}
	operatorCfg := cfg
	operatorCfg.Domain = operatorDomain
	return sidecarIdentityRef(operatorCfg, sidecarID, operatorVersion, operatorPDA.Base58()), nil
}

// bootIdentityFacts are the locally-derived/observed values the on-chain
// SidecarIdentityEntry must match. Split out so verifySidecarIdentity is unit
// testable against a mock reader without touching disk or /proc.
type bootIdentityFacts struct {
	signingPubkey    [32]byte
	encryptionPubkey [32]byte
	domainHash       [32]byte
	tlsFingerprint   [32]byte
	binaryHash       [32]byte
}

func bootIdentityTLSCertPath(cfg Config) string {
	if strings.TrimSpace(cfg.BootIdentity.TLSCertPath) != "" {
		return strings.TrimSpace(cfg.BootIdentity.TLSCertPath)
	}
	return strings.TrimSpace(cfg.TLS.CertPath)
}

// bootIdentityInputs computes the bindings: the derived operator's signing +
// encryption pubkeys, this store's domain hash, the serving TLS cert
// fingerprint (sha256 of the leaf cert DER — matches LicenseEntry.tls_cert_fingerprint),
// and the running binary hash.
func bootIdentityInputs(cfg Config, operator *identity.Private) (bootIdentityFacts, error) {
	var in bootIdentityFacts
	pub := operator.Public()
	sign, err := signPubkey32(pub)
	if err != nil {
		return in, err
	}
	box, err := boxPubkey32(pub)
	if err != nil {
		return in, err
	}
	tlsFP, err := tlsCertFingerprint(bootIdentityTLSCertPath(cfg))
	if err != nil {
		return in, err
	}
	selfHash, err := sha256OfFile(shardExeProc)
	if err != nil {
		return in, fmt.Errorf("hash self binary %s: %w", shardExeProc, err)
	}
	in.signingPubkey = sign
	in.encryptionPubkey = box
	in.domainHash = primitives.StoreDomainHash(cfg.Domain)
	in.tlsFingerprint = tlsFP
	in.binaryHash = selfHash
	return in, nil
}

// verifySidecarIdentity fetches the on-chain SidecarIdentityEntry and requires it
// Active with EVERY binding matching `in`. FAIL-CLOSED: a missing PDA, an RPC
// error, a non-Active status, or any field mismatch returns a non-nil error.
func verifySidecarIdentity(ctx context.Context, cr chainReader, pdaB58 string, in bootIdentityFacts) error {
	sid, err := cr.FetchSidecarIdentity(ctx, pdaB58)
	if err != nil {
		return fmt.Errorf("check=sidecar_identity: fetch %s: %w", pdaB58, err)
	}
	if err := sid.Status.RequireActive(); err != nil {
		return fmt.Errorf("check=sidecar_identity: status %s not Active: %w", sid.Status, err)
	}
	for _, c := range []struct {
		field    string
		got, exp [32]byte
	}{
		{"signing_pubkey", sid.SigningPubkey, in.signingPubkey},
		{"encryption_pubkey", sid.EncryptionPubkey, in.encryptionPubkey},
		{"domain_hash", sid.DomainHash, in.domainHash},
		{"tls_cert_fingerprint", sid.TLSCertFingerprint, in.tlsFingerprint},
		{"binary_hash", sid.BinaryHash, in.binaryHash},
	} {
		if c.got != c.exp {
			return fmt.Errorf("check=sidecar_identity: %s on-chain %x != local %x", c.field, c.got[:], c.exp[:])
		}
	}
	return nil
}

// loadSidecarShards reads the three deploy-provisioned attest shards.
func loadSidecarShards(dir string) (derive.SidecarShards, error) {
	var sh derive.SidecarShards
	for _, f := range []struct {
		name string
		dst  *[32]byte
	}{
		{"author.shard", &sh.AuthorShard},
		{"host-observation.shard", &sh.HostObservationShard},
		{"release.shard", &sh.ReleaseShard},
	} {
		raw, err := os.ReadFile(filepath.Join(dir, f.name))
		if err != nil {
			return sh, fmt.Errorf("read %s: %w", f.name, err)
		}
		val, err := parseShard32(raw)
		if err != nil {
			return sh, fmt.Errorf("%s: %w", f.name, err)
		}
		*f.dst = val
	}
	return sh, nil
}

// parseShard32 accepts a shard as either 64 lowercase/uppercase hex chars
// (whitespace trimmed) or exactly 32 raw bytes.
func parseShard32(raw []byte) ([32]byte, error) {
	var out [32]byte
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 64 {
		b, err := hex.DecodeString(trimmed)
		if err != nil {
			return out, fmt.Errorf("not valid 32-byte hex: %w", err)
		}
		copy(out[:], b)
		return out, nil
	}
	if len(raw) == 32 {
		copy(out[:], raw)
		return out, nil
	}
	return out, fmt.Errorf("want 64 hex chars or 32 raw bytes, got %d bytes", len(raw))
}

// tlsCertFingerprint returns sha256 of the leaf certificate's DER bytes (the
// first CERTIFICATE PEM block), matching the on-chain
// SidecarIdentityEntry/LicenseEntry tls_cert_fingerprint definition (sha256(cert.DER)).
func tlsCertFingerprint(certPath string) ([32]byte, error) {
	var zero [32]byte
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return zero, fmt.Errorf("read tls cert %s: %w", certPath, err)
	}
	for rest := pemBytes; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return sha256.Sum256(block.Bytes), nil
		}
	}
	return zero, fmt.Errorf("tls cert %s: no CERTIFICATE PEM block", certPath)
}

// sha256OfFile streams the file at path through a SHA-256 hasher.
func sha256OfFile(path string) ([32]byte, error) {
	var zero [32]byte
	f, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return zero, err
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
