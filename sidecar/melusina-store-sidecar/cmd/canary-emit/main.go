// Command canary-emit is the LIVE canary wire-emitter for the governed
// store-sidecar in-place upgrade (melusina-store-update-apply.py, the
// AWAIT_CANARY_SIGNATURES edge).
//
// The governed apply's health-gate canary re-publishes the EXACT-CURRENT (no-op)
// first catalog pointer through the v2 store gate to prove the freshly-installed
// binary serves + gates before the outcome is committed. That publish is driven
// by a v2 melusina-attest publish-request envelope (envelope.KindPublishRequest)
// signed OFFLINE by the store publisher (accept_publishers key), addressed to the
// store's kv1 OPERATOR identity (the envelope destination). Until this tool there
// was no producer that BUILT that wire against LIVE identities / material /
// chain-evidence — canary_control_producer.py only WRAPS a pre-built wire, and
// the isolated gate proof used a test-only signer with mock identities. This tool
// closes that gap.
//
// It is the exact analogue of cmd/submit's buildEnvelope (the REUSED publish
// signer), specialised for the canary: it emits BOTH the stage and promote wires
// under caller-pinned deterministic nonces + a deadline-covering TTL, and writes
// the canary_control_producer.py input fixture (which carries the offline
// signer's seed + both wires + the exact-current RELEASE/SPK/metadata). It never
// POSTs and never writes on-chain.
//
// Two subcommands respect the custody split (HT13):
//
//	operator-public  derive the kv1 operator identity.Public (the envelope
//	                 DESTINATION) from the LIVE config + the three attest shards.
//	                 Runs where the shards live (the box). Prints ONLY the derived
//	                 Public (pubkeys are public); never a shard byte.
//	sign             build the two publish-request wires + the producer fixture
//	                 from the operator Public (above) + the publisher signing
//	                 identity + the exact-current material. Runs where the
//	                 publisher key lives (offline). The seed is written into the
//	                 fixture file (0600) for the producer; it is never printed.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	defaultProgramIDB58 = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"
	defaultChainID      = "solana:devnet"
	stageTarget         = "/publish/stage"
	promoteTarget       = "/publish"
	// maxTransportTTL mirrors the envelope transport ceiling AND the canary
	// control-envelope lifetime cap (CanaryEnvelope.parse: expires-issued <= 30m).
	maxTransportTTL = 30 * time.Minute
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: canary-emit <operator-public|operator-seeds|sign-update-manifest|sign> [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "operator-public":
		err = runOperatorPublic(os.Args[2:])
	case "sign":
		err = runSign(os.Args[2:])
	case "operator-seeds":
		err = runOperatorSeeds(os.Args[2:])
	case "sign-update-manifest":
		err = runSignUpdateManifest(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q (want operator-public|operator-seeds|sign-update-manifest|sign)", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "canary-emit: %v\n", err)
		os.Exit(1)
	}
}

// ── config (minimal; the store's own Config is package main and not importable) ──

type storeConfigFile struct {
	LicenseNFTMint string `json:"license_nft_mint"`
	ProgramID      string `json:"program_id"`
	Domain         string `json:"domain"`
	BootIdentity   struct {
		ShardsDir          string `json:"shards_dir"`
		SidecarID          string `json:"sidecar_id"`
		ChainID            string `json:"chain_id"`
		KeyVersion         uint32 `json:"key_version"`
		OperatorKeyVersion uint32 `json:"operator_key_version"`
		OperatorDomain     string `json:"operator_domain"`
	} `json:"boot_identity"`
}

// publisherKeyFile is the offline publisher signing identity (the envelope
// SOURCE): a validated attest Ref plus the 32-byte ed25519 sign seed and 32-byte
// x25519 box seed (hex). Byte-identical to cmd/submit's publisherKeyFile.
type publisherKeyFile struct {
	Ref      identity.Ref `json:"ref"`
	SignSeed string       `json:"sign_seed_hex"`
	BoxSeed  string       `json:"box_seed_hex"`
}

// ── operator-public ──────────────────────────────────────────────────────────

func runOperatorPublic(args []string) error {
	fs := flag.NewFlagSet("operator-public", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to the LIVE store config JSON (required)")
	shardsDir := fs.String("shards", "", "override boot_identity.shards_dir (the three attest shards)")
	expect := fs.String("expect-sign-pubkey", "", "cross-check: the derived operator sign pubkey MUST equal this base58 (the live boot operator)")
	out := fs.String("out", "", "write the operator identity.Public JSON here (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("--config is required")
	}
	cfg, err := loadStoreConfig(*configPath)
	if err != nil {
		return err
	}
	dir := strings.TrimSpace(*shardsDir)
	if dir == "" {
		dir = strings.TrimSpace(cfg.BootIdentity.ShardsDir)
	}
	if dir == "" {
		return errors.New("no shards dir (neither --shards nor config boot_identity.shards_dir)")
	}

	ref, err := operatorRef(cfg)
	if err != nil {
		return err
	}
	shards, err := loadSidecarShards(dir)
	if err != nil {
		return fmt.Errorf("load shards: %w", err)
	}
	op, err := derive.DeriveSidecar(ref, shards)
	if err != nil {
		return fmt.Errorf("derive operator: %w", err)
	}
	pub := op.Public()
	if err := pub.Validate(); err != nil {
		return fmt.Errorf("derived operator public invalid: %w", err)
	}
	if e := strings.TrimSpace(*expect); e != "" && pub.SignPubkeyB58 != e {
		return fmt.Errorf("derived operator sign pubkey %s != expected %s (the ref does not match the live boot operator)", pub.SignPubkeyB58, e)
	}
	body, err := json.MarshalIndent(pub, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if strings.TrimSpace(*out) != "" {
		if err := os.WriteFile(*out, body, 0o644); err != nil {
			return err
		}
	} else {
		os.Stdout.Write(body)
	}
	// Diagnostics are PUBLIC (pubkeys + identity digest). No shard byte is ever emitted.
	fmt.Fprintf(os.Stderr, "operator sign_pubkey_b58 = %s\n", pub.SignPubkeyB58)
	fmt.Fprintf(os.Stderr, "operator box_pubkey_b58  = %s\n", pub.BoxPubkeyB58)
	fmt.Fprintf(os.Stderr, "operator identity digest = %s\n", pub.DigestHex())
	fmt.Fprintf(os.Stderr, "operator PDA (ref.pda)   = %s (kv=%d, domain=%s)\n", pub.Ref.PDA, pub.Ref.KeyVersion, pub.Ref.Domain)
	return nil
}

// operatorRef reconstructs the stable kv1 operator identity Ref exactly as the
// store's boot_identity.operatorIdentityRef does (operator_key_version, then
// key_version, then 1; operator_domain overrides domain). A drift here derives a
// different key, which the destination-digest gate rejects — but we cross-check
// the sign pubkey in operator-public to catch it loudly instead.
func operatorRef(cfg storeConfigFile) (identity.Ref, error) {
	programID, err := primitives.PubkeyFromBase58(programIDOf(cfg))
	if err != nil {
		return identity.Ref{}, fmt.Errorf("program_id: %w", err)
	}
	licenseMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(cfg.LicenseNFTMint))
	if err != nil {
		return identity.Ref{}, fmt.Errorf("license_nft_mint: %w", err)
	}
	sidecarID := strings.TrimSpace(cfg.BootIdentity.SidecarID)
	if err := primitives.ValidateSidecarID(sidecarID); err != nil {
		return identity.Ref{}, fmt.Errorf("boot_identity.sidecar_id: %w", err)
	}
	bindingVersion := cfg.BootIdentity.KeyVersion
	if bindingVersion == 0 {
		bindingVersion = 1
	}
	operatorVersion := cfg.BootIdentity.OperatorKeyVersion
	if operatorVersion == 0 {
		operatorVersion = bindingVersion
	}
	operatorDomain := strings.TrimSpace(cfg.BootIdentity.OperatorDomain)
	if operatorDomain == "" {
		operatorDomain = strings.TrimSpace(cfg.Domain)
	}
	chainID := strings.TrimSpace(cfg.BootIdentity.ChainID)
	if chainID == "" {
		return identity.Ref{}, errors.New("boot_identity.chain_id is required")
	}
	operatorPDA, _, err := pda.SidecarIdentity(licenseMint, sidecarID, operatorVersion, programID)
	if err != nil {
		return identity.Ref{}, fmt.Errorf("derive operator SidecarIdentity PDA: %w", err)
	}
	return identity.Ref{
		Kind:        identity.KindSidecar,
		ChainID:     chainID,
		ProgramID:   programID.Base58(),
		LicenseMint: strings.TrimSpace(cfg.LicenseNFTMint),
		Domain:      operatorDomain,
		PDA:         operatorPDA.Base58(),
		SidecarID:   sidecarID,
		KeyVersion:  operatorVersion,
	}, nil
}

// loadSidecarShards reads the three deploy-provisioned attest shards, matching
// the store's boot_identity.loadSidecarShards (64 hex chars OR 32 raw bytes).
// The shard bytes are SECRET (HT13); they are consumed into the HKDF and never
// returned to a caller that prints.
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

// ── operator-seeds ─────────────────────────────────────────────────────────────
//
// Reproduces the kv1 operator's HKDF-derived sign+box seeds from the LIVE shards
// (identical to derive.DeriveSidecar, cross-checked against it) and writes the
// operator publisher-identity file {ref, sign_seed_hex, box_seed_hex} (0600) that
// the existing `sign` subcommand + canary_control_producer.py consume. This lets
// the canary WIRE + CONTROL be offline-signed by the REAL operator key (== the
// on-chain store authority F616.signing_pubkey), so the store's operator-signed
// receipts verify against the REAL kv1 operator pubkey. The seeds are written to a
// 0600 file for the offline signer and are NEVER printed (HT13).
func runOperatorSeeds(args []string) error {
	fs := flag.NewFlagSet("operator-seeds", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to the LIVE store config JSON (required)")
	shardsDir := fs.String("shards", "", "override boot_identity.shards_dir")
	expect := fs.String("expect-sign-pubkey", "", "cross-check: derived operator sign pubkey MUST equal this base58")
	out := fs.String("out", "", "write the operator publisher-identity JSON here (0600) (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *out == "" {
		return errors.New("--config and --out are required")
	}
	cfg, err := loadStoreConfig(*configPath)
	if err != nil {
		return err
	}
	dir := strings.TrimSpace(*shardsDir)
	if dir == "" {
		dir = strings.TrimSpace(cfg.BootIdentity.ShardsDir)
	}
	if dir == "" {
		return errors.New("no shards dir")
	}
	ref, err := operatorRef(cfg)
	if err != nil {
		return err
	}
	shards, err := loadSidecarShards(dir)
	if err != nil {
		return fmt.Errorf("load shards: %w", err)
	}
	// Reproduce derive.derive() exactly (labels + info are the attest v1 domain).
	ikm := append(append(append([]byte{}, shards.AuthorShard[:]...),
		shards.HostObservationShard[:]...), shards.ReleaseShard[:]...)
	refBytes, err := json.Marshal(ref)
	if err != nil {
		return err
	}
	refDigest := sha256.Sum256(refBytes)
	info := fmt.Sprintf("%s|kv=%d|ref=%x", ref.Kind, ref.KeyVersion, refDigest[:])
	master, err := hkdf32(ikm, []byte("melusina-attest/sidecar-master/v1"), []byte(info))
	if err != nil {
		return err
	}
	signSeed, err := hkdf32(master[:], nil, []byte("melusina-attest/sign-seed/v1"))
	if err != nil {
		return err
	}
	boxSeed, err := hkdf32(master[:], nil, []byte("melusina-attest/box-seed/v1"))
	if err != nil {
		return err
	}
	// Cross-check: NewPrivate(seeds) must equal DeriveSidecar(shards).
	reproduced, err := identity.NewPrivate(ref, signSeed, boxSeed)
	if err != nil {
		return err
	}
	authoritative, err := derive.DeriveSidecar(ref, shards)
	if err != nil {
		return err
	}
	if reproduced.Public().SignPubkeyB58 != authoritative.Public().SignPubkeyB58 ||
		reproduced.Public().BoxPubkeyB58 != authoritative.Public().BoxPubkeyB58 {
		return errors.New("seed reproduction diverged from DeriveSidecar (HKDF mismatch)")
	}
	if e := strings.TrimSpace(*expect); e != "" && reproduced.Public().SignPubkeyB58 != e {
		return fmt.Errorf("derived operator sign pubkey %s != expected %s", reproduced.Public().SignPubkeyB58, e)
	}
	body, err := json.MarshalIndent(map[string]any{
		"ref":           ref,
		"sign_seed_hex": hex.EncodeToString(signSeed[:]),
		"box_seed_hex":  hex.EncodeToString(boxSeed[:]),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(body, '\n'), 0o600); err != nil {
		return err
	}
	// PUBLIC diagnostics only (never the seeds).
	fmt.Fprintf(os.Stderr, "operator sign_pubkey_b58 = %s\n", reproduced.Public().SignPubkeyB58)
	fmt.Fprintf(os.Stderr, "operator PDA             = %s (kv=%d)\n", ref.PDA, ref.KeyVersion)
	fmt.Fprintf(os.Stderr, "publisher-identity (seeds, 0600) written = %s\n", *out)
	return nil
}

// sign-update-manifest signs the legacy shell update manifest in place with
// the live store operator identity. The checker canonicalizes the JSON by
// removing `signature`, sorting keys, and using compact separators; Go's
// encoding/json applies the same deterministic ordering to map keys. Deriving
// and signing here keeps every shard and private-key byte on the store host.
func runSignUpdateManifest(args []string) error {
	fs := flag.NewFlagSet("sign-update-manifest", flag.ContinueOnError)
	configPath := fs.String("config", "", "path to the LIVE store config JSON (required)")
	shardsDir := fs.String("shards", "", "override boot_identity.shards_dir")
	expect := fs.String("expect-sign-pubkey", "", "derived operator sign pubkey must equal this base58")
	inputPath := fs.String("input", "", "unsigned update manifest JSON (required)")
	outPath := fs.String("out", "", "signed update manifest JSON (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*configPath) == "" || strings.TrimSpace(*inputPath) == "" || strings.TrimSpace(*outPath) == "" {
		return errors.New("--config, --input, and --out are required")
	}
	cfg, err := loadStoreConfig(*configPath)
	if err != nil {
		return err
	}
	dir := strings.TrimSpace(*shardsDir)
	if dir == "" {
		dir = strings.TrimSpace(cfg.BootIdentity.ShardsDir)
	}
	if dir == "" {
		return errors.New("no shards dir (neither --shards nor config boot_identity.shards_dir)")
	}
	ref, err := operatorRef(cfg)
	if err != nil {
		return err
	}
	shards, err := loadSidecarShards(dir)
	if err != nil {
		return fmt.Errorf("load shards: %w", err)
	}
	op, err := derive.DeriveSidecar(ref, shards)
	if err != nil {
		return fmt.Errorf("derive operator: %w", err)
	}
	pub := op.Public()
	if e := strings.TrimSpace(*expect); e != "" && pub.SignPubkeyB58 != e {
		return fmt.Errorf("derived operator sign pubkey %s != expected %s", pub.SignPubkeyB58, e)
	}
	raw, err := os.ReadFile(*inputPath)
	if err != nil {
		return fmt.Errorf("read input manifest: %w", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("parse input manifest: %w", err)
	}
	delete(manifest, "signature")
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("canonicalize manifest: %w", err)
	}
	sig := op.Sign(canonical)
	if !pub.Verify(canonical, sig) {
		return errors.New("internal signature verification failed")
	}
	manifest["signature"] = base64.StdEncoding.EncodeToString(sig)
	signed, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode signed manifest: %w", err)
	}
	if err := os.WriteFile(*outPath, append(signed, '\n'), 0o644); err != nil {
		return fmt.Errorf("write signed manifest: %w", err)
	}
	fmt.Fprintf(os.Stderr, "update manifest signed by = %s\n", pub.SignPubkeyB58)
	fmt.Fprintf(os.Stderr, "canonical sha256         = %x\n", sha256.Sum256(canonical))
	fmt.Fprintf(os.Stderr, "signed manifest written  = %s\n", *outPath)
	return nil
}

func hkdf32(ikm, salt, info []byte) ([32]byte, error) {
	var outv [32]byte
	r := hkdf.New(sha256.New, ikm, salt, info)
	if _, err := io.ReadFull(r, outv[:]); err != nil {
		return outv, err
	}
	return outv, nil
}

// ── sign ─────────────────────────────────────────────────────────────────────

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	operatorPublic := fs.String("operator-public", "", "operator identity.Public JSON (the envelope destination; from `operator-public`) (required)")
	publisherKey := fs.String("publisher-identity", "", "publisher signing identity JSON {ref, sign_seed_hex, box_seed_hex} (required)")
	releasePath := fs.String("release", "", "path to the exact-current RELEASE.json bytes (envelope Body) (required)")
	spkPath := fs.String("spk", "", "path to the exact-current app.spk bytes (RequestHash=sha256) (required)")
	metadataPath := fs.String("metadata", "", "path to the exact-current metadata.json bytes (required)")
	releaseEntryPDA := fs.String("release-entry-pda", "", "chain evidence: the app's on-chain ReleaseEntry PDA (base58) (required)")
	verifiedSlot := fs.Uint64("verified-slot", 0, "chain evidence: verified_slot (a real finalized slot; must be > 0) (required)")
	chainID := fs.String("chain-id", defaultChainID, "chain evidence chain_id")
	programID := fs.String("program-id", defaultProgramIDB58, "chain evidence program_id")
	nowUnix := fs.Int64("now-unix", 0, "issue time (unix seconds); 0 => now")
	ttlSeconds := fs.Int64("ttl-seconds", 1200, "envelope TTL seconds (<= 1800; must cover the deadline)")
	deadlineUnix := fs.Int64("deadline-unix", 0, "the governed-apply canary deadline (unix seconds); if set, expires must exceed deadline+60")
	stageNonce := fs.String("stage-nonce", "", "deterministic nonce for the stage wire (required)")
	promoteNonce := fs.String("promote-nonce", "", "deterministic nonce for the promote wire (required)")
	txid := fs.String("txid", "", "apply transaction id (recorded in the fixture for the control producer) (required)")
	walDigest := fs.String("wal-digest", "", "the apply WAL digest the control envelope binds (required)")
	outFixture := fs.String("out-fixture", "", "write the canary_control_producer.py input fixture here (0600) (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, v := range map[string]string{
		"--operator-public": *operatorPublic, "--publisher-identity": *publisherKey,
		"--release": *releasePath, "--spk": *spkPath, "--metadata": *metadataPath,
		"--release-entry-pda": *releaseEntryPDA, "--stage-nonce": *stageNonce,
		"--promote-nonce": *promoteNonce, "--txid": *txid, "--wal-digest": *walDigest,
		"--out-fixture": *outFixture,
	} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if *verifiedSlot == 0 {
		return errors.New("--verified-slot must be > 0 (envelope chain evidence requires it)")
	}
	if *stageNonce == *promoteNonce {
		return errors.New("--stage-nonce and --promote-nonce must differ (distinct replay scopes)")
	}

	dstBytes, err := os.ReadFile(*operatorPublic)
	if err != nil {
		return fmt.Errorf("read operator-public: %w", err)
	}
	dst, err := identity.ParsePublicJSON(dstBytes)
	if err != nil {
		return fmt.Errorf("parse operator identity.Public: %w", err)
	}
	keyRaw, err := os.ReadFile(*publisherKey)
	if err != nil {
		return fmt.Errorf("read publisher-identity: %w", err)
	}
	var pk publisherKeyFile
	if err := json.Unmarshal(keyRaw, &pk); err != nil {
		return fmt.Errorf("parse publisher-identity JSON: %w", err)
	}
	signSeed, err := seed32FromHex(pk.SignSeed)
	if err != nil {
		return fmt.Errorf("publisher sign_seed_hex: %w", err)
	}
	boxSeed, err := seed32FromHex(pk.BoxSeed)
	if err != nil {
		return fmt.Errorf("publisher box_seed_hex: %w", err)
	}
	pub, err := identity.NewPrivate(pk.Ref, signSeed, boxSeed)
	if err != nil {
		return fmt.Errorf("derive publisher identity: %w", err)
	}

	release, err := readNonEmpty(*releasePath)
	if err != nil {
		return err
	}
	spk, err := readNonEmpty(*spkPath)
	if err != nil {
		return err
	}
	metadata, err := readNonEmpty(*metadataPath)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if *nowUnix != 0 {
		now = time.Unix(*nowUnix, 0).UTC()
	}
	ttl := time.Duration(*ttlSeconds) * time.Second
	if ttl <= 0 || ttl > maxTransportTTL {
		return fmt.Errorf("--ttl-seconds must be in (0, %d]", int(maxTransportTTL.Seconds()))
	}
	expires := now.Add(ttl)
	if *deadlineUnix != 0 && expires.Unix() <= *deadlineUnix+60 {
		return fmt.Errorf("TTL too short: expires=%d must exceed deadline+60=%d (widen --ttl-seconds within the 1800s cap)", expires.Unix(), *deadlineUnix+60)
	}

	chain := envelope.ChainEvidence{
		ChainID:         strings.TrimSpace(*chainID),
		ProgramID:       strings.TrimSpace(*programID),
		VerifiedSlot:    *verifiedSlot,
		ReleaseEntryPDA: strings.TrimSpace(*releaseEntryPDA),
	}
	spkSum := sha256.Sum256(spk)
	requestHash := hex.EncodeToString(spkSum[:])

	sign := func(target, nonce string) (envelope.Signed, error) {
		return envelope.Sign(envelope.KindPublishRequest, pub, dst, envelope.SignOptions{
			Method:      http.MethodPost,
			Target:      target,
			Body:        release,
			RequestHash: requestHash,
			Now:         now,
			TTL:         ttl,
			Nonce:       nonce,
			Chain:       chain,
		})
	}
	stageWire, err := sign(stageTarget, *stageNonce)
	if err != nil {
		return fmt.Errorf("sign stage wire: %w", err)
	}
	promoteWire, err := sign(promoteTarget, *promoteNonce)
	if err != nil {
		return fmt.Errorf("sign promote wire: %w", err)
	}

	// The fixture is EXACTLY canary_control_producer.py's input contract. It
	// carries the offline signer's seed so the producer can control-sign the
	// OUTER envelope with the same key; the fixture is written 0600 and the seed
	// is never printed (HT13).
	fixture := map[string]any{
		"publisher_seed_hex": strings.TrimSpace(pk.SignSeed),
		"authorized_signer":  pub.Public().SignPubkeyB58,
		"release_b64":        base64.StdEncoding.EncodeToString(release),
		"spk_b64":            base64.StdEncoding.EncodeToString(spk),
		"metadata_b64":       base64.StdEncoding.EncodeToString(metadata),
		"txid":               strings.TrimSpace(*txid),
		"wal_digest":         strings.TrimSpace(*walDigest),
		"stage_wire":         stageWire,
		"promote_wire":       promoteWire,
	}
	fixBytes, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return err
	}
	fixBytes = append(fixBytes, '\n')
	if err := os.WriteFile(*outFixture, fixBytes, 0o600); err != nil {
		return fmt.Errorf("write fixture: %w", err)
	}

	// PUBLIC diagnostics only.
	fmt.Fprintf(os.Stderr, "authorized_signer (source) = %s\n", pub.Public().SignPubkeyB58)
	fmt.Fprintf(os.Stderr, "destination sign_pubkey    = %s\n", dst.SignPubkeyB58)
	fmt.Fprintf(os.Stderr, "destination digest         = %s\n", dst.DigestHex())
	fmt.Fprintf(os.Stderr, "request_hash (sha256 spk)  = %s\n", requestHash)
	fmt.Fprintf(os.Stderr, "release_entry_pda          = %s\n", chain.ReleaseEntryPDA)
	fmt.Fprintf(os.Stderr, "verified_slot              = %d\n", chain.VerifiedSlot)
	fmt.Fprintf(os.Stderr, "issued/expires (unix)      = %d / %d\n", now.Unix(), expires.Unix())
	fmt.Fprintf(os.Stderr, "stage   payload_hash/nonce = %s / %s\n", stageWire.PayloadHash, *stageNonce)
	fmt.Fprintf(os.Stderr, "promote payload_hash/nonce = %s / %s\n", promoteWire.PayloadHash, *promoteNonce)
	fmt.Fprintf(os.Stderr, "fixture written            = %s (0600)\n", *outFixture)
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func loadStoreConfig(path string) (storeConfigFile, error) {
	var cfg storeConfigFile
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	if strings.TrimSpace(cfg.Domain) == "" {
		return cfg, errors.New("config: domain is required")
	}
	if strings.TrimSpace(cfg.LicenseNFTMint) == "" {
		return cfg, errors.New("config: license_nft_mint is required")
	}
	return cfg, nil
}

func programIDOf(cfg storeConfigFile) string {
	if s := strings.TrimSpace(cfg.ProgramID); s != "" {
		return s
	}
	return defaultProgramIDB58
}

func readNonEmpty(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return b, nil
}

func seed32FromHex(h string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("want 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}
