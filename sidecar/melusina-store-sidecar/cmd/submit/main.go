// Command submit is the paired sealed-v3 publish client (FEDERATED-STORE-MVP
// §C3). It REPLACES the gh-pages force-push: instead of writing the catalog
// itself, it packs the publisher's CLAIMS (the canonical RELEASE.json) into a
// signed artifact envelope and POSTs them — together with the SPK bytes — to a
// store sidecar's gated POST /publish (the C2.3 receive contract). The sidecar
// is the SINGLE WRITER; this client never touches git.
//
// Trust flow (FEDERATED-STORE-MVP §0): the client signs an envelope binding
// RequestHash=sha256(SPK) and Body=RELEASE.json, addressed to the sidecar's
// operator identity (the envelope destination). On a 200 the store returns a
// store-signed provenance Receipt; the client then re-derives the store's
// on-chain StoreOperatorAuthorization, reads its store_authority, and verifies
// the receipt's operatorSignature (ed25519 over the RAW 96 bytes
// appHash||releaseHash||servingDomainHash, contract C-2) against that on-chain
// key. A receipt the chain does not vouch for is a FAILURE (exit 1) — the store
// saying "I stored it" is worthless unless the on-chain store_authority signed
// the tuple.
//
// This command is a separate main package in the SAME module as the sidecar; it
// reuses the monorepo libs via the module's existing path replaces but does NOT
// import the sidecar's package main, so the Receipt shape is re-declared locally
// for parsing.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// programIDB58 is the license-registry program the federated store verifies
// against (FEDERATED-STORE-MVP §1). It is the program that owns the
// ReleaseEntry + StoreOperatorAuthorization PDAs.
const programIDB58 = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"

// defaultChainID is the chain the envelope ChainEvidence is bound to when the
// publisher key file does not pin one. The sidecar does not gate on chain_id
// itself, but envelope.ChainEvidence.Validate requires a non-empty value.
const defaultChainID = "solana:devnet"

// Receipt mirrors the store-signed provenance receipt JSON returned by the C2.3
// /publish handler (sidecar provenance.go). It is re-declared here (NOT imported
// from the sidecar's package main) so cmd/submit can PARSE the response. The
// operator signs the RAW 96 bytes appHash||releaseHash||servingDomainHash; the
// hex/base58 below are presentation only.
type Receipt struct {
	AppHash           string `json:"appHash"`           // lowercase hex of [32]byte
	ReleaseHash       string `json:"releaseHash"`       // lowercase hex of [32]byte
	ServingDomainHash string `json:"servingDomainHash"` // lowercase hex of [32]byte
	OperatorSignature string `json:"operatorSignature"` // base58 of the 64-byte ed25519 signature
	StoredAt          int64  `json:"storedAt"`          // unix seconds
}

// ReleaseClaims is the subset of the canonical RELEASE.json (melusina-release-v1)
// the submit client needs to (a) assert sha256(SPK)==appHash locally before
// uploading and (b) re-derive the StoreOperatorAuthorization for receipt
// verification. The full RELEASE.json is sent verbatim as the envelope Body —
// the sidecar re-checks every trust field on-chain, so this struct only reads
// what the client itself uses.
type ReleaseClaims struct {
	AppHash       string `json:"appHash"`
	ReleaseHash   string `json:"releaseHash"`
	MasterNftMint string `json:"masterNftMint"`
}

// publisherKeyFile is the on-disk publisher signing identity. It is the
// publisher's attest identity (the envelope SOURCE): a validated identity.Ref
// plus the 32-byte ed25519 sign seed and 32-byte x25519 box seed (hex). The
// envelope's signature is produced from this key; the sidecar binds the release
// to the publisher's PDA on-chain, so the seeds here are the publisher's, never
// the store's.
type publisherKeyFile struct {
	Ref      identity.Ref `json:"ref"`
	SignSeed string       `json:"sign_seed_hex"`
	BoxSeed  string       `json:"box_seed_hex"`
}

// publishRequest is the JSON wire form the sidecar's /publish accepts when the
// client does not use multipart. Mirrors handler.go publishRequest. base64-std.
type publishRequest struct {
	Envelope   envelope.Signed `json:"envelope"`
	ReleaseB64 string          `json:"release_b64"`
	SPKB64     string          `json:"spk_b64"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "submit: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	store        string
	spkPath      string
	releasePath  string
	publisherKey string // path; or env name via --publisher-key env:NAME
	storePubkey  string // path to the sidecar operator identity.Public JSON
	licenseMint  string // store operator's license_nft_mint (StoreOperatorAuthz seed)
	domain       string // store serving domain (store_domain_hash seed)
	rpcURL       string // Solana JSON-RPC for receipt verification
	verifiedSlot uint64 // ChainEvidence.verified_slot (publisher's local pre-check slot)
	useMultipart bool
	timeout      time.Duration
}

func parseFlags(args []string) (options, error) {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	var o options
	fs.StringVar(&o.store, "store", "", "store sidecar base URL, e.g. https://store.example.org (required)")
	fs.StringVar(&o.spkPath, "spk", "", "path to the .spk package bytes (required)")
	fs.StringVar(&o.releasePath, "release", "", "path to the canonical RELEASE.json (required)")
	fs.StringVar(&o.publisherKey, "publisher-key", "", "publisher signing identity: a path, or env:NAME to read the JSON from $NAME (required)")
	fs.StringVar(&o.storePubkey, "store-pubkey", "", "path to the sidecar operator identity.Public JSON (the envelope destination; required — the sidecar exposes no well-known identity endpoint yet)")
	fs.StringVar(&o.licenseMint, "license-mint", "", "store operator license_nft_mint (base58); StoreOperatorAuthorization seed for receipt verification (required)")
	fs.StringVar(&o.domain, "domain", "", "store serving domain (bare host); store_domain_hash seed for receipt verification (defaults to the host in --store)")
	fs.StringVar(&o.rpcURL, "rpc-url", "", "Solana JSON-RPC endpoint used to read the on-chain store_authority for receipt verification (required)")
	fs.Uint64Var(&o.verifiedSlot, "verified-slot", 1, "ChainEvidence verified_slot for the envelope (publisher's local on-chain pre-check slot)")
	fs.BoolVar(&o.useMultipart, "multipart", false, "POST as multipart/form-data {envelope,release,spk} instead of the JSON wire form")
	fs.DurationVar(&o.timeout, "timeout", 60*time.Second, "HTTP request timeout")
	if err := fs.Parse(args); err != nil {
		return o, err
	}

	var missing []string
	if o.store == "" {
		missing = append(missing, "--store")
	}
	if o.spkPath == "" {
		missing = append(missing, "--spk")
	}
	if o.releasePath == "" {
		missing = append(missing, "--release")
	}
	if o.publisherKey == "" {
		missing = append(missing, "--publisher-key")
	}
	if o.storePubkey == "" {
		missing = append(missing, "--store-pubkey")
	}
	if o.licenseMint == "" {
		missing = append(missing, "--license-mint")
	}
	if o.rpcURL == "" {
		missing = append(missing, "--rpc-url")
	}
	if len(missing) > 0 {
		return o, fmt.Errorf("missing required flag(s): %s", strings.Join(missing, " "))
	}
	if o.verifiedSlot == 0 {
		// envelope.ChainEvidence.Validate rejects verified_slot==0.
		return o, errors.New("--verified-slot must be > 0 (envelope chain evidence requires it)")
	}
	if o.domain == "" {
		o.domain = hostFromURL(o.store)
	}
	return o, nil
}

func run(args []string, stdout, stderr io.Writer) error {
	o, err := parseFlags(args)
	if err != nil {
		return err
	}

	spk, err := os.ReadFile(o.spkPath)
	if err != nil {
		return fmt.Errorf("read spk %s: %w", o.spkPath, err)
	}
	if len(spk) == 0 {
		return fmt.Errorf("spk %s is empty", o.spkPath)
	}
	releaseBytes, err := os.ReadFile(o.releasePath)
	if err != nil {
		return fmt.Errorf("read release %s: %w", o.releasePath, err)
	}

	// Local pre-check: sha256(SPK) must equal release.appHash. The sidecar
	// re-checks this on-chain; failing here saves a doomed round-trip and names
	// the mismatch with publisher-side context.
	var claims ReleaseClaims
	if err := json.Unmarshal(releaseBytes, &claims); err != nil {
		return fmt.Errorf("parse RELEASE.json %s: %w", o.releasePath, err)
	}
	appSum := sha256.Sum256(spk)
	appHashHex := hex.EncodeToString(appSum[:])
	wantAppHash := strings.ToLower(strings.TrimSpace(claims.AppHash))
	if appHashHex != wantAppHash {
		return fmt.Errorf("check=spk_sha256: sha256(spk)=%s != release.appHash=%s", appHashHex, wantAppHash)
	}

	pubPriv, err := loadPublisherKey(o.publisherKey)
	if err != nil {
		return fmt.Errorf("publisher key: %w", err)
	}
	dst, err := loadStorePubkey(o.storePubkey)
	if err != nil {
		return fmt.Errorf("store pubkey: %w", err)
	}

	// Build the signed artifact envelope: KindArtifact addressed to the store
	// operator, binding RequestHash=sha256(SPK) and Body=RELEASE.json, carrying
	// the on-chain evidence (ReleaseEntry PDA, program, slot). BodyHash is set
	// explicitly to sha256(release) — the sidecar requires sha256(release) ==
	// envelope.body_hash.
	sig, err := buildEnvelope(pubPriv, dst, spk, releaseBytes, claims, o.verifiedSlot)
	if err != nil {
		return fmt.Errorf("envelope: %w", err)
	}

	// POST to <store>/publish.
	resp, status, err := postPublish(context.Background(), o, sig, releaseBytes, spk)
	if err != nil {
		return fmt.Errorf("publish POST: %w", err)
	}
	if status != http.StatusOK {
		// The sidecar names the failing check in the body (e.g. "check=spk_sha256").
		return fmt.Errorf("store rejected publish: HTTP %d: %s", status, strings.TrimSpace(string(resp)))
	}

	var receipt Receipt
	if err := json.Unmarshal(resp, &receipt); err != nil {
		return fmt.Errorf("decode receipt: %w", err)
	}

	// Verify the store-signed provenance receipt against the ON-CHAIN
	// store_authority. A store that returns 200 but a receipt the chain does not
	// vouch for is a FAILURE — the install-side trust (C4) depends on this exact
	// check, so the publish client refuses to call it a success.
	cr := verify.NewRPCClient(o.rpcURL)
	if err := verifyReceipt(context.Background(), cr, o.licenseMint, o.domain, receipt); err != nil {
		return fmt.Errorf("receipt verification: %w", err)
	}

	out, _ := json.MarshalIndent(receipt, "", "  ")
	fmt.Fprintf(stdout, "PUBLISH OK — store-signed provenance receipt verified against on-chain store_authority\n%s\n", out)
	return nil
}

// buildEnvelope constructs the sealed-v3 signed artifact envelope. The sidecar's
// envelope.Verify requires Kind==artifact, Destination==operator, RequestHash==
// sha256(SPK), and sha256(Body)==BodyHash; we set all of them here.
func buildEnvelope(src *identity.Private, dst identity.Public, spk, releaseBytes []byte, claims ReleaseClaims, verifiedSlot uint64) (envelope.Signed, error) {
	spkSum := sha256.Sum256(spk)
	relSum := sha256.Sum256(releaseBytes)

	chain := envelope.ChainEvidence{
		ChainID:      firstNonEmpty(src.Public().Ref.ChainID, defaultChainID),
		ProgramID:    firstNonEmpty(src.Public().Ref.ProgramID, programIDB58),
		VerifiedSlot: verifiedSlot,
	}
	// Pin the ReleaseEntry PDA as chain evidence when the masterNftMint is
	// present and parseable (it is re-derived + checked by the sidecar against
	// the release.masterNftMint anyway; this is the publisher's claimed PDA).
	if mm := strings.TrimSpace(claims.MasterNftMint); mm != "" {
		if relPDA, err := releaseEntryPDA(mm, spkSum); err == nil {
			chain.ReleaseEntryPDA = relPDA
		}
	}

	return envelope.Sign(envelope.KindArtifact, src, dst, envelope.SignOptions{
		Body:        releaseBytes,
		BodyHash:    hex.EncodeToString(relSum[:]),
		RequestHash: hex.EncodeToString(spkSum[:]),
		TTL:         5 * time.Minute,
		Chain:       chain,
	})
}

// releaseEntryPDA derives the ReleaseEntry PDA base58 from the masterNftMint and
// the app_hash (= sha256(SPK)), matching the sidecar's VerifyPublish derivation.
func releaseEntryPDA(masterMintB58 string, appHash [32]byte) (string, error) {
	mm, err := primitives.PubkeyFromBase58(masterMintB58)
	if err != nil {
		return "", err
	}
	programID, err := primitives.PubkeyFromBase58(programIDB58)
	if err != nil {
		return "", err
	}
	relPDA, _, err := pda.Release(mm, appHash, programID)
	if err != nil {
		return "", err
	}
	return relPDA.Base58(), nil
}

// postPublish sends the publish to <store>/publish in either the JSON wire form
// or multipart/form-data, returning the raw body + status code.
func postPublish(ctx context.Context, o options, sig envelope.Signed, releaseBytes, spk []byte) ([]byte, int, error) {
	url := strings.TrimRight(o.store, "/") + "/publish"
	client := &http.Client{Timeout: o.timeout}

	var (
		req *http.Request
		err error
	)
	if o.useMultipart {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		envBytes, merr := json.Marshal(sig)
		if merr != nil {
			return nil, 0, fmt.Errorf("marshal envelope: %w", merr)
		}
		if werr := writePart(mw, "envelope", "envelope.json", envBytes); werr != nil {
			return nil, 0, werr
		}
		if werr := writePart(mw, "release", "RELEASE.json", releaseBytes); werr != nil {
			return nil, 0, werr
		}
		if werr := writePart(mw, "spk", "app.spk", spk); werr != nil {
			return nil, 0, werr
		}
		if cerr := mw.Close(); cerr != nil {
			return nil, 0, cerr
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
	} else {
		body, merr := json.Marshal(publishRequest{
			Envelope:   sig,
			ReleaseB64: stdB64(releaseBytes),
			SPKB64:     stdB64(spk),
		})
		if merr != nil {
			return nil, 0, fmt.Errorf("marshal JSON body: %w", merr)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return out, resp.StatusCode, nil
}

func writePart(mw *multipart.Writer, field, filename string, data []byte) error {
	w, err := mw.CreateFormFile(field, filename)
	if err != nil {
		return fmt.Errorf("create %s part: %w", field, err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write %s part: %w", field, err)
	}
	return nil
}

// storeOperatorAuthzFetcher is the slice of *verify.RPCClient receipt
// verification needs. An interface so tests can inject a deterministic reader
// (no live RPC in unit tests — memory melusina-devnet-rpc).
type storeOperatorAuthzFetcher interface {
	FetchStoreOperatorAuthz(ctx context.Context, addrB58 string) (status verify.AuthorizationStatus, storeAuthority verify.Pubkey, allowedTierMask uint8, isRoot bool, storeDomainHash [32]byte, err error)
}

// compile-time assertion: the production client satisfies the fetcher.
var _ storeOperatorAuthzFetcher = (*verify.RPCClient)(nil)

// verifyReceipt re-derives the store's StoreOperatorAuthorization PDA
// (seeds ["store_operator", license_nft_mint, store_domain_hash]), reads the
// on-chain store_authority, and verifies the receipt's operatorSignature
// (ed25519 over the RAW 96 bytes appHash||releaseHash||servingDomainHash) under
// that key. FAIL-CLOSED: a missing/non-Active authz, a domain-hash mismatch, a
// malformed receipt field, or an invalid signature all return an error.
func verifyReceipt(ctx context.Context, cr storeOperatorAuthzFetcher, licenseMintB58, domain string, receipt Receipt) error {
	programID, err := primitives.PubkeyFromBase58(programIDB58)
	if err != nil {
		return fmt.Errorf("check=program_id: %w", err)
	}
	licenseMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(licenseMintB58))
	if err != nil {
		return fmt.Errorf("check=license_mint: bad --license-mint: %w", err)
	}
	storeDomainHash := primitives.StoreDomainHash(domain)
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, storeDomainHash, programID)
	if err != nil {
		return fmt.Errorf("check=store_operator_authz: derive PDA: %w", err)
	}
	status, storeAuthority, _, _, onchainDomainHash, err := cr.FetchStoreOperatorAuthz(ctx, authzPDA.Base58())
	if err != nil {
		return fmt.Errorf("check=store_operator_authz: fetch %s: %w", authzPDA.Base58(), err)
	}
	if err := status.RequireActive(); err != nil {
		return fmt.Errorf("check=store_operator_authz: status %s not Active: %w", status, err)
	}
	// Bind the store_domain_hash the chain pins to the domain we derived the PDA
	// from (defends against a confused-domain receipt).
	if onchainDomainHash != storeDomainHash {
		return fmt.Errorf("check=store_operator_authz: on-chain store_domain_hash %x != derived %x", onchainDomainHash[:], storeDomainHash[:])
	}

	appHash, err := hash32FromHex(receipt.AppHash)
	if err != nil {
		return fmt.Errorf("check=receipt: appHash: %w", err)
	}
	releaseHash, err := hash32FromHex(receipt.ReleaseHash)
	if err != nil {
		return fmt.Errorf("check=receipt: releaseHash: %w", err)
	}
	servingDomainHash, err := hash32FromHex(receipt.ServingDomainHash)
	if err != nil {
		return fmt.Errorf("check=receipt: servingDomainHash: %w", err)
	}
	// The receipt's servingDomainHash MUST be the store's domain hash; otherwise
	// the operator signed a tuple for a different store.
	if servingDomainHash != storeDomainHash {
		return fmt.Errorf("check=receipt: servingDomainHash %x != store_domain_hash %x", servingDomainHash[:], storeDomainHash[:])
	}

	sigBytes, err := primitives.DecodeBase58(strings.TrimSpace(receipt.OperatorSignature))
	if err != nil {
		return fmt.Errorf("check=receipt: operatorSignature not base58: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("check=receipt: operatorSignature must be %d bytes, got %d", ed25519.SignatureSize, len(sigBytes))
	}

	msg := receiptMessage(appHash, releaseHash, servingDomainHash)
	pubKey := ed25519.PublicKey(storeAuthority[:])
	if !ed25519.Verify(pubKey, msg, sigBytes) {
		return errors.New("check=receipt: operatorSignature does not verify against on-chain store_authority")
	}
	return nil
}

// receiptMessage assembles the EXACT bytes the operator signs / a verifier
// re-derives: the raw 96 bytes appHash||releaseHash||servingDomainHash (contract
// C-2, byte-identical to the sidecar's provenance.go receiptMessage).
func receiptMessage(appHash, releaseHash, servingDomainHash [32]byte) []byte {
	msg := make([]byte, 0, 96)
	msg = append(msg, appHash[:]...)
	msg = append(msg, releaseHash[:]...)
	msg = append(msg, servingDomainHash[:]...)
	return msg
}

// loadPublisherKey reads the publisher signing identity from a path or, when the
// argument is "env:NAME", from the environment variable NAME.
func loadPublisherKey(arg string) (*identity.Private, error) {
	var raw []byte
	if name, ok := strings.CutPrefix(arg, "env:"); ok {
		val := os.Getenv(name)
		if val == "" {
			return nil, fmt.Errorf("env %s is empty", name)
		}
		raw = []byte(val)
	} else {
		b, err := os.ReadFile(arg)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", arg, err)
		}
		raw = b
	}
	var f publisherKeyFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse publisher key JSON: %w", err)
	}
	signSeed, err := seed32FromHex(f.SignSeed)
	if err != nil {
		return nil, fmt.Errorf("sign_seed_hex: %w", err)
	}
	boxSeed, err := seed32FromHex(f.BoxSeed)
	if err != nil {
		return nil, fmt.Errorf("box_seed_hex: %w", err)
	}
	priv, err := identity.NewPrivate(f.Ref, signSeed, boxSeed)
	if err != nil {
		return nil, fmt.Errorf("derive identity: %w", err)
	}
	return priv, nil
}

// loadStorePubkey reads the sidecar operator's full identity.Public (the
// envelope destination) from a JSON file. The sidecar matches the destination by
// identity Digest, so the FULL Public struct is required, not just the raw key.
func loadStorePubkey(path string) (identity.Public, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return identity.Public{}, fmt.Errorf("read %s: %w", path, err)
	}
	pub, err := identity.ParsePublicJSON(b)
	if err != nil {
		return identity.Public{}, fmt.Errorf("parse store operator identity.Public: %w", err)
	}
	return pub, nil
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

func hash32FromHex(h string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(h)))
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("want 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func stdB64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// hostFromURL extracts the bare host from a store base URL (no scheme/port/path)
// for use as the store_domain_hash seed when --domain is not given.
func hostFromURL(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		// strip :port (but not part of an unbracketed host with no port)
		s = s[:i]
	}
	return s
}
