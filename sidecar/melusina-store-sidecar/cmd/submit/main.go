// Command submit is the paired sealed-v3 publish client (FEDERATED-STORE-MVP
// §C3). It REPLACES the gh-pages force-push: instead of writing the catalog
// itself, it packs the publisher's CLAIMS (the canonical RELEASE.json) into a
// signed publish-request envelope (envelope.KindPublishRequest) and POSTs
// them — together with the SPK bytes — to a
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
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-attest/pda"
	"github.com/hrbrlife/melusina-identity-gate/verify"
	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
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

const (
	appPromoteTarget           = "/publish"
	appStageTarget             = "/publish/stage"
	controlPublishTargetPrefix = "/control/v1/releases/"
	controlPublishTargetSuffix = "/publish"
	controlRequestEnvelopeTTL  = 15 * time.Minute
	preparedSubmissionSchema   = "melusina-submit-prepared-v1"
)

// Receipt mirrors the store-signed provenance receipt JSON returned by the C2.3
// /publish handler (sidecar provenance.go). It is re-declared here (NOT imported
// from the sidecar's package main) so cmd/submit can PARSE the response. The
// operator signs the RAW 96 bytes appHash||releaseHash||servingDomainHash; the
// hex/base58 below are presentation only.
type Receipt struct {
	Schema            string             `json:"schema"`
	AppHash           string             `json:"appHash"`           // lowercase hex of [32]byte
	ReleaseHash       string             `json:"releaseHash"`       // lowercase hex of [32]byte
	ServingDomainHash string             `json:"servingDomainHash"` // lowercase hex of [32]byte
	OperatorSignature string             `json:"operatorSignature"` // base58 of the 64-byte ed25519 signature
	StoredAt          int64              `json:"storedAt"`          // unix seconds
	Stage             *StageReceipt      `json:"stage"`
	Rollout           *AppRolloutReceipt `json:"rollout"`
	Catalog           *AppCatalogPointer `json:"catalog"`
}

// PublishReceipt is the historical machine receipt shape for a staged/published
// Store artifact.  Golden-MVP publication now starts from the catalog-keyed
// mel-release path, but the promotion object remains the cryptographic source
// of truth; duplicated top-level proofs must match before a finalizer consumes
// them.
type PublishReceipt struct {
	Schema       string             `json:"schema"`
	App          PublishReceiptApp  `json:"app"`
	Stage        *StageReceipt      `json:"stage"`
	Promotion    *Receipt           `json:"promotion"`
	RolloutProof *AppRolloutReceipt `json:"rolloutProof"`
	CatalogProof *AppCatalogPointer `json:"catalogProof"`
}

type PublishReceiptApp struct {
	AppID     string `json:"appId"`
	PackageID string `json:"packageId"`
	Version   string `json:"version"`
}

type StageReceipt struct {
	Schema            string `json:"schema"`
	StageID           string `json:"stageId"`
	AppID             string `json:"appId"`
	AppHash           string `json:"appHash"`
	ReleaseHash       string `json:"releaseHash"`
	ServingDomainHash string `json:"servingDomainHash"`
	StoredAt          int64  `json:"storedAt"`
	OperatorSignature string `json:"operatorSignature"`
}

type AppRolloutReceipt struct {
	Schema             string `json:"schema"`
	AppID              string `json:"appId"`
	CurrentStageID     string `json:"currentStageId"`
	CurrentAppHash     string `json:"currentAppHash"`
	CurrentVersion     string `json:"currentVersion"`
	PreviousStageID    string `json:"previousStageId,omitempty"`
	PreviousAppHash    string `json:"previousAppHash,omitempty"`
	PreviousVersion    string `json:"previousVersion,omitempty"`
	ActivatedAt        int64  `json:"activatedAt"`
	PreviousValidUntil int64  `json:"previousValidUntil,omitempty"`
	ServingDomainHash  string `json:"servingDomainHash"`
	OperatorSignature  string `json:"operatorSignature"`
}

type AppCatalogPointer struct {
	Schema             string `json:"schema"`
	AppID              string `json:"appId"`
	PackageID          string `json:"packageId"`
	Version            string `json:"version"`
	AppHash            string `json:"appHash"`
	ReleaseHash        string `json:"releaseHash"`
	StageID            string `json:"stageId"`
	CatalogSHA256      string `json:"catalogSha256"`
	PreviousAppHash    string `json:"previousAppHash,omitempty"`
	PreviousVersion    string `json:"previousVersion,omitempty"`
	PreviousValidUntil int64  `json:"previousValidUntil,omitempty"`
	ServingDomainHash  string `json:"servingDomainHash"`
	PublishedAt        int64  `json:"publishedAt"`
	OperatorSignature  string `json:"operatorSignature"`
}

// ReleaseClaims is the subset of the canonical RELEASE.json (melusina-release-v1)
// the submit client needs to (a) assert apphash.Canonical(spk,metadata)==appHash
// locally before uploading and (b) re-derive the StoreOperatorAuthorization for
// receipt verification. The full RELEASE.json is sent verbatim as the envelope Body —
// the sidecar re-checks every trust field on-chain, so this struct only reads
// what the client itself uses.
type ReleaseClaims struct {
	AppHash               string `json:"appHash"`
	ReleaseHash           string `json:"releaseHash"`
	Version               string `json:"version"`
	MasterNftMint         string `json:"masterNftMint"`
	RuntimeContractSHA256 string `json:"runtimeContractSha256,omitempty"`
	RuntimeContractSchema string `json:"runtimeContractSchema,omitempty"`
}

// submittedReceiptIntent is the exact local candidate identity a store receipt
// must acknowledge. Signature verification proves who signed a receipt; this
// binding separately proves that the signer acknowledged this invocation's
// candidate rather than returning a valid stale receipt for another publish.
type submittedReceiptIntent struct {
	AppID       string `json:"appId"`
	AppHash     string `json:"appHash"`
	ReleaseHash string `json:"releaseHash"`
	StageID     string `json:"stageId"`
}

// preparedSubmission is a short-lived, locally signed handoff for a trusted
// transport relay. The relay gets the envelope and public release artifacts,
// never the publisher identity. Receipt acceptance still happens locally and
// binds the store-signed response to this exact candidate.
type preparedSubmission struct {
	Schema   string                 `json:"schema"`
	Target   string                 `json:"target"`
	Envelope envelope.Signed        `json:"envelope"`
	Expected submittedReceiptIntent `json:"expected"`
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
	Envelope           envelope.Signed `json:"envelope"`
	ReleaseB64         string          `json:"release_b64"`
	SPKB64             string          `json:"spk_b64"`
	MetadataB64        string          `json:"metadata_b64"`
	RuntimeContractB64 string          `json:"runtime_contract_b64,omitempty"`
	Developer          string          `json:"developer,omitempty"`
	Repo               string          `json:"repo,omitempty"`
	Slug               string          `json:"slug,omitempty"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "submit: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	store               string
	spkPath             string
	metadataPath        string
	releasePath         string
	runtimeContractPath string
	publisherKey        string // path; or env name via --publisher-key env:NAME
	storePubkey         string // path to the sidecar operator identity.Public JSON
	licenseMint         string // store operator's license_nft_mint (StoreOperatorAuthz seed)
	domain              string // store serving domain (store_domain_hash seed)
	rpcURL              string // Solana JSON-RPC for receipt verification
	verifiedSlot        uint64 // ChainEvidence.verified_slot (publisher's local pre-check slot)
	useMultipart        bool
	stageOnly           bool
	developer           string
	repo                string
	slug                string
	receiptOut          string
	verifyReceiptPath   string
	prepareOut          string
	preparedSubmission  string
	// requestOut and controlDossier enable a constrained, file-only worker
	// primitive. It signs an exact future Pearl control request, but never
	// opens a network connection, stages bytes, or changes chain/catalog state.
	// Both fields must occur together; the target is derived rather than supplied.
	requestOut     string
	controlDossier string
	timeout        time.Duration
}

func parseFlags(args []string) (options, error) {
	fs := flag.NewFlagSet("submit", flag.ContinueOnError)
	var o options
	fs.StringVar(&o.store, "store", "", "store sidecar base URL, e.g. https://store.example.org (required)")
	fs.StringVar(&o.spkPath, "spk", "", "path to the .spk package bytes (required)")
	fs.StringVar(&o.metadataPath, "metadata", "", "path to the app metadata.json (required; bound into the on-chain appHash)")
	fs.StringVar(&o.releasePath, "release", "", "path to the canonical RELEASE.json (required)")
	fs.StringVar(&o.runtimeContractPath, "runtime-contract", "", "path to the raw RUNTIME-CONTRACT.json when RELEASE.json binds one")
	fs.StringVar(&o.publisherKey, "publisher-key", "", "publisher signing identity: a path, or env:NAME to read the JSON from $NAME (required)")
	fs.StringVar(&o.storePubkey, "store-pubkey", "", "path to the sidecar operator identity.Public JSON (the envelope destination; required — the sidecar exposes no well-known identity endpoint yet)")
	fs.StringVar(&o.licenseMint, "license-mint", "", "store operator license_nft_mint (base58); StoreOperatorAuthorization seed for receipt verification (required)")
	fs.StringVar(&o.domain, "domain", "", "store serving domain (bare host); store_domain_hash seed for receipt verification (defaults to the host in --store)")
	fs.StringVar(&o.rpcURL, "rpc-url", "", "Solana JSON-RPC endpoint used to read the on-chain store_authority for receipt verification (required)")
	fs.Uint64Var(&o.verifiedSlot, "verified-slot", 1, "ChainEvidence verified_slot for the envelope (publisher's local on-chain pre-check slot)")
	fs.BoolVar(&o.useMultipart, "multipart", false, "POST as multipart/form-data {envelope,release,spk} instead of the JSON wire form")
	fs.BoolVar(&o.stageOnly, "stage", false, "privately stage the candidate before chain mutation; return a signed staging receipt")
	fs.StringVar(&o.developer, "developer", "", "catalog developer path segment (required with --repo/--slug for a first publish)")
	fs.StringVar(&o.repo, "repo", "", "catalog repository path segment (required with --developer/--slug for a first publish)")
	fs.StringVar(&o.slug, "slug", "", "catalog app path segment (required with --developer/--repo for a first publish)")
	fs.StringVar(&o.receiptOut, "receipt-out", "", "write the verified raw receipt JSON to this path")
	fs.StringVar(&o.verifyReceiptPath, "verify-receipt", "", "verify a saved promotion or app-publish receipt against the on-chain store authority without publishing")
	fs.StringVar(&o.prepareOut, "prepare-out", "", "write a signed publish handoff and exit without POSTing; use --verify-receipt --prepared-submission to accept the returned receipt")
	fs.StringVar(&o.preparedSubmission, "prepared-submission", "", "prepared handoff to bind a --verify-receipt result to the exact submitted candidate")
	fs.StringVar(&o.requestOut, "request-out", "", "owner-only path for one 15-minute exact Pearl control publish request; performs no HTTP call")
	fs.StringVar(&o.controlDossier, "control-dossier", "", "24-character lower-hex Bazaar Control dossier id; required with --request-out")
	fs.DurationVar(&o.timeout, "timeout", 60*time.Second, "HTTP request timeout")
	if err := fs.Parse(args); err != nil {
		return o, err
	}

	var missing []string
	verifyMode := o.verifyReceiptPath != ""
	requestMode := o.requestOut != "" || o.controlDossier != ""
	if verifyMode {
		if o.spkPath != "" || o.metadataPath != "" || o.releasePath != "" || o.runtimeContractPath != "" ||
			o.publisherKey != "" || o.storePubkey != "" || o.stageOnly || o.useMultipart ||
			o.developer != "" || o.repo != "" || o.slug != "" || o.receiptOut != "" || o.prepareOut != "" || requestMode {
			return o, errors.New("--verify-receipt cannot be combined with publish, stage, catalog, or receipt-output flags")
		}
		if o.licenseMint == "" {
			missing = append(missing, "--license-mint")
		}
		if o.rpcURL == "" {
			missing = append(missing, "--rpc-url")
		}
		if o.domain == "" && o.store != "" {
			o.domain = hostFromURL(o.store)
		}
		if o.domain == "" {
			missing = append(missing, "--domain (or --store)")
		}
		if len(missing) > 0 {
			return o, fmt.Errorf("missing required flag(s): %s", strings.Join(missing, " "))
		}
		return o, nil
	}
	if o.preparedSubmission != "" {
		return o, errors.New("--prepared-submission requires --verify-receipt")
	}
	if o.prepareOut != "" && o.receiptOut != "" {
		return o, errors.New("--prepare-out cannot be combined with --receipt-out")
	}
	if requestMode {
		if o.requestOut == "" || !validControlDossierID(o.controlDossier) {
			return o, errors.New("--request-out and a 24-character lower-hex --control-dossier are required together")
		}
		if o.prepareOut != "" || o.stageOnly || o.useMultipart || o.receiptOut != "" || o.store != "" || o.licenseMint != "" || o.domain != "" || o.rpcURL != "" {
			return o, errors.New("--request-out is file-only and cannot be combined with store, stage, multipart, receipt, or chain-verification flags")
		}
		for label, value := range map[string]string{"--spk": o.spkPath, "--metadata": o.metadataPath, "--release": o.releasePath, "--publisher-key": o.publisherKey, "--store-pubkey": o.storePubkey} {
			if strings.TrimSpace(value) == "" {
				missing = append(missing, label)
			}
		}
		if len(missing) > 0 {
			return o, fmt.Errorf("missing required flag(s): %s", strings.Join(missing, " "))
		}
		if err := validateSlotHint(o); err != nil {
			return o, err
		}
		return o, nil
	}
	if o.store == "" {
		missing = append(missing, "--store")
	}
	if o.spkPath == "" {
		missing = append(missing, "--spk")
	}
	if o.metadataPath == "" {
		missing = append(missing, "--metadata")
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
	if err := validateSlotHint(o); err != nil {
		return o, err
	}
	if o.domain == "" {
		o.domain = hostFromURL(o.store)
	}
	return o, nil
}

func validateSlotHint(o options) error {
	slotFields := 0
	for _, value := range []string{o.developer, o.repo, o.slug} {
		if strings.TrimSpace(value) != "" {
			slotFields++
		}
	}
	if slotFields != 0 && slotFields != 3 {
		return errors.New("--developer, --repo, and --slug must be supplied together")
	}
	return nil
}

func run(args []string, stdout, stderr io.Writer) error {
	o, err := parseFlags(args)
	if err != nil {
		return err
	}
	if o.verifyReceiptPath != "" {
		return runVerifyReceipt(o, stdout)
	}
	spk, err := os.ReadFile(o.spkPath)
	if err != nil {
		return fmt.Errorf("read spk %s: %w", o.spkPath, err)
	}
	if len(spk) == 0 {
		return fmt.Errorf("spk %s is empty", o.spkPath)
	}
	metadata, err := os.ReadFile(o.metadataPath)
	if err != nil {
		return fmt.Errorf("read metadata %s: %w", o.metadataPath, err)
	}
	if len(metadata) == 0 {
		return fmt.Errorf("metadata %s is empty", o.metadataPath)
	}
	releaseBytes, err := os.ReadFile(o.releasePath)
	if err != nil {
		return fmt.Errorf("read release %s: %w", o.releasePath, err)
	}

	// Local pre-check: the on-chain appHash is the TREE-HASH over {app.spk,
	// metadata.json} (apphash.Canonical), NOT sha256(spk); it must equal
	// release.appHash. The sidecar re-checks this on-chain; failing here saves a
	// doomed round-trip and names the mismatch with publisher-side context.
	var claims ReleaseClaims
	if err := json.Unmarshal(releaseBytes, &claims); err != nil {
		return fmt.Errorf("parse RELEASE.json %s: %w", o.releasePath, err)
	}
	appHashHex, err := apphash.Canonical(bytes.NewReader(spk), metadata)
	if err != nil {
		return fmt.Errorf("check=app_hash: compute app-hash: %w", err)
	}
	wantAppHash := strings.ToLower(strings.TrimSpace(claims.AppHash))
	if appHashHex != wantAppHash {
		return fmt.Errorf("check=app_hash: apphash(spk,metadata)=%s != release.appHash=%s", appHashHex, wantAppHash)
	}
	runtimeContract, err := readAndValidateRuntimeContract(o.runtimeContractPath, spk, metadata, claims)
	if err != nil {
		return fmt.Errorf("check=runtime_contract: %w", err)
	}
	expectedReceipt, err := buildSubmittedReceiptIntentWithRuntimeContract(spk, metadata, runtimeContract, claims, o.developer, o.repo, o.slug)
	if err != nil {
		return fmt.Errorf("check=receipt_submission: %w", err)
	}

	pubPriv, err := loadPublisherKey(o.publisherKey)
	if err != nil {
		return fmt.Errorf("publisher key: %w", err)
	}
	dst, err := loadStorePubkey(o.storePubkey)
	if err != nil {
		return fmt.Errorf("store pubkey: %w", err)
	}

	// Select the purpose before signing. App envelopes are never route-less and
	// a stage envelope is cryptographically distinct from a promotion envelope.
	// The file-only control mode derives its target from the Pearl dossier; it
	// never accepts a route supplied by a worker or terminal.
	target := appPromoteTarget
	if o.stageOnly {
		target = appStageTarget
	}
	if o.requestOut != "" {
		target, err = controlPublishTarget(o.controlDossier)
		if err != nil {
			return fmt.Errorf("control target: %w", err)
		}
	}

	// Build the signed publish-request envelope: KindPublishRequest addressed
	// to the store operator, binding RequestHash=sha256(SPK) and
	// Body=RELEASE.json, carrying the on-chain evidence (ReleaseEntry PDA,
	// program, slot). BodyHash is set explicitly to sha256(release) — the
	// sidecar requires sha256(release) == envelope.body_hash.
	//
	// The envelope must outlive the upload: the sidecar verifies it only after
	// the full body arrives, so on a slow uplink a large SPK can take longer to
	// transfer than a short-lived envelope survives. Size the TTL to the
	// operator-declared -timeout window plus verify margin, floored at 5m.
	envTTL := o.timeout + 2*time.Minute
	if envTTL < 5*time.Minute {
		envTTL = 5 * time.Minute
	}
	// A control request is a final transport envelope, not a durable approval
	// object. It is intentionally fixed at the command window so a worker cannot
	// make an effectively long-lived publisher capability by inflating timeout.
	if o.requestOut != "" {
		envTTL = controlRequestEnvelopeTTL
	}
	sig, err := buildEnvelope(pubPriv, dst, target, spk, releaseBytes, claims, o.verifiedSlot, envTTL)
	if err != nil {
		return fmt.Errorf("envelope: %w", err)
	}
	if o.prepareOut != "" {
		prepared := preparedSubmission{
			Schema: preparedSubmissionSchema, Target: target, Envelope: sig, Expected: expectedReceipt,
		}
		if err := writePreparedSubmission(o.prepareOut, prepared); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "PREPARED OK — signed publish handoff written to %s; no POST was made\n", o.prepareOut)
		return nil
	}
	if o.requestOut != "" {
		body, err := marshalControlPublishRequest(sig, releaseBytes, spk, metadata, runtimeContract, o.developer, o.repo, o.slug)
		if err != nil {
			return fmt.Errorf("control request: %w", err)
		}
		output, err := writeOwnerOnlyControlRequest(o.requestOut, body)
		if err != nil {
			return fmt.Errorf("control request: %w", err)
		}
		digest := sha256.Sum256(body)
		fmt.Fprintf(stdout, "CONTROL REQUEST PREPARED — exact request written to %s (sha256 %x); no network, chain, stage, or catalog action occurred\n", output, digest)
		return nil
	}

	resp, status, err := postPublishWithRuntimeContract(context.Background(), o, target, sig, releaseBytes, spk, metadata, runtimeContract)
	if err != nil {
		return fmt.Errorf("publish POST: %w", err)
	}
	if status != http.StatusOK {
		// The sidecar names the failing check in the body (e.g. "check=app_hash").
		return fmt.Errorf("store rejected publish: HTTP %d: %s", status, strings.TrimSpace(string(resp)))
	}

	// Verify the store-signed receipt against the ON-CHAIN
	// store_authority. A store that returns 200 but a receipt the chain does not
	// vouch for is a FAILURE — the install-side trust (C4) depends on this exact
	// check, so the publish client refuses to call it a success.
	cr := verify.NewRPCClient(o.rpcURL)
	if o.stageOnly {
		receipt, err := acceptStageReceipt(context.Background(), cr, o.licenseMint, o.domain, resp, expectedReceipt, o.receiptOut)
		if err != nil {
			return fmt.Errorf("stage receipt verification: %w", err)
		}
		out, _ := json.MarshalIndent(receipt, "", "  ")
		fmt.Fprintf(stdout, "STAGE OK — private persistence receipt verified against on-chain store_authority\n%s\n", out)
		return nil
	}
	receipt, err := acceptPromotionReceipt(context.Background(), cr, o.licenseMint, o.domain, resp, expectedReceipt, o.receiptOut)
	if err != nil {
		return fmt.Errorf("receipt verification: %w", err)
	}

	out, _ := json.MarshalIndent(receipt, "", "  ")
	fmt.Fprintf(stdout, "PUBLISH OK — store-signed provenance receipt verified against on-chain store_authority\n%s\n", out)
	return nil
}

func buildSubmittedReceiptIntent(spk, metadata []byte, claims ReleaseClaims, developer, repo, slug string) (submittedReceiptIntent, error) {
	return buildSubmittedReceiptIntentWithRuntimeContract(spk, metadata, nil, claims, developer, repo, slug)
}

func buildSubmittedReceiptIntentWithRuntimeContract(spk, metadata, runtimeContract []byte, claims ReleaseClaims, developer, repo, slug string) (submittedReceiptIntent, error) {
	var metadataIdentity struct {
		AppID string `json:"appId"`
	}
	if err := json.Unmarshal(metadata, &metadataIdentity); err != nil {
		return submittedReceiptIntent{}, fmt.Errorf("parse metadata.json identity: %w", err)
	}
	appID := strings.TrimSpace(metadataIdentity.AppID)
	if appID == "" {
		return submittedReceiptIntent{}, errors.New("metadata.json appId is required")
	}
	appHash, err := hash32FromHex(strings.ToLower(strings.TrimSpace(claims.AppHash)))
	if err != nil {
		return submittedReceiptIntent{}, fmt.Errorf("appHash: %w", err)
	}
	releaseHash, err := hash32FromHex(strings.ToLower(strings.TrimSpace(claims.ReleaseHash)))
	if err != nil {
		return submittedReceiptIntent{}, fmt.Errorf("releaseHash: %w", err)
	}
	version := strings.TrimSpace(claims.Version)
	if version == "" {
		return submittedReceiptIntent{}, errors.New("release version is required")
	}
	masterMint := strings.TrimSpace(claims.MasterNftMint)
	if masterMint == "" {
		return submittedReceiptIntent{}, errors.New("release masterNftMint is required")
	}

	spkHash := sha256.Sum256(spk)
	metadataHash := sha256.Sum256(metadata)
	runtimeContractHash := sha256.Sum256(runtimeContract)
	versionHash := sha256.Sum256([]byte(version))
	masterMintHash := sha256.Sum256([]byte(masterMint))
	stageHasher := sha256.New()
	_, _ = stageHasher.Write([]byte("melusina-app-stage-v1\x00"))
	_, _ = stageHasher.Write(spkHash[:])
	_, _ = stageHasher.Write(metadataHash[:])
	binding := runtimecontract.Binding{SPK: spk, Metadata: metadata, AppHash: claims.AppHash, Version: claims.Version, ReleaseContractSHA256: claims.RuntimeContractSHA256, ReleaseContractSchema: claims.RuntimeContractSchema}
	if runtimecontract.RequiresContract(binding) {
		if _, err := runtimecontract.Validate(runtimeContract, binding); err != nil {
			return submittedReceiptIntent{}, fmt.Errorf("runtime contract: %w", err)
		}
		_, _ = stageHasher.Write([]byte("runtime-contract-v1\x00"))
		_, _ = stageHasher.Write(runtimeContractHash[:])
	} else if len(runtimeContract) != 0 {
		return submittedReceiptIntent{}, errors.New("runtime contract supplied but RELEASE.json does not bind one")
	}
	_, _ = stageHasher.Write(releaseHash[:])
	_, _ = stageHasher.Write(versionHash[:])
	_, _ = stageHasher.Write(masterMintHash[:])
	for _, part := range []string{developer, repo, slug} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		_, _ = stageHasher.Write(size[:])
		_, _ = stageHasher.Write([]byte(part))
	}

	return submittedReceiptIntent{
		AppID:       appID,
		AppHash:     hex.EncodeToString(appHash[:]),
		ReleaseHash: hex.EncodeToString(releaseHash[:]),
		StageID:     hex.EncodeToString(stageHasher.Sum(nil)),
	}, nil
}

func acceptStageReceipt(ctx context.Context, cr storeOperatorAuthzFetcher, licenseMint, domain string, raw []byte, expected submittedReceiptIntent, receiptOut string) (StageReceipt, error) {
	var receipt StageReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return StageReceipt{}, fmt.Errorf("decode stage receipt: %w", err)
	}
	if err := verifyStageReceipt(ctx, cr, licenseMint, domain, receipt); err != nil {
		return StageReceipt{}, err
	}
	if receipt.AppID != expected.AppID ||
		!strings.EqualFold(receipt.AppHash, expected.AppHash) ||
		!strings.EqualFold(receipt.ReleaseHash, expected.ReleaseHash) ||
		!strings.EqualFold(receipt.StageID, expected.StageID) {
		return StageReceipt{}, fmt.Errorf("check=receipt_submission: signed stage receipt does not match submitted appId/appHash/releaseHash/stageId")
	}
	if err := writeReceiptFile(receiptOut, raw); err != nil {
		return StageReceipt{}, err
	}
	return receipt, nil
}

func acceptPromotionReceipt(ctx context.Context, cr storeOperatorAuthzFetcher, licenseMint, domain string, raw []byte, expected submittedReceiptIntent, receiptOut string) (Receipt, error) {
	var receipt Receipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode receipt: %w", err)
	}
	if err := verifyReceipt(ctx, cr, licenseMint, domain, receipt); err != nil {
		return Receipt{}, err
	}
	if receipt.Stage == nil || receipt.Catalog == nil ||
		receipt.Stage.AppID != expected.AppID || receipt.Catalog.AppID != expected.AppID ||
		!strings.EqualFold(receipt.AppHash, expected.AppHash) ||
		!strings.EqualFold(receipt.ReleaseHash, expected.ReleaseHash) ||
		!strings.EqualFold(receipt.Stage.StageID, expected.StageID) {
		return Receipt{}, fmt.Errorf("check=receipt_submission: signed promotion receipt does not match submitted appId/appHash/releaseHash/stageId")
	}
	if err := writeReceiptFile(receiptOut, raw); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func runVerifyReceipt(o options, stdout io.Writer) error {
	raw, err := os.ReadFile(o.verifyReceiptPath)
	if err != nil {
		return fmt.Errorf("read receipt %s: %w", o.verifyReceiptPath, err)
	}
	client := verify.NewRPCClient(o.rpcURL)
	if o.preparedSubmission != "" {
		prepared, err := readPreparedSubmission(o.preparedSubmission)
		if err != nil {
			return err
		}
		switch prepared.Target {
		case appPromoteTarget:
			if _, err := acceptPromotionReceipt(context.Background(), client, o.licenseMint, o.domain, raw, prepared.Expected, ""); err != nil {
				return fmt.Errorf("prepared promotion receipt verification: %w", err)
			}
		case appStageTarget:
			if _, err := acceptStageReceipt(context.Background(), client, o.licenseMint, o.domain, raw, prepared.Expected, ""); err != nil {
				return fmt.Errorf("prepared stage receipt verification: %w", err)
			}
		default:
			return fmt.Errorf("prepared submission has unsupported target %q", prepared.Target)
		}
		fmt.Fprintf(stdout, "PREPARED RECEIPT OK — store proof verified against on-chain authority and exact handoff\n")
		return nil
	}
	receipt, err := decodeReceiptForVerification(raw)
	if err != nil {
		return fmt.Errorf("decode receipt %s: %w", o.verifyReceiptPath, err)
	}
	if err := verifyReceipt(context.Background(), client, o.licenseMint, o.domain, receipt); err != nil {
		return fmt.Errorf("receipt verification: %w", err)
	}
	fmt.Fprintf(stdout, "RECEIPT OK — saved promotion proof verified against on-chain store_authority\n")
	return nil
}

func writePreparedSubmission(path string, prepared preparedSubmission) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("prepare-out path is required")
	}
	if prepared.Schema != preparedSubmissionSchema || (prepared.Target != appPromoteTarget && prepared.Target != appStageTarget) ||
		prepared.Envelope.Payload.Target != prepared.Target || prepared.Expected.AppID == "" ||
		prepared.Expected.AppHash == "" || prepared.Expected.ReleaseHash == "" || prepared.Expected.StageID == "" {
		return errors.New("prepared submission is incomplete or internally inconsistent")
	}
	raw, err := json.MarshalIndent(prepared, "", "  ")
	if err != nil {
		return fmt.Errorf("prepare-out: encode: %w", err)
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("prepare-out: write temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("prepare-out: rename: %w", err)
	}
	return nil
}

func readPreparedSubmission(path string) (preparedSubmission, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return preparedSubmission{}, fmt.Errorf("read prepared submission %s: %w", path, err)
	}
	var prepared preparedSubmission
	if err := json.Unmarshal(raw, &prepared); err != nil {
		return preparedSubmission{}, fmt.Errorf("decode prepared submission %s: %w", path, err)
	}
	if prepared.Schema != preparedSubmissionSchema || (prepared.Target != appPromoteTarget && prepared.Target != appStageTarget) ||
		prepared.Envelope.Payload.Target != prepared.Target || prepared.Expected.AppID == "" ||
		prepared.Expected.AppHash == "" || prepared.Expected.ReleaseHash == "" || prepared.Expected.StageID == "" {
		return preparedSubmission{}, errors.New("prepared submission is incomplete or internally inconsistent")
	}
	return prepared, nil
}

func decodeReceiptForVerification(raw []byte) (Receipt, error) {
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return Receipt{}, err
	}
	switch header.Schema {
	case "melusina-app-promotion-receipt-v1":
		var receipt Receipt
		if err := json.Unmarshal(raw, &receipt); err != nil {
			return Receipt{}, err
		}
		return receipt, nil
	case "melusina-app-publish-receipt-v1":
		var wrapper PublishReceipt
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			return Receipt{}, err
		}
		if wrapper.Promotion == nil || wrapper.Promotion.Stage == nil ||
			wrapper.Promotion.Rollout == nil || wrapper.Promotion.Catalog == nil {
			return Receipt{}, errors.New("publish receipt lacks complete signed promotion proof")
		}
		if wrapper.Stage == nil || wrapper.RolloutProof == nil || wrapper.CatalogProof == nil {
			return Receipt{}, errors.New("publish receipt lacks duplicated stage, rollout, or catalog proof")
		}
		if *wrapper.Stage != *wrapper.Promotion.Stage ||
			*wrapper.RolloutProof != *wrapper.Promotion.Rollout ||
			*wrapper.CatalogProof != *wrapper.Promotion.Catalog {
			return Receipt{}, errors.New("publish receipt duplicated proofs differ from signed promotion")
		}
		catalog := wrapper.Promotion.Catalog
		if wrapper.App.AppID != catalog.AppID || wrapper.App.PackageID != catalog.PackageID ||
			wrapper.App.Version != catalog.Version {
			return Receipt{}, errors.New("publish receipt app identity differs from signed catalog pointer")
		}
		return *wrapper.Promotion, nil
	default:
		return Receipt{}, fmt.Errorf("unsupported schema %q", header.Schema)
	}
}

// buildEnvelope constructs the sealed-v3 signed publish-request envelope. The
// sidecar's envelope.Verify requires Kind==publish-request (envelope.KindPublishRequest),
// Destination==operator, RequestHash==sha256(SPK), and sha256(Body)==BodyHash;
// we set all of them here.
func buildEnvelope(src *identity.Private, dst identity.Public, target string, spk, releaseBytes []byte, claims ReleaseClaims, verifiedSlot uint64, ttl time.Duration) (envelope.Signed, error) {
	if !isAllowedPublisherEnvelopeTarget(target) {
		return envelope.Signed{}, fmt.Errorf("publisher envelope target must be exactly %q, %q, or a Pearl dossier publish route", appPromoteTarget, appStageTarget)
	}
	spkSum := sha256.Sum256(spk)
	relSum := sha256.Sum256(releaseBytes)

	chain := envelope.ChainEvidence{
		ChainID:      firstNonEmpty(src.Public().Ref.ChainID, defaultChainID),
		ProgramID:    firstNonEmpty(src.Public().Ref.ProgramID, programIDB58),
		VerifiedSlot: verifiedSlot,
	}
	// Pin the ReleaseEntry PDA as chain evidence when the masterNftMint + appHash
	// are present and parseable. The PDA is seeded by the app_hash (the tree-hash
	// over {app.spk, metadata.json}, = claims.AppHash) — NOT sha256(spk) — matching
	// the sidecar's VerifyPublish derivation. It is re-derived + checked by the
	// sidecar anyway; this is the publisher's claimed PDA.
	if mm := strings.TrimSpace(claims.MasterNftMint); mm != "" {
		if appHash, err := hash32FromHex(claims.AppHash); err == nil {
			if relPDA, err := releaseEntryPDA(mm, appHash); err == nil {
				chain.ReleaseEntryPDA = relPDA
			}
		}
	}

	return envelope.Sign(envelope.KindPublishRequest, src, dst, envelope.SignOptions{
		Method:      http.MethodPost,
		Target:      target,
		Body:        releaseBytes,
		BodyHash:    hex.EncodeToString(relSum[:]),
		RequestHash: hex.EncodeToString(spkSum[:]),
		TTL:         ttl,
		Chain:       chain,
	})
}

func controlPublishTarget(dossierID string) (string, error) {
	if !validControlDossierID(dossierID) {
		return "", errors.New("dossier id must be exactly 24 lowercase hexadecimal characters")
	}
	return controlPublishTargetPrefix + dossierID + controlPublishTargetSuffix, nil
}

func validControlDossierID(value string) bool {
	if len(value) != 24 {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func isControlPublishTarget(target string) bool {
	if !strings.HasPrefix(target, controlPublishTargetPrefix) || !strings.HasSuffix(target, controlPublishTargetSuffix) {
		return false
	}
	dossierID := strings.TrimSuffix(strings.TrimPrefix(target, controlPublishTargetPrefix), controlPublishTargetSuffix)
	return validControlDossierID(dossierID)
}

func isAllowedPublisherEnvelopeTarget(target string) bool {
	return target == appPromoteTarget || target == appStageTarget || isControlPublishTarget(target)
}

// marshalControlPublishRequest emits the exact normal JSON publish wire body
// that the Pearl will later send through the Store Link. It is deliberately a
// pure function: a worker can prepare the candidate without receiving a store
// URL, RPC URL, or any way to call the sidecar directly.
func marshalControlPublishRequest(sig envelope.Signed, releaseBytes, spk, metadata, runtimeContract []byte, developer, repo, slug string) ([]byte, error) {
	if sig.Payload.Method != http.MethodPost || !isControlPublishTarget(sig.Payload.Target) {
		return nil, errors.New("signed envelope is not for one exact Pearl control publish route")
	}
	body, err := json.Marshal(publishRequest{
		Envelope:           sig,
		ReleaseB64:         stdB64(releaseBytes),
		SPKB64:             stdB64(spk),
		MetadataB64:        stdB64(metadata),
		RuntimeContractB64: stdB64(runtimeContract),
		Developer:          developer,
		Repo:               repo,
		Slug:               slug,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal JSON wire body: %w", err)
	}
	return body, nil
}

// writeOwnerOnlyControlRequest writes a prepared control request exactly once.
// The request includes a short-lived publisher envelope, so it must not be
// left in /tmp, made group-readable, or overwrite an existing candidate. The
// enclosing worker directory is part of the custody boundary: it must be a
// real, owner-only directory rather than a symlinked shared workspace.
func writeOwnerOnlyControlRequest(path string, body []byte) (string, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return "", errors.New("--request-out must be an absolute path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("canonicalize output path: %w", err)
	}
	if err := rejectTemporaryPath(abs); err != nil {
		return "", err
	}
	parent := filepath.Dir(abs)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("resolve output directory: %w", err)
	}
	if resolvedParent != parent {
		return "", errors.New("output directory must not contain a symlink")
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return "", fmt.Errorf("stat output directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", errors.New("output directory must be a real owner-only (0700) directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return "", errors.New("output directory must be owned by the invoking user")
	}
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return "", fmt.Errorf("create exclusive owner-only output: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = f.Close()
			_ = os.Remove(abs)
		}
	}()
	if _, err := f.Write(body); err != nil {
		return "", fmt.Errorf("write output: %w", err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("sync output: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close output: %w", err)
	}
	keep = true
	return abs, nil
}

func rejectTemporaryPath(path string) error {
	tmp, err := filepath.Abs(os.TempDir())
	if err != nil {
		return fmt.Errorf("resolve temporary directory: %w", err)
	}
	rel, err := filepath.Rel(tmp, path)
	if err != nil {
		return fmt.Errorf("compare temporary directory: %w", err)
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return errors.New("--request-out must not be inside the temporary directory")
	}
	return nil
}

// releaseEntryPDA derives the ReleaseEntry PDA base58 from the masterNftMint and
// the app_hash (the tree-hash over {app.spk, metadata.json}), matching the
// sidecar's VerifyPublish derivation.
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
// or multipart/form-data, returning the raw body + status code. metadata is the
// app's metadata.json bytes, bound into the on-chain appHash the sidecar recomputes.
func postPublish(ctx context.Context, o options, endpoint string, sig envelope.Signed, releaseBytes, spk, metadata []byte) ([]byte, int, error) {
	return postPublishWithRuntimeContract(ctx, o, endpoint, sig, releaseBytes, spk, metadata, nil)
}

func postPublishWithRuntimeContract(ctx context.Context, o options, endpoint string, sig envelope.Signed, releaseBytes, spk, metadata, runtimeContract []byte) ([]byte, int, error) {
	if endpoint != appPromoteTarget && endpoint != appStageTarget {
		return nil, 0, fmt.Errorf("app publish endpoint must be exactly %q or %q", appPromoteTarget, appStageTarget)
	}
	if sig.Payload.Method != http.MethodPost || sig.Payload.Target != endpoint {
		return nil, 0, fmt.Errorf("signed app publish purpose %s %q does not match POST %q", sig.Payload.Method, sig.Payload.Target, endpoint)
	}
	url := strings.TrimRight(o.store, "/") + endpoint
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
		if werr := writePart(mw, "metadata", "metadata.json", metadata); werr != nil {
			return nil, 0, werr
		}
		if len(runtimeContract) != 0 {
			if werr := writePart(mw, "runtime_contract", "RUNTIME-CONTRACT.json", runtimeContract); werr != nil {
				return nil, 0, werr
			}
		}
		for name, value := range map[string]string{
			"developer": o.developer,
			"repo":      o.repo,
			"slug":      o.slug,
		} {
			if value != "" {
				if werr := mw.WriteField(name, value); werr != nil {
					return nil, 0, fmt.Errorf("write %s field: %w", name, werr)
				}
			}
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
			Envelope:           sig,
			ReleaseB64:         stdB64(releaseBytes),
			SPKB64:             stdB64(spk),
			MetadataB64:        stdB64(metadata),
			RuntimeContractB64: stdB64(runtimeContract),
			Developer:          o.developer,
			Repo:               o.repo,
			Slug:               o.slug,
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

func readAndValidateRuntimeContract(path string, spk, metadata []byte, claims ReleaseClaims) ([]byte, error) {
	binding := runtimecontract.Binding{
		SPK: spk, Metadata: metadata, AppHash: claims.AppHash, Version: claims.Version,
		ReleaseContractSHA256: claims.RuntimeContractSHA256, ReleaseContractSchema: claims.RuntimeContractSchema,
	}
	if !runtimecontract.RequiresContract(binding) {
		if strings.TrimSpace(path) != "" {
			return nil, errors.New("--runtime-contract was supplied but RELEASE.json does not bind one")
		}
		return nil, nil
	}
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("RELEASE.json binds a runtime contract; pass --runtime-contract")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if _, err := runtimecontract.Validate(raw, binding); err != nil {
		return nil, err
	}
	return raw, nil
}

func writeReceiptFile(path string, raw []byte) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("receipt-out: decode verified response: %w", err)
	}
	pretty, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("receipt-out: encode: %w", err)
	}
	pretty = append(pretty, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pretty, 0o600); err != nil {
		return fmt.Errorf("receipt-out: write temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("receipt-out: rename: %w", err)
	}
	return nil
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
	pubKey, storeDomainHash, err := receiptAuthority(ctx, cr, licenseMintB58, domain)
	if err != nil {
		return err
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
	if !ed25519.Verify(pubKey, msg, sigBytes) {
		return errors.New("check=receipt: operatorSignature does not verify against on-chain store_authority")
	}
	if receipt.Schema != "melusina-app-promotion-receipt-v1" {
		return fmt.Errorf("check=receipt: schema %q is not melusina-app-promotion-receipt-v1", receipt.Schema)
	}
	if receipt.Stage == nil || receipt.Rollout == nil || receipt.Catalog == nil {
		return errors.New("check=receipt: signed stage, rollout and catalog proofs are required")
	}
	if err := verifyStageReceiptWithAuthority(pubKey, storeDomainHash, *receipt.Stage); err != nil {
		return err
	}
	if err := verifyRolloutReceiptWithAuthority(pubKey, storeDomainHash, *receipt.Rollout); err != nil {
		return err
	}
	if err := verifyCatalogPointerWithAuthority(pubKey, storeDomainHash, *receipt.Catalog); err != nil {
		return err
	}
	if receipt.Stage.AppHash != receipt.AppHash || receipt.Stage.ReleaseHash != receipt.ReleaseHash {
		return errors.New("check=receipt: stage proof does not match provenance tuple")
	}
	if receipt.Rollout.AppID != receipt.Stage.AppID ||
		receipt.Rollout.CurrentStageID != receipt.Stage.StageID ||
		receipt.Rollout.CurrentAppHash != receipt.Stage.AppHash {
		return errors.New("check=receipt: rollout proof does not select staged candidate")
	}
	if receipt.Catalog.AppID != receipt.Rollout.AppID ||
		receipt.Catalog.StageID != receipt.Rollout.CurrentStageID ||
		receipt.Catalog.AppHash != receipt.Rollout.CurrentAppHash ||
		receipt.Catalog.Version != receipt.Rollout.CurrentVersion ||
		receipt.Catalog.ReleaseHash != receipt.ReleaseHash ||
		receipt.Catalog.PreviousAppHash != receipt.Rollout.PreviousAppHash ||
		receipt.Catalog.PreviousVersion != receipt.Rollout.PreviousVersion ||
		receipt.Catalog.PreviousValidUntil != receipt.Rollout.PreviousValidUntil {
		return errors.New("check=receipt: catalog pointer does not match promoted rollout")
	}
	return nil
}

func receiptAuthority(ctx context.Context, cr storeOperatorAuthzFetcher, licenseMintB58, domain string) (ed25519.PublicKey, [32]byte, error) {
	var zero [32]byte
	programID, err := primitives.PubkeyFromBase58(programIDB58)
	if err != nil {
		return nil, zero, fmt.Errorf("check=program_id: %w", err)
	}
	licenseMint, err := primitives.PubkeyFromBase58(strings.TrimSpace(licenseMintB58))
	if err != nil {
		return nil, zero, fmt.Errorf("check=license_mint: bad --license-mint: %w", err)
	}
	storeDomainHash := primitives.StoreDomainHash(domain)
	authzPDA, _, err := pda.StoreOperatorAuthorization(licenseMint, storeDomainHash, programID)
	if err != nil {
		return nil, zero, fmt.Errorf("check=store_operator_authz: derive PDA: %w", err)
	}
	status, storeAuthority, _, _, onchainDomainHash, err := cr.FetchStoreOperatorAuthz(ctx, authzPDA.Base58())
	if err != nil {
		return nil, zero, fmt.Errorf("check=store_operator_authz: fetch %s: %w", authzPDA.Base58(), err)
	}
	if err := status.RequireActive(); err != nil {
		return nil, zero, fmt.Errorf("check=store_operator_authz: status %s not Active: %w", status, err)
	}
	// Bind the store_domain_hash the chain pins to the domain we derived the PDA
	// from (defends against a confused-domain receipt).
	if onchainDomainHash != storeDomainHash {
		return nil, zero, fmt.Errorf("check=store_operator_authz: on-chain store_domain_hash %x != derived %x", onchainDomainHash[:], storeDomainHash[:])
	}
	return ed25519.PublicKey(storeAuthority[:]), storeDomainHash, nil
}

func verifyStageReceipt(ctx context.Context, cr storeOperatorAuthzFetcher, licenseMintB58, domain string, receipt StageReceipt) error {
	if receipt.Schema != "melusina-app-stage-receipt-v1" {
		return errors.New("check=stage_receipt: schema mismatch")
	}
	pubKey, storeDomainHash, err := receiptAuthority(ctx, cr, licenseMintB58, domain)
	if err != nil {
		return err
	}
	return verifyStageReceiptWithAuthority(pubKey, storeDomainHash, receipt)
}

func verifyStageReceiptWithAuthority(pubKey ed25519.PublicKey, storeDomainHash [32]byte, receipt StageReceipt) error {
	if receipt.Schema != "melusina-app-stage-receipt-v1" {
		return errors.New("check=stage_receipt: schema mismatch")
	}
	stageID, err := hash32FromHex(receipt.StageID)
	if err != nil {
		return fmt.Errorf("check=stage_receipt: stageId: %w", err)
	}
	appHash, err := hash32FromHex(receipt.AppHash)
	if err != nil {
		return fmt.Errorf("check=stage_receipt: appHash: %w", err)
	}
	releaseHash, err := hash32FromHex(receipt.ReleaseHash)
	if err != nil {
		return fmt.Errorf("check=stage_receipt: releaseHash: %w", err)
	}
	domainHash, err := hash32FromHex(receipt.ServingDomainHash)
	if err != nil {
		return fmt.Errorf("check=stage_receipt: servingDomainHash: %w", err)
	}
	if domainHash != storeDomainHash {
		return errors.New("check=stage_receipt: serving domain mismatch")
	}
	sig, err := primitives.DecodeBase58(receipt.OperatorSignature)
	if err != nil {
		return fmt.Errorf("check=stage_receipt: signature: %w", err)
	}
	msg := stageReceiptMessage(stageID, appHash, releaseHash, domainHash, receipt.StoredAt)
	if !ed25519.Verify(pubKey, msg, sig) {
		return errors.New("check=stage_receipt: signature does not verify against on-chain store_authority")
	}
	return nil
}

func stageReceiptMessage(stageID, appHash, releaseHash, domainHash [32]byte, storedAt int64) []byte {
	msg := make([]byte, 0, len("melusina-app-stage-receipt-v1\x00")+32*4+8)
	msg = append(msg, []byte("melusina-app-stage-receipt-v1\x00")...)
	msg = append(msg, stageID[:]...)
	msg = append(msg, appHash[:]...)
	msg = append(msg, releaseHash[:]...)
	msg = append(msg, domainHash[:]...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(storedAt))
	return append(msg, ts[:]...)
}

func verifyRolloutReceiptWithAuthority(pubKey ed25519.PublicKey, storeDomainHash [32]byte, receipt AppRolloutReceipt) error {
	if receipt.Schema != "melusina-app-rollout-v1" {
		return errors.New("check=rollout_receipt: schema mismatch")
	}
	domainHash, err := hash32FromHex(receipt.ServingDomainHash)
	if err != nil || domainHash != storeDomainHash {
		return errors.New("check=rollout_receipt: serving domain mismatch")
	}
	msg, err := rolloutReceiptMessage(receipt, domainHash)
	if err != nil {
		return fmt.Errorf("check=rollout_receipt: %w", err)
	}
	sig, err := primitives.DecodeBase58(receipt.OperatorSignature)
	if err != nil || !ed25519.Verify(pubKey, msg, sig) {
		return errors.New("check=rollout_receipt: signature does not verify against on-chain store_authority")
	}
	return nil
}

func rolloutReceiptMessage(receipt AppRolloutReceipt, domainHash [32]byte) ([]byte, error) {
	currentStage, err := hash32FromHex(receipt.CurrentStageID)
	if err != nil {
		return nil, fmt.Errorf("current stage id: %w", err)
	}
	currentHash, err := hash32FromHex(receipt.CurrentAppHash)
	if err != nil {
		return nil, fmt.Errorf("current app hash: %w", err)
	}
	var previousStage, previousHash [32]byte
	if receipt.PreviousStageID != "" {
		previousStage, err = hash32FromHex(receipt.PreviousStageID)
		if err != nil {
			return nil, fmt.Errorf("previous stage id: %w", err)
		}
	}
	if receipt.PreviousAppHash != "" {
		previousHash, err = hash32FromHex(receipt.PreviousAppHash)
		if err != nil {
			return nil, fmt.Errorf("previous app hash: %w", err)
		}
	}
	appIDHash := sha256.Sum256([]byte(receipt.AppID))
	currentVersionHash := sha256.Sum256([]byte(receipt.CurrentVersion))
	previousVersionHash := sha256.Sum256([]byte(receipt.PreviousVersion))
	msg := make([]byte, 0, len("melusina-app-rollout-receipt-v1\x00")+32*8+16)
	msg = append(msg, []byte("melusina-app-rollout-receipt-v1\x00")...)
	msg = append(msg, appIDHash[:]...)
	msg = append(msg, currentVersionHash[:]...)
	msg = append(msg, currentStage[:]...)
	msg = append(msg, currentHash[:]...)
	msg = append(msg, previousVersionHash[:]...)
	msg = append(msg, previousStage[:]...)
	msg = append(msg, previousHash[:]...)
	msg = append(msg, domainHash[:]...)
	var times [16]byte
	binary.BigEndian.PutUint64(times[0:8], uint64(receipt.ActivatedAt))
	binary.BigEndian.PutUint64(times[8:16], uint64(receipt.PreviousValidUntil))
	return append(msg, times[:]...), nil
}

func verifyCatalogPointerWithAuthority(pubKey ed25519.PublicKey, storeDomainHash [32]byte, pointer AppCatalogPointer) error {
	if pointer.Schema != "melusina-app-catalog-pointer-v1" {
		return errors.New("check=catalog_pointer: schema mismatch")
	}
	domainHash, err := hash32FromHex(pointer.ServingDomainHash)
	if err != nil || domainHash != storeDomainHash {
		return errors.New("check=catalog_pointer: serving domain mismatch")
	}
	msg, err := catalogPointerMessage(pointer, domainHash)
	if err != nil {
		return fmt.Errorf("check=catalog_pointer: %w", err)
	}
	sig, err := primitives.DecodeBase58(pointer.OperatorSignature)
	if err != nil || !ed25519.Verify(pubKey, msg, sig) {
		return errors.New("check=catalog_pointer: signature does not verify against on-chain store_authority")
	}
	return nil
}

func catalogPointerMessage(pointer AppCatalogPointer, domainHash [32]byte) ([]byte, error) {
	appHash, err := hash32FromHex(pointer.AppHash)
	if err != nil {
		return nil, fmt.Errorf("app hash: %w", err)
	}
	releaseHash, err := hash32FromHex(pointer.ReleaseHash)
	if err != nil {
		return nil, fmt.Errorf("release hash: %w", err)
	}
	stageID, err := hash32FromHex(pointer.StageID)
	if err != nil {
		return nil, fmt.Errorf("stage id: %w", err)
	}
	catalogHash, err := hash32FromHex(pointer.CatalogSHA256)
	if err != nil {
		return nil, fmt.Errorf("catalog hash: %w", err)
	}
	var previousHash [32]byte
	if pointer.PreviousAppHash != "" {
		previousHash, err = hash32FromHex(pointer.PreviousAppHash)
		if err != nil {
			return nil, fmt.Errorf("previous app hash: %w", err)
		}
	}
	appIDHash := sha256.Sum256([]byte(pointer.AppID))
	packageIDHash := sha256.Sum256([]byte(pointer.PackageID))
	versionHash := sha256.Sum256([]byte(pointer.Version))
	previousVersionHash := sha256.Sum256([]byte(pointer.PreviousVersion))
	msg := make([]byte, 0, len("melusina-app-catalog-pointer-v1\x00")+32*10+16)
	msg = append(msg, []byte("melusina-app-catalog-pointer-v1\x00")...)
	msg = append(msg, appIDHash[:]...)
	msg = append(msg, packageIDHash[:]...)
	msg = append(msg, versionHash[:]...)
	msg = append(msg, appHash[:]...)
	msg = append(msg, releaseHash[:]...)
	msg = append(msg, stageID[:]...)
	msg = append(msg, catalogHash[:]...)
	msg = append(msg, previousVersionHash[:]...)
	msg = append(msg, previousHash[:]...)
	msg = append(msg, domainHash[:]...)
	var times [16]byte
	binary.BigEndian.PutUint64(times[0:8], uint64(pointer.PublishedAt))
	binary.BigEndian.PutUint64(times[8:16], uint64(pointer.PreviousValidUntil))
	return append(msg, times[:]...), nil
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
