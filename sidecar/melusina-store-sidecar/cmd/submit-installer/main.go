// Command submit-installer publishes one immutable whole-file release through
// the root store's gated POST /publish/installer API. Immediately gated classes
// are downloaded and verified in the same invocation. A sidecar is staged
// first, then becomes downloadable only after a signed DesiredGeneration and
// SidecarIdentity cascade verify its exact bytes; it never writes the catalog
// directly.
//
// With --envelope-out it only signs: it writes the signed /publish/installer
// envelope (the exact bytes of the multipart "envelope" part this command
// would otherwise send) and contacts nothing, as submit-generation
// --envelope-out does for /publish/generation. A release publisher produces it
// off-host; the Store host later sends it with the artifact through the
// Store's own /publish/installer gate, which re-verifies the signer against
// accept_publishers, the purpose binding, the durable nonce and the
// InstallerReleaseEntry exactly as for an online publication.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/installerpublish"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// systemProgramID is never a license registry.
const systemProgramID = "11111111111111111111111111111111"

const sidecarClass = "sidecar"

// maxEnvelopeBytes bounds the signed envelope written by --envelope-out. A
// signed installer envelope is about two kilobytes; the Store host reads a
// pre-signed envelope through the same 64 KiB ceiling.
const maxEnvelopeBytes = 64 << 10

// Named refusals. Each names the input or check that refused, so an operator
// who reads one knows which file or flag to fix.
const (
	refuseArtifact     = "check=artifact"
	refusePublisherKey = "check=publisher_key"
	refuseStorePubkey  = "check=store_pubkey"
	refuseLifetime     = "check=envelope_lifetime"
	refuseSelfVerify   = "check=envelope_self_verify"
	refuseEnvelopeOut  = "check=envelope_out"
)

type publisherKeyFile struct {
	Ref      identity.Ref `json:"ref"`
	SignSeed string       `json:"sign_seed_hex"`
	BoxSeed  string       `json:"box_seed_hex"`
}

type options struct {
	store        string
	class        string
	name         string
	artifactPath string
	publisherKey string
	storePubkey  string
	storeID      string
	storeDomain  string
	licenseMint  string
	programID    string
	verifiedSlot uint64
	timeout      time.Duration
	envelopeOut  string
}

type publishResult struct {
	Class         string `json:"class"`
	Name          string `json:"name"`
	InstallerHash string `json:"installer_hash"`
	Path          string `json:"path"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "submit-installer:", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (options, error) {
	fs := flag.NewFlagSet("submit-installer", flag.ContinueOnError)
	var o options
	fs.StringVar(&o.store, "store", "", "store base URL (required)")
	fs.StringVar(&o.class, "class", "", "release class, served at /releases/<class>/<name> (required). For a DesiredGeneration component it must be that component's componentClass: shell, sidecar or data; the Store refuses to promote a component staged under any other class. deployer is the bootstrap bundle, which no generation names")
	fs.StringVar(&o.name, "name", "", "immutable served filename (required)")
	fs.StringVar(&o.artifactPath, "artifact", "", "whole-file artifact path (required)")
	fs.StringVar(&o.publisherKey, "publisher-key", "", "publisher identity JSON path or env:NAME (required)")
	fs.StringVar(&o.storePubkey, "store-pubkey", "", "store operator identity.Public JSON path (required)")
	fs.StringVar(&o.storeID, "store-id", "", "profile-bound destination Store ID (required)")
	fs.StringVar(&o.storeDomain, "store-domain", "", "profile-bound destination Store domain (required)")
	fs.StringVar(&o.licenseMint, "license-mint", "", "destination Store install licence mint (required)")
	fs.StringVar(&o.programID, "program-id", "", "license-registry program named in the envelope chain evidence: the estate profile's programs.license-registry.programId (required; there is no default registry)")
	fs.Uint64Var(&o.verifiedSlot, "verified-slot", 1, "publisher chain-evidence slot")
	fs.DurationVar(&o.timeout, "timeout", 10*time.Minute, "upload + read-back timeout; the signed envelope lives --timeout plus two minutes (at least five minutes, at most one hour)")
	fs.StringVar(&o.envelopeOut, "envelope-out", "", "write the signed /publish/installer envelope (the exact multipart envelope part) atomically to this path; do not contact the store. --store names the Store the envelope is for and is not contacted")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	var missing []string
	for name, value := range map[string]string{
		"--store": o.store, "--class": o.class, "--name": o.name,
		"--artifact": o.artifactPath, "--publisher-key": o.publisherKey,
		"--store-pubkey": o.storePubkey, "--program-id": o.programID,
		"--store-id": o.storeID, "--store-domain": o.storeDomain, "--license-mint": o.licenseMint,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return o, fmt.Errorf("missing required flag(s): %s", strings.Join(missing, " "))
	}
	if key, err := primitives.PubkeyFromBase58(o.programID); err != nil || key.Base58() != o.programID || o.programID == systemProgramID {
		return o, errors.New("--program-id must be the canonical base58 license-registry program, not the System Program")
	}
	if !safeSegment(o.class) || !safeSegment(o.name) {
		return o, errors.New("--class and --name must each be one safe path segment")
	}
	if o.verifiedSlot == 0 {
		return o, errors.New("--verified-slot must be greater than zero")
	}
	if o.timeout <= 0 {
		return o, errors.New("--timeout must be positive")
	}
	return o, nil
}

func run(args []string, stdout io.Writer) error {
	o, err := parseFlags(args)
	if err != nil {
		return err
	}
	artifact, err := os.ReadFile(o.artifactPath)
	if err != nil {
		return fmt.Errorf("%s: read --artifact: %w", refuseArtifact, err)
	}
	if len(artifact) == 0 {
		return fmt.Errorf("%s: artifact is empty", refuseArtifact)
	}
	artifactHash := sha256.Sum256(artifact)
	hashHex := hex.EncodeToString(artifactHash[:])

	publisher, err := loadPublisherKey(o.publisherKey)
	if err != nil {
		return fmt.Errorf("%s: %w", refusePublisherKey, err)
	}
	destination, err := loadStorePubkey(o.storePubkey)
	if err != nil {
		return fmt.Errorf("%s: %w", refuseStorePubkey, err)
	}
	// A publisher key minted under another registry belongs to another
	// estate; refuse the mix instead of letting either program win.
	if keyProgram := publisher.Public().Ref.ProgramID; keyProgram != "" && keyProgram != o.programID {
		return fmt.Errorf("check=program_id: publisher key is bound to license-registry program %s, not --program-id %s", keyProgram, o.programID)
	}
	// The envelope's chain is the one the publisher key was minted under
	// (keygen publisher -chain-id). There is no default chain: the key loader
	// refuses a key without one (identity.Ref.Validate: chain_id is required),
	// so no compiled fallback can name the retiring estate's cluster, as one
	// here once did (K-TEN-03).
	ttl := o.timeout + 2*time.Minute
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	if ttl > envelope.MaxTransportLifetime {
		return fmt.Errorf("%s: --timeout %s gives a %s envelope; the Store accepts at most %s", refuseLifetime, o.timeout, ttl, envelope.MaxTransportLifetime)
	}
	signed, err := installerpublish.Sign(publisher, destination, o.class, o.name, hashHex,
		o.storeID, o.storeDomain, o.licenseMint, o.programID, o.verifiedSlot, ttl)
	if err != nil {
		return fmt.Errorf("sign envelope: %w", err)
	}
	bindingDigest, err := verifySignedInstallerEnvelope(signed, publisher.Public(), destination, o, hashHex)
	if err != nil {
		return err
	}
	envelopeBytes, err := json.Marshal(signed)
	if err != nil {
		return fmt.Errorf("marshal signed installer envelope: %w", err)
	}
	if len(envelopeBytes) > maxEnvelopeBytes {
		return fmt.Errorf("%s: signed envelope is %d bytes, above the %d byte ceiling", refuseSelfVerify, len(envelopeBytes), maxEnvelopeBytes)
	}

	// Envelope-only: the release publisher signs off-host and the Store host
	// sends these exact bytes with the artifact later. Nothing is contacted
	// and no publisher key reaches the host. The file is immutable input to a
	// later authorized POST, not a publication receipt.
	if strings.TrimSpace(o.envelopeOut) != "" {
		if err := atomicWrite(o.envelopeOut, envelopeBytes); err != nil {
			return fmt.Errorf("%s: write signed installer envelope: %w", refuseEnvelopeOut, err)
		}
		envelopeSum := sha256.Sum256(envelopeBytes)
		return json.NewEncoder(stdout).Encode(map[string]any{
			"status":          "SIGNED_INSTALLER_ENVELOPE_OK",
			"envelopePath":    o.envelopeOut,
			"envelopeSha256":  hex.EncodeToString(envelopeSum[:]),
			"class":           o.class,
			"name":            o.name,
			"artifactSha256":  hashHex,
			"bindingSha256":   bindingDigest,
			"signerPubkeyB58": publisher.Public().SignPubkeyB58,
			"target":          installerpublish.Target,
			"expiresAtMs":     signed.Payload.ExpiresAtMs,
		})
	}

	client := &http.Client{Timeout: o.timeout}
	result, err := publish(context.Background(), client, o, envelopeBytes, artifact)
	if err != nil {
		return err
	}
	if result.Class != o.class || result.Name != o.name ||
		!strings.EqualFold(result.InstallerHash, hashHex) {
		return fmt.Errorf("store response mismatch: %#v", result)
	}
	if o.class == sidecarClass {
		// A sidecar's public GET is deliberately gated by the signed generation
		// that this upload is about to help create. Requiring GET read-back here
		// would make first publication circular: the store must not serve the
		// bytes before its generation names them, while the generation promotion
		// independently re-hashes the staged file and re-verifies its complete
		// SidecarIdentity authority cascade.
		fmt.Fprintf(stdout, "PUBLISH SIDECAR STAGED class=%s name=%s sha256=%s path=%s; pending signed DesiredGeneration verification\n",
			result.Class, result.Name, hashHex, result.Path)
		return nil
	}
	if err := verifyServed(context.Background(), client, o.store, result.Path, artifactHash); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "PUBLISH INSTALLER OK class=%s name=%s sha256=%s path=%s\n",
		result.Class, result.Name, hashHex, result.Path)
	return nil
}

// verifySignedInstallerEnvelope re-verifies the envelope this command just
// signed the way the Store's /publish/installer gate will: the signature
// against the publisher's own key, the Store operator destination, the
// artifact digest and the purpose binding (POST /publish/installer, class,
// name and the Store audience). It returns the binding digest. An envelope
// that would not pass is never written or sent.
func verifySignedInstallerEnvelope(signed envelope.Signed, publisher identity.Public, destination identity.Public,
	o options, artifactSHA256 string) (string, error) {
	binding, err := installerpublish.Digest(o.class, o.name, artifactSHA256,
		o.storeID, o.storeDomain, o.licenseMint, o.programID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", refuseSelfVerify, err)
	}
	if strings.TrimSpace(signed.SignatureB58) == "" {
		return "", fmt.Errorf("%s: the envelope carries no signature", refuseSelfVerify)
	}
	if signed.Payload.Method != http.MethodPost || signed.Payload.Target != installerpublish.Target ||
		signed.Payload.BodyHashHex != binding || signed.Payload.RequestHashHex != artifactSHA256 {
		return "", fmt.Errorf("%s: the envelope does not bind POST %s, this artifact and this Store audience", refuseSelfVerify, installerpublish.Target)
	}
	if err := envelope.Verify(signed, envelope.VerifyOptions{
		ExpectedKind:            envelope.KindPublishRequest,
		ExpectedSignerPubkeyB58: publisher.SignPubkeyB58,
		ExpectedDestination:     &destination,
		ExpectedRequestHash:     artifactSHA256,
		NonceCache:              envelope.NewMemoryNonceCache(),
	}); err != nil {
		return "", fmt.Errorf("%s: %w", refuseSelfVerify, err)
	}
	return binding, nil
}

// publish sends the exact signed envelope bytes (the same bytes
// --envelope-out writes) with the artifact as the Store's multipart form.
func publish(ctx context.Context, client *http.Client, o options, envelopeBytes []byte, artifact []byte) (publishResult, error) {
	var result publishResult
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := writePart(mw, "envelope", "envelope.json", envelopeBytes); err != nil {
		return result, err
	}
	if err := mw.WriteField("class", o.class); err != nil {
		return result, err
	}
	if err := mw.WriteField("name", o.name); err != nil {
		return result, err
	}
	if err := writePart(mw, "artifact", o.name, artifact); err != nil {
		return result, err
	}
	if err := mw.Close(); err != nil {
		return result, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(o.store, "/")+"/publish/installer", &body)
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("publish POST: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("store rejected publish: HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return result, fmt.Errorf("decode publish result: %w", err)
	}
	return result, nil
}

func verifyServed(ctx context.Context, client *http.Client, store, servedPath string, wantHash [32]byte) error {
	base, err := url.Parse(strings.TrimRight(store, "/") + "/")
	if err != nil {
		return err
	}
	cleanPath := path.Clean("/" + strings.TrimSpace(servedPath))
	base.Path = cleanPath
	base.RawQuery = ""
	base.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("served read-back: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("served read-back HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	wantHex := hex.EncodeToString(wantHash[:])
	if !strings.EqualFold(resp.Header.Get("X-Store-Gate"), "verified") ||
		!strings.EqualFold(resp.Header.Get("X-Store-InstallerHash"), wantHex) {
		return fmt.Errorf("served read-back lacks matching verified gate headers")
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, resp.Body); err != nil {
		return fmt.Errorf("hash served read-back: %w", err)
	}
	if got := hex.EncodeToString(digest.Sum(nil)); got != wantHex {
		return fmt.Errorf("served read-back sha256=%s want=%s", got, wantHex)
	}
	return nil
}

func writePart(mw *multipart.Writer, field, filename string, data []byte) error {
	part, err := mw.CreateFormFile(field, filename)
	if err != nil {
		return err
	}
	_, err = part.Write(data)
	return err
}

func loadPublisherKey(arg string) (*identity.Private, error) {
	var raw []byte
	if name, ok := strings.CutPrefix(arg, "env:"); ok {
		value := os.Getenv(name)
		if value == "" {
			return nil, fmt.Errorf("env %s is empty", name)
		}
		raw = []byte(value)
	} else {
		value, err := os.ReadFile(arg)
		if err != nil {
			return nil, err
		}
		raw = value
	}
	var file publisherKeyFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, err
	}
	signSeed, err := seed32(file.SignSeed)
	if err != nil {
		return nil, fmt.Errorf("sign_seed_hex: %w", err)
	}
	boxSeed, err := seed32(file.BoxSeed)
	if err != nil {
		return nil, fmt.Errorf("box_seed_hex: %w", err)
	}
	return identity.NewPrivate(file.Ref, signSeed, boxSeed)
}

func loadStorePubkey(file string) (identity.Public, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return identity.Public{}, err
	}
	return identity.ParsePublicJSON(raw)
}

func seed32(value string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return out, err
	}
	if len(raw) != len(out) {
		return out, fmt.Errorf("want 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func safeSegment(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// atomicWrite writes data to path through a private temporary file in the
// same directory, as submit-generation --envelope-out does.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".installer-envelope-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
