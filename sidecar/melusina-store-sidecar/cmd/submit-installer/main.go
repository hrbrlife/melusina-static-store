// Command submit-installer publishes one immutable whole-file release through
// the root store's gated POST /publish/installer API, then downloads the served
// object and verifies its gate headers and bytes. It is the supported publisher
// for shell, deployer, sidecar, and bootstrap artifacts; it never writes the
// catalog directly.
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
	"strings"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
)

const defaultProgramID = "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb"

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
	verifiedSlot uint64
	timeout      time.Duration
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
	fs.StringVar(&o.class, "class", "", "release class, e.g. deployer or sidecar (required)")
	fs.StringVar(&o.name, "name", "", "immutable served filename (required)")
	fs.StringVar(&o.artifactPath, "artifact", "", "whole-file artifact path (required)")
	fs.StringVar(&o.publisherKey, "publisher-key", "", "publisher identity JSON path or env:NAME (required)")
	fs.StringVar(&o.storePubkey, "store-pubkey", "", "store operator identity.Public JSON path (required)")
	fs.Uint64Var(&o.verifiedSlot, "verified-slot", 1, "publisher chain-evidence slot")
	fs.DurationVar(&o.timeout, "timeout", 10*time.Minute, "upload + read-back timeout")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	var missing []string
	for name, value := range map[string]string{
		"--store": o.store, "--class": o.class, "--name": o.name,
		"--artifact": o.artifactPath, "--publisher-key": o.publisherKey,
		"--store-pubkey": o.storePubkey,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return o, fmt.Errorf("missing required flag(s): %s", strings.Join(missing, " "))
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
		return fmt.Errorf("read artifact: %w", err)
	}
	if len(artifact) == 0 {
		return errors.New("artifact is empty")
	}
	artifactHash := sha256.Sum256(artifact)
	hashHex := hex.EncodeToString(artifactHash[:])

	publisher, err := loadPublisherKey(o.publisherKey)
	if err != nil {
		return fmt.Errorf("publisher key: %w", err)
	}
	destination, err := loadStorePubkey(o.storePubkey)
	if err != nil {
		return fmt.Errorf("store pubkey: %w", err)
	}
	ttl := o.timeout + 2*time.Minute
	if ttl < 5*time.Minute {
		ttl = 5 * time.Minute
	}
	signed, err := envelope.Sign(envelope.KindPublishRequest, publisher, destination, envelope.SignOptions{
		RequestHash: hashHex,
		TTL:         ttl,
		Chain: envelope.ChainEvidence{
			ChainID:      firstNonEmpty(publisher.Public().Ref.ChainID, "solana:devnet"),
			ProgramID:    firstNonEmpty(publisher.Public().Ref.ProgramID, defaultProgramID),
			VerifiedSlot: o.verifiedSlot,
		},
	})
	if err != nil {
		return fmt.Errorf("sign envelope: %w", err)
	}

	client := &http.Client{Timeout: o.timeout}
	result, err := publish(context.Background(), client, o, signed, artifact)
	if err != nil {
		return err
	}
	if result.Class != o.class || result.Name != o.name ||
		!strings.EqualFold(result.InstallerHash, hashHex) {
		return fmt.Errorf("store response mismatch: %#v", result)
	}
	if err := verifyServed(context.Background(), client, o.store, result.Path, artifactHash); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "PUBLISH INSTALLER OK class=%s name=%s sha256=%s path=%s\n",
		result.Class, result.Name, hashHex, result.Path)
	return nil
}

func publish(ctx context.Context, client *http.Client, o options, signed envelope.Signed, artifact []byte) (publishResult, error) {
	var result publishResult
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	envelopeBytes, err := json.Marshal(signed)
	if err != nil {
		return result, err
	}
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

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
