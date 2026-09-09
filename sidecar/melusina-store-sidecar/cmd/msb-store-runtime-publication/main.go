// This keyless browser service transmits two exact, previously signed original
// Store requests. It never signs, edits the served tree, selects a host action,
// replaces a Store gate or accepts a caller-controlled network destination.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-attest/envelope"
	"github.com/hrbrlife/melusina-attest/identity"
	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	listen       = "127.0.0.1:18448"
	origin       = "http://" + listen
	storeURL     = "https://bazaar.melusina-os.org"
	storeID      = "melusina-os-root-store"
	publisher    = "ARX39MQQR1c7cT8L9ARbeg7AWw975gPGr9EE9oygKv1P"
	operator     = "4J2hbufiTKmvgfxjGVNqhoQXiKVDsYwaor6hcaDKjzZV"
	sourceCommit = "bce85bc6b9bd68bf411c047f3a7853684d7830b0"
	artifactName = "melusina-store-sidecar-1.0.63-8fff30321ed86347.bin"
	artifactSHA  = "8fff30321ed863475947e2dac28e05df93bd4bf12fef79423a08f3e0797b77bb"
	artifactSize = 16749761
	baselineSHA  = "2fff22ea7ede6cf7d4ed0105b936092bb9a3e5d1b180ff05803a8fe8708b7de7"
	previousSHA  = "d58781728276bf9577781a0ec79fcc2a38876154e859214529455dee7309fff3"
	maxPrepared  = 24 << 20
)

//go:embed original-generation-210.json original-store-public.json chain-readback.cjs static/*
var assets embed.FS

type preparedArtifact struct {
	Schema         string `json:"schema"`
	Store          string `json:"store"`
	Method         string `json:"method"`
	Target         string `json:"target"`
	Class          string `json:"class"`
	Name           string `json:"name"`
	ArtifactSHA256 string `json:"artifactSha256"`
	ArtifactBytes  int    `json:"artifactBytes"`
	ContentType    string `json:"contentType"`
	Body           []byte `json:"bodyBase64"`
}
type preparedGeneration struct {
	Envelope   envelope.Signed `json:"envelope"`
	RequestB64 string          `json:"request_b64"`
}
type generationRequest struct {
	Schema                    string                              `json:"schema"`
	Channel                   string                              `json:"channel"`
	ExpectedCurrentGeneration uint64                              `json:"expectedCurrentGeneration"`
	Components                []componentrelease.ComponentRelease `json:"components"`
}
type fixedInputs struct {
	artifact                               preparedArtifact
	generation                             preparedGeneration
	artifactRaw, generationRaw, requestRaw []byte
	request                                generationRequest
	destination                            identity.Public
	baseline                               componentrelease.DesiredGeneration
	artifactEnvelope                       envelope.Signed
	digest                                 string
}
type journal struct {
	Schema          string    `json:"schema"`
	Digest          string    `json:"digest"`
	ArtifactState   string    `json:"artifactState"`
	GenerationState string    `json:"generationState"`
	Receipts        []receipt `json:"receipts"`
}
type receipt struct {
	Action         string          `json:"action"`
	At             time.Time       `json:"at"`
	RequestSHA256  string          `json:"requestSHA256"`
	Authority      json.RawMessage `json:"authority"`
	HTTPStatus     int             `json:"httpStatus"`
	Response       json.RawMessage `json:"response,omitempty"`
	Error          string          `json:"error,omitempty"`
	ReadbackSHA256 string          `json:"readbackSHA256,omitempty"`
}
type service struct {
	checkInputs  func(fixedInputs) error
	revision     uint64
	mu           sync.Mutex
	in           fixedInputs
	state, token string
	j            journal
	client       *http.Client
	authority    func(context.Context) (json.RawMessage, error)
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func exactJSON(raw []byte, target any) error {
	// Marshal/unmarshal equality also rejects duplicate, alias and unknown fields;
	// whitespace is accepted but field names and values cannot be reinterpreted.
	var tree any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&tree); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	if err := unique(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	var expected any
	ed := json.NewDecoder(bytes.NewReader(canonical))
	ed.UseNumber()
	if err = ed.Decode(&expected); err != nil {
		return err
	}
	if !reflect.DeepEqual(tree, expected) {
		return errors.New("noncanonical or aliased JSON fields")
	}
	return nil
}
func unique(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON too deep")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		v, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch v {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[strings.ToLower(s)] {
					return errors.New("duplicate or aliased JSON key")
				}
				seen[strings.ToLower(s)] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, e = d.Token()
		return e
	}
	return walk(0)
}
func readOwned(name string, max int64) ([]byte, error) {
	f, e := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Size() > max || sys.Uid != uint32(os.Getuid()) || sys.Nlink != 1 || st.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("input must be an owned bounded protected regular file")
	}
	return io.ReadAll(f)
}
func verifyEnvelope(s envelope.Signed, in fixedInputs, hash string) error {
	if s.Payload.ChainEvidence.ChainID != "solana:devnet" || s.Payload.ChainEvidence.ProgramID != "7anRCW8UAFwdSAAxkrK7TmptukNKY74nZrNPfRKzzWLb" || s.Payload.ChainEvidence.VerifiedSlot == 0 {
		return errors.New("original devnet evidence required")
	}
	return envelope.Verify(s, envelope.VerifyOptions{ExpectedKind: envelope.KindPublishRequest, ExpectedSignerPubkeyB58: publisher, ExpectedDestination: &in.destination, ExpectedRequestHash: hash, NonceCache: envelope.NewMemoryNonceCache()})
}
func expectedRequest(base componentrelease.DesiredGeneration) generationRequest {
	out := generationRequest{Schema: "melusina-generation-promote-v1", Channel: "dev", ExpectedCurrentGeneration: 210, Components: append([]componentrelease.ComponentRelease(nil), base.Components...)}
	for i, c := range out.Components {
		if c.ComponentID == "melusina-store-sidecar" {
			c.Version = "1.0.63"
			c.ArtifactName = artifactName
			c.SHA256 = artifactSHA
			c.SizeBytes = artifactSize
			c.BundleURL = storeURL + "/releases/sidecar/" + artifactName
			c.PreviousSHA256 = previousSHA
			c.PreviousVersion = "1.0.61"
			out.Components[i] = c
		}
	}
	return out
}
func loadInputs(dir string) (fixedInputs, error) {
	var in fixedInputs
	var e error
	in.artifactRaw, e = readOwned(filepath.Join(dir, "artifact-prepared.json"), maxPrepared)
	if e != nil {
		return in, e
	}
	in.generationRaw, e = readOwned(filepath.Join(dir, "generation-prepared.json"), 1<<20)
	if e != nil {
		return in, e
	}
	if e = exactJSON(in.artifactRaw, &in.artifact); e != nil {
		return in, e
	}
	if e = exactJSON(in.generationRaw, &in.generation); e != nil {
		return in, e
	}
	pub, _ := assets.ReadFile("original-store-public.json")
	if sha(pub) != "0750ade356004583023a3eff76395a326d94e4b4a5f853f039d082d7f8a1b79e" {
		return in, errors.New("original operator public input changed")
	}
	if e = json.Unmarshal(pub, &in.destination); e != nil {
		return in, e
	}
	if in.destination.SignPubkeyB58 != operator {
		return in, errors.New("original operator identity changed")
	}
	raw, _ := assets.ReadFile("original-generation-210.json")
	if sha(raw) != baselineSHA {
		return in, errors.New("retained generation210 bytes changed")
	}
	if e = exactJSON(raw, &in.baseline); e != nil {
		return in, e
	}
	key, e := primitives.DecodeBase58(operator)
	if e != nil {
		return in, e
	}
	if e = componentrelease.Verify(ed25519.PublicKey(key), storeID, in.baseline); e != nil {
		return in, e
	}
	in.requestRaw, e = base64.StdEncoding.Strict().DecodeString(in.generation.RequestB64)
	if e != nil {
		return in, e
	}
	if e = exactJSON(in.requestRaw, &in.request); e != nil {
		return in, e
	}
	expected := expectedRequest(in.baseline)
	if !reflect.DeepEqual(in.request, expected) {
		return in, errors.New("only exact210→211 Store1.0.63 change with original physical rollback floor is allowed")
	}
	if e = validateArtifact(&in); e != nil {
		return in, e
	}
	in.digest = sha(append(append([]byte("melusina-original-store-runtime-publication-v1\x00"), []byte(sha(in.artifactRaw))...), []byte(sha(in.generationRaw))...))
	return in, verifyInputs(in)
}
func validateArtifact(in *fixedInputs) error {
	a := in.artifact
	if a.Schema != "melusina-installer-publish-prepared-v1" || a.Store != storeURL || a.Method != "POST" || a.Target != "/publish/installer" || a.Class != "sidecar" || a.Name != artifactName || a.ArtifactSHA256 != artifactSHA || a.ArtifactBytes != artifactSize {
		return errors.New("artifact descriptor differs from reviewed original Store candidate")
	}
	media, params, e := mime.ParseMediaType(a.ContentType)
	if e != nil || media != "multipart/form-data" || len(params) != 1 || params["boundary"] == "" {
		return errors.New("invalid exact multipart content type")
	}
	var rebuilt bytes.Buffer
	writer := multipart.NewWriter(&rebuilt)
	if e = writer.SetBoundary(params["boundary"]); e != nil {
		return e
	}
	r := multipart.NewReader(bytes.NewReader(a.Body), params["boundary"])
	expected := []string{"envelope", "class", "name", "artifact"}
	for _, name := range expected {
		p, e := r.NextPart()
		if e != nil || p.FormName() != name {
			return errors.New("multipart fields are not in original canonical order")
		}
		b, e := io.ReadAll(io.LimitReader(p, artifactSize+1))
		p.Close()
		if e != nil {
			return e
		}
		if name == "envelope" || name == "artifact" {
			w, e := writer.CreateFormFile(name, p.FileName())
			if e != nil {
				return e
			}
			if _, e = w.Write(b); e != nil {
				return e
			}
		} else if e = writer.WriteField(name, string(b)); e != nil {
			return e
		}
		switch name {
		case "envelope":
			if p.FileName() != "envelope.json" {
				return errors.New("wrong envelope filename")
			}
			if e = exactJSON(b, &in.artifactEnvelope); e != nil {
				return e
			}
		case "class":
			if p.FileName() != "" || string(b) != "sidecar" {
				return errors.New("wrong artifact class")
			}
		case "name":
			if p.FileName() != "" || string(b) != artifactName {
				return errors.New("wrong artifact name")
			}
		case "artifact":
			if p.FileName() != artifactName || len(b) != artifactSize || sha(b) != artifactSHA {
				return errors.New("artifact bytes differ from reviewed ELF")
			}
		}
	}
	if _, e = r.NextPart(); e != io.EOF {
		return errors.New("extra multipart part")
	}
	if e = writer.Close(); e != nil {
		return e
	}
	if !bytes.Equal(rebuilt.Bytes(), a.Body) {
		return errors.New("multipart differs from exact original wire encoding")
	}
	return nil
}
func verifyInputs(in fixedInputs) error {
	if e := verifyEnvelope(in.artifactEnvelope, in, artifactSHA); e != nil {
		return fmt.Errorf("artifact envelope: %w", e)
	}
	if e := verifyEnvelope(in.generation.Envelope, in, sha(in.requestRaw)); e != nil {
		return fmt.Errorf("generation envelope: %w", e)
	}
	p := in.generation.Envelope.Payload
	if p.Method != "POST" || p.Target != "/publish/generation" || p.BodyHashHex != sha(in.requestRaw) {
		return errors.New("generation envelope is not exact POST /publish/generation")
	}
	return nil
}
func writeNew(dir, name string, b []byte) error {
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (s *service) save() error {
	b, e := json.Marshal(s.j)
	if e != nil {
		return e
	}
	s.revision++
	name := "journal-" + fmt.Sprintf("%04d", s.revision) + "-" + s.j.ArtifactState + "-" + s.j.GenerationState + ".json"
	return writeNew(s.state, name, b)
}
func (s *service) getGeneration(ctx context.Context) ([]byte, componentrelease.DesiredGeneration, error) {
	var d componentrelease.DesiredGeneration
	r, e := http.NewRequestWithContext(ctx, "GET", storeURL+"/update/generation.json", nil)
	if e != nil {
		return nil, d, e
	}
	resp, e := s.client.Do(r)
	if e != nil {
		return nil, d, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if e != nil {
		return nil, d, e
	}
	if resp.StatusCode != 200 || len(b) > 1<<20 {
		return nil, d, errors.New("original served generation unavailable")
	}
	if e = exactJSON(b, &d); e != nil {
		return nil, d, e
	}
	k, _ := primitives.DecodeBase58(operator)
	if e = componentrelease.Verify(ed25519.PublicKey(k), storeID, d); e != nil {
		return nil, d, e
	}
	return b, d, nil
}
func (s *service) verify(ctx context.Context) (json.RawMessage, error) {
	if s.checkInputs == nil {
		return nil, errors.New("original envelope verifier unavailable")
	}
	if e := s.checkInputs(s.in); e != nil {
		return nil, e
	}
	authority, e := s.authority(ctx)
	if e != nil {
		return nil, e
	}
	r, e := http.NewRequestWithContext(ctx, "GET", storeURL+"/publish/generation", nil)
	if e != nil {
		return nil, e
	}
	resp, e := s.client.Do(r)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if e != nil || len(raw) > 4096 || resp.StatusCode != 200 {
		return nil, errors.New("original signed generation CAS readiness unavailable")
	}
	var ready struct {
		Schema              string `json:"schema"`
		Status              string `json:"status"`
		CurrentGenerationID uint64 `json:"currentGenerationId"`
	}
	if e = exactJSON(raw, &ready); e != nil {
		return nil, e
	}
	if ready.Schema != "melusina-generation-promote-readiness-v1" || ready.Status != "ready" || ready.CurrentGenerationID != 210 {
		return nil, errors.New("original Store no longer has reviewed signed generation210")
	}
	// R32 adoption intentionally makes the old public target unservable. The
	// Store's original readiness handler verifies its persisted signed generation
	// before exposing this immutable CAS floor. Held full210 bytes remain signed
	// and pinned; every supplied component is independently rechecked by Store.
	return authority, nil
}
func (s *service) perform(ctx context.Context, action string) error {
	authority, e := s.verify(ctx)
	if e != nil {
		return e
	}
	var body []byte
	var target, contentType string
	if action == "stage" {
		if s.j.ArtifactState != "ready" || s.j.GenerationState != "ready" {
			return errors.New("artifact stage already attempted")
		}
		body = s.in.artifact.Body
		target = "/publish/installer"
		contentType = s.in.artifact.ContentType
		s.j.ArtifactState = "uncertain"
	} else if action == "promote" {
		if s.j.ArtifactState != "staged" || s.j.GenerationState != "ready" {
			return errors.New("exact artifact stage receipt required and generation must be unattempted")
		}
		body = s.in.generationRaw
		target = "/publish/generation"
		contentType = "application/json"
		s.j.GenerationState = "uncertain"
	} else {
		return errors.New("unknown fixed action")
	}
	rec := receipt{Action: action, At: time.Now().UTC(), RequestSHA256: sha(body), Authority: authority}
	s.j.Receipts = append(s.j.Receipts, rec)
	if e = s.save(); e != nil {
		return e
	}
	r, e := http.NewRequestWithContext(ctx, "POST", storeURL+target, bytes.NewReader(body))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", contentType)
	resp, e := s.client.Do(r)
	if e != nil {
		s.j.Receipts[len(s.j.Receipts)-1].Error = e.Error()
		_ = s.save()
		return fmt.Errorf("unknown Store outcome; retry refused: %w", e)
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	rec.HTTPStatus = resp.StatusCode
	if e != nil || len(raw) > 1<<20 {
		return errors.New("unknown bounded Store response; retry refused")
	}
	if json.Valid(raw) {
		rec.Response = raw
	}
	if resp.StatusCode != 200 {
		rec.Error = fmt.Sprintf("Store refused HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		s.j.Receipts[len(s.j.Receipts)-1] = rec
		_ = s.save()
		return errors.New(rec.Error)
	}
	if action == "stage" {
		var result struct {
			Class         string `json:"class"`
			Name          string `json:"name"`
			InstallerHash string `json:"installer_hash"`
			Path          string `json:"path"`
		}
		if e = exactJSON(raw, &result); e != nil {
			return fmt.Errorf("stage response invalid: %w", e)
		}
		if result.Class != "sidecar" || result.Name != artifactName || result.InstallerHash != artifactSHA || result.Path != "/releases/sidecar/"+artifactName {
			return errors.New("stage response differs from exact artifact")
		}
		s.j.ArtifactState = "staged"
	} else {
		var result struct {
			GenerationID       uint64 `json:"generationId"`
			PreviousGeneration uint64 `json:"previousGeneration"`
			GenerationHash     string `json:"generationHash"`
			ServedSHA256       string `json:"servedSha256"`
			Path               string `json:"path"`
		}
		if e = exactJSON(raw, &result); e != nil {
			return e
		}
		served, d, e := s.getGeneration(ctx)
		if e != nil {
			return e
		}
		if result.GenerationID != 211 || result.PreviousGeneration != 210 || result.GenerationHash != d.GenerationHash || result.ServedSHA256 != sha(served) || result.Path != "/update/generation.json" || d.GenerationID != 211 || d.PreviousGeneration != 210 || !reflect.DeepEqual(d.Components, s.in.request.Components) || d.Channel != "dev" || d.BundleOrigin != storeURL {
			return errors.New("promoted signed generation does not preserve exact reviewed cohort")
		}
		if e = writeNew(s.state, "generation-211.json", served); e != nil {
			return e
		}
		rec.ReadbackSHA256 = sha(served)
		s.j.GenerationState = "promoted"
	}
	s.j.Receipts[len(s.j.Receipts)-1] = rec
	return s.save()
}

func (s *service) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		if r.Host != listen || r.URL.RawQuery != "" || r.URL.RawPath != "" {
			http.Error(w, "wrong fixed origin", 421)
			return
		}
		if r.Method == "GET" {
			switch r.URL.Path {
			case "/", "/app.js":
				name := "static/index.html"
				typ := "text/html; charset=utf-8"
				if r.URL.Path == "/app.js" {
					name = "static/app.js"
					typ = "application/javascript"
				}
				b, _ := assets.ReadFile(name)
				w.Header().Set("Content-Type", typ)
				w.Write(b)
				return
			case "/v1/status":
				s.mu.Lock()
				defer s.mu.Unlock()
				json.NewEncoder(w).Encode(map[string]any{"sourceCommit": sourceCommit, "artifactSHA256": artifactSHA, "artifactBytes": artifactSize, "publisher": publisher, "store": storeURL, "generationBefore": 210, "generationAfter": 211, "physicalRollbackVersion": "1.0.61", "physicalRollbackSHA256": previousSHA, "expiresAtMs": min(s.in.artifactEnvelope.Payload.ExpiresAtMs, s.in.generation.Envelope.Payload.ExpiresAtMs), "digest": s.in.digest, "token": s.token, "journal": s.j})
				return
			case "/v1/receipt":
				s.mu.Lock()
				defer s.mu.Unlock()
				w.Header().Set("Content-Disposition", "attachment; filename=store-runtime-publication-receipt.json")
				json.NewEncoder(w).Encode(s.j)
				return
			}
		}
		if r.Method != "POST" || r.Header.Get("Origin") != origin || r.Header.Get("Content-Type") != "application/json" || (r.Header.Get("Sec-Fetch-Site") != "same-origin" && r.Header.Get("Sec-Fetch-Site") != "none") {
			http.Error(w, "exact same-origin browser request required", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		b, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, "bounded request required", 400)
			return
		}
		var v struct {
			Digest string `json:"digest"`
			Token  string `json:"token"`
		}
		if e = exactJSON(b, &v); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if v.Digest != s.in.digest || v.Token != s.token {
			http.Error(w, "reviewed session token differs", 403)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
		defer cancel()
		switch r.URL.Path {
		case "/v1/verify":
			var proof json.RawMessage
			proof, e = s.verify(ctx)
			if e == nil {
				json.NewEncoder(w).Encode(map[string]any{"verified": true, "authority": proof})
				return
			}
		case "/v1/stage":
			e = s.perform(ctx, "stage")
		case "/v1/promote":
			e = s.perform(ctx, "promote")
		default:
			http.NotFound(w, r)
			return
		}
		if e != nil {
			http.Error(w, e.Error(), 409)
			return
		}
		json.NewEncoder(w).Encode(s.j)
	})
}

func main() {
	var input, state, root string
	var requestOut string
	flag.StringVar(&input, "inputs", "", "owned directory with two original signed prepared requests")
	flag.StringVar(&state, "state", "", "new private durable browser journal directory")
	flag.StringVar(&root, "deployer-source", "", "original source containing exact pinned authority protocols")
	flag.StringVar(&requestOut, "request-out", "", "prepare exact unsigned generation request only, no network")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal(errors.New("unexpected argument"))
	}
	if requestOut != "" {
		if input != "" || state != "" || root != "" || !filepath.IsAbs(requestOut) {
			fatal(errors.New("request-out is a separate absolute preparation operation"))
		}
		b, _ := assets.ReadFile("original-generation-210.json")
		var d componentrelease.DesiredGeneration
		if sha(b) != baselineSHA {
			fatal(errors.New("baseline pin changed"))
		}
		if e := json.Unmarshal(b, &d); e != nil {
			fatal(e)
		}
		b, _ = json.Marshal(expectedRequest(d))
		if e := writeNew(filepath.Dir(requestOut), filepath.Base(requestOut), b); e != nil {
			fatal(e)
		}
		fmt.Println("PREPARED_ONLY exact unsigned generation210→211 request; Store not contacted")
		return
	}
	if !filepath.IsAbs(input) || !filepath.IsAbs(state) || !filepath.IsAbs(root) {
		fatal(errors.New("absolute input, new state and original source directories required"))
	}
	in, e := loadInputs(input)
	if e != nil {
		fatal(e)
	}
	if e = os.Mkdir(state, 0o700); e != nil {
		fatal(fmt.Errorf("new private state directory required; prior outcomes must be preserved: %w", e))
	}
	for name, b := range map[string][]byte{"artifact-prepared.json": in.artifactRaw, "generation-prepared.json": in.generationRaw} {
		if e = writeNew(state, name, b); e != nil {
			fatal(e)
		}
	}
	token := make([]byte, 32)
	if _, e = rand.Read(token); e != nil {
		fatal(e)
	}
	client := &http.Client{Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	script, _ := assets.ReadFile("chain-readback.cjs")
	s := &service{in: in, state: state, token: hex.EncodeToString(token), client: client, checkInputs: verifyInputs, j: journal{Schema: "melusina-original-store-runtime-publication-journal-v1", Digest: in.digest, ArtifactState: "ready", GenerationState: "ready", Receipts: []receipt{}}, authority: func(ctx context.Context) (json.RawMessage, error) {
		cmd := exec.CommandContext(ctx, "/usr/bin/node", "-e", string(script), root)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "NODE_OPTIONS="}
		out, e := cmd.CombinedOutput()
		if e != nil {
			return nil, fmt.Errorf("original authority readback refused: %s", strings.TrimSpace(string(out)))
		}
		if len(out) > 8192 || !json.Valid(out) {
			return nil, errors.New("invalid bounded authority readback")
		}
		return json.RawMessage(out), nil
	}}
	if e = s.save(); e != nil {
		fatal(e)
	}
	fmt.Println("Original Store1.0.63 publisher review: " + origin + "/ (no operation until rendered approval)")
	srv := &http.Server{Addr: listen, Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	fatal(srv.ListenAndServe())
}
func fatal(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
