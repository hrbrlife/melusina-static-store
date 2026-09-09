package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/catalogselection"
	"github.com/hrbrlife/melusina-store-sidecar/internal/finalizationinput"
	"github.com/hrbrlife/melusina-store-sidecar/internal/releasefinalizer"
	"github.com/hrbrlife/melusina-store-sidecar/staging"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

//go:embed static/* original-store-public.json chain-readback.cjs
var assets embed.FS

type journal struct {
	Schema       string                    `json:"schema"`
	Digest       string                    `json:"digest"`
	Sequence     int                       `json:"sequence"`
	Previous     string                    `json:"previous"`
	StageState   string                    `json:"stageState"`
	PublishState string                    `json:"publishState"`
	Stage        *staging.Receipt          `json:"stageReceipt"`
	Pointer      *catalogselection.Pointer `json:"catalogPointer"`
	Events       []event                   `json:"events"`
}
type event struct {
	Action        string          `json:"action"`
	At            time.Time       `json:"at"`
	RequestSHA256 string          `json:"requestSHA256,omitempty"`
	Status        int             `json:"httpStatus,omitempty"`
	Response      json.RawMessage `json:"response,omitempty"`
	Error         string          `json:"error,omitempty"`
	Evidence      json.RawMessage `json:"evidence,omitempty"`
}
type chainFacts struct {
	Slot         uint64   `json:"slot"`
	RegisteredAt *int64   `json:"registeredAt"`
	Index        string   `json:"index"`
	Status       string   `json:"proposalStatus"`
	Approved     []string `json:"approved"`
}
type service struct {
	mu                   sync.Mutex
	c                    candidate
	state, token, source string
	j                    journal
	last                 string
	failed               bool
	client               *http.Client
	authority            func(context.Context) (ed25519.PublicKey, [32]byte, error)
	chain                func(context.Context, publicPlan) (json.RawMessage, error)
	executed             func(context.Context, []byte) error
}

func (s *service) plan() publicPlan {
	return publicPlan{"melusina-first-bazaar-browser-plan-v1", s.c.author, s.j.Stage}
}
func writeNew(dir, name string, b []byte) error {
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
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
	if s.failed {
		return errors.New("journal persistence previously failed")
	}
	s.j.Sequence++
	s.j.Previous = s.last
	b, e := json.Marshal(s.j)
	if e == nil {
		e = writeNew(s.state, fmt.Sprintf("journal-%06d.json", s.j.Sequence), b)
	}
	if e != nil {
		s.failed = true
		return e
	}
	s.last = sha(b)
	return nil
}
func (s *service) loadJournal() error {
	names, e := os.ReadDir(s.state)
	if e != nil {
		return e
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })
	n := 0
	last := ""
	for _, v := range names {
		if !strings.HasPrefix(v.Name(), "journal-") {
			continue
		}
		n++
		if v.Name() != fmt.Sprintf("journal-%06d.json", n) {
			return errors.New("journal history is not contiguous")
		}
		b, e := owned(filepath.Join(s.state, v.Name()), 4<<20)
		if e != nil {
			return e
		}
		var j journal
		if e = exact(b, &j); e != nil {
			return e
		}
		if j.Schema != "melusina-first-bazaar-publication-journal-v1" || j.Digest != s.c.digest || j.Sequence != n || j.Previous != last || len(j.Events) > 64 {
			return errors.New("journal chain or exact candidate differs")
		}
		s.j = j
		last = sha(b)
	}
	s.last = last
	if n == 0 {
		s.j = journal{Schema: "melusina-first-bazaar-publication-journal-v1", Digest: s.c.digest, StageState: "ready", PublishState: "ready", Events: []event{}}
		return s.save()
	}
	if s.j.StageState != "ready" && s.j.StageState != "attempted" && s.j.StageState != "staged" {
		return errors.New("invalid retained staging state")
	}
	if s.j.PublishState != "ready" && s.j.PublishState != "attempted" && s.j.PublishState != "published" {
		return errors.New("invalid retained publication state")
	}
	return nil
}
func (s *service) get(ctx context.Context, path string, max int64) ([]byte, int, error) {
	r, e := http.NewRequestWithContext(ctx, "GET", storeURL+path, nil)
	if e != nil {
		return nil, 0, e
	}
	resp, e := s.client.Do(r)
	if e != nil {
		return nil, 0, e
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, resp.StatusCode, errors.New("bounded original Store read failed")
	}
	return b, resp.StatusCode, nil
}
func (s *service) verify(ctx context.Context) (chainFacts, json.RawMessage, error) {
	var facts chainFacts
	pub, d, e := s.authority(ctx)
	if e != nil {
		return facts, nil, e
	}
	if primitives.EncodeBase58(pub) != operator || d != primitives.StoreDomainHash(domain) {
		return facts, nil, errors.New("original Store operator changed")
	}
	if s.j.Stage != nil {
		if e = staging.VerifyExpected(pub, d, staging.Expected{StageID: s.c.stageID, AppID: appID, AppHash: appHash, ReleaseHash: releaseHash}, *s.j.Stage); e != nil {
			return facts, nil, e
		}
	}
	raw, status, e := s.get(ctx, "/release-info", 16384)
	if e != nil || status != 200 {
		return facts, nil, errors.New("original Store successor runtime is unavailable")
	}
	var runtime struct {
		Schema     string `json:"schema"`
		Component  string `json:"componentId"`
		Generation uint64 `json:"generationId"`
		Version    string `json:"version"`
		PID        int    `json:"pid"`
		SHA        string `json:"artifactSha256"`
	}
	if e = exact(raw, &runtime); e != nil {
		return facts, nil, e
	}
	if runtime.Schema != "melusina-runtime-release-info-v1" || runtime.Component != "melusina-store-sidecar" || runtime.Generation != 211 || runtime.Version != "1.0.63" || runtime.PID <= 0 || runtime.SHA != runtimeArtifact {
		return facts, nil, errors.New("original Store211 runtime marker differs")
	}
	proof, e := s.chain(ctx, s.plan())
	if e != nil {
		return facts, nil, e
	}
	if e = exact(proof, &facts); e != nil {
		return facts, nil, e
	}
	if facts.Slot == 0 || facts.Index != fmt.Sprint(s.c.ceremony.TransactionIndex) {
		return facts, nil, errors.New("original Core finalized locator differs")
	}
	return facts, proof, nil
}
func (s *service) verifyPointer(ctx context.Context, finalRelease []byte) (*catalogselection.Pointer, error) {
	pub, d, e := s.authority(ctx)
	if e != nil {
		return nil, e
	}
	if primitives.EncodeBase58(pub) != operator || d != primitives.StoreDomainHash(domain) {
		return nil, errors.New("Store authority changed")
	}
	raw, status, e := s.get(ctx, "/apps/pointers/"+appID+".json", 64<<10)
	if e != nil || status != 200 {
		return nil, errors.New("exact original Store selected pointer is not observed")
	}
	var p catalogselection.Pointer
	if e = exact(raw, &p); e != nil {
		return nil, e
	}
	if e = catalogselection.Verify(pub, p); e != nil {
		return nil, e
	}
	if p.AppID != appID || p.PackageID != spkSHA[:32] || p.Version != version || p.AppHash != appHash || p.ReleaseHash != releaseHash || p.StageID != s.c.stageID || p.ServingDomainHash != hex.EncodeToString(d[:]) || p.PreviousAppHash != "" || p.PreviousVersion != "" || p.PreviousValidUntil != 0 || p.PublishedAt <= 0 || p.PublishedAt > time.Now().Unix()+120 {
		return nil, errors.New("signed pointer differs from first original publication")
	}
	index, status, e := s.get(ctx, "/apps/index.json", 8<<20)
	if e != nil || status != 200 || sha(index) != p.CatalogSHA256 {
		return nil, errors.New("signed pointer catalog hash is not served")
	}
	var catalog struct {
		Apps []map[string]json.RawMessage `json:"apps"`
	}
	if e = json.Unmarshal(index, &catalog); e != nil {
		return nil, e
	}
	count := 0
	for _, row := range catalog.Apps {
		var id string
		_ = json.Unmarshal(row["appId"], &id)
		if id == appID {
			count++
			var got map[string]any
			var want map[string]any
			b, _ := json.Marshal(row)
			if json.Unmarshal(b, &got) != nil || json.Unmarshal(s.c.metadata, &want) != nil {
				return nil, errors.New("catalog row invalid")
			}
			var release map[string]any
			if json.Unmarshal(finalRelease, &release) != nil {
				return nil, errors.New("verified final release unavailable")
			}
			delete(release, "$schema")
			want["tier"] = "regular"
			want["domains"] = []any{"*"}
			want["capabilities"] = nil
			want["attest"] = release
			at, ok := release["signedAtUnix"].(float64)
			if !ok {
				return nil, errors.New("verified final timestamp unavailable")
			}
			want["updatedAt"] = at * 1000
			if !sameJSON(got, want) {
				return nil, errors.New("selected first app catalog projection differs from original metadata and final release")
			}

		}
	}
	if count != 1 {
		return nil, errors.New("exact first app catalog row absent or duplicated")
	}
	return &p, nil
}
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func (s *service) recoverStage(ctx context.Context, raw []byte) error {
	if s.j.StageState != "attempted" || s.j.Stage != nil {
		return errors.New("only an unresolved original stage may accept its retained signed receipt")
	}
	var r staging.Receipt
	if e := exact(raw, &r); e != nil {
		return e
	}
	pub, d, e := s.authority(ctx)
	if e != nil {
		return e
	}
	if primitives.EncodeBase58(pub) != operator || d != primitives.StoreDomainHash(domain) {
		return errors.New("original operator changed")
	}
	if r.StoredAt <= 0 || r.StoredAt > time.Now().Unix()+120 {
		return errors.New("invalid original staging timestamp")
	}
	if e = staging.VerifyExpected(pub, d, staging.Expected{StageID: s.c.stageID, AppID: appID, AppHash: appHash, ReleaseHash: releaseHash}, r); e != nil {
		return e
	}
	s.j.Stage = &r
	s.j.StageState = "staged"
	s.j.Events = append(s.j.Events, event{Action: "recover-stage-receipt", At: time.Now().UTC(), Response: raw})
	return s.save()
}

// The timestamp is read through the separately pinned browser protocol, then
// the original Go Core observer independently verifies every final claim before
// this local, keyless descriptor can exist. It does not send to the Store.
func (s *service) prepareFinal(ctx context.Context) error {
	if s.failed || s.j.StageState != "staged" || s.j.Stage == nil || len(s.j.Events) >= 60 {
		return errors.New("original signed stage and available journal required")
	}
	facts, proof, e := s.verify(ctx)
	if e != nil {
		return e
	}
	if facts.RegisteredAt == nil {
		return errors.New("original Core execution is not finalized")
	}
	return s.retainFinal(ctx, *facts.RegisteredAt, proof)
}

// Called only with the fixed verifier's actual registration time. The second
// independent observer below must still accept the complete descriptor.
func (s *service) retainFinal(ctx context.Context, registeredAt int64, proof json.RawMessage) error {
	claims, e := finalizationinput.DecodeReleaseDescriptor(s.c.provisional)
	if e != nil {
		return e
	}
	claims.SignedAtUnix = registeredAt
	raw, e := json.Marshal(claims)
	if e != nil {
		return e
	}
	if e = validateRelease(s.c, raw, registeredAt); e != nil {
		return e
	}
	if e = s.executed(ctx, raw); e != nil {
		return e
	}
	name := filepath.Join(s.c.dir, "RELEASE.final.json")
	retained, e := owned(name, 128<<10)
	if e == nil {
		return validateRelease(s.c, retained, registeredAt)
	}
	if !os.IsNotExist(e) {
		return e
	}
	s.j.Events = append(s.j.Events, event{Action: "verified-final-descriptor-intent", At: time.Now().UTC(), RequestSHA256: sha(raw), Evidence: proof})
	if e = s.save(); e != nil {
		return e
	}
	return writeNew(s.c.dir, "RELEASE.final.json", raw)
}
func (s *service) perform(ctx context.Context, action string) error {
	if s.failed || len(s.j.Events) >= 60 {
		return errors.New("journal is unavailable or full")
	}
	facts, proof, e := s.verify(ctx)
	if e != nil {
		return e
	}
	if action == "recover-publication" {
		if s.j.PublishState != "attempted" {
			return errors.New("only unresolved publication may be recovered")
		}
		return s.readPublication(ctx, proof)
	}
	target := "/publish/stage"
	release := s.c.provisional
	file := "stage-prepared.json"
	if action == "stage" {
		if s.j.StageState != "ready" || s.j.Stage != nil || facts.RegisteredAt != nil {
			return errors.New("first stage already attempted or release already registered")
		}
	} else if action == "publish" {
		if s.j.StageState != "staged" || s.j.PublishState != "ready" || facts.RegisteredAt == nil {
			return errors.New("receipted stage and finalized Core execution required")
		}
		target = "/publish"
		file = "publish-prepared.json"
		release, e = owned(filepath.Join(s.c.dir, "RELEASE.final.json"), 128<<10)
		if e != nil {
			return e
		}
		if e = validateRelease(s.c, release, *facts.RegisteredAt); e != nil {
			return e
		}
		if e = s.executed(ctx, release); e != nil {
			return e
		}
	} else {
		return errors.New("unknown first publication action")
	}
	prepared, e := owned(filepath.Join(s.c.dir, file), 128<<10)
	if e != nil {
		return e
	}
	body, e := submission(s.c, target, release, prepared)
	if e != nil {
		return e
	} // Immediately before durable intent and the only write.
	return s.sendOnce(ctx, action, target, body, proof)
}

// Only perform supplies a cryptographically validated body in production.
// Persist the fixed candidate intent before one send; this method never retries.
func (s *service) sendOnce(ctx context.Context, action, target string, body []byte, proof json.RawMessage) error {
	if s.failed || (action != "stage" && action != "publish") || (action == "stage" && (target != "/publish/stage" || s.j.StageState != "ready")) || (action == "publish" && (target != "/publish" || s.j.StageState != "staged" || s.j.PublishState != "ready")) {
		return errors.New("fixed action was already attempted or does not match phase")
	}
	var e error
	if action == "stage" {
		s.j.StageState = "attempted"
	} else {
		s.j.PublishState = "attempted"
	}
	s.j.Events = append(s.j.Events, event{Action: action + "-intent", At: time.Now().UTC(), RequestSHA256: sha(body), Evidence: proof})
	if e = s.save(); e != nil {
		return e
	}
	r, e := http.NewRequestWithContext(ctx, "POST", storeURL+target, bytes.NewReader(body))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := s.client.Do(r)
	record := event{Action: action + "-result", At: time.Now().UTC(), RequestSHA256: sha(body)}
	if e != nil {
		record.Error = "Store reply uncertain: " + e.Error()
	} else {
		defer resp.Body.Close()
		record.Status = resp.StatusCode
		b, re := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		if re != nil || len(b) > 1<<20 {
			record.Error = "bounded Store reply unavailable"
		} else if json.Valid(b) {
			record.Response = b
		} else {
			record.Error = "Store refused: " + string(b[:min(len(b), 2048)])
		}
	}
	s.j.Events = append(s.j.Events, record)
	if e = s.save(); e != nil {
		return e
	}
	if record.Status != 200 || record.Error != "" {
		return errors.New("Store result is refused or uncertain; automatic replay is disabled")
	}
	if action == "stage" {
		return s.recoverStage(ctx, record.Response)
	}
	return s.readPublication(ctx, proof)
}
func (s *service) readPublication(ctx context.Context, proof json.RawMessage) error {
	facts, _, e := s.verify(ctx)
	if e != nil || facts.RegisteredAt == nil {
		return errors.New("finalized original Core registration unavailable")
	}
	release, e := owned(filepath.Join(s.c.dir, "RELEASE.final.json"), 128<<10)
	if e != nil {
		return e
	}
	if e = validateRelease(s.c, release, *facts.RegisteredAt); e != nil {
		return e
	}
	if e = s.executed(ctx, release); e != nil {
		return e
	}
	p, e := s.verifyPointer(ctx, release)
	if e != nil {
		return e
	}
	s.j.Pointer = p
	s.j.PublishState = "published"
	s.j.Events = append(s.j.Events, event{Action: "verified-selected-publication", At: time.Now().UTC(), Evidence: proof})
	return s.save()
}

func (s *service) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self' https://api.devnet.solana.com; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		if r.Host != listen || r.URL.RawPath != "" || r.URL.RawQuery != "" {
			http.Error(w, "fixed first Bazaar origin required", 421)
			return
		}
		if r.Method == "GET" {
			if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/static/") {
				name := "static/index.html"
				if r.URL.Path != "/" {
					name = strings.TrimPrefix(r.URL.Path, "/")
				}
				b, e := assets.ReadFile(name)
				if e != nil {
					http.NotFound(w, r)
					return
				}
				typ := "application/javascript"
				if name == "static/index.html" {
					typ = "text/html; charset=utf-8"
				}
				w.Header().Set("Content-Type", typ)
				w.Write(b)
				return
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1/status":
				json.NewEncoder(w).Encode(map[string]any{"digest": s.c.digest, "token": s.token, "plan": s.plan(), "journal": s.j, "source": source, "spkSHA256": spkSHA, "spkBytes": spkBytes, "runtimeSHA256": runtimeSHA, "store": storeURL})
			case "/v1/plan":
				w.Header().Set("Content-Disposition", "attachment; filename=first-bazaar-core-plan.json")
				json.NewEncoder(w).Encode(s.plan())
			case "/v1/receipt":
				w.Header().Set("Content-Disposition", "attachment; filename=first-bazaar-publication-receipt.json")
				json.NewEncoder(w).Encode(s.j)
			default:
				http.NotFound(w, r)
			}
			return
		}
		if r.Method != "POST" || r.Header.Get("Origin") != origin || r.Header.Get("Content-Type") != "application/json" || (r.Header.Get("Sec-Fetch-Site") != "same-origin" && r.Header.Get("Sec-Fetch-Site") != "none") {
			http.Error(w, "exact same-origin rendered operation required", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		b, e := io.ReadAll(r.Body)
		if e != nil {
			http.Error(w, "bounded first app request required", 400)
			return
		}
		var q struct {
			Token   string          `json:"token"`
			Digest  string          `json:"digest"`
			Receipt json.RawMessage `json:"receipt,omitempty"`
		}
		if e = exact(b, &q); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if q.Token != s.token || q.Digest != s.c.digest {
			http.Error(w, "exact reviewed session differs", 403)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		switch r.URL.Path {
		case "/v1/verify":
			_, _, e = s.verify(ctx)
			if e == nil && s.j.PublishState == "published" {
				var release []byte
				release, e = owned(filepath.Join(s.c.dir, "RELEASE.final.json"), 128<<10)
				if e == nil {
					e = s.executed(ctx, release)
				}
				if e == nil {
					_, e = s.verifyPointer(ctx, release)
				}
			}
		case "/v1/stage":
			e = s.perform(ctx, "stage")
		case "/v1/publish":
			e = s.perform(ctx, "publish")
		case "/v1/prepare-final":
			e = s.prepareFinal(ctx)
		case "/v1/recover-publication":
			e = s.perform(ctx, "recover-publication")
		case "/v1/recover-stage":
			e = s.recoverStage(ctx, q.Receipt)
		default:
			http.NotFound(w, r)
			return
		}
		if e != nil {
			http.Error(w, e.Error(), 409)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.j)
	})
}

func main() {
	var input, state, sourceRoot string
	flag.StringVar(&input, "inputs", "", "original first preparation directory")
	flag.StringVar(&state, "state", "", "private durable first publication journal")
	flag.StringVar(&sourceRoot, "source", "", "this exact command's public source directory")
	flag.Parse()
	fatal := func(e error) {
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
	}
	if flag.NArg() != 0 {
		fatal(errors.New("unexpected first publication options"))
	}
	c, e := loadCandidate(input)
	fatal(e)
	if e = os.Mkdir(state, 0o700); e != nil && !os.IsExist(e) {
		fatal(e)
	}
	fatal(privateDir(state))
	if !filepath.IsAbs(sourceRoot) {
		fatal(errors.New("absolute original public command source required"))
	}
	for _, name := range []string{"chain-readback.cjs", "static/web3.js", "static/registry.js", "static/core.js", "static/protocol.js"} {
		want, _ := assets.ReadFile(name)
		got, e := owned(filepath.Join(sourceRoot, name), 4<<20)
		fatal(e)
		if !bytes.Equal(want, got) {
			fatal(errors.New("public checker source differs from embedded reviewed bytes"))
		}
	}
	observer, e := staging.NewAuthorityObserver(rpcURL, license, domain)
	fatal(e)
	coreObserver, e := releasefinalizer.NewCoreProposalObserver(releasefinalizer.CoreProposalObserverConfig{RPCURL: rpcURL, Members: members})
	fatal(e)
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	client := &http.Client{Transport: t, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Store redirects refused") }}
	token := make([]byte, 32)
	_, e = rand.Read(token)
	fatal(e)
	s := &service{c: c, state: state, source: sourceRoot, token: hex.EncodeToString(token), client: client, authority: observer.Observe}
	s.executed = func(ctx context.Context, release []byte) error {
		_, e := coreObserver.ObserveSelectedRelease(ctx, appID, c.stageID, c.ceremony.TransactionPDA, release)
		return e
	}
	s.chain = func(ctx context.Context, p publicPlan) (json.RawMessage, error) {
		b, e := json.Marshal(p)
		if e != nil {
			return nil, e
		}
		script, e := assets.ReadFile("chain-readback.cjs")
		if e != nil {
			return nil, e
		}
		cmd := exec.CommandContext(ctx, "/usr/bin/node", "-e", string(script), sourceRoot)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "NODE_OPTIONS="}
		cmd.Stdin = bytes.NewReader(b)
		out, e := cmd.Output()
		if e != nil {
			return nil, errors.New("original first-release chain verifier refused")
		}
		if len(out) > 32768 || !json.Valid(out) {
			return nil, errors.New("bounded public chain proof required")
		}
		return json.RawMessage(out), nil
	}
	fatal(s.loadJournal())
	fmt.Println("FIRST Bazaar review: " + origin + "/; no Store or chain action before rendered approval")
	server := &http.Server{Addr: listen, Handler: s.handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	fatal(server.ListenAndServe())
}
