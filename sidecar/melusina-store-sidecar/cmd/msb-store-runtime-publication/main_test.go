package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func TestOriginalGenerationAndOperatorPins(t *testing.T) {
	raw, _ := assets.ReadFile("original-generation-210.json")
	if sha(raw) != baselineSHA {
		t.Fatal("original generation changed")
	}
	var d componentrelease.DesiredGeneration
	if e := exactJSON(raw, &d); e != nil {
		t.Fatal(e)
	}
	key, _ := primitives.DecodeBase58(operator)
	if e := componentrelease.Verify(ed25519.PublicKey(key), storeID, d); e != nil {
		t.Fatal(e)
	}
	p := expectedRequest(d)
	if p.ExpectedCurrentGeneration != 210 || len(p.Components) != 5 {
		t.Fatal("original cohort changed")
	}
	for i, c := range p.Components {
		if c.ComponentID != "melusina-store-sidecar" {
			if !reflect.DeepEqual(c, d.Components[i]) {
				t.Fatal("unrelated component/floor changed")
			}
			continue
		}
		if c.Version != "1.0.63" || c.SHA256 != artifactSHA || c.PreviousSHA256 != previousSHA || c.PreviousVersion != "1.0.61" {
			t.Fatal("actual physical rollback floor lost")
		}
		c.Version = d.Components[i].Version
		c.SHA256 = d.Components[i].SHA256
		c.ArtifactName = d.Components[i].ArtifactName
		c.SizeBytes = d.Components[i].SizeBytes
		c.BundleURL = d.Components[i].BundleURL
		c.PreviousSHA256 = d.Components[i].PreviousSHA256
		c.PreviousVersion = d.Components[i].PreviousVersion
		if !reflect.DeepEqual(c, d.Components[i]) {
			t.Fatal("Store chain identity changed")
		}
	}
	pub, _ := assets.ReadFile("original-store-public.json")
	if sha(pub) != "0750ade356004583023a3eff76395a326d94e4b4a5f853f039d082d7f8a1b79e" {
		t.Fatal("original Store authority input changed")
	}
}
func TestExactJSONRefusesAmbiguousAuthority(t *testing.T) {
	type value struct {
		Digest string `json:"digest"`
		Token  string `json:"token"`
	}
	for _, raw := range []string{`{"digest":"x","token":"y","digest":"z"}`, `{"Digest":"x","token":"y"}`, `{"digest":"x","token":"y","extra":1}`, `{"digest":"x","token":"y"}{}`, `{"digest":null,"token":"y"}`} {
		var v value
		if e := exactJSON([]byte(raw), &v); e == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	var v value
	if e := exactJSON([]byte(" {\n\"digest\":\"x\",\"token\":\"y\" } "), &v); e != nil {
		t.Fatal(e)
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int, raw string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(raw)), Header: make(http.Header)}
}
func testService(t *testing.T) *service {
	t.Helper()
	s := &service{state: t.TempDir(), token: "test-only-session", in: fixedInputs{digest: "test-only-digest", artifact: preparedArtifact{Body: []byte("test prepared wire"), ContentType: "multipart/form-data; boundary=test"}}, j: journal{Schema: "test-only-no-authority", ArtifactState: "ready", GenerationState: "ready", Receipts: []receipt{}}, authority: func(context.Context) (json.RawMessage, error) { return json.RawMessage(`{"testOnly":true}`), nil }, checkInputs: func(fixedInputs) error { return nil }}
	return s
}
func readiness() *http.Response {
	return response(200, `{"schema":"melusina-generation-promote-readiness-v1","status":"ready","currentGenerationId":210}`)
}
func TestStageFreezesBeforeStoreAndNeverRepeats(t *testing.T) {
	s := testService(t)
	posts := 0
	s.client = &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method == "GET" && r.URL.String() == storeURL+"/publish/generation" {
			return readiness(), nil
		}
		posts++
		if r.Method != "POST" || r.URL.String() != storeURL+"/publish/installer" {
			t.Fatal("escaped fixed transport")
		}
		entries, _ := os.ReadDir(s.state)
		if len(entries) != 1 {
			t.Fatal("intent not durably frozen before POST")
		}
		b, _ := os.ReadFile(filepath.Join(s.state, entries[0].Name()))
		if !bytes.Contains(b, []byte(`"artifactState":"uncertain"`)) {
			t.Fatal("unresolved intent not recorded")
		}
		wire, _ := io.ReadAll(r.Body)
		if !bytes.Equal(wire, s.in.artifact.Body) {
			t.Fatal("signed body changed")
		}
		return response(200, `{"class":"sidecar","name":"`+artifactName+`","installer_hash":"`+artifactSHA+`","path":"/releases/sidecar/`+artifactName+`"}`), nil
	})}
	if e := s.perform(context.Background(), "stage"); e != nil {
		t.Fatal(e)
	}
	if s.j.ArtifactState != "staged" || posts != 1 {
		t.Fatal("stage outcome missing")
	}
	if e := s.perform(context.Background(), "stage"); e == nil {
		t.Fatal("repeated stage")
	}
	if posts != 1 {
		t.Fatal("second Store POST")
	}
	entries, _ := os.ReadDir(s.state)
	if len(entries) != 2 {
		t.Fatal("intent/result conservation missing")
	}
}
func TestUncertainAndRefusedStageCannotPromoteOrRetry(t *testing.T) {
	for _, failure := range []string{"network", "wrong-result", "store-refused"} {
		t.Run(failure, func(t *testing.T) {
			s := testService(t)
			posts := 0
			s.client = &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
				if r.Method == "GET" {
					return readiness(), nil
				}
				posts++
				if failure == "network" {
					return nil, errors.New("test lost response")
				}
				if failure == "store-refused" {
					return response(403, "original gate refused"), nil
				}
				return response(200, `{"class":"sidecar","name":"wrong","installer_hash":"`+artifactSHA+`","path":"/releases/sidecar/wrong"}`), nil
			})}
			if e := s.perform(context.Background(), "stage"); e == nil {
				t.Fatal("accepted unknown/refused outcome")
			}
			if e := s.perform(context.Background(), "stage"); e == nil {
				t.Fatal("retried uncertain intent")
			}
			if e := s.perform(context.Background(), "promote"); e == nil {
				t.Fatal("promoted without exact stage receipt")
			}
			if posts != 1 || s.j.ArtifactState != "uncertain" {
				t.Fatal("unknown outcome lost")
			}
		})
	}
}
func TestMissingAuthorityExpiredEnvelopeAndChangedCASNeverContactWrite(t *testing.T) {
	for _, failure := range []string{"authority", "envelope", "verifier-absent", "cas"} {
		t.Run(failure, func(t *testing.T) {
			s := testService(t)
			posts := 0
			s.client = &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
				if r.Method == "POST" {
					posts++
				}
				return response(200, `{"schema":"melusina-generation-promote-readiness-v1","status":"ready","currentGenerationId":212}`), nil
			})}
			if failure == "authority" {
				s.authority = func(context.Context) (json.RawMessage, error) { return nil, errors.New("R32 not adopted") }
			}
			if failure == "envelope" {
				s.checkInputs = func(fixedInputs) error { return errors.New("expired original envelope") }
			}
			if failure == "verifier-absent" {
				s.checkInputs = nil
			}
			if e := s.perform(context.Background(), "stage"); e == nil {
				t.Fatal("failed precondition accepted")
			}
			entries, _ := os.ReadDir(s.state)
			if posts != 0 || len(entries) != 0 || s.j.ArtifactState != "ready" {
				t.Fatal("preflight refusal wrote an intent or contacted Store POST")
			}
		})
	}
}
func TestBrowserOriginTokenAndActionIsolation(t *testing.T) {
	s := testService(t)
	s.client = &http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("refused browser request contacted Store")
		return nil, errors.New("unreachable")
	})}
	for _, test := range []struct{ host, origin, fetch, body, path string }{{"evil.example", origin, "same-origin", `{"digest":"test-only-digest","token":"test-only-session"}`, "/v1/stage"}, {listen, "https://evil.example", "cross-site", `{"digest":"test-only-digest","token":"test-only-session"}`, "/v1/stage"}, {listen, origin, "same-origin", `{"digest":"changed","token":"test-only-session"}`, "/v1/stage"}, {listen, origin, "same-origin", `{"digest":"test-only-digest","token":"wrong"}`, "/v1/stage"}, {listen, origin, "same-origin", `{"digest":"test-only-digest","token":"test-only-session"}`, "/v1/arbitrary"}} {
		r := httptest.NewRequest("POST", origin+test.path, strings.NewReader(test.body))
		r.Host = test.host
		r.Header.Set("Origin", test.origin)
		r.Header.Set("Sec-Fetch-Site", test.fetch)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.handler().ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatal("unauthorized request accepted")
		}
	}
}
func TestProtectedInputsAndImmutableJournal(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "input")
	if e := os.WriteFile(p, []byte("first"), 0o600); e != nil {
		t.Fatal(e)
	}
	if _, e := readOwned(p, 10); e != nil {
		t.Fatal(e)
	}
	if _, e := readOwned(p, 4); e == nil {
		t.Fatal("oversize accepted")
	}
	if e := os.Chmod(p, 0o660); e != nil {
		t.Fatal(e)
	}
	if _, e := readOwned(p, 10); e == nil {
		t.Fatal("group writable accepted")
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if _, e := readOwned(link, 10); e == nil {
		t.Fatal("input symlink accepted")
	}
	if e := writeNew(dir, "input", []byte("replacement")); e == nil {
		t.Fatal("prior evidence overwritten")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "first" {
		t.Fatal("prior bytes lost")
	}
}

func TestArtifactAndGenerationCryptographyCannotUseSyntheticAuthority(t *testing.T) {
	in := fixedInputs{artifact: preparedArtifact{Schema: "melusina-installer-publish-prepared-v1", Store: storeURL, Method: "POST", Target: "/publish/installer", Class: "sidecar", Name: artifactName, ArtifactSHA256: artifactSHA, ArtifactBytes: artifactSize, ContentType: "multipart/form-data; boundary=test", Body: []byte("--test--\r\n")}}
	if err := validateArtifact(&in); err == nil {
		t.Fatal("missing exact signed ELF accepted")
	}
	if err := verifyInputs(in); err == nil {
		t.Fatal("synthetic unsigned input became original publisher authority")
	}
	for _, mutate := range []func(*preparedArtifact){func(a *preparedArtifact) { a.Store = "https://evil.example" }, func(a *preparedArtifact) { a.Target = "/publish" }, func(a *preparedArtifact) { a.Class = "shell" }, func(a *preparedArtifact) { a.Name = "other.bin" }, func(a *preparedArtifact) { a.ArtifactSHA256 = previousSHA }, func(a *preparedArtifact) { a.ArtifactBytes++ }} {
		other := in
		mutate(&other.artifact)
		if err := validateArtifact(&other); err == nil {
			t.Fatal("cross-scope descriptor accepted")
		}
	}
}

func TestPromotionRejectsUnsignedSuccessAndPreservesUncertainIntent(t *testing.T) {
	s := testService(t)
	s.j.ArtifactState = "staged"
	s.in.generationRaw = []byte(`{"testOnly":"signed wrapper fixture"}`)
	posts := 0
	s.client = &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			posts++
			if r.URL.String() != storeURL+"/publish/generation" {
				t.Fatal("escaped promotion route")
			}
			return response(200, `{"generationId":211,"previousGeneration":210,"generationHash":"fabricated","servedSha256":"fabricated","path":"/update/generation.json"}`), nil
		}
		if r.URL.Path == "/publish/generation" {
			return readiness(), nil
		}
		raw, _ := assets.ReadFile("original-generation-210.json")
		return response(200, string(raw)), nil
	})}
	if err := s.perform(context.Background(), "promote"); err == nil {
		t.Fatal("old signed generation accepted as new publication")
	}
	if s.j.GenerationState != "uncertain" {
		t.Fatal("unverified outcome became success")
	}
	if err := s.perform(context.Background(), "promote"); err == nil {
		t.Fatal("uncertain generation retried")
	}
	if posts != 1 {
		t.Fatal("promotion repeated")
	}
}

func TestReadbackScriptOnlyLoadsReviewedPublicProtocols(t *testing.T) {
	b, _ := assets.ReadFile("chain-readback.cjs")
	s := string(b)
	for _, forbidden := range []string{"sendTransaction", "sendRawTransaction", "signTransaction", "9222", "privateKey", "key-file"} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("authority observer acquired %s", forbidden)
		}
	}
	for _, required := range []string{"getGenesisHash", "getMultipleAccounts", "55000", "1985n", "if(!r.applied)", "53cee56bd30bf119800e7cd311cd9e24c2ef6c3f9dc16b65187c10732faaafd1"} {
		if !strings.Contains(s, required) {
			t.Fatalf("observer lost %s", required)
		}
	}
}
