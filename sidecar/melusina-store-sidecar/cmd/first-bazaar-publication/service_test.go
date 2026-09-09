package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func testService(t *testing.T) *service {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	s := &service{c: candidate{digest: strings.Repeat("a", 64), stageID: stageID()}, state: dir, token: strings.Repeat("b", 64)}
	if e := s.loadJournal(); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestIntentSurvivesLostReplyRestartAndRefusesSecondSend(t *testing.T) {
	s := testService(t)
	calls := 0
	s.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.String() != storeURL+"/publish/stage" {
			t.Fatal("wrong fixed Store effect")
		}
		raw, e := os.ReadFile(filepath.Join(s.state, "journal-000002.json"))
		if e != nil {
			t.Fatal("intent did not precede transport", e)
		}
		var j journal
		if e = json.Unmarshal(raw, &j); e != nil || j.StageState != "attempted" || len(j.Events) != 1 || j.Events[0].RequestSHA256 != sha([]byte("synthetic bounded transport bytes")) {
			t.Fatal("exact intent absent")
		}
		return nil, errors.New("synthetic lost reply")
	})}
	if e := s.sendOnce(context.Background(), "stage", "/publish/stage", []byte("synthetic bounded transport bytes"), json.RawMessage(`{"synthetic":true}`)); e == nil {
		t.Fatal("lost reply accepted")
	}
	if calls != 1 || s.j.StageState != "attempted" || s.j.Stage != nil {
		t.Fatal("uncertain outcome lost")
	}
	resumed := &service{c: s.c, state: s.state, client: s.client}
	if e := resumed.loadJournal(); e != nil {
		t.Fatal(e)
	}
	if resumed.j.StageState != "attempted" || len(resumed.j.Events) != 2 {
		t.Fatal("restart lost intent/result")
	}
	if e := resumed.sendOnce(context.Background(), "stage", "/publish/stage", []byte("different"), nil); e == nil || calls != 1 {
		t.Fatal("restart blindly retried")
	}
	if e := resumed.sendOnce(context.Background(), "publish", "/publish", []byte("different"), nil); e == nil || calls != 1 {
		t.Fatal("publication without staged receipt allowed")
	}
}
func TestJournalWriteFailurePreventsStoreEffect(t *testing.T) {
	s := testService(t)
	if e := os.WriteFile(filepath.Join(s.state, "journal-000002.json"), []byte("retained conflicting evidence"), 0o600); e != nil {
		t.Fatal(e)
	}
	calls := 0
	s.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return nil, errors.New("unreachable") })}
	if e := s.sendOnce(context.Background(), "stage", "/publish/stage", []byte("synthetic"), nil); e == nil || calls != 0 || !s.failed {
		t.Fatal("Store effect escaped failed durable intent")
	}
	if e := s.save(); e == nil {
		t.Fatal("failed journal silently resumed")
	}
}
func TestJournalCannotChangeCandidateOrLoseAncestor(t *testing.T) {
	s := testService(t)
	s.j.Events = append(s.j.Events, event{Action: "synthetic-preserved"})
	if e := s.save(); e != nil {
		t.Fatal(e)
	}
	other := &service{c: candidate{digest: strings.Repeat("b", 64)}, state: s.state}
	if e := other.loadJournal(); e == nil {
		t.Fatal("another candidate adopted journal")
	}
	if e := os.Remove(filepath.Join(s.state, "journal-000001.json")); e != nil {
		t.Fatal(e)
	}
	same := &service{c: s.c, state: s.state}
	if e := same.loadJournal(); e == nil {
		t.Fatal("missing ancestor accepted")
	}
}
func TestBrowserBoundaryIsClosedAndReadOnlyUntilExactAction(t *testing.T) {
	s := testService(t)
	h := s.handler()
	for _, v := range []struct {
		method, path, origin, body string
		code                       int
	}{{"GET", "/", "", "", 200}, {"GET", "/v1/status", "", "", 200}, {"GET", "/v1/stage", "", "", 404}, {"POST", "/v1/stage", "https://foreign.invalid", `{}`, 403}, {"POST", "/v1/stage", origin, `{"token":"bad","digest":"bad"}`, 403}, {"POST", "/v1/stage", origin, `{"token":"a","token":"b","digest":"c"}`, 400}, {"POST", "/v1/execute", origin, `{"token":"` + s.token + `","digest":"` + s.c.digest + `"}`, 404}} {
		r := httptest.NewRequest(v.method, origin+v.path, strings.NewReader(v.body))
		r.Host = listen
		r.Header.Set("Origin", v.origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != v.code {
			t.Fatalf("%s %s =%d want%d: %s", v.method, v.path, w.Code, v.code, w.Body.String())
		}
	}
	if len(s.j.Events) != 0 {
		t.Fatal("read or refused request changed journal")
	}
	r := httptest.NewRequest("GET", origin+"/", nil)
	r.Host = "foreign.invalid"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 421 {
		t.Fatal("foreign Host accepted")
	}
}
func TestActualAuthorReleaseCannotUsePreparationTimeAsFinalExecution(t *testing.T) {
	raw, e := os.ReadFile("../prepare-first-bazaar/testdata/first-bazaar-author-preparation.json")
	if e != nil {
		t.Fatal(e)
	}
	c := candidate{}
	if e = json.Unmarshal(raw, &c.ceremony); e != nil {
		t.Fatal(e)
	}
	release := map[string]any{"$schema": "melusina-release-v1", "appHash": appHash, "releaseHash": releaseHash, "version": version, "signedAtUnix": c.ceremony.CreatedAtUnix, "masterNftMint": master, "licenseSquadsVault": vault, "releaseEntryPda": c.ceremony.ReleaseEntryPDA, "authorSig": c.ceremony.AuthorSig, "quorumPolicy": c.ceremony.QuorumPolicy, "releaseNonce": c.ceremony.ReleaseNonce, "runtimeContractSha256": runtimeSHA, "runtimeContractSchema": "melusina-app-runtime-contract-v1"}
	b, _ := json.Marshal(release)
	if e = validateRelease(c, b, c.ceremony.CreatedAtUnix); e != nil {
		t.Fatal(e)
	}
	if e = validateRelease(c, b, c.ceremony.CreatedAtUnix+60); e == nil {
		t.Fatal("author preparation timestamp substituted for actual registration")
	}
	if stageID() != "48c54596156edd575105614b93e213ec36751345a2e7b6a8607109c95696a4be" {
		t.Fatal("browser/Store stage framing differs")
	}
}
func TestMalformedOrForeignPublisherHandoffCannotReachTransport(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{}`), []byte(`{"schema":"melusina-submit-prepared-v1","target":"/publish/installer","envelope":{},"expected":{}}`)} {
		if _, e := submission(candidate{}, "/publish/stage", []byte("public release"), raw); e == nil {
			t.Fatal("foreign envelope accepted")
		}
	}
	s := testService(t)
	if e := s.sendOnce(context.Background(), "stage", "https://foreign.invalid", nil, nil); e == nil {
		t.Fatal("arbitrary transport target accepted")
	}
	f := filepath.Join(t.TempDir(), "input")
	if e := os.WriteFile(f, []byte("public"), 0o600); e != nil {
		t.Fatal(e)
	}
	if _, e := owned(f, 2); e == nil {
		t.Fatal("oversized input accepted")
	}
	link := f + "-link"
	if e := os.Symlink(f, link); e != nil {
		t.Fatal(e)
	}
	if _, e := owned(link, 100); e == nil {
		t.Fatal("input symlink accepted")
	}
}

func TestFinalDescriptorRequiresIndependentExecutionAndNeverOverwrites(t *testing.T) {
	s := testService(t)
	raw, e := os.ReadFile("../prepare-first-bazaar/testdata/first-bazaar-author-preparation.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &s.c.ceremony); e != nil {
		t.Fatal(e)
	}
	s.c.dir = t.TempDir()
	s.c.provisional, e = json.Marshal(map[string]any{"$schema": "melusina-release-v1", "appHash": appHash, "releaseHash": releaseHash, "version": version, "signedAtUnix": s.c.ceremony.CreatedAtUnix, "masterNftMint": master, "licenseSquadsVault": vault, "releaseEntryPda": s.c.ceremony.ReleaseEntryPDA, "authorSig": s.c.ceremony.AuthorSig, "quorumPolicy": s.c.ceremony.QuorumPolicy, "releaseNonce": s.c.ceremony.ReleaseNonce, "runtimeContractSha256": runtimeSHA, "runtimeContractSchema": "melusina-app-runtime-contract-v1"})
	if e != nil {
		t.Fatal(e)
	}
	at := s.c.ceremony.CreatedAtUnix + 60
	path := filepath.Join(s.c.dir, "RELEASE.final.json")
	s.executed = func(context.Context, []byte) error { return errors.New("synthetic independent execution refusal") }
	if e = s.retainFinal(context.Background(), at, nil); e == nil {
		t.Fatal("unverified final descriptor accepted")
	}
	if _, e = os.Stat(path); !os.IsNotExist(e) || len(s.j.Events) != 0 {
		t.Fatal("independent refusal wrote a descriptor or intent")
	}
	calls := 0
	s.executed = func(_ context.Context, release []byte) error { calls++; return validateRelease(s.c, release, at) }
	if e = s.retainFinal(context.Background(), at, json.RawMessage(`{"synthetic":true}`)); e != nil {
		t.Fatal(e)
	}
	final, e := owned(path, 128<<10)
	if e != nil || validateRelease(s.c, final, at) != nil || calls != 1 {
		t.Fatal("actual author fields or observed timestamp were not retained")
	}
	if e = s.retainFinal(context.Background(), at, nil); e != nil || calls != 2 || len(s.j.Events) != 1 {
		t.Fatal("idempotent verified descriptor changed history")
	}
	if e = os.WriteFile(path, []byte("retained conflicting evidence"), 0o600); e != nil {
		t.Fatal(e)
	}
	if e = s.retainFinal(context.Background(), at, nil); e == nil {
		t.Fatal("conflicting final descriptor overwritten")
	}
	kept, _ := os.ReadFile(path)
	if string(kept) != "retained conflicting evidence" {
		t.Fatal("last-copy conflicting evidence was changed")
	}
}

func TestInstalledOriginalCandidateReadOnly(t *testing.T) {
	dir := os.Getenv("MSB_FIRST_BAZAAR_INPUTS")
	if dir == "" {
		t.Skip("requires explicit original permanent package/preparation path")
	}
	c, e := loadCandidate(dir)
	if e != nil {
		t.Fatal(e)
	}
	if c.stageID != stageID() || len(c.spk) != spkBytes || c.digest == "" || c.ceremony.TransactionIndex == 0 {
		t.Fatal("original installed candidate scope differs")
	}
}
