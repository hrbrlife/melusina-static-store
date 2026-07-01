package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// goldenShellManifestCanonical pins the EXACT canonical bytes the operator signs
// for the sample manifest below — the whole point of B2-04 is that these bytes are
// byte-identical to the install-side consumer's manifest_canonical_bytes
// (melusina-update-checker.py: json.dumps(payload, sort_keys=True,
// separators=(",",":")) over the object minus "signature"). Verified byte-for-byte
// against CPython json (see TestUpdateManifest_CanonicalBytes_CrossCheckPython).
const goldenShellManifestCanonical = `{"build":30,"bundle_url":"https://bazaar.example.org/releases/shell/sandstorm-30.tar.xz","channel":"dev","sha256":"06b5c766bf1482ee3893f4737f657f68e667ea00b6c66102bbca8fbbd8c7a695","size":181612956,"tarball":"sandstorm-30.tar.xz","version":"build-30"}`

func sampleShellRelease() shellRelease {
	return shellRelease{
		Build:   30,
		Version: "build-30",
		Tarball: "sandstorm-30.tar.xz",
		SHA256:  "06b5c766bf1482ee3893f4737f657f68e667ea00b6c66102bbca8fbbd8c7a695",
		Size:    181612956,
		Class:   "shell",
		Channel: "dev",
	}
}

func sampleManifestConfig() Config {
	return Config{
		Domain:        "store.example.org",
		PublicBaseURL: "https://bazaar.example.org",
	}
}

// (a) Golden: the assembled manifest canonicalises to the exact consumer bytes.
func TestUpdateManifest_CanonicalBytes_Golden(t *testing.T) {
	m, err := assembleUpdateManifest(sampleManifestConfig(), sampleShellRelease())
	if err != nil {
		t.Fatalf("assembleUpdateManifest: %v", err)
	}
	got, err := manifestCanonicalBytes(m)
	if err != nil {
		t.Fatalf("manifestCanonicalBytes: %v", err)
	}
	if string(got) != goldenShellManifestCanonical {
		t.Fatalf("canonical bytes drifted from the consumer contract\n got: %s\nwant: %s", got, goldenShellManifestCanonical)
	}
	// Structural invariants the consumer's manifest_canonical_bytes depends on.
	if bytes.Contains(got, []byte(", ")) || bytes.Contains(got, []byte(`": `)) {
		t.Error("canonical bytes are not compact (found a space after a separator)")
	}
	if bytes.HasSuffix(got, []byte("\n")) {
		t.Error("canonical bytes must not end in a newline (Encoder newline not stripped)")
	}
	if bytes.Contains(got, []byte("signature")) {
		t.Error("canonical bytes must exclude the signature key")
	}
	// Keys must be sorted (build < bundle_url < channel < sha256 < size < tarball < version).
	if idx := bytes.Index(got, []byte(`"channel"`)); idx < bytes.Index(got, []byte(`"bundle_url"`)) {
		t.Error("keys are not lexicographically sorted")
	}
}

// (a′) Cross-check against the ACTUAL CPython consumer canonicalisation. Skips when
// python3 is unavailable so the suite stays hermetic, but proves the contract when
// it is (the consumer runs python3).
func TestUpdateManifest_CanonicalBytes_CrossCheckPython(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available — skipping cross-language canonical-bytes check")
	}
	m, err := assembleUpdateManifest(sampleManifestConfig(), sampleShellRelease())
	if err != nil {
		t.Fatalf("assembleUpdateManifest: %v", err)
	}
	objJSON, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	// A faithful copy of melusina-update-checker.py::manifest_canonical_bytes.
	const script = "import json,sys\n" +
		"data=json.load(sys.stdin)\n" +
		"payload={k:v for k,v in data.items() if k!='signature'}\n" +
		"sys.stdout.buffer.write(json.dumps(payload,sort_keys=True,separators=(',',':')).encode())\n"
	cmd := exec.Command(py, "-c", script)
	cmd.Stdin = bytes.NewReader(objJSON)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("python canonicalisation failed: %v\n%s", err, errBuf.String())
	}
	goBytes, err := manifestCanonicalBytes(m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(goBytes, out.Bytes()) {
		t.Fatalf("Go canonical bytes != CPython consumer bytes\n go: %s\n py: %s", goBytes, out.Bytes())
	}
	if string(out.Bytes()) != goldenShellManifestCanonical {
		t.Fatalf("CPython bytes drifted from the pinned golden\n py: %s\nwant: %s", out.Bytes(), goldenShellManifestCanonical)
	}
}

// (b) Round-trip: produce → the served signature verifies exactly as the consumer
// verifies it (parse JSON, recompute canonical bytes, ed25519.Verify vs operator pubkey).
func TestUpdateManifest_RoundTripVerify(t *testing.T) {
	cfg := sampleManifestConfig()
	op := newTestIdentity(t, "store-operator", randPubkeyB58(t), cfg.Domain)
	m, err := assembleUpdateManifest(cfg, sampleShellRelease())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signUpdateManifest(op, m)
	if err != nil {
		t.Fatalf("signUpdateManifest: %v", err)
	}
	sig, canonical := consumerVerifyInputs(t, signed)
	pub, err := op.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		t.Fatal("operator signature did not verify over the consumer's canonical bytes")
	}
}

// (c) Tamper: any post-signing edit to a manifest field breaks verification.
func TestUpdateManifest_TamperFailsVerify(t *testing.T) {
	cfg := sampleManifestConfig()
	op := newTestIdentity(t, "store-operator", randPubkeyB58(t), cfg.Domain)
	m, err := assembleUpdateManifest(cfg, sampleShellRelease())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signUpdateManifest(op, m)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := op.Public().SignPublicKey()
	if err != nil {
		t.Fatal(err)
	}

	tamper := map[string]func(map[string]any){
		"build":      func(d map[string]any) { d["build"] = json.Number("31") },                // claim a newer build
		"bundle_url": func(d map[string]any) { d["bundle_url"] = "https://evil.example/x.xz" }, // redirect the download
		"sha256":     func(d map[string]any) { d["sha256"] = strings.Repeat("00", 32) },        // swap the pinned hash
	}
	for field, mutate := range tamper {
		t.Run(field, func(t *testing.T) {
			data := decodeManifest(t, signed)
			mutate(data)
			tampered, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			sig, canonical := consumerVerifyInputs(t, tampered)
			if ed25519.Verify(pub, canonical, sig) {
				t.Fatalf("tampered manifest (%s) MUST NOT verify", field)
			}
		})
	}
}

// (d) operator nil → 503, mirroring the /publish gate fail-closed (handler.go).
func TestHandleUpdateManifest_OperatorNil_503(t *testing.T) {
	cfg := sampleManifestConfig()
	cfg.DistDir = t.TempDir()
	writeSampleShellDescriptor(t, cfg.DistDir) // present, to prove the 503 is the operator gate
	svc := &publishService{cfg: cfg, operator: nil}

	w := doUpdateManifest(t, svc, http.MethodGet)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("operator nil: want 503, got %d (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "no operator identity") {
		t.Errorf("503 body should name the operator gate, got %q", w.Body.String())
	}
}

// (d) Happy path via the handler: 200, application/json, verifies as the consumer
// would, and the SAME bytes are written through to <DistDir>/update/manifest.json.
func TestHandleUpdateManifest_Serves_SignedAndWritesThrough(t *testing.T) {
	cfg := sampleManifestConfig()
	cfg.DistDir = t.TempDir()
	writeSampleShellDescriptor(t, cfg.DistDir)
	op := newTestIdentity(t, "store-operator", randPubkeyB58(t), cfg.Domain)
	svc := &publishService{cfg: cfg, operator: op}

	w := doUpdateManifest(t, svc, http.MethodGet)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := w.Body.Bytes()

	sig, canonical := consumerVerifyInputs(t, body)
	pub, _ := op.Public().SignPublicKey()
	if !ed25519.Verify(pub, canonical, sig) {
		t.Fatal("served manifest signature did not verify")
	}
	assertBundleURLIsBazaar(t, decodeManifest(t, body))

	onDisk, err := os.ReadFile(filepath.Join(cfg.DistDir, "update", "manifest.json"))
	if err != nil {
		t.Fatalf("write-through file missing: %v", err)
	}
	if !bytes.Equal(onDisk, body) {
		t.Fatal("write-through file differs from the served bytes")
	}

	// HEAD returns headers with no body.
	hw := doUpdateManifest(t, svc, http.MethodHead)
	if hw.Code != http.StatusOK || hw.Body.Len() != 0 {
		t.Fatalf("HEAD: want 200 + empty body, got %d len=%d", hw.Code, hw.Body.Len())
	}
}

// (d) Fail-closed when there is nothing authentic to advertise.
func TestHandleUpdateManifest_MissingDescriptor_503(t *testing.T) {
	cfg := sampleManifestConfig()
	cfg.DistDir = t.TempDir() // no update/shell-release.json
	op := newTestIdentity(t, "store-operator", randPubkeyB58(t), cfg.Domain)
	svc := &publishService{cfg: cfg, operator: op}

	w := doUpdateManifest(t, svc, http.MethodGet)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing descriptor: want 503, got %d (%s)", w.Code, w.Body.String())
	}
}

// (d) Fail-closed when no public bazaar base is configured (bundle_url would be
// unreachable / internal).
func TestHandleUpdateManifest_NoPublicBase_503(t *testing.T) {
	cfg := sampleManifestConfig()
	cfg.PublicBaseURL = ""
	cfg.DistDir = t.TempDir()
	writeSampleShellDescriptor(t, cfg.DistDir)
	op := newTestIdentity(t, "store-operator", randPubkeyB58(t), cfg.Domain)
	svc := &publishService{cfg: cfg, operator: op}

	w := doUpdateManifest(t, svc, http.MethodGet)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no public_base_url: want 503, got %d (%s)", w.Code, w.Body.String())
	}
}

// (e) bundle_url is on the bazaar, never GitHub — and a GitHub public base is refused.
func TestUpdateManifest_BundleURLOnBazaarNeverGitHub(t *testing.T) {
	cfg := sampleManifestConfig()
	m, err := assembleUpdateManifest(cfg, sampleShellRelease())
	if err != nil {
		t.Fatal(err)
	}
	assertBundleURLIsBazaar(t, m)

	for _, bad := range []string{
		"https://hrbrlife.github.io/melusina-static-store",
		"https://github.com/hrbrlife/melusina-static-store/releases/download/v0",
		"https://raw.githubusercontent.com/hrbrlife/x",
		"http://bazaar.example.org", // non-https
		"",                          // unset
	} {
		badCfg := cfg
		badCfg.PublicBaseURL = bad
		if _, err := assembleUpdateManifest(badCfg, sampleShellRelease()); err == nil {
			t.Errorf("assembleUpdateManifest accepted a forbidden public_base_url %q — must reject", bad)
		}
	}
}

// loadShellRelease rejects a descriptor that could not produce a usable manifest.
func TestLoadShellRelease_RejectsMalformed(t *testing.T) {
	cases := map[string]shellRelease{
		"zero_build":     {Build: 0, Tarball: "s.tar.xz", SHA256: strings.Repeat("a", 64)},
		"short_sha":      {Build: 1, Tarball: "s.tar.xz", SHA256: "abc"},
		"non_hex_sha":    {Build: 1, Tarball: "s.tar.xz", SHA256: strings.Repeat("z", 64)},
		"unsafe_tarball": {Build: 1, Tarball: "../evil", SHA256: strings.Repeat("a", 64)},
		"negative_size":  {Build: 1, Tarball: "s.tar.xz", SHA256: strings.Repeat("a", 64), Size: -1},
	}
	for name, sr := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			up := filepath.Join(dir, "update")
			if err := os.MkdirAll(up, 0o755); err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(sr)
			if err := os.WriteFile(filepath.Join(up, "shell-release.json"), b, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := loadShellRelease(dir); err == nil {
				t.Fatalf("loadShellRelease accepted malformed descriptor %q", name)
			}
		})
	}
}

// The route is wired into newRouter and reaches the SIGNING handler (not the
// catch-all FileServer). Proven on a fresh DistDir that has the shell descriptor
// but NO manifest.json yet: a FileServer read would 404, so a signed 200 can only
// come from handleUpdateManifest.
func TestNewRouter_UpdateManifestRouteWired(t *testing.T) {
	cfg := sampleManifestConfig()
	cfg.DistDir = t.TempDir()
	writeSampleShellDescriptor(t, cfg.DistDir)
	if _, err := os.Stat(filepath.Join(cfg.DistDir, "update", "manifest.json")); err == nil {
		t.Fatal("precondition: manifest.json must NOT exist before the first request")
	}
	op := newTestIdentity(t, "store-operator", randPubkeyB58(t), cfg.Domain)
	h := newRouter(cfg, op, nil, nil)

	r := httptest.NewRequest(http.MethodGet, "/update/manifest.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("router did not route /update/manifest.json to the signing handler: got %d (%s)", w.Code, w.Body.String())
	}
	sig, canonical := consumerVerifyInputs(t, w.Body.Bytes())
	pub, _ := op.Public().SignPublicKey()
	if !ed25519.Verify(pub, canonical, sig) {
		t.Fatal("router-served manifest did not verify (wrong handler?)")
	}
}

// ── test helpers ──────────────────────────────────────────────────────────────

// consumerVerifyInputs replicates melusina-update-checker.py's verify path over
// the SERVED manifest bytes: parse JSON (numbers as json.Number, matching Python's
// int semantics), base64-decode data["signature"] (must be 64 bytes), and recompute
// manifest_canonical_bytes over the parsed object minus the signature.
func consumerVerifyInputs(t *testing.T, servedJSON []byte) (sig, canonical []byte) {
	t.Helper()
	data := decodeManifest(t, servedJSON)
	sigB64, ok := data["signature"].(string)
	if !ok || sigB64 == "" {
		t.Fatal("served manifest carries no string signature")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode signature b64: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	canonical, err = manifestCanonicalBytes(data)
	if err != nil {
		t.Fatalf("recompute canonical: %v", err)
	}
	return sig, canonical
}

func decodeManifest(t *testing.T, b []byte) map[string]any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var data map[string]any
	if err := dec.Decode(&data); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return data
}

func assertBundleURLIsBazaar(t *testing.T, m map[string]any) {
	t.Helper()
	u, _ := m["bundle_url"].(string)
	if u == "" {
		t.Fatal("bundle_url missing/empty")
	}
	if !strings.HasPrefix(u, "https://bazaar.example.org/") {
		t.Errorf("bundle_url %q is not on the configured bazaar base", u)
	}
	if strings.Contains(strings.ToLower(u), "github") {
		t.Errorf("bundle_url %q points at GitHub — forbidden", u)
	}
}

func writeSampleShellDescriptor(t *testing.T, distDir string) {
	t.Helper()
	dir := filepath.Join(distDir, "update")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(sampleShellRelease())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "shell-release.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func doUpdateManifest(t *testing.T, svc *publishService, method string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "/update/manifest.json", nil)
	w := httptest.NewRecorder()
	svc.handleUpdateManifest(w, r)
	return w
}
