package componentrelease

// PROPOSED reviewed patch (rev-2) from SYSTEM-RELEASE-RAIL-SIDECARS (card 000b) for
// the SHELL controller module. Target file:
//   internal/componentrelease/adapter_binary_replace.go
// Wire in the controller startup:  RegisterAdapter(NewBinaryReplaceAdapter(nil))
//
// Implements ApplyBinaryReplace = "binary-replace": atomically replace a SINGLE
// executable at ComponentInstall.InstallRoot (the FULL absolute executable path,
// ratified convention), restart the unit once, and return an EXACT Rollback.
// Covers swaprail, store, chainwatch, ailagoon, mermail, namedcoin, remotebak, dns,
// wolfdog, fineract-proxy.
//
// rev-2 addresses the verifier's sidecar_adapter_probe.py (idx 21118/21119),
// RATIFIED requirements:
//   (1) NEVER prune the prior binary in Apply — the retained prior is the rollback
//       floor and must live until the controller's terminal commit. keepOldBuilds
//       pruning is a controller-driven, post-commit action (PruneSupersededBackups).
//   (2) A failed restart restores the prior binary in place AND returns a usable
//       Rollback handle (never nil on the failure path).
//   (3) Staging opens the fresh staged file O_CREATE|O_EXCL|O_NOFOLLOW — a
//       preexisting or symlinked staged path is refused, never followed.
//   (4) Version ORDERING AUTHORITY is the controller's monotonic generation/mint
//       semantics; Verify enforces only exact size+hash and floor EQUALITY
//       (sha == previousSha256 replay refusal). compareVersions is retained as a
//       correct, non-lexical helper for callers that need ordering, but Verify
//       does not use it.
//   (5) Probe binds a STRUCTURED self-report field whose value EXACTLY equals the
//       applied hash — a hash merely embedded in prose is not accepted.
//   split fetchers: Stage uses an origin-pinned, no-redirect bundle getter; Probe
//   uses a loopback-only, no-redirect getter. One permissive client cannot serve
//   both. An injected getter (tests / controller override) is used for both.
//
// Division of trust (adapter.go): the CONTROLLER runs the chain-authority gate
// before Apply; this adapter never touches the chain. Stdlib only.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// HTTPGetter fetches a URL body. Injectable so the controller can pass its shared,
// policy-scoped fetchers; nil selects the split defaults (see NewBinaryReplaceAdapter).
type HTTPGetter func(ctx context.Context, url string) (io.ReadCloser, error)

type binaryReplaceAdapter struct {
	stageGet HTTPGetter // origin-pinned bundle fetch
	probeGet HTTPGetter // loopback-only self-report fetch
}

// NewBinaryReplaceAdapter returns the binary-replace adapter. A nil getter selects
// the split default policies (origin-pinned no-redirect for Stage, loopback-only
// no-redirect for Probe). A non-nil getter is used for BOTH phases (test/override).
func NewBinaryReplaceAdapter(get HTTPGetter) Adapter {
	if get == nil {
		return NewBinaryReplaceAdapterWithFetchers(defaultBundleGet, defaultLoopbackGet)
	}
	return NewBinaryReplaceAdapterWithFetchers(get, get)
}

// NewBinaryReplaceAdapterWithFetchers lets the controller inject the two
// policy-scoped fetchers explicitly (recommended in production).
func NewBinaryReplaceAdapterWithFetchers(stageGet, probeGet HTTPGetter) Adapter {
	return &binaryReplaceAdapter{stageGet: stageGet, probeGet: probeGet}
}

func (a *binaryReplaceAdapter) Kind() string { return ApplyBinaryReplace }

// prevBackupDir holds the retained prior executable for exact rollback. Kept as a
// sibling of the target so a restore is same-filesystem (atomic rename).
func prevBackupDir(installRoot string) string {
	return filepath.Join(filepath.Dir(installRoot), ".rrs-prev")
}

// Stage streams the desired bundle into a FRESH, non-followed staged file WITHOUT
// touching the live component, measuring sha256 + size (capped at exactly
// desired.SizeBytes so a lying origin cannot exhaust disk).
func (a *binaryReplaceAdapter) Stage(ctx context.Context, desired ComponentRelease, install ComponentInstall, workDir string) (Staged, error) {
	if desired.SizeBytes <= 0 {
		return Staged{}, fmt.Errorf("binary-replace stage %s: desired sizeBytes must be positive", desired.ComponentID)
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return Staged{}, fmt.Errorf("binary-replace stage %s: workdir: %w", desired.ComponentID, err)
	}
	dst := filepath.Join(workDir, desired.ComponentID+".staged")
	// O_EXCL|O_NOFOLLOW: refuse a preexisting or symlinked staged path rather than
	// follow it and overwrite an attacker-chosen target.
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o755)
	if err != nil {
		return Staged{}, fmt.Errorf("binary-replace stage %s: open fresh staged file: %w", desired.ComponentID, err)
	}
	body, err := a.stageGet(ctx, desired.BundleURL)
	if err != nil {
		f.Close()
		_ = os.Remove(dst)
		return Staged{}, fmt.Errorf("binary-replace stage %s: fetch %s: %w", desired.ComponentID, desired.BundleURL, err)
	}
	defer body.Close()
	h := sha256.New()
	// Read at most SizeBytes+1 so an oversized artifact is detected, not truncated.
	n, cerr := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, desired.SizeBytes+1))
	if closeErr := f.Close(); cerr == nil {
		cerr = closeErr
	}
	if cerr != nil {
		_ = os.Remove(dst)
		return Staged{}, fmt.Errorf("binary-replace stage %s: download: %w", desired.ComponentID, cerr)
	}
	if n != desired.SizeBytes {
		_ = os.Remove(dst)
		return Staged{}, fmt.Errorf("binary-replace stage %s: size mismatch (got %d, want %d)", desired.ComponentID, n, desired.SizeBytes)
	}
	return Staged{
		ComponentID: desired.ComponentID,
		Path:        dst,
		SHA256:      hex.EncodeToString(h.Sum(nil)),
		SizeBytes:   n,
	}, nil
}

// Verify confirms the staged bytes match desired exactly and refuses a replay of
// the rollback floor. Ordering authority (is this a forward generation?) is the
// controller's; Verify does only exact size+hash and floor EQUALITY checks.
func (a *binaryReplaceAdapter) Verify(ctx context.Context, staged Staged, desired ComponentRelease, install ComponentInstall) error {
	if staged.SizeBytes != desired.SizeBytes {
		return fmt.Errorf("binary-replace verify %s: size %d != desired %d", desired.ComponentID, staged.SizeBytes, desired.SizeBytes)
	}
	if !strings.EqualFold(staged.SHA256, desired.SHA256) {
		return fmt.Errorf("binary-replace verify %s: sha256 %s != desired %s", desired.ComponentID, staged.SHA256, strings.ToLower(desired.SHA256))
	}
	// Re-hash the on-disk bytes (defence in depth: what Apply installs, not the
	// streamed measurement).
	got, err := sha256File(staged.Path)
	if err != nil {
		return fmt.Errorf("binary-replace verify %s: re-hash: %w", desired.ComponentID, err)
	}
	if !strings.EqualFold(got, desired.SHA256) {
		return fmt.Errorf("binary-replace verify %s: on-disk sha256 %s != desired %s", desired.ComponentID, got, strings.ToLower(desired.SHA256))
	}
	// Floor equality: refuse re-applying the exact prior artifact (replay / no-op).
	if desired.PreviousSHA256 != "" && strings.EqualFold(desired.SHA256, desired.PreviousSHA256) {
		return fmt.Errorf("binary-replace verify %s: desired sha256 equals previousSha256 (replay refused)", desired.ComponentID)
	}
	return nil
}

// Apply retains the exact prior binary, atomically replaces the executable, and
// restarts once. It NEVER prunes the retained prior (that is the rollback floor
// until the controller's terminal commit). On restart failure it restores the
// prior binary in place AND returns a usable Rollback (never nil).
func (a *binaryReplaceAdapter) Apply(ctx context.Context, staged Staged, desired ComponentRelease, install ComponentInstall) (Rollback, error) {
	target := install.InstallRoot
	backupDir := prevBackupDir(target)
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return nil, fmt.Errorf("binary-replace apply %s: backup dir: %w", desired.ComponentID, err)
	}

	// 1. Retain the exact prior binary (if the target exists) for rollback.
	var backupPath string
	if _, statErr := os.Stat(target); statErr == nil {
		prevSHA, herr := sha256File(target)
		if herr != nil {
			return nil, fmt.Errorf("binary-replace apply %s: hash prior: %w", desired.ComponentID, herr)
		}
		backupPath = filepath.Join(backupDir, filepath.Base(target)+"."+shortSHA(prevSHA))
		if err := atomicCopy(target, backupPath, 0o755); err != nil {
			return nil, fmt.Errorf("binary-replace apply %s: retain prior: %w", desired.ComponentID, err)
		}
	}

	// rollback restores the EXACT prior binary and restarts. Built before restart so
	// every failure path can hand it back.
	rollback := func(rbctx context.Context) error {
		if backupPath == "" {
			_ = os.Remove(target) // fresh install: remove new + stop
			return stop(rbctx, install)
		}
		if err := atomicCopy(backupPath, target, 0o755); err != nil {
			return fmt.Errorf("binary-replace rollback %s: restore prior: %w", desired.ComponentID, err)
		}
		return restart(rbctx, install)
	}

	// 2. Atomic replace: staged bytes -> fresh temp on the SAME dir/fs -> rename.
	if err := atomicCopy(staged.Path, target, 0o755); err != nil {
		return rollback, fmt.Errorf("binary-replace apply %s: atomic replace: %w", desired.ComponentID, err)
	}

	// 3. Restart exactly once. On failure, restore the prior binary in place and
	//    hand back the usable rollback.
	if err := restart(ctx, install); err != nil {
		if backupPath != "" {
			_ = atomicCopy(backupPath, target, 0o755)
		} else {
			_ = os.Remove(target)
		}
		return rollback, fmt.Errorf("binary-replace apply %s: restart %s: %w", desired.ComponentID, install.ServiceUnit, err)
	}
	return rollback, nil
}

// Probe proves the component is really SERVING: it runs the registry HealthCommand
// (exit 0 == healthy) and, if SelfReportURL is set, requires a STRUCTURED
// self-report field whose value EXACTLY equals the applied hash.
func (a *binaryReplaceAdapter) Probe(ctx context.Context, desired ComponentRelease, install ComponentInstall) error {
	if len(install.HealthCommand) == 0 {
		return fmt.Errorf("binary-replace probe %s: empty healthCommand (registry invariant violated)", desired.ComponentID)
	}
	if err := runArgv(ctx, install.HealthCommand); err != nil {
		return fmt.Errorf("binary-replace probe %s: health command failed: %w", desired.ComponentID, err)
	}
	if install.SelfReportURL != "" {
		body, err := a.probeGet(ctx, install.SelfReportURL)
		if err != nil {
			return fmt.Errorf("binary-replace probe %s: self-report fetch: %w", desired.ComponentID, err)
		}
		defer body.Close()
		raw, err := io.ReadAll(io.LimitReader(body, maxSelfReportBytes+1))
		if err != nil {
			return fmt.Errorf("binary-replace probe %s: read self-report: %w", desired.ComponentID, err)
		}
		// An oversized body is REFUSED, never truncated — a valid prefix must not
		// be able to hide trailing bytes that a lenient parser would honour.
		if len(raw) > maxSelfReportBytes {
			return fmt.Errorf("binary-replace probe %s: self-report exceeds %d bytes", desired.ComponentID, maxSelfReportBytes)
		}
		if !selfReportBindsHash(raw, desired.SHA256) {
			return fmt.Errorf("binary-replace probe %s: self-report does not bind the applied hash %s in a structured field", desired.ComponentID, strings.ToLower(desired.SHA256))
		}
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// selfReportHashField is the ONE structured field a self-report must carry whose
// value is the running artifact's sha256. Binding a specific field (not "any
// string field that happens to equal the hash") prevents a status message or an
// unrelated field from laundering the desired hash.
const selfReportHashField = "artifactSha256"

// maxSelfReportBytes bounds the probe's self-report read. An oversized body is
// refused (never truncated) so a valid prefix cannot hide trailing bytes.
const maxSelfReportBytes = 1 << 20

// selfReportBindsHash requires the self-report to be a single JSON object whose
// EXACT `artifactSha256` field equals the applied hash. It refuses: a hash in any
// other field (laundering), a case-shadowed duplicate of the field (a decoy
// `ArtifactSha256` that encoding/json would fold onto the same struct field), and
// trailing data after the object.
func selfReportBindsHash(raw []byte, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" {
		return false
	}
	if selfReportHasFoldedDuplicateKeys(raw) {
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil {
		return false
	}
	if dec.More() {
		return false // trailing data after the object
	}
	rawVal, ok := obj[selfReportHashField]
	if !ok {
		return false // the hash is not in the exact named field
	}
	var s string
	if err := json.Unmarshal(rawVal, &s); err != nil {
		return false
	}
	return strings.ToLower(strings.TrimSpace(s)) == want
}

// selfReportHasFoldedDuplicateKeys reports whether any object in the document has
// two keys equal under case folding (strings.EqualFold) — the ambiguity a
// case-insensitive struct decode would resolve order-dependently.
func selfReportHasFoldedDuplicateKeys(raw []byte) bool {
	return scanFoldedDupKeys(json.NewDecoder(strings.NewReader(string(raw)))) != nil
}

func scanFoldedDupKeys(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		var keys []string
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := kt.(string)
			for _, k := range keys {
				if strings.EqualFold(k, key) {
					return fmt.Errorf("case-shadowed duplicate key %q vs %q", k, key)
				}
			}
			keys = append(keys, key)
			if err := scanFoldedDupKeys(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := scanFoldedDupKeys(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	}
	return nil
}

func defaultBundleGet(ctx context.Context, url string) (io.ReadCloser, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, fmt.Errorf("bundle url must be https, got %q", url)
	}
	return noRedirectGet(ctx, url)
}

func defaultLoopbackGet(ctx context.Context, url string) (io.ReadCloser, error) {
	u, err := neturl.Parse(url)
	if err != nil {
		return nil, err
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
	default:
		return nil, fmt.Errorf("self-report must be loopback, got host %q", u.Hostname())
	}
	return noRedirectGet(ctx, url)
}

func noRedirectGet(ctx context.Context, url string) (io.ReadCloser, error) {
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not allowed")
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return resp.Body, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func shortSHA(s string) string {
	if len(s) >= 12 {
		return s[:12]
	}
	return s
}

// atomicCopy writes src to a FRESH unique temp beside dst, fsyncs it, then renames
// it into place so a crash cannot leave a torn executable. The temp is created with
// os.CreateTemp (fresh random name — no preexisting path, no symlink to follow).
func atomicCopy(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".rrs-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, dst)
}

func restart(ctx context.Context, install ComponentInstall) error {
	if len(install.RestartCommand) > 0 {
		return runArgv(ctx, install.RestartCommand)
	}
	return runArgv(ctx, []string{"systemctl", "restart", install.ServiceUnit})
}

func stop(ctx context.Context, install ComponentInstall) error {
	return runArgv(ctx, []string{"systemctl", "stop", install.ServiceUnit})
}

func runArgv(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return errors.New("empty argv")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// PruneSupersededBackups deletes retained prior binaries older than the current
// rollback floor, keeping `keep` of them. The controller calls this AFTER a
// generation's terminal commit — never inside Apply, where the retained prior is
// the live rollback floor.
func PruneSupersededBackups(installRoot, keepBase string, keep int) {
	if keep < 0 {
		keep = 0
	}
	dir := prevBackupDir(installRoot)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type fi struct {
		path string
		mod  int64
	}
	var backups []fi
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), keepBase+".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, fi{filepath.Join(dir, e.Name()), info.ModTime().UnixNano()})
	}
	// newest first
	for i := 0; i < len(backups); i++ {
		for j := i + 1; j < len(backups); j++ {
			if backups[j].mod > backups[i].mod {
				backups[i], backups[j] = backups[j], backups[i]
			}
		}
	}
	for i := keep; i < len(backups); i++ {
		_ = os.Remove(backups[i].path)
	}
}

// compareVersions is a correct (non-lexical, non-trailing-only) ordering helper for
// callers that need it: it understands the mint form gen-<ordinal>-<sha8> (compares
// the ordinal numerically) and dotted semver (field-wise numeric). It is NOT used
// by Verify — version ordering authority is the controller's generation/mint
// semantics. Returns -1 / 0 / 1.
func compareVersions(a, b string) int {
	if oa, ok := genOrdinal(a); ok {
		if ob, ok2 := genOrdinal(b); ok2 {
			return cmpInt(oa, ob)
		}
	}
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, aerr := strconv.Atoi(as[i])
		bi, berr := strconv.Atoi(bs[i])
		if aerr == nil && berr == nil {
			if ai != bi {
				return cmpInt(ai, bi)
			}
			continue
		}
		if c := strings.Compare(as[i], bs[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(as), len(bs))
}

// genOrdinal extracts N from "gen-N-<sha8>" (or "gen-N"), reporting ok=false for a
// non-generation form.
func genOrdinal(s string) (int, bool) {
	if !strings.HasPrefix(s, "gen-") {
		return 0, false
	}
	rest := s[len("gen-"):]
	if i := strings.IndexByte(rest, '-'); i >= 0 {
		rest = rest[:i]
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}
	return n, true
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
