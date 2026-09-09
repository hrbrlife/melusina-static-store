// Command prepare-first-bazaar prepares the one authorized FIRST Bazaar Control
// source selection. It has no signer, Store write, proposal or install action.
// General mel-release source/branch rules are deliberately unchanged.
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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/apphash"
	"github.com/hrbrlife/melusina-store-sidecar/internal/runtimecontract"
)

const (
	firstPolicy     = "melusina-first-bazaar-original-main-v1"
	firstID         = "zukk3pav049f7wr4a12x76ytpgmsyt3136sz1hev4zy8g33f1310"
	firstCommit     = "161b99160c5f47dcdacb8b68b57bced0d6b88c95"
	firstTree       = "7723513927f32814e19954417020f8d3ea35768c"
	firstRepository = "https://github.com/melusina-os/bazaar-control-pearl"
	firstSHA        = "1228db1458c0f3e2955031b257a2347708687f310fd421e9da40cdcea73a2f34"
	firstSize       = 14027720
)

type sourceSelection struct {
	Schema           string `json:"schema"`
	Kind             string `json:"kind"`
	AppID            string `json:"appId"`
	Repository       string `json:"repository"`
	Branch           string `json:"branch"`
	Commit           string `json:"commit"`
	Tree             string `json:"tree"`
	Version          string `json:"version"`
	SPKSHA256        string `json:"spkSha256"`
	SPKBytes         int    `json:"spkBytes"`
	RequiredApproval string `json:"requiredApproval"`
}

func selection() sourceSelection {
	return sourceSelection{Schema: firstPolicy, Kind: "initial-onboarding", AppID: firstID, Repository: firstRepository, Branch: "main", Commit: firstCommit, Tree: firstTree, Version: "0.1.0", SPKSHA256: firstSHA, SPKBytes: firstSize, RequiredApproval: "original Core 3-of-4 executes exact ReleaseEntry before original Store publication"}
}
func selectedMain(heads, origin, tree string) error {
	if strings.TrimSuffix(strings.TrimSpace(origin), ".git") != firstRepository {
		return errors.New("original first Bazaar source repository differs")
	}
	lines := strings.Fields(heads)
	if len(lines) != 2 || lines[0] != firstCommit || lines[1] != "refs/heads/main" {
		return errors.New("only the original existing main at161b991 with no unreviewed source refs is selected")
	}
	if strings.TrimSpace(tree) != firstTree {
		return errors.New("original selected source tree differs")
	}
	return nil
}
func git(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/git", append([]string{"--no-replace-objects"}, args...)...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0"}
	raw, e := cmd.CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("original source observation: %s", strings.TrimSpace(string(raw)))
	}
	if len(raw) > 1<<20 {
		return "", errors.New("source observation too large")
	}
	return string(raw), nil
}

func authenticatedSourceRead(ctx context.Context, home string) (*exec.Cmd, error) {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || strings.TrimSpace(home) != home {
		return nil, errors.New("original source credentials require a canonical existing user home")
	}
	// Only this fixed remote read uses the operator's existing Git credential
	// configuration. It runs outside a repository and takes no alternate remote,
	// branch, credential, hook, protocol, refspec or command from the request.
	// Local object/remote metadata reads above retain their sterile configuration.
	cmd := exec.CommandContext(ctx, "/usr/bin/git", "--no-replace-objects", "ls-remote", "--heads", firstRepository+".git")
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0"}
	return cmd, nil
}

func advertisedSource(ctx context.Context) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	cmd, err := authenticatedSourceRead(ctx, home)
	if err != nil {
		return "", err
	}
	raw, err := cmd.Output()
	if err != nil {
		// Credential-helper diagnostics are never copied into public preparation
		// output; no access token or private configuration is exported.
		return "", fmt.Errorf("original authenticated source advertisement refused: %w", err)
	}
	if len(raw) > 1<<20 {
		return "", errors.New("original source advertisement exceeds its bound")
	}
	return string(raw), nil
}
func observeSource(ctx context.Context, repo string) error {
	if !filepath.IsAbs(repo) {
		return errors.New("absolute original source repository required")
	}
	origin, e := git(ctx, repo, "remote", "get-url", "origin")
	if e != nil {
		return e
	}
	tree, e := git(ctx, repo, "rev-parse", firstCommit+"^{tree}")
	if e != nil {
		return e
	} // Git objects are selected; dirty/untracked work is never built or changed.
	heads, e := advertisedSource(ctx)
	if e != nil {
		return e
	}
	return selectedMain(heads, origin, tree)
}
func digest(raw []byte) string { x := sha256.Sum256(raw); return hex.EncodeToString(x[:]) }
func metadata() []byte {
	v := map[string]any{"appId": firstID, "name": "Bazaar Control", "version": "0.1.0", "marketingVersion": "0.1.0", "versionNumber": 1, "packageId": firstSHA[:32], "sha256": firstSHA, "shortDescription": "Governed Bazaar releases", "description": "An operator release desk for reviewing and retaining exact Store release evidence. Initial setup remains disconnected until an actual Store Link capability is selected. The grain creates and preserves its own command identity for later governed enrollment.", "codeLink": firstRepository, "createdAt": int64(1788935169000), "updatedAt": int64(1788935169000), "categories": []string{"Developer Tools"}, "installation": map[string]string{"audience": "operator", "install_mode": "owner-only", "pearl_role": "workflow", "client_access": "none", "admin_surface": "same-pearl"}, "sourceAdmission": selection()}
	raw, _ := json.MarshalIndent(v, "", "  ")
	return append(raw, '\n')
}
func contract(hash string) runtimecontract.Contract {
	return runtimecontract.Contract{SchemaURL: runtimecontract.SchemaURL, Schema: runtimecontract.Schema, App: runtimecontract.App{AppID: firstID, Version: "0.1.0", SPKSHA256: firstSHA, AppHash: hash}, Sidecars: []runtimecontract.Sidecar{}, LaunchProbe: runtimecontract.VisibleProbe{Kind: "visible-ui", Steps: []runtimecontract.ProbeStep{{Action: "The original R32 owner installs Bazaar Control from its governed original Store listing and creates a release desk pearl.", ExpectedResult: "The original app identity opens at version1 and displays the release desk with Store disconnected."}, {Action: "Open the native enrollment page and export the public command identity from this actual grain.", ExpectedResult: "The actual grain's durable public command key is exported; reload preserves the same key. No release is approved or published."}}, ExpectedResult: "The original owner can open the first release desk and export its actual durable command identity. Publication remains unavailable until governed Store enrollment and an authenticated Store Link are complete."}, Fixtures: []runtimecontract.Fixture{{Name: "first operator bootstrap", Purpose: "Establish the actual first-grain identity for original governed enrollment", Setup: "Use the existing original R32 owner account; select no substitute Store Link and submit no release."}}, Cleanup: runtimecontract.Cleanup{Steps: []string{"Retain the original first grain and public enrollment evidence for governed setup. Close the test view; do not delete the durable command identity."}}}
}
func readPackage(name string) ([]byte, error) {
	fd, e := syscall.Open(name, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	ss, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Size() != firstSize || ss.Uid != uint32(os.Getuid()) || st.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("first package must be exact protected original custody bytes")
	}
	raw, e := io.ReadAll(f)
	if e != nil {
		return nil, e
	}
	if digest(raw) != firstSHA {
		return nil, errors.New("package differs from the two original reproduced and SPK-verified packs")
	}
	return raw, nil
}
func writeNew(dir, name string, raw []byte) error {
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if e != nil {
		return e
	}
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func prepare(repo, spk, out string) error {
	if !filepath.IsAbs(spk) || !filepath.IsAbs(out) {
		return errors.New("absolute original package and new output directory required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if e := observeSource(ctx, repo); e != nil {
		return e
	}
	body, e := readPackage(spk)
	if e != nil {
		return e
	}
	meta := metadata()
	hash, e := apphash.Canonical(bytes.NewReader(body), meta)
	if e != nil {
		return e
	}
	appHash := hash
	c := contract(appHash)
	runtimeRaw, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	runtimeRaw = append(runtimeRaw, '\n')
	if _, e = runtimecontract.Validate(runtimeRaw, runtimecontract.Binding{SPK: body, Metadata: meta, AppHash: appHash, Version: "0.1.0", ReleaseContractSHA256: digest(runtimeRaw), ReleaseContractSchema: runtimecontract.Schema}); e != nil {
		return e
	}
	if e = os.Mkdir(out, 0o700); e != nil {
		return fmt.Errorf("new private output required: %w", e)
	}
	if e = os.Mkdir(filepath.Join(out, "app"), 0o700); e != nil {
		return e
	}
	for name, raw := range map[string][]byte{"app.spk": body, "metadata.json": meta} {
		if e = writeNew(filepath.Join(out, "app"), name, raw); e != nil {
			return e
		}
	}
	if e = writeNew(out, "RUNTIME-CONTRACT.json", runtimeRaw); e != nil {
		return e
	}
	record := map[string]any{"schema": "melusina-first-bazaar-prepared-source-v1", "sourceSelection": selection(), "observedAt": time.Now().UTC(), "appHash": appHash, "metadataSHA256": digest(meta), "runtimeContractSHA256": digest(runtimeRaw), "catalogSlot": map[string]string{"developer": "melusina-os", "repo": "bazaar-control-pearl", "slug": "bazaar-control"}, "nextAuthority": "Original author prepares the exact payload; original Store privately stages and signs the exact candidate receipt; original Core3-of-4 executes ReleaseEntry; original Store publishes; root installs only from Store.", "authenticatedHistoricalBaseline": false, "baselineAfterFirstPublication": map[string]any{"branch": "main", "commit": firstCommit, "requires": "actual original Core execution and original Store signed catalog pointer"}, "publicationPerformed": false, "proposalCreated": false, "installed": false}
	raw, _ := json.MarshalIndent(record, "", "  ")
	if e = writeNew(out, "source-selection.json", append(raw, '\n')); e != nil {
		return e
	}
	for _, dir := range []string{filepath.Join(out, "app"), out, filepath.Dir(out)} {
		f, e := os.Open(dir)
		if e != nil {
			return e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return e
		}
	}
	fmt.Printf("PREPARED_ONLY first Bazaar source and exact package: appHash=%s metadataSHA256=%s runtimeContractSHA256=%s\n", appHash, digest(meta), digest(runtimeRaw))
	return nil
}
func main() {
	repo := flag.String("source", "", "original Bazaar repository (read-only)")
	spk := flag.String("spk", "", "original protected first package")
	out := flag.String("out", "", "new private preparation directory")
	verifyAuthor := flag.String("verify-author-dir", "", "verify the original author state and write a new provisional release in an existing private preparation directory; no network or signer")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected arguments")
		os.Exit(2)
	}
	if *verifyAuthor != "" {
		if *repo != "" || *spk != "" || *out != "" {
			fmt.Fprintln(os.Stderr, "author verification cannot be combined with source preparation options")
			os.Exit(2)
		}
		if e := verifyFirstAuthor(*verifyAuthor); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if e := prepare(*repo, *spk, *out); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
