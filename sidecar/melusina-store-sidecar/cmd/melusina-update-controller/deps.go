package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	"github.com/hrbrlife/melusina-store-sidecar/internal/hostupdate"
)

const (
	maxGenerationBytes  = 4 << 20
	maxReleaseInfoBytes = 64 << 10
)

// buildPollDeps wires the REAL production PollDeps around the poller library. Every
// collaborator is a real host/chain/network implementation; the poller derives
// BeforeMutation (policy+chain re-read) and RuntimeGate itself. The trust anchors
// (operator key, store id, origin, chain pins, allowlist) all come from the
// root-owned config, never the fetched document.
func buildPollDeps(cfg ControllerConfig, expectedUID uint32) (hostupdate.PollDeps, error) {
	opKey, err := cfg.operatorKey()
	if err != nil {
		return hostupdate.PollDeps{}, err
	}
	registry, err := componentrelease.LoadComponentRegistry(cfg.ComponentRegistryPath)
	if err != nil {
		return hostupdate.PollDeps{}, fmt.Errorf("load component registry allowlist: %w", err)
	}
	wal, err := hostupdate.NewWALStore(cfg.StateDir)
	if err != nil {
		return hostupdate.PollDeps{}, fmt.Errorf("open WAL store: %w", err)
	}
	chain, err := newSolanaChainGate(cfg)
	if err != nil {
		return hostupdate.PollDeps{}, fmt.Errorf("chain gate: %w", err)
	}

	apply := hostupdate.ApplyDeps{
		Registry:               registry,
		WAL:                    wal,
		Runner:                 hostupdate.DefaultRunner(),
		StagingRoot:            cfg.stagingRoot(),
		RuntimeMarkerBackupDir: filepath.Join(cfg.StateDir, "runtime-marker-backups"),
		Observe: func(id string) string {
			ci, ok := registry.Components[id]
			if !ok {
				return ""
			}
			return observeFor(ci)
		},
		ChainGate: chain.gate,
		Policy:    cfg.policy(),
	}

	return hostupdate.PollDeps{
		State:           newFileControllerStateStore(cfg.StateDir, expectedUID),
		LoadPolicy:      func(context.Context) (hostupdate.UpdatePolicy, error) { return cfg.policy(), nil },
		FetchVerified:   newFetchVerified(cfg, opKey),
		Notify:          newNotifier(cfg.notifyPath()),
		Now:             func() int64 { return time.Now().Unix() },
		Apply:           apply,
		RuntimeObserver: newRuntimeObserver(),
	}, nil
}

// newFetchVerified performs an origin-pinned, no-redirect HTTP GET of the signed
// generation and verifies it against the pinned operator key + destination store id,
// then pins bundleOrigin. RawSHA256 is the sha256 of the exact fetched bytes (the
// poller's anti-equivocation anchor).
func newFetchVerified(cfg ControllerConfig, opKey ed25519.PublicKey) func(context.Context) (hostupdate.VerifiedGeneration, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect refused: the generation URL is origin-pinned")
		},
	}
	return func(ctx context.Context) (hostupdate.VerifiedGeneration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.StoreGenerationURL, nil)
		if err != nil {
			return hostupdate.VerifiedGeneration{}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return hostupdate.VerifiedGeneration{}, fmt.Errorf("fetch generation: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return hostupdate.VerifiedGeneration{}, fmt.Errorf("fetch generation: HTTP %d", resp.StatusCode)
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxGenerationBytes+1))
		if err != nil {
			return hostupdate.VerifiedGeneration{}, err
		}
		if int64(len(raw)) > maxGenerationBytes {
			return hostupdate.VerifiedGeneration{}, errors.New("generation document exceeds bounded read limit")
		}
		var doc componentrelease.DesiredGeneration
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil {
			return hostupdate.VerifiedGeneration{}, fmt.Errorf("decode generation: %w", err)
		}
		if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
			return hostupdate.VerifiedGeneration{}, errors.New("generation document has trailing data")
		}
		if err := componentrelease.Verify(opKey, cfg.ExpectedStoreID, doc); err != nil {
			return hostupdate.VerifiedGeneration{}, fmt.Errorf("verify generation: %w", err)
		}
		if doc.BundleOrigin != cfg.BundleOrigin {
			return hostupdate.VerifiedGeneration{}, fmt.Errorf("generation bundleOrigin %q != pinned %q", doc.BundleOrigin, cfg.BundleOrigin)
		}
		sum := sha256.Sum256(raw)
		return hostupdate.VerifiedGeneration{Doc: doc, RawSHA256: hex.EncodeToString(sum[:])}, nil
	}
}

// releaseInfoReport is the component's structured /release-info self-report. The
// controller binds it to the desired tuple in the poller's RuntimeGate.
type releaseInfoReport struct {
	Schema         string `json:"schema"`
	ComponentID    string `json:"componentId"`
	GenerationID   uint64 `json:"generationId"`
	Version        string `json:"version"`
	PID            int    `json:"pid"`
	ArtifactSHA256 string `json:"artifactSha256"`
}

func newRuntimeObserver() func(context.Context, componentrelease.ComponentRelease, componentrelease.ComponentInstall) (hostupdate.RuntimeEvidence, error) {
	return func(ctx context.Context, c componentrelease.ComponentRelease, install componentrelease.ComponentInstall) (hostupdate.RuntimeEvidence, error) {
		if strings.TrimSpace(install.SelfReportURL) == "" {
			return hostupdate.RuntimeEvidence{}, fmt.Errorf("component %s has no selfReportUrl to bind the running build", c.ComponentID)
		}
		body, err := componentrelease.FetchSelfReport(ctx, install)
		if err != nil {
			return hostupdate.RuntimeEvidence{}, fmt.Errorf("fetch %s release-info: %w", c.ComponentID, err)
		}
		defer body.Close()
		raw, err := io.ReadAll(io.LimitReader(body, maxReleaseInfoBytes+1))
		if err != nil {
			return hostupdate.RuntimeEvidence{}, err
		}
		if int64(len(raw)) > maxReleaseInfoBytes {
			return hostupdate.RuntimeEvidence{}, errors.New("release-info exceeds bounded read limit")
		}
		r, err := decodeReleaseInfo(raw)
		if err != nil {
			return hostupdate.RuntimeEvidence{}, fmt.Errorf("decode %s release-info: %w", c.ComponentID, err)
		}
		return hostupdate.RuntimeEvidence{
			Schema:         r.Schema,
			ComponentID:    r.ComponentID,
			GenerationID:   r.GenerationID,
			Version:        r.Version,
			PID:            r.PID,
			ArtifactSHA256: r.ArtifactSHA256,
		}, nil
	}
}

// decodeReleaseInfo accepts exactly one object with the six canonical runtime
// fields. json.Decoder's DisallowUnknownFields is necessary but insufficient:
// it accepts duplicate keys (last one wins) and does not itself prove EOF.
// Runtime identity cannot be order-dependent, so reject folded duplicates and
// trailing JSON before decoding the typed report.
func decodeReleaseInfo(raw []byte) (releaseInfoReport, error) {
	if err := validateReleaseInfoObject(raw); err != nil {
		return releaseInfoReport{}, err
	}
	var r releaseInfoReport
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return releaseInfoReport{}, err
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return releaseInfoReport{}, errors.New("release-info has trailing data")
	}
	return r, nil
}

func validateReleaseInfoObject(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return errors.New("release-info must be one JSON object")
	}
	allowed := map[string]struct{}{
		"schema": {}, "componentId": {}, "generationId": {},
		"version": {}, "pid": {}, "artifactSha256": {},
	}
	seen := map[string]string{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("release-info object key is not a string")
		}
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("release-info has unknown field %q", key)
		}
		folded := strings.ToLower(key)
		if prior, exists := seen[folded]; exists {
			return fmt.Errorf("release-info has duplicate or case-shadowed field %q vs %q", prior, key)
		}
		seen[folded] = key
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
	}
	if token, err := dec.Token(); err != nil {
		return err
	} else if delim, ok := token.(json.Delim); !ok || delim != '}' {
		return errors.New("release-info object did not terminate")
	}
	if len(seen) != len(allowed) {
		return errors.New("release-info is missing one or more required fields")
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("release-info has trailing data")
	}
	return nil
}

// observeFor returns the currently-installed artifact hash for the delta check that
// lets ApplyGeneration skip an already-installed component. For binary-replace,
// InstallRoot is the executable file. Any error yields "" — an unknown delta safely
// means "do not skip", never a false skip.
func observeFor(install componentrelease.ComponentInstall) string {
	info, err := os.Lstat(install.InstallRoot)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	f, err := os.Open(install.InstallRoot)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func newNotifier(path string) func(context.Context, hostupdate.VerifiedGeneration) error {
	return func(_ context.Context, vg hostupdate.VerifiedGeneration) error {
		payload := struct {
			Schema         string `json:"schema"`
			GenerationID   uint64 `json:"generationId"`
			GenerationHash string `json:"generationHash"`
			RawSHA256      string `json:"rawSha256"`
			StoreID        string `json:"storeId"`
			Channel        string `json:"channel"`
			Components     int    `json:"components"`
		}{
			Schema:         "melusina-pending-update-notification-v1",
			GenerationID:   vg.Doc.GenerationID,
			GenerationHash: vg.Doc.GenerationHash,
			RawSHA256:      vg.RawSHA256,
			StoreID:        vg.Doc.StoreID,
			Channel:        vg.Doc.Channel,
			Components:     len(vg.Doc.Components),
		}
		raw, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		return atomicWriteFile(path, append(raw, '\n'))
	}
}

func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	cleanup = false
	return fsyncDir(dir)
}
