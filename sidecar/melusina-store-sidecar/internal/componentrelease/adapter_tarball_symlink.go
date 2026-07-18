package componentrelease

// tarball-symlink-swap is the shell adapter. Its desired hash is the signed
// tar.xz archive hash, not the hash of an executable within that archive. Each
// extracted generation therefore carries install-local metadata binding the
// selected generation directory to that verified archive.

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ulikunitz/xz"
)

const (
	tarballMetadataName    = ".rrs-release-artifact.json"
	tarballMetadataSchema  = "melusina-tarball-release-artifact-v1"
	maxTarballEntries      = 100000
	maxTarballExtractBytes = int64(8 << 30)
)

type tarballReleaseMetadata struct {
	Schema       string `json:"schema"`
	ArtifactSHA  string `json:"artifactSha256"`
	ArtifactSize int64  `json:"artifactSizeBytes"`
	Version      string `json:"version"`
}

type tarballSymlinkAdapter struct {
	stageGet HTTPGetter
	probeGet HTTPGetter
}

// NewTarballSymlinkAdapter constructs the built-in shell bundle adapter. A nil
// getter retains the same split origin/loopback fetch policy as binary-replace.
func NewTarballSymlinkAdapter(get HTTPGetter) Adapter {
	if get == nil {
		return NewTarballSymlinkAdapterWithFetchers(defaultBundleGet, defaultLoopbackGet)
	}
	return NewTarballSymlinkAdapterWithFetchers(get, get)
}

func NewTarballSymlinkAdapterWithFetchers(stageGet, probeGet HTTPGetter) Adapter {
	return &tarballSymlinkAdapter{stageGet: stageGet, probeGet: probeGet}
}

func (*tarballSymlinkAdapter) Kind() string { return ApplyTarballSymlinkSwap }

func (a *tarballSymlinkAdapter) Stage(ctx context.Context, desired ComponentRelease, install ComponentInstall, workDir string) (Staged, error) {
	if desired.SizeBytes <= 0 {
		return Staged{}, fmt.Errorf("tarball stage %s: desired sizeBytes must be positive", desired.ComponentID)
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return Staged{}, fmt.Errorf("tarball stage %s: workdir: %w", desired.ComponentID, err)
	}
	dst := filepath.Join(workDir, desired.ComponentID+".tar.xz")
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return Staged{}, fmt.Errorf("tarball stage %s: open fresh staged archive: %w", desired.ComponentID, err)
	}
	body, err := a.stageGet(ctx, desired.BundleURL)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(dst)
		return Staged{}, fmt.Errorf("tarball stage %s: fetch %s: %w", desired.ComponentID, desired.BundleURL, err)
	}
	defer body.Close()
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, desired.SizeBytes+1))
	if closeErr := f.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = os.Remove(dst)
		return Staged{}, fmt.Errorf("tarball stage %s: download: %w", desired.ComponentID, copyErr)
	}
	if n != desired.SizeBytes {
		_ = os.Remove(dst)
		return Staged{}, fmt.Errorf("tarball stage %s: size mismatch (got %d, want %d)", desired.ComponentID, n, desired.SizeBytes)
	}
	return Staged{ComponentID: desired.ComponentID, Path: dst, SHA256: hex.EncodeToString(h.Sum(nil)), SizeBytes: n}, nil
}

func (a *tarballSymlinkAdapter) Verify(_ context.Context, staged Staged, desired ComponentRelease, install ComponentInstall) error {
	if err := validateTarballInstall(install); err != nil {
		return fmt.Errorf("tarball verify %s: %w", desired.ComponentID, err)
	}
	if staged.SizeBytes != desired.SizeBytes || !strings.EqualFold(staged.SHA256, desired.SHA256) {
		return fmt.Errorf("tarball verify %s: staged archive does not match signed size/hash", desired.ComponentID)
	}
	got, size, err := measureRegularFileNoFollow(staged.Path)
	if err != nil {
		return fmt.Errorf("tarball verify %s: re-hash staged archive: %w", desired.ComponentID, err)
	}
	if size != desired.SizeBytes || !strings.EqualFold(got, desired.SHA256) {
		return fmt.Errorf("tarball verify %s: staged archive changed after measurement", desired.ComponentID)
	}
	if desired.PreviousSHA256 != "" && strings.EqualFold(desired.SHA256, desired.PreviousSHA256) {
		return fmt.Errorf("tarball verify %s: desired sha256 equals previousSha256 (replay refused)", desired.ComponentID)
	}
	if desired.PreviousSHA256 != "" {
		prior, err := TarballCurrentTarget(install)
		if err != nil {
			return fmt.Errorf("tarball verify %s: resolve rollback floor: %w", desired.ComponentID, err)
		}
		meta, err := readTarballMetadata(prior)
		if err != nil {
			return fmt.Errorf("tarball verify %s: read rollback floor: %w", desired.ComponentID, err)
		}
		if !strings.EqualFold(meta.ArtifactSHA, desired.PreviousSHA256) {
			return fmt.Errorf("tarball verify %s: installed archive sha256 %s != signed previousSha256 %s", desired.ComponentID, meta.ArtifactSHA, strings.ToLower(desired.PreviousSHA256))
		}
	}
	return nil
}

func (a *tarballSymlinkAdapter) Apply(ctx context.Context, staged Staged, desired ComponentRelease, install ComponentInstall) (Rollback, error) {
	if err := validateTarballInstall(install); err != nil {
		return nil, fmt.Errorf("tarball apply %s: %w", desired.ComponentID, err)
	}
	got, size, err := measureRegularFileNoFollow(staged.Path)
	if err != nil {
		return nil, fmt.Errorf("tarball apply %s: revalidate staged archive: %w", desired.ComponentID, err)
	}
	if size != desired.SizeBytes || !strings.EqualFold(got, desired.SHA256) {
		return nil, fmt.Errorf("tarball apply %s: staged archive changed after Verify", desired.ComponentID)
	}
	oldTarget, hadPrior, err := currentTarballTargetIfAny(install)
	if err != nil {
		return nil, fmt.Errorf("tarball apply %s: resolve current target: %w", desired.ComponentID, err)
	}
	if hadPrior {
		meta, err := readTarballMetadata(oldTarget)
		if err != nil {
			return nil, fmt.Errorf("tarball apply %s: read current metadata: %w", desired.ComponentID, err)
		}
		if desired.PreviousSHA256 == "" || !strings.EqualFold(meta.ArtifactSHA, desired.PreviousSHA256) {
			return nil, fmt.Errorf("tarball apply %s: current archive sha256 %s does not equal signed previousSha256", desired.ComponentID, meta.ArtifactSHA)
		}
	} else if desired.PreviousSHA256 != "" {
		return nil, fmt.Errorf("tarball apply %s: signed previousSha256 supplied but current symlink is absent", desired.ComponentID)
	}
	genDir := filepath.Join(install.InstallRoot, "release-"+shortSHA(strings.ToLower(desired.SHA256)))
	if !pathWithin(install.InstallRoot, genDir) {
		return nil, fmt.Errorf("tarball apply %s: generated path escapes installRoot", desired.ComponentID)
	}
	if _, err := os.Lstat(genDir); err == nil {
		return nil, fmt.Errorf("tarball apply %s: generation directory already exists: %s", desired.ComponentID, genDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("tarball apply %s: inspect generation dir: %w", desired.ComponentID, err)
	}
	if err := extractTarXZNoFollow(staged.Path, genDir); err != nil {
		_ = os.RemoveAll(genDir)
		return nil, fmt.Errorf("tarball apply %s: safe extraction: %w", desired.ComponentID, err)
	}
	meta := tarballReleaseMetadata{Schema: tarballMetadataSchema, ArtifactSHA: strings.ToLower(desired.SHA256), ArtifactSize: desired.SizeBytes, Version: desired.Version}
	if err := writeTarballMetadata(genDir, meta); err != nil {
		_ = os.RemoveAll(genDir)
		return nil, fmt.Errorf("tarball apply %s: write release metadata: %w", desired.ComponentID, err)
	}
	rollback := func(rbctx context.Context) error {
		if !hadPrior {
			if err := removeCurrentIfPointsTo(install, genDir); err != nil {
				return fmt.Errorf("tarball rollback %s: remove fresh current: %w", desired.ComponentID, err)
			}
			return stop(rbctx, install)
		}
		if err := validateTarballTarget(install, oldTarget, desired.PreviousSHA256); err != nil {
			return fmt.Errorf("tarball rollback %s: retained prior invalid: %w", desired.ComponentID, err)
		}
		if err := atomicRepointCurrent(install, oldTarget); err != nil {
			return fmt.Errorf("tarball rollback %s: repoint prior: %w", desired.ComponentID, err)
		}
		return restart(rbctx, install)
	}
	if err := atomicRepointCurrent(install, genDir); err != nil {
		return rollback, fmt.Errorf("tarball apply %s: switch current symlink: %w", desired.ComponentID, err)
	}
	if err := restart(ctx, install); err != nil {
		_ = rollback(ctx)
		return rollback, fmt.Errorf("tarball apply %s: restart %s: %w", desired.ComponentID, install.ServiceUnit, err)
	}
	return rollback, nil
}

func (a *tarballSymlinkAdapter) Probe(ctx context.Context, desired ComponentRelease, install ComponentInstall) error {
	return (&binaryReplaceAdapter{probeGet: a.probeGet}).Probe(ctx, desired, install)
}

// TarballCurrentTarget resolves the selected generation only if the symlink and
// target remain inside the install-local root and carry valid release metadata.
func TarballCurrentTarget(install ComponentInstall) (string, error) {
	if err := validateTarballInstall(install); err != nil {
		return "", err
	}
	target, present, err := currentTarballTargetIfAny(install)
	if err != nil {
		return "", err
	}
	if !present {
		return "", errors.New("current symlink is absent")
	}
	if _, err := readTarballMetadata(target); err != nil {
		return "", err
	}
	return target, nil
}

// TarballCurrentTargetForArtifact is the controller-facing selection proof used
// both before persisting a WAL rollback floor and while binding a running shell
// process. It refuses a changed symlink or metadata record instead of treating
// the selected directory as an implicit trust anchor.
func TarballCurrentTargetForArtifact(install ComponentInstall, wantSHA string) (string, error) {
	target, err := TarballCurrentTarget(install)
	if err != nil {
		return "", err
	}
	if err := validateTarballTarget(install, target, wantSHA); err != nil {
		return "", err
	}
	return target, nil
}

// RestoreTarballCurrent restores an exact persisted generation selected by a
// WAL entry. It performs no restart; the controller restores the runtime marker
// first, then restarts exactly once. A fresh install removes its current link
// only when it still points to the signed toHash generation.
func RestoreTarballCurrent(install ComponentInstall, priorPath, fromSHA, toSHA string) error {
	if err := validateTarballInstall(install); err != nil {
		return err
	}
	if fromSHA == "" || priorPath == "" {
		return removeCurrentIfPointsToArtifact(install, toSHA)
	}
	if err := validateTarballTarget(install, priorPath, fromSHA); err != nil {
		return err
	}
	return atomicRepointCurrent(install, priorPath)
}

// InstalledArtifactSHA256 returns the truthful delta observation for each
// implemented kind. A tarball reports its verified archive hash from metadata.
func InstalledArtifactSHA256(install ComponentInstall) (string, error) {
	switch install.ApplyKind {
	case ApplyBinaryReplace:
		sha, _, err := measureRegularFileNoFollow(install.InstallRoot)
		return sha, err
	case ApplyTarballSymlinkSwap:
		target, err := TarballCurrentTarget(install)
		if err != nil {
			return "", err
		}
		meta, err := readTarballMetadata(target)
		if err != nil {
			return "", err
		}
		return meta.ArtifactSHA, nil
	default:
		return "", fmt.Errorf("installed artifact observation for applyKind %q is not implemented", install.ApplyKind)
	}
}

func validateTarballInstall(install ComponentInstall) error {
	if install.ApplyKind != ApplyTarballSymlinkSwap {
		return fmt.Errorf("wrong applyKind %q", install.ApplyKind)
	}
	if !filepath.IsAbs(install.InstallRoot) || !filepath.IsAbs(install.CurrentSymlink) || !pathWithin(install.InstallRoot, install.CurrentSymlink) {
		return errors.New("installRoot/currentSymlink must be absolute and currentSymlink must remain under installRoot")
	}
	info, err := os.Lstat(install.InstallRoot)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("installRoot is not a real directory")
	}
	return nil
}

func currentTarballTargetIfAny(install ComponentInstall) (string, bool, error) {
	info, err := os.Lstat(install.CurrentSymlink)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return "", false, fmt.Errorf("current path %s is not a symlink", install.CurrentSymlink)
	}
	target, err := filepath.EvalSymlinks(install.CurrentSymlink)
	if err != nil {
		return "", false, err
	}
	if !pathWithin(install.InstallRoot, target) {
		return "", false, fmt.Errorf("current target %s escapes installRoot", target)
	}
	info, err = os.Stat(target)
	if err != nil {
		return "", false, err
	}
	if !info.IsDir() {
		return "", false, fmt.Errorf("current target %s is not a directory", target)
	}
	return target, true, nil
}

func readTarballMetadata(target string) (tarballReleaseMetadata, error) {
	var meta tarballReleaseMetadata
	path := filepath.Join(target, tarballMetadataName)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return meta, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return meta, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return meta, errors.New("release metadata is not a bounded regular file")
	}
	// json.Decoder accepts a duplicate key with last-one-wins semantics. Metadata
	// selects the installed artifact, so that ambiguity is a fail-closed error.
	// Reuse the recursive folded-duplicate scanner used for structured reports.
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return meta, err
	}
	if selfReportHasFoldedDuplicateKeys(raw) {
		return meta, errors.New("release metadata has duplicate or case-shadowed keys")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&meta); err != nil {
		return meta, err
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return meta, errors.New("release metadata has trailing data")
	}
	if meta.Schema != tarballMetadataSchema || len(meta.ArtifactSHA) != 64 || meta.ArtifactSize <= 0 || strings.TrimSpace(meta.Version) == "" {
		return meta, errors.New("release metadata has invalid fields")
	}
	if _, err := hex.DecodeString(meta.ArtifactSHA); err != nil {
		return meta, errors.New("release metadata has invalid sha256")
	}
	meta.ArtifactSHA = strings.ToLower(meta.ArtifactSHA)
	return meta, nil
}

func writeTarballMetadata(target string, meta tarballReleaseMetadata) error {
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	path := filepath.Join(target, tarballMetadataName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return syncDir(target)
}

func extractTarXZNoFollow(archivePath, target string) error {
	if err := os.Mkdir(target, 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(archivePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("archive is not a regular file")
	}
	xzr, err := xz.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(xzr)
	var entries int
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxTarballEntries {
			return fmt.Errorf("too many archive entries")
		}
		name, err := safeTarballName(hdr.Name)
		if err != nil {
			return err
		}
		out := filepath.Join(target, name)
		if !pathWithin(target, out) {
			return fmt.Errorf("archive path escapes target: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if hdr.FileInfo().Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("archive dir %q is group/world writable", hdr.Name)
			}
			if err := os.MkdirAll(out, hdr.FileInfo().Mode().Perm()&0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if hdr.Size < 0 || hdr.Size > maxTarballExtractBytes-total {
				return fmt.Errorf("archive size limit exceeded")
			}
			if hdr.FileInfo().Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("archive file %q is group/world writable", hdr.Name)
			}
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				return err
			}
			outf, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, hdr.FileInfo().Mode().Perm()&0o755)
			if err != nil {
				return err
			}
			n, copyErr := io.Copy(outf, io.LimitReader(tr, hdr.Size+1))
			if copyErr == nil && n != hdr.Size {
				copyErr = io.ErrUnexpectedEOF
			}
			if syncErr := outf.Sync(); copyErr == nil {
				copyErr = syncErr
			}
			if closeErr := outf.Close(); copyErr == nil {
				copyErr = closeErr
			}
			if copyErr != nil {
				return copyErr
			}
			total += n
		default:
			return fmt.Errorf("archive entry %q has forbidden type %d", hdr.Name, hdr.Typeflag)
		}
	}
	return syncDir(target)
}

func safeTarballName(name string) (string, error) {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	return clean, nil
}

func atomicRepointCurrent(install ComponentInstall, target string) error {
	if !pathWithin(install.InstallRoot, target) {
		return errors.New("symlink target escapes installRoot")
	}
	parent := filepath.Dir(install.CurrentSymlink)
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("current symlink parent is not a real directory")
	}
	if info, err := os.Lstat(install.CurrentSymlink); err == nil && info.Mode()&os.ModeSymlink == 0 {
		return errors.New("current path exists but is not a symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp := filepath.Join(parent, "."+filepath.Base(install.CurrentSymlink)+".rrs-new")
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, install.CurrentSymlink); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(parent)
}

func removeCurrentIfPointsTo(install ComponentInstall, want string) error {
	target, present, err := currentTarballTargetIfAny(install)
	if errors.Is(err, os.ErrNotExist) || !present {
		return nil
	}
	if err != nil {
		return err
	}
	if target != want {
		return fmt.Errorf("current target %s is not applied target %s", target, want)
	}
	if err := os.Remove(install.CurrentSymlink); err != nil {
		return err
	}
	return syncDir(filepath.Dir(install.CurrentSymlink))
}

func removeCurrentIfPointsToArtifact(install ComponentInstall, wantSHA string) error {
	target, present, err := currentTarballTargetIfAny(install)
	if errors.Is(err, os.ErrNotExist) || !present {
		return nil
	}
	if err != nil {
		return err
	}
	if err := validateTarballTarget(install, target, wantSHA); err != nil {
		return fmt.Errorf("current generation is not signed toHash: %w", err)
	}
	if err := os.Remove(install.CurrentSymlink); err != nil {
		return err
	}
	return syncDir(filepath.Dir(install.CurrentSymlink))
}

func validateTarballTarget(install ComponentInstall, target, wantSHA string) error {
	if !pathWithin(install.InstallRoot, target) {
		return errors.New("target escapes installRoot")
	}
	meta, err := readTarballMetadata(target)
	if err != nil {
		return err
	}
	if !strings.EqualFold(meta.ArtifactSHA, wantSHA) {
		return fmt.Errorf("target archive sha256 %s != expected %s", meta.ArtifactSHA, wantSHA)
	}
	return nil
}

func pathWithin(root, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
