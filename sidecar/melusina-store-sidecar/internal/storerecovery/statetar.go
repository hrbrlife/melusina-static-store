package storerecovery

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// store-state-tar-v1.
//
// The stream is a PAX tar. Its first member is MANIFEST.json: the canonical
// JSON StateManifestV1, signed by the Store operator key. Every other member
// is one entry of one durable Store root, named roots/<root>[/<relative path>],
// in exactly the order the manifest lists them: depth-first, parents before
// children, siblings by name. A member is a directory, a regular file or a
// symlink whose target is one sibling name; nothing else is representable.
// Headers carry only the name, type, permission bits, size, modification time
// and link target; owner, group, user and group names are always zero and
// empty, and no other PAX record is written or accepted.
//
// The bytes are a function of the state alone: the same entries, contents,
// permission bits and modification times give the same stream wherever the
// roots live on disk, because the stream names roots, never host paths. The
// signature is Ed25519, which is deterministic, so the signed manifest is too.
//
// Import is strict: the manifest must verify under the operator key the
// caller already trusts (the recovery kit's rootStore.operatorKey), then every
// header must equal the manifest's entry and every file must hash to it, in
// order, with nothing missing, extra or reordered. The state is extracted into
// fresh sibling staging paths and moved onto the targets only after the whole
// stream and the caller's own check have passed.
const (
	StateManifestSchema = "melusina.store-state-manifest.v1"
	StateFormat         = "store-state-tar-v1"
	// StateSubjectKind is the RemoteBak subject kind of a store-state-tar-v1
	// backup.
	StateSubjectKind = "store-state"

	StateManifestMember = "MANIFEST.json"
	stateRootsPrefix    = "roots/"
	stateManifestDomain = "MELUSINA_STORE_STATE_MANIFEST_V1\n"

	// MaxStateMembers bounds the manifest. A Store generation holds at most
	// 512 members and the generation root at most 256 entries; private stages
	// and receipts add to that, well below this bound.
	MaxStateMembers = 1 << 18
	// MaxStateManifestBytes bounds the manifest document.
	MaxStateManifestBytes = 128 << 20

	maxMemberPathBytes = 4096
	maxSegmentBytes    = 255
	symlinkMode        = 0o777

	memberTypeDir     = "dir"
	memberTypeFile    = "file"
	memberTypeSymlink = "symlink"

	stagingMarker = ".store-state-import-"
)

var (
	rootNamePattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	storeIDPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)
	generationIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)
	sha256HexPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	allowedPAXRecords   = map[string]bool{"mtime": true, "path": true, "linkpath": true, "size": true}
)

// RootKind says whether a Store root is a directory tree or one file.
type RootKind string

const (
	RootDirectory RootKind = "dir"
	RootFile      RootKind = "file"
)

// Root is one durable Store root: a fixed name in the stream and the host
// path it lives at on this machine.
type Root struct {
	Name string
	Kind RootKind
	Path string
}

// StateRootV1 names one root in the manifest.
type StateRootV1 struct {
	Name string   `json:"name"`
	Kind RootKind `json:"kind"`
}

// StateMemberV1 is one entry of the stream. MTime is Unix nanoseconds. A
// symlink carries mode 0777, time zero and its target; a file carries its
// size and SHA-256; a directory carries neither.
type StateMemberV1 struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	MTime  int64  `json:"mtime"`
	SHA256 string `json:"sha256"`
	Target string `json:"target"`
}

// StateManifestV1 is the signed first member of a store-state-tar-v1 stream.
// It records no time of its own: the RemoteBak receipt carries the backup
// time, and a timestamp here would make identical state produce different
// bytes.
type StateManifestV1 struct {
	Schema            string          `json:"schema"`
	Format            string          `json:"format"`
	StoreID           string          `json:"storeId"`
	OperatorKey       string          `json:"operatorKey"`
	CurrentGeneration string          `json:"currentGeneration"`
	Roots             []StateRootV1   `json:"roots"`
	Members           []StateMemberV1 `json:"members"`
	Signature         string          `json:"signature"`
}

// StateHeader is what the Store asserts about the state it exports.
type StateHeader struct {
	StoreID           string
	OperatorKey       string
	CurrentGeneration string
}

// Signer signs a message with the Store operator key (identity.Private.Sign).
type Signer func(message []byte) []byte

// StateSummary is the public result of a verified stream.
type StateSummary struct {
	Manifest       StateManifestV1
	ManifestSHA256 string
	StreamSHA256   string
	StreamBytes    int64
}

// ExportState writes the store-state-tar-v1 stream of roots to w. The caller
// must hold the Store's writer exclusion for the whole call: a member that
// changes between the manifest pass and the write pass refuses the export,
// and the partial output must then be discarded.
func ExportState(w io.Writer, roots []Root, header StateHeader, sign Signer) (StateSummary, error) {
	if sign == nil {
		return StateSummary{}, Refuse(RefusalStateHeaderInvalid, "signer")
	}
	operatorKey, err := parseEd25519Key(header.OperatorKey)
	if err != nil || !storeIDPattern.MatchString(header.StoreID) || (header.CurrentGeneration != "" && !generationIDPattern.MatchString(header.CurrentGeneration)) {
		return StateSummary{}, Refuse(RefusalStateHeaderInvalid, "")
	}
	sorted, err := validateRoots(roots)
	if err != nil {
		return StateSummary{}, err
	}
	var members []StateMemberV1
	var sources []string
	for _, root := range sorted {
		if err := collectRoot(root, &members, &sources); err != nil {
			return StateSummary{}, err
		}
	}
	manifest := StateManifestV1{
		Schema: StateManifestSchema, Format: StateFormat,
		StoreID: header.StoreID, OperatorKey: header.OperatorKey, CurrentGeneration: header.CurrentGeneration,
		Roots: make([]StateRootV1, len(sorted)), Members: members,
	}
	for index, root := range sorted {
		manifest.Roots[index] = StateRootV1{Name: root.Name, Kind: root.Kind}
	}
	if err := validateManifestShape(manifest); err != nil {
		return StateSummary{}, err
	}
	message, err := stateSigningMessage(manifest)
	if err != nil {
		return StateSummary{}, err
	}
	signature := sign(message)
	if !ed25519.Verify(operatorKey, message, signature) {
		return StateSummary{}, Refuse(RefusalStateManifestSignature, "the signer is not the declared operator key")
	}
	manifest.Signature = base64.RawURLEncoding.EncodeToString(signature)
	manifestBytes, err := canonicalDocument(manifest)
	if err != nil {
		return StateSummary{}, err
	}
	if len(manifestBytes) > MaxStateManifestBytes {
		return StateSummary{}, Refuse(RefusalStateTooLarge, "manifest")
	}

	stream := sha256.New()
	counter := &countingWriter{}
	tw := tar.NewWriter(io.MultiWriter(w, stream, counter))
	if err := tw.WriteHeader(manifestHeader(int64(len(manifestBytes)))); err != nil {
		return StateSummary{}, fmt.Errorf("write %s header: %w", StateManifestMember, err)
	}
	if _, err := tw.Write(manifestBytes); err != nil {
		return StateSummary{}, fmt.Errorf("write %s: %w", StateManifestMember, err)
	}
	for index, member := range manifest.Members {
		if err := writeMember(tw, member, sources[index]); err != nil {
			return StateSummary{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return StateSummary{}, fmt.Errorf("close store-state stream: %w", err)
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	return StateSummary{
		Manifest:       manifest,
		ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		StreamSHA256:   hex.EncodeToString(stream.Sum(nil)),
		StreamBytes:    counter.n,
	}, nil
}

// VerifyState reads a whole store-state-tar-v1 stream and writes nothing. It
// is the check a backup runner makes on what it is about to seal, and the
// check a restorer makes on what it pulled back.
func VerifyState(r io.Reader, operatorKey, storeID string) (StateSummary, error) {
	stream := sha256.New()
	counter := &countingWriter{}
	tr := tar.NewReader(io.TeeReader(r, io.MultiWriter(stream, counter)))
	manifest, manifestDigest, err := readManifest(tr, operatorKey, storeID)
	if err != nil {
		return StateSummary{}, err
	}
	if err := streamMembers(tr, manifest, nil); err != nil {
		return StateSummary{}, err
	}
	if err := requireStreamEnd(r); err != nil {
		return StateSummary{}, err
	}
	return StateSummary{Manifest: manifest, ManifestSHA256: manifestDigest, StreamSHA256: hex.EncodeToString(stream.Sum(nil)), StreamBytes: counter.n}, nil
}

// requireStreamEnd refuses any byte after the end-of-archive footer. The
// exporter writes none, so a restore must hand back exactly the stream it was
// given: its length and SHA-256 are in the export summary.
func requireStreamEnd(r io.Reader) error {
	var probe [1]byte
	n, err := io.ReadFull(r, probe[:])
	if n != 0 {
		return Refuse(RefusalStateStreamMalformed, "data after the end of the archive")
	}
	if !errors.Is(err, io.EOF) {
		return Refuse(RefusalStateStreamMalformed, "the stream did not end cleanly")
	}
	return nil
}

// ImportOptions names what a restore trusts and where it writes.
type ImportOptions struct {
	// OperatorKey is the base58 Ed25519 key the manifest must be signed by.
	OperatorKey string
	// StoreID is the Store the state must belong to.
	StoreID string
	// Targets are this host's roots. Their names and kinds must equal the
	// manifest's. Each target must be absent, or an empty directory for a
	// directory root; its parent must exist.
	Targets []Root
	// BeforeCommit runs after the whole stream has been verified and
	// extracted, with the staged path of every root, and before anything is
	// moved onto a target. A non-nil error refuses the import and removes the
	// staging.
	BeforeCommit func(manifest StateManifestV1, staged map[string]string) error
	// Random names the staging paths; nil is crypto/rand.
	Random io.Reader
}

// ImportState restores a verified store-state-tar-v1 stream onto empty
// targets. Nothing reaches a target unless every member verified and
// BeforeCommit accepted the staged state.
func ImportState(r io.Reader, opts ImportOptions) (StateSummary, error) {
	targets, err := validateRoots(opts.Targets)
	if err != nil {
		return StateSummary{}, err
	}
	random := opts.Random
	if random == nil {
		random = rand.Reader
	}
	stream := sha256.New()
	counter := &countingWriter{}
	tr := tar.NewReader(io.TeeReader(r, io.MultiWriter(stream, counter)))
	manifest, manifestDigest, err := readManifest(tr, opts.OperatorKey, opts.StoreID)
	if err != nil {
		return StateSummary{}, err
	}
	if len(targets) != len(manifest.Roots) {
		return StateSummary{}, Refuse(RefusalStateRootSetMismatch, "")
	}
	for index, target := range targets {
		if manifest.Roots[index].Name != target.Name || manifest.Roots[index].Kind != target.Kind {
			return StateSummary{}, Refuse(RefusalStateRootSetMismatch, target.Name)
		}
	}

	plan, err := prepareTargets(targets, random)
	if err != nil {
		return StateSummary{}, err
	}
	committed := false
	defer func() {
		if !committed {
			plan.removeStaging()
		}
	}()
	extractor := &stagingExtractor{plan: plan}
	if err := streamMembers(tr, manifest, extractor); err != nil {
		return StateSummary{}, err
	}
	if err := requireStreamEnd(r); err != nil {
		return StateSummary{}, err
	}
	if err := extractor.finish(manifest); err != nil {
		return StateSummary{}, err
	}
	if opts.BeforeCommit != nil {
		staged := make(map[string]string, len(plan.roots))
		for _, root := range plan.roots {
			staged[root.root.Name] = root.staging
		}
		if err := opts.BeforeCommit(manifest, staged); err != nil {
			return StateSummary{}, err
		}
	}
	if err := plan.commit(); err != nil {
		return StateSummary{}, err
	}
	committed = true
	return StateSummary{Manifest: manifest, ManifestSHA256: manifestDigest, StreamSHA256: hex.EncodeToString(stream.Sum(nil)), StreamBytes: counter.n}, nil
}

// DecodeStateManifest strictly decodes a manifest document: its own fields
// only, no duplicate key, canonical encoding, and a well-formed shape. It does
// not check the signature; readManifest does, against the caller's key.
func DecodeStateManifest(raw []byte) (StateManifestV1, error) {
	var manifest StateManifestV1
	if err := decodeCanonical(raw, MaxStateManifestBytes, &manifest); err != nil {
		return StateManifestV1{}, Refuse(RefusalStateManifestMalformed, err.Error())
	}
	if err := validateManifestShape(manifest); err != nil {
		return StateManifestV1{}, err
	}
	return manifest, nil
}

// ── roots and the manifest pass ─────────────────────────────────────────────

func validateRoots(roots []Root) ([]Root, error) {
	if len(roots) == 0 {
		return nil, Refuse(RefusalStateRootInvalid, "no roots")
	}
	sorted := append([]Root(nil), roots...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for index, root := range sorted {
		if !rootNamePattern.MatchString(root.Name) || (root.Kind != RootDirectory && root.Kind != RootFile) {
			return nil, Refuse(RefusalStateRootInvalid, root.Name)
		}
		if index > 0 && sorted[index-1].Name == root.Name {
			return nil, Refuse(RefusalStateRootInvalid, "duplicate root "+root.Name)
		}
		if !filepath.IsAbs(root.Path) || filepath.Clean(root.Path) != root.Path || root.Path == string(filepath.Separator) {
			return nil, Refuse(RefusalStateRootInvalid, root.Name+" must be an absolute clean path")
		}
	}
	for i := range sorted {
		for j := range sorted {
			if i != j && pathWithin(sorted[i].Path, sorted[j].Path) {
				return nil, Refuse(RefusalStateRootsOverlap, sorted[j].Name+" within "+sorted[i].Name)
			}
		}
	}
	return sorted, nil
}

// pathWithin reports whether child is parent or lies below it.
func pathWithin(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

func collectRoot(root Root, members *[]StateMemberV1, sources *[]string) error {
	info, err := os.Lstat(root.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Refuse(RefusalStateRootMissing, root.Name)
	}
	if err != nil {
		return Refuse(RefusalStateRootMissing, root.Name+": "+err.Error())
	}
	memberPath := stateRootsPrefix + root.Name
	switch root.Kind {
	case RootFile:
		if !info.Mode().IsRegular() {
			return Refuse(RefusalStateMemberUnsupported, memberPath+" is not a regular file")
		}
	case RootDirectory:
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return Refuse(RefusalStateMemberUnsupported, memberPath+" is not a real directory")
		}
	}
	return collectEntry(root.Path, memberPath, info, members, sources)
}

func collectEntry(path, memberPath string, info os.FileInfo, members *[]StateMemberV1, sources *[]string) error {
	if len(*members) >= MaxStateMembers {
		return Refuse(RefusalStateTooLarge, "members")
	}
	member, err := memberFor(path, memberPath, info)
	if err != nil {
		return err
	}
	*members = append(*members, member)
	*sources = append(*sources, path)
	if member.Type != memberTypeDir {
		return nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return Refuse(RefusalStateRootMissing, memberPath+": "+err.Error())
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		childMember := memberPath + "/" + name
		if !validSegment(name) || len(childMember) > maxMemberPathBytes {
			return Refuse(RefusalStateMemberPathUnsafe, memberPath+"/"+strconvQuote(name))
		}
		childPath := filepath.Join(path, name)
		childInfo, err := os.Lstat(childPath)
		if err != nil {
			return Refuse(RefusalStateMemberChanged, childMember)
		}
		if err := collectEntry(childPath, childMember, childInfo, members, sources); err != nil {
			return err
		}
	}
	return nil
}

func memberFor(path, memberPath string, info os.FileInfo) (StateMemberV1, error) {
	mode := info.Mode()
	if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return StateMemberV1{}, Refuse(RefusalStateMemberUnsupported, memberPath+" carries a setuid, setgid or sticky bit")
	}
	member := StateMemberV1{Path: memberPath, Mode: uint32(mode.Perm()), MTime: info.ModTime().UnixNano()}
	switch {
	case mode.IsDir():
		member.Type = memberTypeDir
	case mode.IsRegular():
		member.Type = memberTypeFile
		size, digest, err := hashRegularFile(path, info)
		if err != nil {
			return StateMemberV1{}, Refuse(RefusalStateMemberChanged, memberPath)
		}
		member.Size, member.SHA256 = size, digest
	case mode&os.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return StateMemberV1{}, Refuse(RefusalStateMemberChanged, memberPath)
		}
		if !validSegment(target) {
			return StateMemberV1{}, Refuse(RefusalStateMemberUnsupported, memberPath+" is a symlink whose target is not one sibling name")
		}
		member.Type, member.Mode, member.MTime, member.Target = memberTypeSymlink, symlinkMode, 0, target
	default:
		return StateMemberV1{}, Refuse(RefusalStateMemberUnsupported, memberPath+" is not a directory, regular file or sibling symlink")
	}
	return member, nil
}

func hashRegularFile(path string, info os.FileInfo) (int64, string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(opened, info) || opened.Size() != info.Size() {
		return 0, "", errors.New("file changed while it was opened")
	}
	digest := sha256.New()
	n, err := io.Copy(digest, f)
	if err != nil || n != info.Size() {
		return 0, "", errors.New("file changed while it was hashed")
	}
	return n, hex.EncodeToString(digest.Sum(nil)), nil
}

// ── the write pass ──────────────────────────────────────────────────────────

func manifestHeader(size int64) *tar.Header {
	return &tar.Header{Name: StateManifestMember, Typeflag: tar.TypeReg, Mode: 0o444, Size: size, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}
}

func memberHeader(member StateMemberV1) *tar.Header {
	header := &tar.Header{Name: member.Path, Mode: int64(member.Mode), ModTime: time.Unix(0, member.MTime), Format: tar.FormatPAX}
	switch member.Type {
	case memberTypeDir:
		header.Typeflag = tar.TypeDir
	case memberTypeFile:
		header.Typeflag = tar.TypeReg
		header.Size = member.Size
	case memberTypeSymlink:
		header.Typeflag = tar.TypeSymlink
		header.Linkname = member.Target
	}
	return header
}

func writeMember(tw *tar.Writer, member StateMemberV1, source string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return Refuse(RefusalStateMemberChanged, member.Path)
	}
	switch member.Type {
	case memberTypeDir:
		if !info.IsDir() || uint32(info.Mode().Perm()) != member.Mode || info.ModTime().UnixNano() != member.MTime {
			return Refuse(RefusalStateMemberChanged, member.Path)
		}
	case memberTypeSymlink:
		target, err := os.Readlink(source)
		if err != nil || info.Mode()&os.ModeSymlink == 0 || target != member.Target {
			return Refuse(RefusalStateMemberChanged, member.Path)
		}
	case memberTypeFile:
		if !info.Mode().IsRegular() || uint32(info.Mode().Perm()) != member.Mode || info.Size() != member.Size || info.ModTime().UnixNano() != member.MTime {
			return Refuse(RefusalStateMemberChanged, member.Path)
		}
	}
	if err := tw.WriteHeader(memberHeader(member)); err != nil {
		return fmt.Errorf("write %s header: %w", member.Path, err)
	}
	if member.Type != memberTypeFile {
		return nil
	}
	f, err := os.OpenFile(source, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return Refuse(RefusalStateMemberChanged, member.Path)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(opened, info) {
		return Refuse(RefusalStateMemberChanged, member.Path)
	}
	digest := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(tw, digest), f, member.Size); err != nil {
		return Refuse(RefusalStateMemberChanged, member.Path)
	}
	var probe [1]byte
	if n, _ := f.Read(probe[:]); n != 0 || hex.EncodeToString(digest.Sum(nil)) != member.SHA256 {
		return Refuse(RefusalStateMemberChanged, member.Path)
	}
	return nil
}

// ── the read pass ───────────────────────────────────────────────────────────

func readManifest(tr *tar.Reader, operatorKey, storeID string) (StateManifestV1, string, error) {
	key, err := parseEd25519Key(operatorKey)
	if err != nil {
		return StateManifestV1{}, "", Refuse(RefusalStateOperatorMismatch, "the expected operator key is not a canonical base58 Ed25519 key")
	}
	header, err := tr.Next()
	if err != nil {
		return StateManifestV1{}, "", Refuse(RefusalStateStreamMalformed, "no "+StateManifestMember)
	}
	if header.Size < 0 || header.Size > MaxStateManifestBytes {
		return StateManifestV1{}, "", Refuse(RefusalStateTooLarge, "manifest")
	}
	if err := matchHeader(header, manifestHeader(header.Size), 0); err != nil {
		return StateManifestV1{}, "", Refuse(RefusalStateStreamMalformed, "the first member is not "+StateManifestMember)
	}
	raw := make([]byte, header.Size)
	if _, err := io.ReadFull(tr, raw); err != nil {
		return StateManifestV1{}, "", Refuse(RefusalStateStreamMalformed, StateManifestMember+" is truncated")
	}
	manifest, err := DecodeStateManifest(raw)
	if err != nil {
		return StateManifestV1{}, "", err
	}
	if manifest.OperatorKey != operatorKey {
		return StateManifestV1{}, "", Refuse(RefusalStateOperatorMismatch, manifest.OperatorKey)
	}
	signature, err := base64.RawURLEncoding.DecodeString(manifest.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return StateManifestV1{}, "", Refuse(RefusalStateManifestSignature, "")
	}
	message, err := stateSigningMessage(manifest)
	if err != nil || !ed25519.Verify(key, message, signature) {
		return StateManifestV1{}, "", Refuse(RefusalStateManifestSignature, "")
	}
	if manifest.StoreID != storeID {
		return StateManifestV1{}, "", Refuse(RefusalStateStoreMismatch, manifest.StoreID)
	}
	digest := sha256.Sum256(raw)
	return manifest, hex.EncodeToString(digest[:]), nil
}

// memberSink receives verified members. A nil sink verifies only.
type memberSink interface {
	directory(member StateMemberV1) error
	symlink(member StateMemberV1) error
	file(member StateMemberV1) (*os.File, error)
}

func streamMembers(tr *tar.Reader, manifest StateManifestV1, sink memberSink) error {
	for _, member := range manifest.Members {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return Refuse(RefusalStateMemberMissing, member.Path)
		}
		if err != nil {
			return Refuse(RefusalStateStreamMalformed, member.Path)
		}
		if err := matchHeader(header, memberHeader(member), member.MTime); err != nil {
			return Refuse(RefusalStateMemberHeaderMismatch, member.Path)
		}
		switch member.Type {
		case memberTypeDir:
			if sink != nil {
				if err := sink.directory(member); err != nil {
					return err
				}
			}
		case memberTypeSymlink:
			if sink != nil {
				if err := sink.symlink(member); err != nil {
					return err
				}
			}
		case memberTypeFile:
			if err := copyVerifiedFile(tr, member, sink); err != nil {
				return err
			}
		}
	}
	header, err := tr.Next()
	if err == nil {
		return Refuse(RefusalStateMemberUnexpected, strconvQuote(header.Name))
	}
	if !errors.Is(err, io.EOF) {
		return Refuse(RefusalStateStreamMalformed, "after the last member")
	}
	return nil
}

func copyVerifiedFile(tr *tar.Reader, member StateMemberV1, sink memberSink) error {
	digest := sha256.New()
	destination := io.Writer(digest)
	var f *os.File
	if sink != nil {
		var err error
		if f, err = sink.file(member); err != nil {
			return err
		}
		defer f.Close()
		destination = io.MultiWriter(f, digest)
	}
	if _, err := io.CopyN(destination, tr, member.Size); err != nil {
		return Refuse(RefusalStateStreamMalformed, member.Path+" is truncated")
	}
	if hex.EncodeToString(digest.Sum(nil)) != member.SHA256 {
		return Refuse(RefusalStateMemberDigestMismatch, member.Path)
	}
	if f != nil {
		if err := f.Sync(); err != nil {
			return Refuse(RefusalStateCommitFailed, member.Path+": "+err.Error())
		}
	}
	return nil
}

// matchHeader requires a read header to be exactly the one the exporter
// writes for the member: same name, type, permission bits, size, time and
// link target, no owner, and no PAX record beyond the four the writer may
// need.
func matchHeader(got, want *tar.Header, mtime int64) error {
	if got.Name != want.Name || got.Typeflag != want.Typeflag || got.Mode != want.Mode || got.Size != want.Size ||
		got.Linkname != want.Linkname || got.ModTime.UnixNano() != mtime ||
		got.Uid != 0 || got.Gid != 0 || got.Uname != "" || got.Gname != "" || got.Devmajor != 0 || got.Devminor != 0 ||
		!got.AccessTime.IsZero() || !got.ChangeTime.IsZero() {
		return errors.New("header differs")
	}
	for key := range got.PAXRecords {
		if !allowedPAXRecords[key] {
			return errors.New("unexpected PAX record")
		}
	}
	return nil
}

// ── manifest shape, encoding and signature ──────────────────────────────────

func validateManifestShape(manifest StateManifestV1) error {
	refuse := func(subject string) error { return Refuse(RefusalStateManifestMalformed, subject) }
	if manifest.Schema != StateManifestSchema || manifest.Format != StateFormat {
		return refuse("schema")
	}
	if !storeIDPattern.MatchString(manifest.StoreID) {
		return refuse("storeId")
	}
	if _, err := parseEd25519Key(manifest.OperatorKey); err != nil {
		return refuse("operatorKey")
	}
	if manifest.CurrentGeneration != "" && !generationIDPattern.MatchString(manifest.CurrentGeneration) {
		return refuse("currentGeneration")
	}
	if len(manifest.Roots) == 0 || len(manifest.Members) == 0 || len(manifest.Members) > MaxStateMembers {
		return refuse("roots or members")
	}
	roots := make(map[string]RootKind, len(manifest.Roots))
	for index, root := range manifest.Roots {
		if !rootNamePattern.MatchString(root.Name) || (root.Kind != RootDirectory && root.Kind != RootFile) {
			return refuse("root " + root.Name)
		}
		if index > 0 && manifest.Roots[index-1].Name >= root.Name {
			return refuse("roots are not sorted and distinct")
		}
		roots[root.Name] = root.Kind
	}
	directories := make(map[string]bool)
	seenRoots := make(map[string]bool, len(roots))
	for index, member := range manifest.Members {
		if index > 0 && compareMemberPaths(manifest.Members[index-1].Path, member.Path) >= 0 {
			return refuse("members are not in canonical order at " + member.Path)
		}
		rest, ok := strings.CutPrefix(member.Path, stateRootsPrefix)
		if !ok || len(member.Path) > maxMemberPathBytes {
			return refuse("member path " + strconvQuote(member.Path))
		}
		segments := strings.Split(rest, "/")
		for _, segment := range segments {
			if !validSegment(segment) {
				return refuse("member path " + strconvQuote(member.Path))
			}
		}
		kind, declared := roots[segments[0]]
		if !declared {
			return refuse("member outside a declared root: " + member.Path)
		}
		if len(segments) == 1 {
			seenRoots[segments[0]] = true
			if (kind == RootDirectory && member.Type != memberTypeDir) || (kind == RootFile && member.Type != memberTypeFile) {
				return refuse("root member kind " + member.Path)
			}
		} else {
			if kind != RootDirectory {
				return refuse("member below a file root: " + member.Path)
			}
			if !directories[stateRootsPrefix+strings.Join(segments[:len(segments)-1], "/")] {
				return refuse("member without a directory parent: " + member.Path)
			}
		}
		switch member.Type {
		case memberTypeDir:
			if member.Mode > 0o777 || member.Size != 0 || member.SHA256 != "" || member.Target != "" {
				return refuse("directory " + member.Path)
			}
			directories[member.Path] = true
		case memberTypeFile:
			if member.Mode > 0o777 || member.Size < 0 || !sha256HexPattern.MatchString(member.SHA256) || member.Target != "" {
				return refuse("file " + member.Path)
			}
		case memberTypeSymlink:
			if member.Mode != symlinkMode || member.Size != 0 || member.MTime != 0 || member.SHA256 != "" || !validSegment(member.Target) {
				return refuse("symlink " + member.Path)
			}
		default:
			return refuse("member type " + member.Path)
		}
	}
	if len(seenRoots) != len(roots) {
		return refuse("a declared root has no member")
	}
	return nil
}

// compareMemberPaths orders member paths segment by segment: a parent before
// its children, siblings by name. This is the depth-first order the exporter
// walks in.
func compareMemberPaths(a, b string) int {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	for index := 0; index < len(as) && index < len(bs); index++ {
		if c := strings.Compare(as[index], bs[index]); c != 0 {
			return c
		}
	}
	return len(as) - len(bs)
}

func stateSigningMessage(manifest StateManifestV1) ([]byte, error) {
	manifest.Signature = ""
	body, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	return append([]byte(stateManifestDomain), body...), nil
}

// canonicalDocument is the one encoding every document of this package uses:
// encoding/json of the typed value, then a newline.
func canonicalDocument(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

// decodeCanonical decodes exactly one value with only its own fields and
// requires the input to be that value's canonical encoding, which also
// refuses a duplicate key and any whitespace variation.
func decodeCanonical(raw []byte, limit int, value any) error {
	if len(raw) == 0 || len(raw) > limit {
		return errors.New("empty or oversized document")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("not exactly the document's own fields")
	}
	canonical, err := canonicalDocument(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return errors.New("not in canonical encoding")
	}
	return nil
}

func validSegment(segment string) bool {
	if segment == "" || segment == "." || segment == ".." || len(segment) > maxSegmentBytes || !utf8.ValidString(segment) {
		return false
	}
	for _, r := range segment {
		if r == '/' || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func strconvQuote(value string) string {
	quoted, _ := json.Marshal(value)
	return string(quoted)
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// ── staging and commit ──────────────────────────────────────────────────────

type stagedRoot struct {
	root          Root
	staging       string
	priorEmptyDir bool
	priorMode     os.FileMode
	committed     bool
}

type importPlan struct {
	roots []*stagedRoot
}

func prepareTargets(targets []Root, random io.Reader) (*importPlan, error) {
	plan := &importPlan{}
	for _, target := range targets {
		parent := filepath.Dir(target.Path)
		parentInfo, err := os.Lstat(parent)
		if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
			return nil, Refuse(RefusalStateRootInvalid, target.Name+" has no real parent directory")
		}
		staged := &stagedRoot{root: target}
		info, err := os.Lstat(target.Path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, Refuse(RefusalStateTargetNotEmpty, target.Name+": "+err.Error())
		case target.Kind == RootDirectory && info.IsDir() && info.Mode()&os.ModeSymlink == 0:
			entries, readErr := os.ReadDir(target.Path)
			if readErr != nil || len(entries) != 0 {
				return nil, Refuse(RefusalStateTargetNotEmpty, target.Name)
			}
			staged.priorEmptyDir, staged.priorMode = true, info.Mode().Perm()
		default:
			return nil, Refuse(RefusalStateTargetNotEmpty, target.Name)
		}
		var nonce [8]byte
		if _, err := io.ReadFull(random, nonce[:]); err != nil {
			return nil, Refuse(RefusalStateCommitFailed, "staging name: "+err.Error())
		}
		staged.staging = filepath.Join(parent, "."+filepath.Base(target.Path)+stagingMarker+hex.EncodeToString(nonce[:]))
		if _, err := os.Lstat(staged.staging); !errors.Is(err, os.ErrNotExist) {
			return nil, Refuse(RefusalStateCommitFailed, "staging path is taken for "+target.Name)
		}
		plan.roots = append(plan.roots, staged)
	}
	return plan, nil
}

func (plan *importPlan) locate(memberPath string) (string, error) {
	rest := strings.TrimPrefix(memberPath, stateRootsPrefix)
	name, relative, _ := strings.Cut(rest, "/")
	for _, root := range plan.roots {
		if root.root.Name == name {
			if relative == "" {
				return root.staging, nil
			}
			return filepath.Join(root.staging, filepath.FromSlash(relative)), nil
		}
	}
	return "", Refuse(RefusalStateRootSetMismatch, name)
}

// removeStaging deletes only the staging paths this import created. Staged
// directories may already carry their final read-only modes, so each is made
// writable by its owner before removal.
func (plan *importPlan) removeStaging() {
	for _, root := range plan.roots {
		if root.committed || !strings.Contains(filepath.Base(root.staging), stagingMarker) {
			continue
		}
		info, err := os.Lstat(root.staging)
		if err != nil {
			continue
		}
		if info.IsDir() {
			_ = filepath.Walk(root.staging, func(path string, info os.FileInfo, err error) error {
				if err == nil && info.IsDir() {
					_ = os.Chmod(path, 0o700)
				}
				return nil
			})
			_ = os.RemoveAll(root.staging)
			continue
		}
		_ = os.Remove(root.staging)
	}
}

func (plan *importPlan) commit() error {
	parents := map[string]bool{}
	for _, root := range plan.roots {
		if root.priorEmptyDir {
			if err := os.Remove(root.root.Path); err != nil {
				plan.rollback()
				return Refuse(RefusalStateTargetNotEmpty, root.root.Name)
			}
		}
		if err := moveNoReplace(root); err != nil {
			if root.priorEmptyDir {
				_ = os.Mkdir(root.root.Path, root.priorMode)
			}
			plan.rollback()
			return Refuse(RefusalStateCommitFailed, root.root.Name+": "+err.Error())
		}
		root.committed = true
		parents[filepath.Dir(root.root.Path)] = true
	}
	for parent := range parents {
		if err := syncDirectory(parent); err != nil {
			return Refuse(RefusalStateCommitFailed, "sync "+parent+": "+err.Error())
		}
	}
	return nil
}

// moveNoReplace moves a staged root onto its target without replacing
// anything that appeared there since the import began: a file root is linked
// (link(2) refuses an existing name) and a directory root is renamed, which
// refuses a directory that is not empty.
func moveNoReplace(root *stagedRoot) error {
	if root.root.Kind == RootFile {
		if err := os.Link(root.staging, root.root.Path); err != nil {
			return err
		}
		return os.Remove(root.staging)
	}
	return os.Rename(root.staging, root.root.Path)
}

// rollback moves every committed root back to its staging path, so a failed
// commit leaves each target as it was before the import.
func (plan *importPlan) rollback() {
	for index := len(plan.roots) - 1; index >= 0; index-- {
		root := plan.roots[index]
		if !root.committed {
			continue
		}
		if err := os.Rename(root.root.Path, root.staging); err == nil {
			root.committed = false
			if root.priorEmptyDir {
				_ = os.Mkdir(root.root.Path, root.priorMode)
			}
		}
	}
}

type stagingExtractor struct {
	plan *importPlan
}

func (e *stagingExtractor) directory(member StateMemberV1) error {
	path, err := e.plan.locate(member.Path)
	if err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return Refuse(RefusalStateCommitFailed, member.Path+": "+err.Error())
	}
	return nil
}

func (e *stagingExtractor) symlink(member StateMemberV1) error {
	path, err := e.plan.locate(member.Path)
	if err != nil {
		return err
	}
	if err := os.Symlink(member.Target, path); err != nil {
		return Refuse(RefusalStateCommitFailed, member.Path+": "+err.Error())
	}
	return nil
}

func (e *stagingExtractor) file(member StateMemberV1) (*os.File, error) {
	path, err := e.plan.locate(member.Path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, Refuse(RefusalStateCommitFailed, member.Path+": "+err.Error())
	}
	return f, nil
}

// finish applies every member's permission bits and time, children before
// their parent so a directory's time is set after its last child was
// created, then makes every staged directory durable.
func (e *stagingExtractor) finish(manifest StateManifestV1) error {
	var directories []string
	for index := len(manifest.Members) - 1; index >= 0; index-- {
		member := manifest.Members[index]
		if member.Type == memberTypeSymlink {
			continue
		}
		path, err := e.plan.locate(member.Path)
		if err != nil {
			return err
		}
		if err := os.Chmod(path, os.FileMode(member.Mode)); err != nil {
			return Refuse(RefusalStateCommitFailed, member.Path+": "+err.Error())
		}
		when := time.Unix(0, member.MTime)
		if err := os.Chtimes(path, when, when); err != nil {
			return Refuse(RefusalStateCommitFailed, member.Path+": "+err.Error())
		}
		if member.Type == memberTypeDir {
			directories = append(directories, path)
		}
	}
	for _, directory := range directories {
		if err := syncDirectory(directory); err != nil {
			return Refuse(RefusalStateCommitFailed, "sync "+directory+": "+err.Error())
		}
	}
	return nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
