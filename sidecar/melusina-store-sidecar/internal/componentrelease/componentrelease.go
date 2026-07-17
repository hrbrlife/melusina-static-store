// Package componentrelease is the greenfield typed component-release protocol for
// the Melusina v2 store. It replaces the shell-only signed update manifest
// (update_manifest.go's map[string]any "build/version/channel/tarball/sha256/
// size/bundle_url/signature") with ONE typed, operator-signed DESIRED-GENERATION
// document that describes EVERY component class (shell, sidecar, python, app) in a
// single monotonic generation.
//
// SCOPE SEPARATION (the load-bearing invariant of this protocol):
//
//   - The REMOTE signed document (DesiredGeneration) NAMES ARTIFACTS and version
//     constraints only: component id/class, version/build, immutable artifact
//     name, exact sha256 + byte size, channel, dependencies, the on-chain
//     authority (kind + PDA + master mint), the store operator/destination
//     identity, release/stage identity, the previous-generation rollback floor,
//     and a detached operator ed25519 signature over the canonical bytes. It
//     NEVER chooses host paths, commands, systemd units, or health commands.
//
//   - The INSTALL-LOCAL ComponentRegistry (a root-owned allowlist on the target,
//     NOT signed by and NOT derived from the remote document) owns every HOST
//     ACTION: install root, staging dir, current symlink, service unit, apply
//     kind, health command, restart command, self-report URL, keep-old count. A
//     component id that is not present in the local allowlist is REFUSED — the
//     remote document can never introduce a new host action, only advance an
//     already-allowlisted component to a new artifact.
//
// This mirrors the repository's existing signing idiom (see app_catalog.go's
// signAppCatalogPointer / verifyAppCatalogPointer and app_stage.go's
// stageReceiptMessage): a domain-separated, length-prefixed canonical byte
// message signed with the boot-identity operator ed25519 key and carried as a
// base58 detached signature. Because BOTH the producer (store sidecar) and the
// consumer (out-of-shell host update controller) are Go and import THIS package,
// there is exactly one canonicalization and one verify implementation — no
// cross-language (Python/Go) byte-matching to drift, which is what made the old
// shell-only manifest fragile.
package componentrelease

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Schema identifiers. A consumer that does not recognize the exact schema string
// fails closed rather than guessing an older/newer shape (there is no
// compatibility branch — greenfield replacement, per CLAUDE.md).
const (
	DesiredGenerationSchema = "melusina-desired-generation-v1"
	ComponentRegistrySchema = "melusina-component-registry-v1"
	// RuntimeReleaseInfoSchema is the exact, structured self-report emitted by
	// a running release component. It is intentionally distinct from the
	// signed DesiredGeneration schema: it binds a local process to a desired
	// component release but carries no authority to choose host actions.
	RuntimeReleaseInfoSchema = "melusina-runtime-release-info-v1"
)

// desiredGenerationDomain and componentReleaseDomain domain-separate the two
// canonical messages so a signature over one can never be replayed as the other.
// The trailing NUL matches the repo convention (appCatalogPointerDomain,
// appStageReceiptDomain).
var (
	desiredGenerationDomain = []byte("melusina-desired-generation-v1\x00")
	componentReleaseDomain  = []byte("melusina-component-release-v1\x00")
)

// Component classes select the ON-CHAIN AUTHORITY model a consumer verifies; a
// class is NOT an apply strategy (that is the registry's ApplyKind, chosen
// locally). shell => InstallerReleaseEntry; sidecar => SidecarIdentityEntry +
// approval cascade; app => ReleaseEntry; data => a separately-versioned data
// artifact riding a sidecar/installer authority (e.g. the OpenSanctions dataset).
const (
	ClassShell   = "shell"
	ClassSidecar = "sidecar"
	ClassApp     = "app"
	ClassData    = "data"
)

// On-chain authority kinds.
//   - installer_release => InstallerReleaseEntry PDA (["installer_release",
//     master_nft_mint, installer_hash], register/revoke/supersede, forward-only)
//     for whole-file system artifacts (shell + data blobs).
//   - release_v2 => ReleaseEntry PDA (["release_v2", master_nft_mint, app_hash],
//     register/revoke) for Sandstorm app packages.
//   - sidecar_identity => the SidecarIdentityEntry (["sidecar_identity",
//     license_nft_mint, sidecar_id, key_version_le]) three-PDA cascade: the
//     identity references a GlobalSidecarApproval (["global_sidecar",
//     master_nft_mint, sidecar_id]) and a LocalSidecarApproval (["local_sidecar",
//     license_nft_mint, sidecar_id]). Verified as a whole for production sidecars.
const (
	AuthorityInstallerRelease = "installer_release"
	AuthorityReleaseV2        = "release_v2"
	AuthoritySidecarIdentity  = "sidecar_identity"
)

// ChainAuthority is the per-component on-chain authority reference. Which fields
// are populated depends on Kind. It is a set of CLAIMS the consumer re-verifies
// against the chain (the PDAs must exist, be Active, and pin this artifact hash)
// — never trusted on its own.
type ChainAuthority struct {
	Kind    string `json:"kind"`    // installer_release | release_v2 | sidecar_identity
	Program string `json:"program"` // base58 program id, e.g. 7anRCW8U...

	MasterNftMint  string `json:"masterNftMint,omitempty"`  // installer_release/release_v2 seed; global-approval seed
	LicenseNftMint string `json:"licenseNftMint,omitempty"` // sidecar_identity / local-approval seed
	ReleasePDA     string `json:"releasePda,omitempty"`     // installer_release | release_v2: InstallerReleaseEntry / ReleaseEntry

	// sidecar_identity cascade:
	SidecarID         string `json:"sidecarId,omitempty"`
	KeyVersion        uint32 `json:"keyVersion,omitempty"`
	IdentityPDA       string `json:"identityPda,omitempty"`       // SidecarIdentityEntry
	GlobalApprovalPDA string `json:"globalApprovalPda,omitempty"` // GlobalSidecarApproval
	LocalApprovalPDA  string `json:"localApprovalPda,omitempty"`  // LocalSidecarApproval
}

// ComponentDependency expresses a required/minimum other-component constraint the
// consumer must satisfy from the SAME generation before applying this component.
// It names a component and a floor, never a host action.
type ComponentDependency struct {
	ComponentID   string `json:"componentId"`
	MinVersion    string `json:"minVersion,omitempty"`
	MinGeneration uint64 `json:"minGeneration,omitempty"`
}

// ComponentRelease is one artifact-naming entry of a DesiredGeneration. Every
// field identifies an artifact or a version/authority constraint; none of them
// is a host path, unit, command, or health check.
type ComponentRelease struct {
	ComponentID    string `json:"componentId"`    // stable id, e.g. "sandstorm-shell", "melusina-store-sidecar"
	ComponentClass string `json:"componentClass"` // shell|sidecar|python|app
	Version        string `json:"version"`        // semver or "build-N"
	Build          int64  `json:"build,omitempty"`

	ArtifactName string `json:"artifactName"` // immutable served filename, e.g. sandstorm-<sha>.tar.xz
	SHA256       string `json:"sha256"`       // lowercase hex sha256 of the SERVED ARTIFACT BYTES (what the consumer downloads + verifies)
	// ContentSHA256 is the CONTENT identity pinned on-chain, DISTINCT from the
	// served-artifact SHA256 when the two differ. For an app (release_v2) the chain
	// pins app_hash = the tree-hash over {app.spk, metadata.json}, which is NOT
	// sha256(the served spk file) — so an app MUST carry both (SHA256 = served
	// bytes, ContentSHA256 = the ReleaseEntry-pinned app tree hash). For whole-file
	// installer_release artifacts (shell/sidecar/data) the on-chain installer_hash
	// == sha256(file), so ContentSHA256 may be omitted (defaults to SHA256).
	ContentSHA256 string `json:"contentSha256,omitempty"`
	SizeBytes     int64  `json:"sizeBytes"` // exact byte size of the served artifact
	BundleURL     string `json:"bundleUrl"` // absolute https under the generation's bundleOrigin; a locator, not a host action

	Chain       ChainAuthority `json:"chain"` // on-chain authority reference (per-class)
	ReleaseHash string         `json:"releaseHash,omitempty"`
	StageID     string         `json:"stageId,omitempty"`

	// Per-component rollback floor: the exact artifact a consumer restores to on a
	// failed apply of THIS component. The generation-level PreviousGeneration is
	// the coarse floor; these two fields pin the fine-grained per-component target.
	PreviousSHA256  string `json:"previousSha256,omitempty"`
	PreviousVersion string `json:"previousVersion,omitempty"`

	Requires []ComponentDependency `json:"requires,omitempty"`
}

// DesiredGeneration is the whole-system, operator-signed release pointer. It is
// the single authoritative "current generation" selector — the chain records are
// per-artifact attestations and enforce no exactly-one-Active invariant, so the
// authoritative current selection lives HERE, bound by GenerationID and the
// detached operator signature.
type DesiredGeneration struct {
	Schema             string             `json:"schema"`
	GenerationID       uint64             `json:"generationId"`   // strictly monotonic; the authoritative current pointer
	GenerationHash     string             `json:"generationHash"` // lowercase hex sha256 of the canonical component set (content identity)
	StoreID            string             `json:"storeId"`        // store operator identity, e.g. "melusina-os-root-store"
	OperatorPubkey     string             `json:"operatorPubkey"` // base58 ed25519 signer; MUST be in the target's pinned store policy
	BundleOrigin       string             `json:"bundleOrigin"`   // absolute https origin every component bundleUrl MUST be under (the pinned bazaar; the controller also checks this == its configured origin)
	Channel            string             `json:"channel"`        // dev|stable
	SignedAtUnix       int64              `json:"signedAtUnix"`   // signed publication time
	PreviousGeneration uint64             `json:"previousGeneration"`
	Components         []ComponentRelease `json:"components"`
	OperatorSignature  string             `json:"operatorSignature"` // base58 detached ed25519 over the canonical message
}

// ── canonical message construction (length-prefixed, order-fixed) ─────────────

func writeLenPrefixed(dst []byte, s string) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	dst = append(dst, n[:]...)
	return append(dst, []byte(s)...)
}

func writeU64(dst []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(dst, b[:]...)
}

func writeU32(dst []byte, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return append(dst, b[:]...)
}

// componentReleaseDigest is the fixed-size (32-byte) canonical digest of a single
// component entry. Requires are sorted by ComponentID so ordering is not
// signable freedom. Every string is length-prefixed so no two distinct field
// sets can collide by concatenation.
func componentReleaseDigest(c ComponentRelease) [32]byte {
	msg := make([]byte, 0, 256)
	msg = append(msg, componentReleaseDomain...)
	msg = writeLenPrefixed(msg, c.ComponentID)
	msg = writeLenPrefixed(msg, c.ComponentClass)
	msg = writeLenPrefixed(msg, c.Version)
	msg = writeU64(msg, uint64(c.Build))
	msg = writeLenPrefixed(msg, c.ArtifactName)
	msg = writeLenPrefixed(msg, strings.ToLower(c.SHA256))
	msg = writeLenPrefixed(msg, strings.ToLower(c.ContentSHA256))
	msg = writeU64(msg, uint64(c.SizeBytes))
	msg = writeLenPrefixed(msg, c.BundleURL)
	msg = writeLenPrefixed(msg, c.Chain.Kind)
	msg = writeLenPrefixed(msg, c.Chain.Program)
	msg = writeLenPrefixed(msg, c.Chain.MasterNftMint)
	msg = writeLenPrefixed(msg, c.Chain.LicenseNftMint)
	msg = writeLenPrefixed(msg, c.Chain.ReleasePDA)
	msg = writeLenPrefixed(msg, c.Chain.SidecarID)
	msg = writeU64(msg, uint64(c.Chain.KeyVersion))
	msg = writeLenPrefixed(msg, c.Chain.IdentityPDA)
	msg = writeLenPrefixed(msg, c.Chain.GlobalApprovalPDA)
	msg = writeLenPrefixed(msg, c.Chain.LocalApprovalPDA)
	msg = writeLenPrefixed(msg, strings.ToLower(c.ReleaseHash))
	msg = writeLenPrefixed(msg, strings.ToLower(c.StageID))
	msg = writeLenPrefixed(msg, strings.ToLower(c.PreviousSHA256))
	msg = writeLenPrefixed(msg, c.PreviousVersion)

	deps := append([]ComponentDependency(nil), c.Requires...)
	sort.Slice(deps, func(i, j int) bool { return deps[i].ComponentID < deps[j].ComponentID })
	msg = writeU32(msg, uint32(len(deps)))
	for _, d := range deps {
		msg = writeLenPrefixed(msg, d.ComponentID)
		msg = writeLenPrefixed(msg, d.MinVersion)
		msg = writeU64(msg, d.MinGeneration)
	}
	return sha256.Sum256(msg)
}

// sortedComponents returns a copy of the components sorted by ComponentID, with
// each component's Requires also copied + sorted by ComponentID, so BOTH the
// signed digest AND the serialized wire form are canonical regardless of how the
// caller assembled the slice (two docs with the same dependency set in a
// different order produce identical bytes).
func sortedComponents(components []ComponentRelease) []ComponentRelease {
	out := make([]ComponentRelease, len(components))
	copy(out, components)
	for i := range out {
		if len(out[i].Requires) > 0 {
			reqs := make([]ComponentDependency, len(out[i].Requires))
			copy(reqs, out[i].Requires)
			sort.Slice(reqs, func(a, b int) bool { return reqs[a].ComponentID < reqs[b].ComponentID })
			out[i].Requires = reqs
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ComponentID < out[j].ComponentID })
	return out
}

// GenerationContentHash is sha256 over the domain-separated, sorted set of
// per-component digests. It is the content identity of a generation: two
// documents with the same component set (any field differing) produce different
// hashes. It is stored in DesiredGeneration.GenerationHash and re-checked on
// verify.
func GenerationContentHash(components []ComponentRelease) [32]byte {
	sorted := sortedComponents(components)
	msg := make([]byte, 0, 64+32*len(sorted))
	msg = append(msg, desiredGenerationDomain...)
	msg = writeU32(msg, uint32(len(sorted)))
	for _, c := range sorted {
		d := componentReleaseDigest(c)
		msg = append(msg, d[:]...)
	}
	return sha256.Sum256(msg)
}

// desiredGenerationMessage is the exact byte string the operator signs. It binds
// every generation-level field plus the content hash of the sorted component
// set (which in turn binds every component field). No floats, all integers
// big-endian, all strings length-prefixed.
func desiredGenerationMessage(doc DesiredGeneration, contentHash [32]byte) []byte {
	msg := make([]byte, 0, 256)
	msg = append(msg, desiredGenerationDomain...)
	msg = writeU64(msg, doc.GenerationID)
	msg = writeLenPrefixed(msg, doc.StoreID)
	msg = writeLenPrefixed(msg, doc.OperatorPubkey)
	msg = writeLenPrefixed(msg, doc.BundleOrigin)
	msg = writeLenPrefixed(msg, doc.Channel)
	msg = writeU64(msg, uint64(doc.SignedAtUnix))
	msg = writeU64(msg, doc.PreviousGeneration)
	msg = append(msg, contentHash[:]...)
	return msg
}

// ── sign / verify ─────────────────────────────────────────────────────────────

// Sign canonicalizes doc (sorts components, recomputes the content hash, fills
// GenerationHash and OperatorPubkey from the operator key), signs the canonical
// message, and returns the completed, signed document. The caller supplies the
// boot-identity operator private key (the same authority that signs the app
// catalog pointer and stage receipt).
func Sign(operator *identity.Private, doc DesiredGeneration) (DesiredGeneration, error) {
	if operator == nil {
		return DesiredGeneration{}, errors.New("no operator identity to sign the desired generation")
	}
	doc.Schema = DesiredGenerationSchema
	doc.Components = sortedComponents(doc.Components)
	if err := doc.validateUnsigned(); err != nil {
		return DesiredGeneration{}, err
	}
	pub, err := operator.Public().SignPublicKey()
	if err != nil {
		return DesiredGeneration{}, fmt.Errorf("operator signing pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return DesiredGeneration{}, errors.New("operator identity has no valid ed25519 signing pubkey")
	}
	// Derive OperatorPubkey via the SAME path Verify compares against
	// (base58 of the raw ed25519 sign key) so the two never disagree.
	doc.OperatorPubkey = primitives.EncodeBase58(pub)
	contentHash := GenerationContentHash(doc.Components)
	doc.GenerationHash = hex.EncodeToString(contentHash[:])
	sig := operator.Sign(desiredGenerationMessage(doc, contentHash))
	if len(sig) != ed25519.SignatureSize {
		return DesiredGeneration{}, fmt.Errorf("operator signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	doc.OperatorSignature = primitives.EncodeBase58(sig)
	return doc, nil
}

// Verify checks the document's structure, that GenerationHash matches the
// recomputed content hash, that OperatorPubkey matches the provided authorized
// key, and that the detached signature verifies. It is fail-closed: any mismatch
// returns an error. `authorized` is the ed25519 key the CONSUMER pins from its
// own store policy (never from the document) — pass the operator key the target
// trusts. `expectedStoreID` is the consumer's own store identity/destination.
func Verify(authorized ed25519.PublicKey, expectedStoreID string, doc DesiredGeneration) error {
	if doc.Schema != DesiredGenerationSchema {
		return fmt.Errorf("desired-generation schema mismatch: %q", doc.Schema)
	}
	if err := doc.validateUnsigned(); err != nil {
		return err
	}
	// Destination is a MANDATORY fail-closed check: an empty expectedStoreID is a
	// destination bypass, not a wildcard. The consumer must pin its own storeId.
	if expectedStoreID == "" {
		return errors.New("expectedStoreID (destination) is required — refusing to verify without a pinned destination")
	}
	if doc.StoreID != expectedStoreID {
		return fmt.Errorf("desired-generation destination mismatch: doc storeId %q != expected %q", doc.StoreID, expectedStoreID)
	}
	if len(authorized) != ed25519.PublicKeySize {
		return errors.New("authorized operator key is not a valid ed25519 public key")
	}
	authB58 := primitives.EncodeBase58(authorized)
	if doc.OperatorPubkey != authB58 {
		return fmt.Errorf("desired-generation signer mismatch: doc operator %q != authorized %q", doc.OperatorPubkey, authB58)
	}
	// generationHash must be the EXACT canonical (lowercase hex) content hash — an
	// uppercase/noncanonical value is rejected, not case-folded, so the served
	// bytes have exactly one valid representation.
	contentHash := GenerationContentHash(doc.Components)
	if doc.GenerationHash != hex.EncodeToString(contentHash[:]) {
		return errors.New("desired-generation content hash is not the canonical lowercase-hex content hash of the component set (generation drift or noncanonical hash)")
	}
	sig, err := primitives.DecodeBase58(doc.OperatorSignature)
	if err != nil {
		return fmt.Errorf("decode operator signature: %w", err)
	}
	if !ed25519.Verify(authorized, desiredGenerationMessage(doc, contentHash), sig) {
		return errors.New("desired-generation operator signature invalid")
	}
	return nil
}

// ── validation ────────────────────────────────────────────────────────────────

func isLowerHex(s string, n int) bool {
	if len(s) != n || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// safeComponentID allows the stable id vocabulary used by the registry keys and
// released artifacts: lowercase alphanumerics plus '-' and '_'. It is not a path
// segment check (that lives in the store's serve_gate.isSafePathSegment); it is
// the identity-token rule shared by the remote doc and the local allowlist.
func safeComponentID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return s[0] != '.' && !strings.Contains(s, "..")
}

func validClass(c string) bool {
	switch c {
	case ClassShell, ClassSidecar, ClassApp, ClassData:
		return true
	}
	return false
}

func validAuthority(a string) bool {
	switch a {
	case AuthorityInstallerRelease, AuthorityReleaseV2, AuthoritySidecarIdentity:
		return true
	}
	return false
}

// authorityForClass returns the ONE on-chain authority kind a component class is
// allowed to ride. Empty for an unknown class.
func authorityForClass(class string) string {
	switch class {
	case ClassShell, ClassData:
		return AuthorityInstallerRelease
	case ClassSidecar:
		return AuthoritySidecarIdentity
	case ClassApp:
		return AuthorityReleaseV2
	}
	return ""
}

// validate checks a component's on-chain authority reference is internally
// complete for its kind. It does NOT touch the chain — the consumer's controller
// re-derives + fetches these PDAs and confirms Active + hash pin at apply time.
func (ca ChainAuthority) validate() error {
	if !validAuthority(ca.Kind) {
		return fmt.Errorf("invalid chain authority kind %q", ca.Kind)
	}
	if strings.TrimSpace(ca.Program) == "" {
		return errors.New("empty chain.program")
	}
	switch ca.Kind {
	case AuthorityInstallerRelease, AuthorityReleaseV2:
		if strings.TrimSpace(ca.MasterNftMint) == "" {
			return fmt.Errorf("%s: empty masterNftMint", ca.Kind)
		}
		if strings.TrimSpace(ca.ReleasePDA) == "" {
			return fmt.Errorf("%s: empty releasePda", ca.Kind)
		}
	case AuthoritySidecarIdentity:
		if strings.TrimSpace(ca.LicenseNftMint) == "" {
			return errors.New("sidecar_identity: empty licenseNftMint")
		}
		if strings.TrimSpace(ca.MasterNftMint) == "" {
			return errors.New("sidecar_identity: empty masterNftMint (global-approval seed)")
		}
		if !safeComponentID(ca.SidecarID) {
			return errors.New("sidecar_identity: sidecarId is not a safe identity token")
		}
		if strings.TrimSpace(ca.IdentityPDA) == "" || strings.TrimSpace(ca.GlobalApprovalPDA) == "" || strings.TrimSpace(ca.LocalApprovalPDA) == "" {
			return errors.New("sidecar_identity: identityPda, globalApprovalPda and localApprovalPda are all required (three-PDA cascade)")
		}
	}
	return nil
}

// validate checks one component entry: real artifact identity, a plausible
// on-chain authority reference, and a bundle URL that is absolute-https and not
// GitHub (the store must never point a self-update at gh-pages).
func (c ComponentRelease) validate() error {
	if !safeComponentID(c.ComponentID) {
		return fmt.Errorf("componentId %q is not a safe identity token", c.ComponentID)
	}
	if !validClass(c.ComponentClass) {
		return fmt.Errorf("component %s: invalid class %q", c.ComponentID, c.ComponentClass)
	}
	if strings.TrimSpace(c.Version) == "" {
		return fmt.Errorf("component %s: empty version", c.ComponentID)
	}
	if c.Build < 0 {
		return fmt.Errorf("component %s: negative build", c.ComponentID)
	}
	if !isSafeArtifactName(c.ArtifactName) {
		return fmt.Errorf("component %s: artifactName %q is not a single safe filename", c.ComponentID, c.ArtifactName)
	}
	if !isLowerHex(c.SHA256, 64) {
		return fmt.Errorf("component %s: sha256 must be 64 lowercase hex chars", c.ComponentID)
	}
	if c.SizeBytes <= 0 {
		return fmt.Errorf("component %s: sizeBytes must be positive", c.ComponentID)
	}
	if err := assertBundleURLOnBazaar(c.BundleURL); err != nil {
		return fmt.Errorf("component %s: %w", c.ComponentID, err)
	}
	if err := c.Chain.validate(); err != nil {
		return fmt.Errorf("component %s: %w", c.ComponentID, err)
	}
	// class <-> on-chain authority must agree — the authority model IS the class
	// (a shell cannot ride a sidecar_identity, a sidecar cannot ride installer_release).
	if want := authorityForClass(c.ComponentClass); c.Chain.Kind != want {
		return fmt.Errorf("component %s: class %q requires authority kind %q, got %q", c.ComponentID, c.ComponentClass, want, c.Chain.Kind)
	}
	// contentSha256 = the on-chain-pinned content hash, distinct from the served
	// artifact sha256. An app MUST carry it (ReleaseEntry pins app_hash != sha256(spk)).
	if c.ContentSHA256 != "" && !isLowerHex(c.ContentSHA256, 64) {
		return fmt.Errorf("component %s: contentSha256 must be 64 lowercase hex chars", c.ComponentID)
	}
	if c.ComponentClass == ClassApp && c.ContentSHA256 == "" {
		return fmt.Errorf("component %s: app class requires contentSha256 (the ReleaseEntry-pinned app tree hash, distinct from the served artifact sha256)", c.ComponentID)
	}
	if c.ReleaseHash != "" && !isLowerHex(c.ReleaseHash, 64) {
		return fmt.Errorf("component %s: releaseHash must be 64 lowercase hex chars", c.ComponentID)
	}
	if c.StageID != "" && !isLowerHex(c.StageID, 64) {
		return fmt.Errorf("component %s: stageId must be 64 lowercase hex chars", c.ComponentID)
	}
	if c.PreviousSHA256 != "" && !isLowerHex(c.PreviousSHA256, 64) {
		return fmt.Errorf("component %s: previousSha256 must be 64 lowercase hex chars", c.ComponentID)
	}
	seenDep := make(map[string]bool, len(c.Requires))
	for _, d := range c.Requires {
		if !safeComponentID(d.ComponentID) {
			return fmt.Errorf("component %s: dependency id %q is not a safe identity token", c.ComponentID, d.ComponentID)
		}
		if seenDep[d.ComponentID] {
			return fmt.Errorf("component %s: duplicate dependency on %q (two conflicting constraints)", c.ComponentID, d.ComponentID)
		}
		seenDep[d.ComponentID] = true
	}
	return nil
}

// validateUnsigned checks everything except the signature (Sign runs it before
// signing; Verify runs it before checking the signature).
func (doc DesiredGeneration) validateUnsigned() error {
	if doc.GenerationID == 0 {
		return errors.New("generationId must be a positive monotonic integer")
	}
	if doc.PreviousGeneration >= doc.GenerationID {
		return fmt.Errorf("previousGeneration %d must be < generationId %d", doc.PreviousGeneration, doc.GenerationID)
	}
	if strings.TrimSpace(doc.StoreID) == "" {
		return errors.New("empty storeId")
	}
	if strings.TrimSpace(doc.Channel) == "" {
		return errors.New("empty channel")
	}
	if doc.SignedAtUnix <= 0 {
		return errors.New("signedAtUnix must be a positive unix time")
	}
	// bundleOrigin is the single pinned https origin every component's bundleUrl
	// must be under — a component cannot point a fetch at an arbitrary host.
	if err := assertBundleURLOnBazaar(doc.BundleOrigin); err != nil {
		return fmt.Errorf("bundleOrigin: %w", err)
	}
	originPrefix := strings.TrimRight(doc.BundleOrigin, "/") + "/"
	if len(doc.Components) == 0 {
		return errors.New("a generation must name at least one component")
	}
	isUpdate := doc.PreviousGeneration > 0
	seen := make(map[string]bool, len(doc.Components))
	for _, c := range doc.Components {
		if seen[c.ComponentID] {
			return fmt.Errorf("duplicate componentId %q", c.ComponentID)
		}
		seen[c.ComponentID] = true
		if err := c.validate(); err != nil {
			return err
		}
		if !strings.HasPrefix(c.BundleURL, originPrefix) {
			return fmt.Errorf("component %s: bundleUrl %q is not under the pinned bundleOrigin %q", c.ComponentID, c.BundleURL, doc.BundleOrigin)
		}
		// An UPDATE generation (previousGeneration > 0) must carry, per component,
		// the rollback floor (previousSha256 + previousVersion) and the release/
		// stage identity — without them health-gated rollback has no exact target.
		if isUpdate {
			if c.PreviousSHA256 == "" || strings.TrimSpace(c.PreviousVersion) == "" {
				return fmt.Errorf("component %s: an update generation requires previousSha256 + previousVersion (rollback floor)", c.ComponentID)
			}
			if c.ReleaseHash == "" || c.StageID == "" {
				return fmt.Errorf("component %s: an update generation requires releaseHash + stageId (release/stage identity)", c.ComponentID)
			}
		}
	}
	// Every dependency must reference a component present in this generation.
	for _, c := range doc.Components {
		for _, d := range c.Requires {
			if !seen[d.ComponentID] {
				return fmt.Errorf("component %s requires %s which is not in this generation", c.ComponentID, d.ComponentID)
			}
		}
	}
	// The dependency graph must be acyclic (the controller applies in topological
	// order; a cycle has no valid apply order).
	if cycle := dependencyCycle(doc.Components); cycle != "" {
		return fmt.Errorf("component dependency cycle involving %s", cycle)
	}
	return nil
}

// dependencyCycle returns a component id participating in a requires[] cycle, or
// "" if the graph is acyclic. Standard white/gray/black DFS.
func dependencyCycle(components []ComponentRelease) string {
	graph := make(map[string][]string, len(components))
	for _, c := range components {
		for _, d := range c.Requires {
			graph[c.ComponentID] = append(graph[c.ComponentID], d.ComponentID)
		}
	}
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(components))
	var found string
	var visit func(string) bool
	visit = func(n string) bool {
		color[n] = gray
		for _, m := range graph[n] {
			if color[m] == gray {
				found = m
				return true
			}
			if color[m] == white && visit(m) {
				return true
			}
		}
		color[n] = black
		return false
	}
	for _, c := range components {
		if color[c.ComponentID] == white && visit(c.ComponentID) {
			return found
		}
	}
	return ""
}

// Component returns the entry for id, or false if absent.
func (doc DesiredGeneration) Component(id string) (ComponentRelease, bool) {
	for _, c := range doc.Components {
		if c.ComponentID == id {
			return c, true
		}
	}
	return ComponentRelease{}, false
}

// isSafeArtifactName rejects an artifact name that is not a single filesystem-safe
// filename (no separators, no '..', no leading dot, printable ascii). It parallels
// serve_gate.isSafePathSegment but is defined here so the shared package has no
// dependency on the store's package main.
func isSafeArtifactName(s string) bool {
	if s == "" || len(s) > 255 || s[0] == '.' {
		return false
	}
	if strings.ContainsAny(s, "/\\") || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// assertBundleURLOnBazaar refuses a non-absolute-https URL or a GitHub-hosted one.
// Once the signature verifies, the consumer treats bundleUrl as authoritative, so
// the store must never sign a self-update that fetches a system binary from
// GitHub (the retired gh-pages path). Mirrors update_manifest.assertBundleURLOnBazaar.
func assertBundleURLOnBazaar(u string) error {
	if !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("must be an absolute https:// URL, got %q", u)
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		// "https://" or "https:///path" has no host — it would make EVERY https
		// host eligible. Reject an origin/URL without a concrete host.
		return fmt.Errorf("must be an absolute https:// URL with a host, got %q", u)
	}
	lower := strings.ToLower(u)
	for _, bad := range []string{"github.com", "githubusercontent.com", "github.io"} {
		if strings.Contains(lower, bad) {
			return fmt.Errorf("bundleUrl must be served from the bazaar, not GitHub (%s)", bad)
		}
	}
	return nil
}
