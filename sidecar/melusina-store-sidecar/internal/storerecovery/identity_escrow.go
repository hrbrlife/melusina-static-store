package storerecovery

import (
	"bytes"
	"crypto/ecdh"
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
	"sort"
	"syscall"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

// Store identity escrow.
//
// The Store operator key is derived from three attest shards and an identity
// Ref (derive.DeriveSidecar). The shards are the only secret: whoever holds
// all three and the public Ref holds the operator. A provider-identity escrow
// document opens for any one of its recipients, so escrowing the shard set as
// one document would hand the whole operator to each holder. Instead each
// shard is escrowed on its own, to its own holders, and no holder may be named
// for two shards: rebuilding the operator needs one holder of every shard.
//
// Flow:
//
//  1. seal (Store host): the Store derives its operator from the shards,
//     checks it is the operator it runs as, and seals each shard to that
//     shard's recipients. It emits three escrow documents and one manifest
//     signed by the operator: the public Ref and keys, and for each shard a
//     commitment, its recipients and its escrow document's digest.
//  2. reseal (each holder, offline): the holder opens its shard, checks it
//     against the manifest's commitment and seals it again to the one-time
//     session key of the replacement host, bound to that exact manifest.
//  3. restore (replacement host): the host opens the three handoffs with its
//     session key, checks every commitment, derives the operator and requires
//     the manifest's keys before it writes the shards.
//
// Recipients are always explicit inputs. This package names no holder and no
// custody location (owner decision D-2).
const (
	IdentityEscrowManifestSchema   = "melusina.store-identity-escrow-manifest.v1"
	IdentityShardEscrowSchema      = "melusina.store-identity-shard-escrow.v1"
	IdentityShardHandoffSchema     = "melusina.store-identity-shard-handoff.v1"
	IdentityEscrowRecipientsSchema = "melusina.store-identity-escrow-recipients.v1"

	identityManifestDomain = "MELUSINA_STORE_IDENTITY_ESCROW_MANIFEST_V1\n"
	shardCommitmentDomain  = "MELUSINA_STORE_IDENTITY_SHARD_COMMITMENT_V1\n"

	// MaxRecipientsPerShard bounds how many holders one shard is sealed to.
	MaxRecipientsPerShard    = 16
	maxIdentityDocumentBytes = 256 << 10
)

// Shard roles, in canonical order. Each role's file in the shards directory
// is <role>.shard, as boot-identity-prep writes it.
const (
	ShardRoleAuthor          = "author"
	ShardRoleHostObservation = "host-observation"
	ShardRoleRelease         = "release"
)

// ShardRoles lists the three roles in canonical order.
var ShardRoles = [...]string{ShardRoleAuthor, ShardRoleHostObservation, ShardRoleRelease}

// ShardFileName is the file a role's shard lives in.
func ShardFileName(role string) string { return role + ".shard" }

func shardOf(shards *derive.SidecarShards, role string) *[32]byte {
	switch role {
	case ShardRoleAuthor:
		return &shards.AuthorShard
	case ShardRoleHostObservation:
		return &shards.HostObservationShard
	case ShardRoleRelease:
		return &shards.ReleaseShard
	}
	return nil
}

// IdentityEscrowRecipientsV1 is the operator's escrow decision: the
// recipients of each shard. It is an input, never a default.
type IdentityEscrowRecipientsV1 struct {
	Schema          string   `json:"schema"`
	Author          []string `json:"author"`
	HostObservation []string `json:"hostObservation"`
	Release         []string `json:"release"`
}

func (r IdentityEscrowRecipientsV1) byRole() map[string][]string {
	return map[string][]string{ShardRoleAuthor: r.Author, ShardRoleHostObservation: r.HostObservation, ShardRoleRelease: r.Release}
}

// IdentityShardEntryV1 is one shard's public record in the manifest.
type IdentityShardEntryV1 struct {
	Role         string   `json:"role"`
	Commitment   string   `json:"commitment"`
	Recipients   []string `json:"recipients"`
	EscrowSHA256 string   `json:"escrowSha256"`
}

// IdentityEscrowManifestV1 is the operator-signed public record of one
// escrow: which identity, which keys it derives, and where each shard went.
type IdentityEscrowManifestV1 struct {
	Schema      string                 `json:"schema"`
	StoreID     string                 `json:"storeId"`
	OperatorRef identity.Ref           `json:"operatorRef"`
	OperatorKey string                 `json:"operatorKey"`
	BoxKey      string                 `json:"boxKey"`
	Shards      []IdentityShardEntryV1 `json:"shards"`
	Signature   string                 `json:"signature"`
}

// IdentityShardEscrowV1 is one shard sealed to each of its recipients. It is
// ciphertext and public values only.
type IdentityShardEscrowV1 struct {
	Schema      string             `json:"schema"`
	StoreID     string             `json:"storeId"`
	Role        string             `json:"role"`
	OperatorKey string             `json:"operatorKey"`
	Commitment  string             `json:"commitment"`
	Envelopes   []SealedEnvelopeV1 `json:"envelopes"`
}

// IdentityShardHandoffV1 is one shard a holder sealed again to a
// replacement host's session key, bound to one manifest.
type IdentityShardHandoffV1 struct {
	Schema         string           `json:"schema"`
	StoreID        string           `json:"storeId"`
	Role           string           `json:"role"`
	OperatorKey    string           `json:"operatorKey"`
	Commitment     string           `json:"commitment"`
	ManifestSHA256 string           `json:"manifestSha256"`
	Envelope       SealedEnvelopeV1 `json:"envelope"`
}

// IdentityEscrow is the output of a seal: every document is public.
type IdentityEscrow struct {
	Manifest       []byte
	ManifestSHA256 string
	Escrows        map[string][]byte
}

// ShardCommitment binds one shard to its Store, role and identity Ref. The
// shards are 32 uniformly random bytes, so the commitment reveals nothing a
// holder could use; it lets a holder and the replacement host prove that the
// shard they hold is the one the operator escrowed.
func ShardCommitment(storeID string, ref identity.Ref, role string, shard [32]byte) (string, error) {
	refJSON, err := json.Marshal(ref)
	if err != nil {
		return "", err
	}
	refDigest := sha256.Sum256(refJSON)
	digest := sha256.New()
	digest.Write([]byte(shardCommitmentDomain))
	digest.Write([]byte(storeID + "\n" + role + "\n"))
	digest.Write(refDigest[:])
	digest.Write(shard[:])
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// DecodeIdentityEscrowRecipients strictly decodes the operator's recipients
// file: its own fields only, no duplicate key, one value.
func DecodeIdentityEscrowRecipients(raw []byte) (IdentityEscrowRecipientsV1, error) {
	var recipients IdentityEscrowRecipientsV1
	if len(raw) == 0 || len(raw) > maxIdentityDocumentBytes || rejectDuplicateKeys(raw) != nil {
		return recipients, Refuse(RefusalIdentityRecipients, "not one JSON document without duplicate keys")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&recipients); err != nil || decoder.More() || recipients.Schema != IdentityEscrowRecipientsSchema {
		return IdentityEscrowRecipientsV1{}, Refuse(RefusalIdentityRecipients, "not exactly a "+IdentityEscrowRecipientsSchema+" document")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return IdentityEscrowRecipientsV1{}, Refuse(RefusalIdentityRecipients, "trailing data")
	}
	return recipients, nil
}

// canonicalRecipientSets validates every role's recipients and returns them
// sorted. Each shard needs between one and MaxRecipientsPerShard distinct
// canonical recipients, and no recipient may hold two shards.
func canonicalRecipientSets(byRole map[string][]string) (map[string][]string, error) {
	sets := make(map[string][]string, len(ShardRoles))
	holders := map[string]string{}
	for _, role := range ShardRoles {
		values := byRole[role]
		if len(values) == 0 || len(values) > MaxRecipientsPerShard {
			return nil, Refuse(RefusalIdentityRecipients, fmt.Sprintf("%s needs between one and %d recipients", role, MaxRecipientsPerShard))
		}
		sorted := append([]string(nil), values...)
		sort.Strings(sorted)
		for index, value := range sorted {
			if index > 0 && sorted[index-1] == value {
				return nil, Refuse(RefusalIdentityRecipients, role+" names a recipient twice")
			}
			if _, err := ParseRecipient(value); err != nil {
				return nil, Refuse(RefusalIdentityRecipients, role+" names a recipient that is not a canonical x25519 key")
			}
			if other, taken := holders[value]; taken {
				return nil, Refuse(RefusalIdentityHolderOverlap, value+" holds "+other+" and "+role)
			}
			holders[value] = role
		}
		sets[role] = sorted
	}
	return sets, nil
}

func validateOperatorRef(ref identity.Ref) error {
	if ref.Kind != identity.KindSidecar || ref.Validate() != nil || ref.SidecarID == "" || ref.AppHashHex != "" || ref.PearlIDHash != "" {
		return Refuse(RefusalIdentityRefInvalid, "")
	}
	return nil
}

// SealIdentityEscrow derives the operator from shards and ref, requires it to
// be expectedOperatorKey, and seals each shard to its recipients.
func SealIdentityEscrow(random io.Reader, storeID string, ref identity.Ref, shards derive.SidecarShards, recipients IdentityEscrowRecipientsV1, expectedOperatorKey string) (IdentityEscrow, error) {
	if random == nil {
		random = rand.Reader
	}
	if !storeIDPattern.MatchString(storeID) {
		return IdentityEscrow{}, Refuse(RefusalIdentityManifestMalformed, "storeId")
	}
	if recipients.Schema != IdentityEscrowRecipientsSchema {
		return IdentityEscrow{}, Refuse(RefusalIdentityRecipients, "schema")
	}
	if err := validateOperatorRef(ref); err != nil {
		return IdentityEscrow{}, err
	}
	sets, err := canonicalRecipientSets(recipients.byRole())
	if err != nil {
		return IdentityEscrow{}, err
	}
	operator, err := derive.DeriveSidecar(ref, shards)
	if err != nil {
		return IdentityEscrow{}, Refuse(RefusalIdentityRefInvalid, err.Error())
	}
	public := operator.Public()
	if public.SignPubkeyB58 != expectedOperatorKey {
		return IdentityEscrow{}, Refuse(RefusalIdentityOperatorMismatch, "the shards and Ref derive "+public.SignPubkeyB58)
	}
	manifest := IdentityEscrowManifestV1{
		Schema: IdentityEscrowManifestSchema, StoreID: storeID, OperatorRef: ref,
		OperatorKey: public.SignPubkeyB58, BoxKey: public.BoxPubkeyB58,
	}
	escrows := make(map[string][]byte, len(ShardRoles))
	for _, role := range ShardRoles {
		shard := *shardOf(&shards, role)
		commitment, err := ShardCommitment(storeID, ref, role, shard)
		if err != nil {
			return IdentityEscrow{}, err
		}
		document := IdentityShardEscrowV1{Schema: IdentityShardEscrowSchema, StoreID: storeID, Role: role, OperatorKey: manifest.OperatorKey, Commitment: commitment}
		for _, recipient := range sets[role] {
			envelope, err := sealTo(random, recipient, escrowBinding(document), shard[:])
			if err != nil {
				return IdentityEscrow{}, Refuse(RefusalIdentityRecipients, role+": "+err.Error())
			}
			document.Envelopes = append(document.Envelopes, envelope)
		}
		clear(shard[:])
		raw, err := canonicalDocument(document)
		if err != nil {
			return IdentityEscrow{}, err
		}
		digest := sha256.Sum256(raw)
		escrows[role] = raw
		manifest.Shards = append(manifest.Shards, IdentityShardEntryV1{Role: role, Commitment: commitment, Recipients: sets[role], EscrowSHA256: hex.EncodeToString(digest[:])})
	}
	message, err := identitySigningMessage(manifest)
	if err != nil {
		return IdentityEscrow{}, err
	}
	manifest.Signature = base64.RawURLEncoding.EncodeToString(operator.Sign(message))
	raw, err := canonicalDocument(manifest)
	if err != nil {
		return IdentityEscrow{}, err
	}
	if _, _, err := VerifyIdentityEscrowManifest(raw, expectedOperatorKey); err != nil {
		return IdentityEscrow{}, err
	}
	digest := sha256.Sum256(raw)
	return IdentityEscrow{Manifest: raw, ManifestSHA256: hex.EncodeToString(digest[:]), Escrows: escrows}, nil
}

// VerifyIdentityEscrowManifest strictly decodes a manifest and requires it to
// be signed by expectedOperatorKey, the key the caller already trusts (the
// recovery kit's rootStore.operatorKey or the owner-signed enrollment).
func VerifyIdentityEscrowManifest(raw []byte, expectedOperatorKey string) (IdentityEscrowManifestV1, string, error) {
	var manifest IdentityEscrowManifestV1
	if err := decodeCanonical(raw, maxIdentityDocumentBytes, &manifest); err != nil {
		return manifest, "", Refuse(RefusalIdentityManifestMalformed, err.Error())
	}
	if manifest.Schema != IdentityEscrowManifestSchema || !storeIDPattern.MatchString(manifest.StoreID) {
		return IdentityEscrowManifestV1{}, "", Refuse(RefusalIdentityManifestMalformed, "schema or storeId")
	}
	if err := validateOperatorRef(manifest.OperatorRef); err != nil {
		return IdentityEscrowManifestV1{}, "", err
	}
	key, err := parseEd25519Key(manifest.OperatorKey)
	if err != nil {
		return IdentityEscrowManifestV1{}, "", Refuse(RefusalIdentityManifestMalformed, "operatorKey")
	}
	if box, err := primitives.PubkeyFromBase58(manifest.BoxKey); err != nil || box.Base58() != manifest.BoxKey {
		return IdentityEscrowManifestV1{}, "", Refuse(RefusalIdentityManifestMalformed, "boxKey")
	}
	if _, err := parseEd25519Key(expectedOperatorKey); err != nil || manifest.OperatorKey != expectedOperatorKey {
		return IdentityEscrowManifestV1{}, "", Refuse(RefusalIdentityOperatorMismatch, manifest.OperatorKey)
	}
	signature, err := base64.RawURLEncoding.DecodeString(manifest.Signature)
	message, messageErr := identitySigningMessage(manifest)
	if err != nil || messageErr != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, message, signature) {
		return IdentityEscrowManifestV1{}, "", Refuse(RefusalIdentityManifestSignature, "")
	}
	if len(manifest.Shards) != len(ShardRoles) {
		return IdentityEscrowManifestV1{}, "", Refuse(RefusalIdentityManifestMalformed, "shards")
	}
	byRole := map[string][]string{}
	for index, entry := range manifest.Shards {
		if entry.Role != ShardRoles[index] || !sha256HexPattern.MatchString(entry.Commitment) || !sha256HexPattern.MatchString(entry.EscrowSHA256) || !sort.StringsAreSorted(entry.Recipients) {
			return IdentityEscrowManifestV1{}, "", Refuse(RefusalIdentityManifestMalformed, "shard "+entry.Role)
		}
		byRole[entry.Role] = entry.Recipients
	}
	if _, err := canonicalRecipientSets(byRole); err != nil {
		return IdentityEscrowManifestV1{}, "", err
	}
	digest := sha256.Sum256(raw)
	return manifest, hex.EncodeToString(digest[:]), nil
}

// DecodeIdentityShardEscrow strictly decodes one escrow document.
func DecodeIdentityShardEscrow(raw []byte) (IdentityShardEscrowV1, error) {
	var document IdentityShardEscrowV1
	if err := decodeCanonical(raw, maxIdentityDocumentBytes, &document); err != nil || document.Schema != IdentityShardEscrowSchema || shardOf(&derive.SidecarShards{}, document.Role) == nil {
		return IdentityShardEscrowV1{}, Refuse(RefusalIdentityDocumentMalformed, "")
	}
	return document, nil
}

// ResealShard is the holder's step. It opens the holder's own envelope in the
// escrow document the manifest names, proves the shard against the
// manifest's commitment, and seals it again to sessionRecipient, the
// replacement host's one-time key. The session recipient must reach the
// holder over a channel the owners authenticate; this function cannot tell a
// genuine session key from another one.
func ResealShard(random io.Reader, manifestRaw []byte, expectedOperatorKey string, escrowRaw []byte, holder *ecdh.PrivateKey, sessionRecipient string) ([]byte, string, error) {
	if random == nil {
		random = rand.Reader
	}
	manifest, manifestSHA256, err := VerifyIdentityEscrowManifest(manifestRaw, expectedOperatorKey)
	if err != nil {
		return nil, "", err
	}
	document, err := DecodeIdentityShardEscrow(escrowRaw)
	if err != nil {
		return nil, "", err
	}
	entry := manifestEntry(manifest, document.Role)
	escrowDigest := sha256.Sum256(escrowRaw)
	if entry == nil || hex.EncodeToString(escrowDigest[:]) != entry.EscrowSHA256 || document.StoreID != manifest.StoreID ||
		document.OperatorKey != manifest.OperatorKey || document.Commitment != entry.Commitment {
		return nil, "", Refuse(RefusalIdentityDocumentMismatch, document.Role)
	}
	if _, err := ParseRecipient(sessionRecipient); err != nil {
		return nil, "", Refuse(RefusalIdentityRecipients, "the session recipient is not a canonical x25519 key")
	}
	if holder == nil {
		return nil, "", Refuse(RefusalIdentityNoEnvelope, document.Role)
	}
	own := EncodeRecipient(holder.PublicKey())
	var plaintext []byte
	found := false
	for _, envelope := range document.Envelopes {
		if envelope.Recipient != own {
			continue
		}
		found = true
		if plaintext, err = openFrom(holder, escrowBinding(document), envelope); err != nil {
			return nil, "", Refuse(RefusalIdentityEnvelopeInvalid, document.Role+": "+err.Error())
		}
		break
	}
	if !found {
		return nil, "", Refuse(RefusalIdentityNoEnvelope, document.Role)
	}
	defer clear(plaintext)
	shard, err := verifiedShard(manifest, document.Role, plaintext)
	if err != nil {
		return nil, "", err
	}
	defer clear(shard[:])
	handoff := IdentityShardHandoffV1{
		Schema: IdentityShardHandoffSchema, StoreID: manifest.StoreID, Role: document.Role,
		OperatorKey: manifest.OperatorKey, Commitment: entry.Commitment, ManifestSHA256: manifestSHA256,
	}
	if handoff.Envelope, err = sealTo(random, sessionRecipient, handoffBinding(handoff), shard[:]); err != nil {
		return nil, "", Refuse(RefusalIdentityRecipients, "session: "+err.Error())
	}
	raw, err := canonicalDocument(handoff)
	if err != nil {
		return nil, "", err
	}
	return raw, document.Role, nil
}

// RestoreIdentity is the replacement host's step: exactly one handoff per
// shard, each sealed to this session and bound to this manifest, each shard
// matching its commitment, and the three together deriving the manifest's
// operator and box keys.
func RestoreIdentity(manifestRaw []byte, expectedOperatorKey string, session *ecdh.PrivateKey, handoffs [][]byte) (derive.SidecarShards, error) {
	var shards derive.SidecarShards
	manifest, manifestSHA256, err := VerifyIdentityEscrowManifest(manifestRaw, expectedOperatorKey)
	if err != nil {
		return shards, err
	}
	if session == nil {
		return shards, Refuse(RefusalIdentityHandoffWrongSession, "")
	}
	sessionRecipient := EncodeRecipient(session.PublicKey())
	seen := map[string]bool{}
	fail := func(err error) (derive.SidecarShards, error) {
		for _, role := range ShardRoles {
			clear(shardOf(&shards, role)[:])
		}
		return derive.SidecarShards{}, err
	}
	for _, raw := range handoffs {
		var handoff IdentityShardHandoffV1
		if err := decodeCanonical(raw, maxIdentityDocumentBytes, &handoff); err != nil || handoff.Schema != IdentityShardHandoffSchema || shardOf(&shards, handoff.Role) == nil {
			return fail(Refuse(RefusalIdentityHandoffMalformed, ""))
		}
		if seen[handoff.Role] {
			return fail(Refuse(RefusalIdentityHandoffRoleDuplicate, handoff.Role))
		}
		seen[handoff.Role] = true
		entry := manifestEntry(manifest, handoff.Role)
		if handoff.StoreID != manifest.StoreID || handoff.OperatorKey != manifest.OperatorKey || handoff.Commitment != entry.Commitment || handoff.ManifestSHA256 != manifestSHA256 {
			return fail(Refuse(RefusalIdentityHandoffMismatch, handoff.Role))
		}
		if handoff.Envelope.Recipient != sessionRecipient {
			return fail(Refuse(RefusalIdentityHandoffWrongSession, handoff.Role))
		}
		plaintext, err := openFrom(session, handoffBinding(handoff), handoff.Envelope)
		if err != nil {
			return fail(Refuse(RefusalIdentityEnvelopeInvalid, handoff.Role+": "+err.Error()))
		}
		shard, err := verifiedShard(manifest, handoff.Role, plaintext)
		clear(plaintext)
		if err != nil {
			return fail(err)
		}
		*shardOf(&shards, handoff.Role) = shard
		clear(shard[:])
	}
	for _, role := range ShardRoles {
		if !seen[role] {
			return fail(Refuse(RefusalIdentityHandoffRoleMissing, role))
		}
	}
	operator, err := derive.DeriveSidecar(manifest.OperatorRef, shards)
	if err != nil {
		return fail(Refuse(RefusalIdentityDerivationMismatch, err.Error()))
	}
	if public := operator.Public(); public.SignPubkeyB58 != manifest.OperatorKey || public.BoxPubkeyB58 != manifest.BoxKey {
		return fail(Refuse(RefusalIdentityDerivationMismatch, "the restored shards derive "+public.SignPubkeyB58))
	}
	return shards, nil
}

// WriteShards writes the three shards into dir exactly as boot-identity-prep
// does (lowercase hex and a newline, mode 0600). dir must be absent, its
// parent a real directory; it is created mode 0700. An existing directory is
// accepted only when it is empty and owner-only.
func WriteShards(dir string, shards derive.SidecarShards) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == string(filepath.Separator) {
		return Refuse(RefusalIdentityTargetNotEmpty, "the shards directory must be an absolute clean path")
	}
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(dir, 0o700); err != nil {
			return Refuse(RefusalIdentityTargetNotEmpty, err.Error())
		}
	case err != nil:
		return Refuse(RefusalIdentityTargetNotEmpty, err.Error())
	default:
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return Refuse(RefusalIdentityTargetNotEmpty, "the shards directory is not an owner-only directory")
		}
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			return Refuse(RefusalIdentityTargetNotEmpty, "")
		}
	}
	for _, role := range ShardRoles {
		shard := shardOf(&shards, role)
		content := []byte(hex.EncodeToString(shard[:]) + "\n")
		err := writeNewSecretFile(filepath.Join(dir, ShardFileName(role)), content)
		clear(content)
		if err != nil {
			return Refuse(RefusalIdentityTargetNotEmpty, err.Error())
		}
	}
	return syncDirectory(dir)
}

func writeNewSecretFile(path string, content []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func verifiedShard(manifest IdentityEscrowManifestV1, role string, plaintext []byte) ([32]byte, error) {
	var shard [32]byte
	if len(plaintext) != len(shard) {
		return shard, Refuse(RefusalIdentityCommitmentMismatch, role)
	}
	copy(shard[:], plaintext)
	commitment, err := ShardCommitment(manifest.StoreID, manifest.OperatorRef, role, shard)
	if err != nil || commitment != manifestEntry(manifest, role).Commitment {
		clear(shard[:])
		return [32]byte{}, Refuse(RefusalIdentityCommitmentMismatch, role)
	}
	return shard, nil
}

func manifestEntry(manifest IdentityEscrowManifestV1, role string) *IdentityShardEntryV1 {
	for index := range manifest.Shards {
		if manifest.Shards[index].Role == role {
			return &manifest.Shards[index]
		}
	}
	return nil
}

func escrowBinding(document IdentityShardEscrowV1) []string {
	return []string{document.Schema, document.StoreID, document.Role, document.OperatorKey, document.Commitment}
}

func handoffBinding(handoff IdentityShardHandoffV1) []string {
	return []string{handoff.Schema, handoff.StoreID, handoff.Role, handoff.OperatorKey, handoff.Commitment, handoff.ManifestSHA256}
}

func identitySigningMessage(manifest IdentityEscrowManifestV1) ([]byte, error) {
	manifest.Signature = ""
	body, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	return append([]byte(identityManifestDomain), body...), nil
}

// rejectDuplicateKeys walks raw as a JSON token stream and refuses an object
// that names one key twice at any depth.
func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, _ := keyToken.(string)
				if keys[key] {
					return errors.New("duplicate key " + key)
				}
				keys[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := decoder.Token()
			return err
		}
		return nil
	}
	return walk()
}
