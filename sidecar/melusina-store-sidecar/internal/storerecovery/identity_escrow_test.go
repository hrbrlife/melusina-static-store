package storerecovery

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hrbrlife/melusina-attest/derive"
	"github.com/hrbrlife/melusina-attest/identity"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

func randomBase58(t *testing.T) string {
	t.Helper()
	var key primitives.Pubkey
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	return key.Base58()
}

func testOperatorRef(t *testing.T) identity.Ref {
	t.Helper()
	return identity.Ref{
		Kind: identity.KindSidecar, ChainID: "solana:recovery-test", ProgramID: randomBase58(t),
		LicenseMint: randomBase58(t), Domain: "store.recovery.test", PDA: randomBase58(t),
		SidecarID: "store", KeyVersion: 1,
	}
}

func testShards(t *testing.T) derive.SidecarShards {
	t.Helper()
	var shards derive.SidecarShards
	for _, role := range ShardRoles {
		if _, err := rand.Read(shardOf(&shards, role)[:]); err != nil {
			t.Fatal(err)
		}
	}
	return shards
}

func testHolder(t *testing.T) (*ecdh.PrivateKey, string) {
	t.Helper()
	private, err := GenerateRecoveryKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private, EncodeRecipient(private.PublicKey())
}

type escrowFixture struct {
	ref         identity.Ref
	shards      derive.SidecarShards
	operatorKey string
	boxKey      string
	holders     map[string][]*ecdh.PrivateKey
	recipients  IdentityEscrowRecipientsV1
	escrow      IdentityEscrow
	session     *ecdh.PrivateKey
}

func newEscrowFixture(t *testing.T) escrowFixture {
	t.Helper()
	f := escrowFixture{ref: testOperatorRef(t), shards: testShards(t), holders: map[string][]*ecdh.PrivateKey{}}
	operator, err := derive.DeriveSidecar(f.ref, f.shards)
	if err != nil {
		t.Fatal(err)
	}
	f.operatorKey, f.boxKey = operator.Public().SignPubkeyB58, operator.Public().BoxPubkeyB58
	f.recipients = IdentityEscrowRecipientsV1{Schema: IdentityEscrowRecipientsSchema}
	for role, count := range map[string]int{ShardRoleAuthor: 2, ShardRoleHostObservation: 1, ShardRoleRelease: 2} {
		for index := 0; index < count; index++ {
			private, recipient := testHolder(t)
			f.holders[role] = append(f.holders[role], private)
			switch role {
			case ShardRoleAuthor:
				f.recipients.Author = append(f.recipients.Author, recipient)
			case ShardRoleHostObservation:
				f.recipients.HostObservation = append(f.recipients.HostObservation, recipient)
			case ShardRoleRelease:
				f.recipients.Release = append(f.recipients.Release, recipient)
			}
		}
	}
	f.escrow, err = SealIdentityEscrow(rand.Reader, testStoreID, f.ref, f.shards, f.recipients, f.operatorKey)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	f.session, _ = testHolder(t)
	return f
}

func (f escrowFixture) handoff(t *testing.T, role string, holder int) []byte {
	t.Helper()
	raw, gotRole, err := ResealShard(rand.Reader, f.escrow.Manifest, f.operatorKey, f.escrow.Escrows[role], f.holders[role][holder], EncodeRecipient(f.session.PublicKey()))
	if err != nil {
		t.Fatalf("reseal %s: %v", role, err)
	}
	if gotRole != role {
		t.Fatalf("reseal returned role %s, want %s", gotRole, role)
	}
	return raw
}

func (f escrowFixture) handoffs(t *testing.T) [][]byte {
	t.Helper()
	return [][]byte{f.handoff(t, ShardRoleRelease, 1), f.handoff(t, ShardRoleAuthor, 0), f.handoff(t, ShardRoleHostObservation, 0)}
}

// One holder of each shard, each resealing to the replacement host's session
// key, rebuilds exactly the shards the Store derived its operator from.
func TestIdentityEscrowRoundTripRestoresExactShards(t *testing.T) {
	f := newEscrowFixture(t)
	restored, err := RestoreIdentity(f.escrow.Manifest, f.operatorKey, f.session, f.handoffs(t))
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored != f.shards {
		t.Fatal("restored shards differ from the escrowed shards")
	}
	dir := filepath.Join(t.TempDir(), "shards")
	if err := WriteShards(dir, restored); err != nil {
		t.Fatalf("write shards: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("shards directory mode = %v, %v", info, err)
	}
	for _, role := range ShardRoles {
		path := filepath.Join(dir, ShardFileName(role))
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		shard := shardOf(&f.shards, role)
		if string(content) != hex.EncodeToString(shard[:])+"\n" {
			t.Fatalf("%s holds %q", path, content)
		}
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", path, info.Mode())
		}
	}
	if err := WriteShards(dir, restored); RefusalName(err) != RefusalIdentityTargetNotEmpty {
		t.Fatalf("a second write over existing shards = %v, want %s", err, RefusalIdentityTargetNotEmpty)
	}
	// Every holder of a shard can do the step, not only the first.
	if _, err := RestoreIdentity(f.escrow.Manifest, f.operatorKey, f.session, [][]byte{f.handoff(t, ShardRoleAuthor, 1), f.handoff(t, ShardRoleHostObservation, 0), f.handoff(t, ShardRoleRelease, 0)}); err != nil {
		t.Fatalf("restore with the other holders: %v", err)
	}
}

func TestIdentityEscrowSealRefuses(t *testing.T) {
	f := newEscrowFixture(t)
	_, otherKey := testOperatorKey(t, 9)
	overlap := f.recipients
	overlap.Release = append(append([]string(nil), overlap.Release...), overlap.Author[0])
	twice := f.recipients
	twice.Author = []string{f.recipients.Author[0], f.recipients.Author[0]}
	none := f.recipients
	none.HostObservation = nil
	pearlRef := f.ref
	pearlRef.Kind = identity.KindPearl
	for _, tc := range []struct {
		name       string
		ref        identity.Ref
		recipients IdentityEscrowRecipientsV1
		key        string
		refusal    string
	}{
		{name: "genuine-control", ref: f.ref, recipients: f.recipients, key: f.operatorKey},
		{name: "one-holder-for-two-shards", ref: f.ref, recipients: overlap, key: f.operatorKey, refusal: RefusalIdentityHolderOverlap},
		{name: "recipient-named-twice", ref: f.ref, recipients: twice, key: f.operatorKey, refusal: RefusalIdentityRecipients},
		{name: "shard-without-holder", ref: f.ref, recipients: none, key: f.operatorKey, refusal: RefusalIdentityRecipients},
		{name: "not-the-running-operator", ref: f.ref, recipients: f.recipients, key: otherKey, refusal: RefusalIdentityOperatorMismatch},
		{name: "not-a-sidecar-ref", ref: pearlRef, recipients: f.recipients, key: f.operatorKey, refusal: RefusalIdentityRefInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SealIdentityEscrow(rand.Reader, testStoreID, tc.ref, f.shards, tc.recipients, tc.key)
			if tc.refusal == "" {
				if err != nil {
					t.Fatalf("positive control refused: %v", err)
				}
				return
			}
			requireRefusal(t, err, tc.refusal)
		})
	}
}

func TestIdentityEscrowResealRefuses(t *testing.T) {
	f := newEscrowFixture(t)
	_, otherKey := testOperatorKey(t, 9)
	stranger, _ := testHolder(t)
	session := EncodeRecipient(f.session.PublicKey())
	flipped := bytes.Replace(f.escrow.Escrows[ShardRoleAuthor], []byte(`"ciphertext":"`), []byte(`"ciphertext":"A`), 1)
	editedManifest := bytes.Replace(f.escrow.Manifest, []byte(`"key_version":1`), []byte(`"key_version":2`), 1)
	if bytes.Equal(editedManifest, f.escrow.Manifest) {
		t.Fatal("fixture: the manifest edit changed nothing")
	}
	for _, tc := range []struct {
		name     string
		manifest []byte
		key      string
		escrow   []byte
		holder   *ecdh.PrivateKey
		refusal  string
	}{
		{name: "genuine-control", manifest: f.escrow.Manifest, key: f.operatorKey, escrow: f.escrow.Escrows[ShardRoleAuthor], holder: f.holders[ShardRoleAuthor][0]},
		{name: "not-a-holder", manifest: f.escrow.Manifest, key: f.operatorKey, escrow: f.escrow.Escrows[ShardRoleAuthor], holder: stranger, refusal: RefusalIdentityNoEnvelope},
		{name: "holder-of-another-shard", manifest: f.escrow.Manifest, key: f.operatorKey, escrow: f.escrow.Escrows[ShardRoleAuthor], holder: f.holders[ShardRoleRelease][0], refusal: RefusalIdentityNoEnvelope},
		{name: "escrow-document-edited", manifest: f.escrow.Manifest, key: f.operatorKey, escrow: flipped, holder: f.holders[ShardRoleAuthor][0], refusal: RefusalIdentityDocumentMismatch},
		{name: "manifest-edited", manifest: editedManifest, key: f.operatorKey, escrow: f.escrow.Escrows[ShardRoleAuthor], holder: f.holders[ShardRoleAuthor][0], refusal: RefusalIdentityManifestSignature},
		{name: "another-operator-expected", manifest: f.escrow.Manifest, key: otherKey, escrow: f.escrow.Escrows[ShardRoleAuthor], holder: f.holders[ShardRoleAuthor][0], refusal: RefusalIdentityOperatorMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ResealShard(rand.Reader, tc.manifest, tc.key, tc.escrow, tc.holder, session)
			if tc.refusal == "" {
				if err != nil {
					t.Fatalf("positive control refused: %v", err)
				}
				return
			}
			requireRefusal(t, err, tc.refusal)
		})
	}
}

// forgedHandoff seals arbitrary bytes to the session as if a holder had
// resealed them: a dishonest or mistaken holder.
func forgedHandoff(t *testing.T, f escrowFixture, role string, payload []byte) []byte {
	t.Helper()
	manifest, manifestSHA256, err := VerifyIdentityEscrowManifest(f.escrow.Manifest, f.operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	handoff := IdentityShardHandoffV1{Schema: IdentityShardHandoffSchema, StoreID: manifest.StoreID, Role: role, OperatorKey: manifest.OperatorKey, Commitment: manifestEntry(manifest, role).Commitment, ManifestSHA256: manifestSHA256}
	if handoff.Envelope, err = sealTo(rand.Reader, EncodeRecipient(f.session.PublicKey()), handoffBinding(handoff), payload); err != nil {
		t.Fatal(err)
	}
	raw, err := canonicalDocument(handoff)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestIdentityRestoreRefuses(t *testing.T) {
	f := newEscrowFixture(t)
	other := newEscrowFixture(t)
	strangerSession, _ := testHolder(t)
	genuine := f.handoffs(t)
	wrongShard := make([]byte, 32)
	if _, err := rand.Read(wrongShard); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		session  *ecdh.PrivateKey
		handoffs [][]byte
		refusal  string
	}{
		{name: "genuine-control", session: f.session, handoffs: genuine},
		{name: "shard-missing", session: f.session, handoffs: genuine[:2], refusal: RefusalIdentityHandoffRoleMissing},
		{name: "shard-twice", session: f.session, handoffs: [][]byte{genuine[0], genuine[1], genuine[1]}, refusal: RefusalIdentityHandoffRoleDuplicate},
		{name: "sealed-to-another-session", session: strangerSession, handoffs: genuine, refusal: RefusalIdentityHandoffWrongSession},
		{name: "handoff-from-another-escrow", session: f.session, handoffs: [][]byte{genuine[0], genuine[1], other.handoff(t, ShardRoleHostObservation, 0)}, refusal: RefusalIdentityHandoffMismatch},
		{name: "holder-resealed-a-wrong-shard", session: f.session, handoffs: [][]byte{genuine[0], genuine[1], forgedHandoff(t, f, ShardRoleHostObservation, wrongShard)}, refusal: RefusalIdentityCommitmentMismatch},
		{name: "handoff-edited", session: f.session, handoffs: [][]byte{genuine[0], genuine[1], bytes.Replace(genuine[2], []byte(`"ciphertext":"`), []byte(`"ciphertext":"A`), 1)}, refusal: RefusalIdentityEnvelopeInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RestoreIdentity(f.escrow.Manifest, f.operatorKey, tc.session, tc.handoffs)
			if tc.refusal == "" {
				if err != nil {
					t.Fatalf("positive control refused: %v", err)
				}
				return
			}
			requireRefusal(t, err, tc.refusal)
		})
	}
}

// A manifest whose commitments and signature are self-consistent but whose
// shards derive another operator is refused at derivation: the commitments
// bind shards to the manifest, the derivation binds them to the operator.
func TestIdentityRestoreRequiresTheDerivedOperator(t *testing.T) {
	f := newEscrowFixture(t)
	signer, signerKey := testOperatorKey(t, 11)
	manifest, _, err := VerifyIdentityEscrowManifest(f.escrow.Manifest, f.operatorKey)
	if err != nil {
		t.Fatal(err)
	}
	manifest.OperatorKey = signerKey
	message, err := identitySigningMessage(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Signature = base64.RawURLEncoding.EncodeToString(signerFor(signer)(message))
	forged, err := canonicalDocument(manifest)
	if err != nil {
		t.Fatal(err)
	}
	forgedSHA := sha256.Sum256(forged)
	var handoffs [][]byte
	for _, role := range ShardRoles {
		handoff := IdentityShardHandoffV1{Schema: IdentityShardHandoffSchema, StoreID: manifest.StoreID, Role: role, OperatorKey: signerKey, Commitment: manifestEntry(manifest, role).Commitment, ManifestSHA256: hex.EncodeToString(forgedSHA[:])}
		shard := shardOf(&f.shards, role)
		if handoff.Envelope, err = sealTo(rand.Reader, EncodeRecipient(f.session.PublicKey()), handoffBinding(handoff), shard[:]); err != nil {
			t.Fatal(err)
		}
		raw, err := canonicalDocument(handoff)
		if err != nil {
			t.Fatal(err)
		}
		handoffs = append(handoffs, raw)
	}
	_, err = RestoreIdentity(forged, signerKey, f.session, handoffs)
	requireRefusal(t, err, RefusalIdentityDerivationMismatch)
}

// shardLeaks names every output that carries one of the shards in any
// encoding.
func shardLeaks(shards derive.SidecarShards, outputs map[string][]byte) []string {
	var leaks []string
	for _, role := range ShardRoles {
		shard := shardOf(&shards, role)
		encodings := map[string][]byte{
			"raw":       shard[:],
			"hex":       []byte(hex.EncodeToString(shard[:])),
			"HEX":       []byte(strings.ToUpper(hex.EncodeToString(shard[:]))),
			"base64":    []byte(base64.StdEncoding.EncodeToString(shard[:])),
			"base64url": []byte(base64.RawURLEncoding.EncodeToString(shard[:])),
			"base58":    []byte(primitives.EncodeBase58(shard[:])),
		}
		for output, raw := range outputs {
			for encoding, needle := range encodings {
				if bytes.Contains(raw, needle) {
					leaks = append(leaks, output+":"+role+":"+encoding)
				}
			}
		}
	}
	return leaks
}

// No public output carries a shard in any encoding.
func TestIdentityEscrowCarriesNoShardBytes(t *testing.T) {
	f := newEscrowFixture(t)
	outputs := map[string][]byte{"manifest": f.escrow.Manifest}
	for role, raw := range f.escrow.Escrows {
		outputs["escrow-"+role] = raw
	}
	for index, raw := range f.handoffs(t) {
		outputs[fmt.Sprintf("handoff-%d", index)] = raw
	}
	if leaks := shardLeaks(f.shards, outputs); len(leaks) != 0 {
		t.Fatalf("public outputs carry shards: %v", leaks)
	}
	// Positive control for the scan itself: each encoding of a shard planted
	// in an output is found.
	shard := shardOf(&f.shards, ShardRoleRelease)
	for encoding, planted := range map[string]string{
		"hex":       hex.EncodeToString(shard[:]),
		"base64url": base64.RawURLEncoding.EncodeToString(shard[:]),
		"base58":    primitives.EncodeBase58(shard[:]),
	} {
		leaky := map[string][]byte{"manifest": append(append([]byte(nil), f.escrow.Manifest...), planted...)}
		if leaks := shardLeaks(f.shards, leaky); len(leaks) == 0 {
			t.Fatalf("the scan does not find a planted %s shard", encoding)
		}
	}
}

func TestIdentityEscrowRecipientsDecodeIsStrict(t *testing.T) {
	f := newEscrowFixture(t)
	good, err := json.MarshalIndent(f.recipients, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIdentityEscrowRecipients(good); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	for name, raw := range map[string][]byte{
		"duplicate-key": bytes.Replace(good, []byte(`"schema"`), []byte(`"author": [],
  "schema"`), 1),
		"unknown-field": bytes.Replace(good, []byte(`"schema"`), []byte(`"custody": "anywhere",
  "schema"`), 1),
		"trailing-value": append(append([]byte(nil), good...), []byte(" {}")...),
		"wrong-schema":   bytes.Replace(good, []byte(IdentityEscrowRecipientsSchema), []byte("melusina.other.v1"), 1),
	} {
		if _, err := DecodeIdentityEscrowRecipients(raw); RefusalName(err) != RefusalIdentityRecipients {
			t.Fatalf("%s: decode = %v, want %s", name, err, RefusalIdentityRecipients)
		}
	}
}

func TestRecoveryKeyFiles(t *testing.T) {
	dir := t.TempDir()
	private, recipient := testHolder(t)
	path := filepath.Join(dir, "session.key")
	if err := WritePrivateKeyFile(path, private); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateKeyFile(path, private); RefusalName(err) != RefusalIdentityKeyFileInvalid {
		t.Fatalf("overwriting a key file = %v", err)
	}
	read, err := ReadPrivateKeyFile(path)
	if err != nil || EncodeRecipient(read.PublicKey()) != recipient {
		t.Fatalf("read back %v, %v", read, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateKeyFile(path); RefusalName(err) != RefusalIdentityKeyFileInvalid {
		t.Fatalf("a group-readable key file = %v, want %s", err, RefusalIdentityKeyFileInvalid)
	}
	if err := DestroyPrivateKeyFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("destroyed key file still exists: %v", err)
	}
	for name, content := range map[string]string{
		"public-key": recipient + "\n",
		"not-base64": "x25519-private:!!!!\n",
		"short":      "x25519-private:AAAA\n",
		"padded":     "x25519-private:" + base64.URLEncoding.EncodeToString(private.Bytes()) + "\n",
	} {
		if _, err := ParsePrivateKey([]byte(content)); RefusalName(err) != RefusalIdentityKeyFileInvalid {
			t.Fatalf("%s: parse = %v", name, err)
		}
	}
}
