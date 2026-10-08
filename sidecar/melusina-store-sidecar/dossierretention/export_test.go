package dossierretention

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, private
}

func fixture(t *testing.T, caseOverride ...string) (*Store, SourceClaim, ScopeClaim, []byte) {
	t.Helper()
	ccashPub, ccash := key(t)
	duePub, due := key(t)
	_, native := key(t)
	_, export := key(t)
	parent := t.TempDir()
	pearl := filepath.Join(parent, "pearl")
	if err := os.Mkdir(pearl, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(parent, "durable"), pearl, ccashPub, duePub,
		"storage-native", native, "storage-export", export)
	if err != nil {
		t.Fatal(err)
	}
	object := []byte("encrypted-dossier-ciphertext")
	objectSum := sha256.Sum256(object)
	sourceSum := sha256.Sum256([]byte("original-receipt"))
	caseRef, testerRef, correlationRef := "case-A", "tester-A", "corr-A"
	if len(caseOverride) == 1 {
		caseRef, testerRef, correlationRef = caseOverride[0], caseOverride[0], caseOverride[0]
	}
	source := SourceClaim{CaseRef: caseRef, TesterRef: testerRef, CorrelationRef: correlationRef,
		ObjectDigest: hex.EncodeToString(objectSum[:]), SourceReceiptDigest: hex.EncodeToString(sourceSum[:]),
		OriginalSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ccash, []byte("original-receipt")))}
	unsignedSource := source
	source.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ccash,
		append([]byte("ccash/dossier-retention-source/v1\n"), canonical(unsignedSource)...)))
	scope := ScopeClaim{CaseRef: source.CaseRef, TesterRef: source.TesterRef, CorrelationRef: source.CorrelationRef,
		ObjectDigest: source.ObjectDigest, SourceReceiptDigest: source.SourceReceiptDigest}
	scope.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(due,
		append([]byte("dueprocess/dossier-retention-scope/v1\n"), canonical(scope)...)))
	return s, source, scope, object
}

func TestExportDossierRetentionIntegrationFixture(t *testing.T) {
	output := os.Getenv("EVIDENCE_PACK_INTEGRATION_OUT")
	ccashPath, scopePath := os.Getenv("EVIDENCE_PACK_CCASH_DOSSIER"), os.Getenv("EVIDENCE_PACK_SCOPE_CLAIM")
	if output == "" || ccashPath == "" || scopePath == "" {
		t.Skip("source claims not set")
	}
	ccashBytes, err := os.ReadFile(ccashPath)
	if err != nil {
		t.Fatal(err)
	}
	var ccashArtifact struct {
		Claim     SourceClaim `json:"claim"`
		Encrypted []byte      `json:"encrypted"`
		PublicKey string      `json:"public_key"`
	}
	if err := json.Unmarshal(ccashBytes, &ccashArtifact); err != nil {
		t.Fatal(err)
	}
	scopeBytes, err := os.ReadFile(scopePath)
	if err != nil {
		t.Fatal(err)
	}
	var scopeArtifact struct {
		Claim     ScopeClaim `json:"claim"`
		PublicKey string     `json:"public_key"`
	}
	if err := json.Unmarshal(scopeBytes, &scopeArtifact); err != nil {
		t.Fatal(err)
	}
	ccashPublic, err := base64.RawURLEncoding.DecodeString(ccashArtifact.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	duePublic, err := base64.RawURLEncoding.DecodeString(scopeArtifact.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	pearl := filepath.Join(root, "pearl")
	if err := os.Mkdir(pearl, 0700); err != nil {
		t.Fatal(err)
	}
	grainRoot := os.Getenv("EVIDENCE_PACK_STORAGE_GRAIN_DIR")
	if grainRoot == "" {
		grainRoot = filepath.Join(root, "durable")
	}
	if err := os.MkdirAll(grainRoot, 0700); err != nil {
		t.Fatal(err)
	}
	native, _, nativeID, err := LoadOrCreateIdentity(grainRoot, "native")
	if err != nil {
		t.Fatal(err)
	}
	export, _, exportID, err := LoadOrCreateIdentity(grainRoot, "member")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(grainRoot, pearl, ccashPublic, duePublic, nativeID, native, exportID, export)
	if err != nil {
		t.Fatal(err)
	}
	source, scope, object := ccashArtifact.Claim, scopeArtifact.Claim, ccashArtifact.Encrypted
	if err := s.Put(source, scope, object); err != nil {
		t.Fatal(err)
	}
	member, err := s.Export("case-1", "case-1", "case-1")
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := json.Marshal(map[string]any{"body": json.RawMessage(member.Body), "key_id": member.KeyID,
		"signature": member.Signature, "public_key": base64.RawURLEncoding.EncodeToString(s.export.Public().(ed25519.PublicKey))})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, artifact, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestExportCompleteDurableDossierAndDeletionRefusal(t *testing.T) {
	s, source, scope, object := fixture(t)
	if err := s.Put(source, scope, object); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(source, scope, object); err != nil {
		t.Fatal("exact retry:", err)
	}
	member, err := s.Export("case-A", "tester-A", "corr-A")
	if err != nil {
		t.Fatal(err)
	}
	if member.KeyID != "storage-export" || len(member.Signature) == 0 {
		t.Fatal("unsigned member")
	}
	var body map[string]any
	if err := json.Unmarshal(member.Body, &body); err != nil {
		t.Fatal(err)
	}
	if body["object_digest"] != source.ObjectDigest || body["subject_digest"] != subject("case-A", "tester-A", "corr-A") {
		t.Fatal("lost source binding")
	}
	for _, needle := range []string{"encrypted-dossier-ciphertext", "original-receipt", "AliceSmith"} {
		if bytes.Contains(member.Body, []byte(needle)) {
			t.Fatalf("private bytes leaked: %s", needle)
		}
	}
	if _, err := s.Delete("case-A", "tester-A", "corr-A"); err == nil || !strings.Contains(err.Error(), "dossier-deletion-under-hold-refused") {
		t.Fatal("hold deletion accepted:", err)
	}
	if _, err := os.Stat(filepath.Join(s.root, source.ObjectDigest+".dossier")); err != nil {
		t.Fatal("object deleted:", err)
	}
}

func TestExportStorageMutationsByName(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*SourceClaim, *ScopeClaim, *[]byte)
		want   string
	}{
		{"cross-tester", func(source *SourceClaim, scope *ScopeClaim, object *[]byte) { scope.TesterRef = "tester-B" }, "pack-cross-tester"},
		{"another-case", func(source *SourceClaim, scope *ScopeClaim, object *[]byte) { scope.CaseRef = "case-B" }, "pack-cross-tester"},
		{"zero-original-signature", func(source *SourceClaim, scope *ScopeClaim, object *[]byte) {
			source.OriginalSignature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}, "evidence-pack-original-signature-invalid"},
		{"object-drift", func(source *SourceClaim, scope *ScopeClaim, object *[]byte) { *object = []byte("different") }, "dossier-object-digest-mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, source, scope, object := fixture(t)
			tc.mutate(&source, &scope, &object)
			if err := s.Put(source, scope, object); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s did not fail by name: %v", tc.want, err)
			}
		})
	}
}
