// Package dossierretention owns durable, encrypted dossier storage and its
// source-signed evidence-pack member. The object root must be outside the
// disposable pearl. No caller can set a hold to false or erase an object.
package dossierretention

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var opaque = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SourceClaim is signed by the Ccash source after it has validated its
// original dossier storage receipt. The full encrypted object is stored here;
// an object digest alone cannot establish retention.
type SourceClaim struct {
	CaseRef             string `json:"case_ref"`
	TesterRef           string `json:"tester_ref"`
	CorrelationRef      string `json:"correlation_ref"`
	ObjectDigest        string `json:"object_digest"`
	SourceReceiptDigest string `json:"source_receipt_digest"`
	OriginalSignature   string `json:"original_signature"`
	Signature           string `json:"signature"`
}

// ScopeClaim is signed by DueProcess after resolving its durable case and
// final dossier. A source request cannot change the subject by supplying a
// different tester or case.
type ScopeClaim struct {
	CaseRef             string `json:"case_ref"`
	TesterRef           string `json:"tester_ref"`
	CorrelationRef      string `json:"correlation_ref"`
	ObjectDigest        string `json:"object_digest"`
	SourceReceiptDigest string `json:"source_receipt_digest"`
	Signature           string `json:"signature"`
}

type stored struct {
	Source SourceClaim `json:"source"`
	Scope  ScopeClaim  `json:"scope"`
}

type Member struct {
	Body      []byte `json:"body"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

type Store struct {
	mu         sync.Mutex
	root       string
	ccash      ed25519.PublicKey
	dueprocess ed25519.PublicKey
	nativeID   string
	native     ed25519.PrivateKey
	exportID   string
	export     ed25519.PrivateKey
}

func canonical(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func subject(caseRef, testerRef, correlationRef string) string {
	h := sha256.Sum256([]byte("dueprocess/evidence-pack-subject/v1\n" + caseRef + "\n" + testerRef + "\n" + correlationRef))
	return hex.EncodeToString(h[:])
}

func sigValid(encoded string, key ed25519.PublicKey, domain string, body any) bool {
	sig, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(key, append([]byte(domain+"\n"), canonical(body)...), sig)
}

func nonzeroSignature(encoded string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	for _, b := range sig {
		if b != 0 {
			return true
		}
	}
	return false
}

func validateClaims(source SourceClaim, scope ScopeClaim, ccash, dueprocess ed25519.PublicKey) error {
	if !opaque.MatchString(source.CaseRef) || !opaque.MatchString(source.TesterRef) ||
		!opaque.MatchString(source.CorrelationRef) || !digest.MatchString(source.ObjectDigest) ||
		!digest.MatchString(source.SourceReceiptDigest) || source.CaseRef == "." || source.CaseRef == ".." {
		return errors.New("dossier-source-claim-invalid")
	}
	if source.CaseRef != scope.CaseRef || source.TesterRef != scope.TesterRef ||
		source.CorrelationRef != scope.CorrelationRef || source.ObjectDigest != scope.ObjectDigest ||
		source.SourceReceiptDigest != scope.SourceReceiptDigest {
		return errors.New("pack-cross-tester")
	}
	if !nonzeroSignature(source.OriginalSignature) {
		return errors.New("evidence-pack-original-signature-invalid")
	}
	unsignedSource := source
	unsignedSource.Signature = ""
	unsignedScope := scope
	unsignedScope.Signature = ""
	if !sigValid(source.Signature, ccash, "ccash/dossier-retention-source/v1", unsignedSource) {
		return errors.New("dossier-ccash-attestation-invalid")
	}
	if !sigValid(scope.Signature, dueprocess, "dueprocess/dossier-retention-scope/v1", unsignedScope) {
		return errors.New("dossier-dueprocess-attestation-invalid")
	}
	return nil
}

// Open pins both upstream authorities and two distinct storage keys. The
// caller supplies custody keys from its governed configuration, never from a
// submitted member. The root is a separate durable mount, not a pearl path.
func Open(root, pearlDir string, ccash, dueprocess ed25519.PublicKey,
	nativeID string, native ed25519.PrivateKey, exportID string, export ed25519.PrivateKey) (*Store, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(pearlDir) || !opaque.MatchString(nativeID) ||
		!opaque.MatchString(exportID) || len(ccash) != ed25519.PublicKeySize ||
		len(dueprocess) != ed25519.PublicKeySize || len(native) != ed25519.PrivateKeySize ||
		len(export) != ed25519.PrivateKeySize || bytes.Equal(native.Public().(ed25519.PublicKey), export.Public().(ed25519.PublicKey)) {
		return nil, errors.New("dossier-storage-authority-invalid")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	actualRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	actualPearl, err := filepath.EvalSymlinks(pearlDir)
	if err != nil {
		return nil, err
	}
	if actualRoot == actualPearl || strings.HasPrefix(actualRoot, actualPearl+string(os.PathSeparator)) ||
		strings.HasPrefix(actualPearl, actualRoot+string(os.PathSeparator)) {
		return nil, errors.New("dossier-storage-inside-pearl")
	}
	return &Store{root: actualRoot, ccash: ccash, dueprocess: dueprocess, nativeID: nativeID,
		native: native, exportID: exportID, export: export}, nil
}

// Put persists the exact encrypted dossier and source claims before a member
// can be exported. Exact retries are idempotent; conflicting bytes are refused.
func (s *Store) Put(source SourceClaim, scope ScopeClaim, encrypted []byte) error {
	if s == nil || len(encrypted) == 0 || len(encrypted) > 64<<20 {
		return errors.New("dossier-object-invalid")
	}
	if err := validateClaims(source, scope, s.ccash, s.dueprocess); err != nil {
		return err
	}
	sum := sha256.Sum256(encrypted)
	if hex.EncodeToString(sum[:]) != source.ObjectDigest {
		return errors.New("dossier-object-digest-mismatch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	objectPath := filepath.Join(s.root, source.ObjectDigest+".dossier")
	indexPath := filepath.Join(s.root, source.CaseRef+".json")
	index := canonical(stored{source, scope})
	if existing, err := os.ReadFile(indexPath); err == nil {
		prior, readErr := os.ReadFile(objectPath)
		if readErr != nil || !bytes.Equal(existing, index) || !bytes.Equal(prior, encrypted) {
			return errors.New("dossier-retention-conflict")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeExclusive(objectPath, encrypted); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		prior, readErr := os.ReadFile(objectPath)
		if readErr != nil || !bytes.Equal(prior, encrypted) {
			return errors.New("dossier-retention-conflict")
		}
	}
	if err := writeExclusive(indexPath, index); err != nil {
		return err
	}
	return syncDir(s.root)
}

func writeExclusive(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *Store) load(caseRef, testerRef, correlationRef string) (stored, error) {
	var record stored
	if s == nil || !opaque.MatchString(caseRef) || !opaque.MatchString(testerRef) || !opaque.MatchString(correlationRef) {
		return record, errors.New("pack-cross-tester")
	}
	info, err := os.Lstat(filepath.Join(s.root, caseRef+".json"))
	if err != nil || !info.Mode().IsRegular() || info.Size() > 8192 {
		return record, errors.New("dossier-retention-record-missing")
	}
	raw, err := os.ReadFile(filepath.Join(s.root, caseRef+".json"))
	if err != nil || json.Unmarshal(raw, &record) != nil || !bytes.Equal(canonical(record), raw) {
		return record, errors.New("dossier-retention-record-invalid")
	}
	if err := validateClaims(record.Source, record.Scope, s.ccash, s.dueprocess); err != nil {
		return record, err
	}
	if record.Scope.CaseRef != caseRef || record.Scope.TesterRef != testerRef || record.Scope.CorrelationRef != correlationRef {
		return record, errors.New("pack-cross-tester")
	}
	object, err := os.ReadFile(filepath.Join(s.root, record.Scope.ObjectDigest+".dossier"))
	if err != nil || len(object) == 0 || len(object) > 64<<20 {
		return record, errors.New("dossier-retention-object-missing")
	}
	sum := sha256.Sum256(object)
	if hex.EncodeToString(sum[:]) != record.Scope.ObjectDigest {
		return record, errors.New("dossier-object-digest-mismatch")
	}
	return record, nil
}

func (s *Store) receipt(action string, record stored) string {
	body := map[string]any{"action": action, "correlation_ref": record.Scope.CorrelationRef,
		"case_ref": record.Scope.CaseRef, "tester_ref": record.Scope.TesterRef,
		"subject_digest":        subject(record.Scope.CaseRef, record.Scope.TesterRef, record.Scope.CorrelationRef),
		"source_receipt_digest": record.Scope.SourceReceiptDigest, "object_digest": record.Scope.ObjectDigest,
		"signer_key_id": s.nativeID}
	if action == "deletion-refused" {
		body["reason_code"] = "legal-hold"
	}
	body["signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.native,
		append([]byte("storage/dossier-retention-receipt/v1\n"), canonical(body)...)))
	return base64.RawURLEncoding.EncodeToString(canonical(body))
}

// Export resolves the subject solely from the verified durable record and
// signs the allowlisted member with the storage export key.
func (s *Store) Export(caseRef, testerRef, correlationRef string) (Member, error) {
	record, err := s.load(caseRef, testerRef, correlationRef)
	if err != nil {
		return Member{}, err
	}
	retrieval := sha256.Sum256([]byte("storage/dossier-retrieval-ref/v1\n" + record.Scope.ObjectDigest))
	body := canonical(map[string]any{
		"case_ref": caseRef, "tester_ref": testerRef, "correlation_ref": correlationRef,
		"subject_digest":    subject(caseRef, testerRef, correlationRef),
		"legal_schedule_id": "retain-all-pending-legal-ruling", "hold": true, "retention_until": nil,
		"storage_receipt": s.receipt("stored", record), "storage_issuer": s.nativeID,
		"object_digest": record.Scope.ObjectDigest, "retrieval_ref": hex.EncodeToString(retrieval[:]),
		"deletion_hold_refusal": s.receipt("deletion-refused", record),
	})
	sum := sha256.Sum256(body)
	var pre bytes.Buffer
	pre.WriteString("dueprocess/evidence-pack-member/v1\n")
	_ = binary.Write(&pre, binary.BigEndian, uint16(len("retention.json")))
	pre.WriteString("retention.json")
	pre.Write(sum[:])
	_ = binary.Write(&pre, binary.BigEndian, uint16(len(correlationRef)))
	pre.WriteString(correlationRef)
	return Member{Body: body, KeyID: s.exportID,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.export, pre.Bytes()))}, nil
}

// Delete is deliberately a refusal while the hold is active. It returns the
// native signed refusal that the evidence-pack member includes.
func (s *Store) Delete(caseRef, testerRef, correlationRef string) (string, error) {
	record, err := s.load(caseRef, testerRef, correlationRef)
	if err != nil {
		return "", err
	}
	return s.receipt("deletion-refused", record), errors.New("dossier-deletion-under-hold-refused")
}
