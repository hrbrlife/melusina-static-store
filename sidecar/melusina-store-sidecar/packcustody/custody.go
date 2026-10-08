// Package packcustody retains signed DueProcess evidence packs outside a
// disposable grain. Its authority roster must be supplied by a governed
// installer delivery; requests cannot nominate verification keys.
package packcustody

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const magic = "DP-EVIDENCE-PK1\n"
const packDomain = "dueprocess/evidence-pack/v1\n"
const memberDomain = "dueprocess/evidence-pack-member/v1\n"
const readDomain = "storage/evidence-pack-read/v1\n"
const maxPack = 256 << 20

var ref = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var roster = []string{"case.json", "configuration.json", "cyberteller.json", "decisions.json", "lease.json", "namedcoin.json", "posting.json", "reconciliation.json", "refusals.json", "retention.json"}
var sources = map[string]string{"case.json": "dueprocess", "configuration.json": "cca", "cyberteller.json": "cyberteller", "decisions.json": "dueprocess", "lease.json": "cca", "namedcoin.json": "namedcoin", "posting.json": "ccash", "reconciliation.json": "ccash", "refusals.json": "dueprocess", "retention.json": "storage"}

type descriptor struct {
	Name            string `json:"name"`
	Size            uint64 `json:"size"`
	SHA256          string `json:"sha256"`
	IssuerKeyID     string `json:"issuer_key_id"`
	IssuerSignature string `json:"issuer_signature"`
}

type manifest struct {
	Version         string       `json:"version"`
	CorrelationRef  string       `json:"correlation_ref"`
	CaseRef         string       `json:"case_ref"`
	CreatedAt       string       `json:"created_at"`
	RetentionUntil  *string      `json:"retention_until"`
	SignerKeyID     string       `json:"signer_key_id"`
	SignerPublicKey string       `json:"signer_public_key"`
	Members         []descriptor `json:"members"`
}

type index struct {
	CaseRef        string `json:"case_ref"`
	TesterRef      string `json:"tester_ref"`
	CorrelationRef string `json:"correlation_ref"`
	SignerKeyID    string `json:"signer_key_id"`
	Digest         string `json:"digest"`
	LegalHold      bool   `json:"legal_hold"`
}

// ReadClaim is signed by the same setup-pinned pack signer that wrote the
// object. The Station UI must authorize the user before it signs this claim.
type ReadClaim struct {
	CaseRef        string `json:"case_ref"`
	TesterRef      string `json:"tester_ref"`
	CorrelationRef string `json:"correlation_ref"`
	IssuedAt       string `json:"issued_at"`
	SignerKeyID    string `json:"signer_key_id"`
	Signature      string `json:"signature"`
}

type Custody struct {
	mu   sync.Mutex
	root string
	pins map[string]ed25519.PublicKey
}

func canonical(value any) []byte {
	// The wire format sorts keys recursively. Encoding a Go struct directly
	// preserves declaration order instead and would reject a genuine pack.
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var tree any
	if decoder.Decode(&tree) != nil {
		return nil
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(tree) != nil {
		return nil
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}

func validRef(s string) bool { return ref.MatchString(s) && s != "." && s != ".." }

func within(path, parent string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel))
}

// Open refuses an in-grain root and copies the public roster so later caller
// mutations cannot replace an accepted authority.
func Open(root, pearl string, pins map[string]ed25519.PublicKey) (*Custody, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(pearl) || len(pins) < 6 {
		return nil, errors.New("evidence-pack-custody-setup-invalid")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	actualRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	actualPearl, err := filepath.EvalSymlinks(pearl)
	if err != nil || within(actualRoot, actualPearl) || within(actualPearl, actualRoot) {
		return nil, errors.New("evidence-pack-custody-inside-pearl")
	}
	copyPins := make(map[string]ed25519.PublicKey, len(pins))
	owners := map[string]string{}
	for id, key := range pins {
		parts := strings.SplitN(id, "/", 2)
		if len(parts) != 2 || !validRef(parts[0]) || !validRef(parts[1]) || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("evidence-pack-custody-pin-invalid")
		}
		encoded := string(key)
		if prior := owners[encoded]; prior != "" && prior != parts[0] {
			return nil, errors.New("evidence-pack-custody-pin-not-distinct")
		}
		owners[encoded] = parts[0]
		copyPins[id] = append(ed25519.PublicKey(nil), key...)
	}
	for _, owner := range []string{"dueprocess", "namedcoin", "cyberteller", "ccash", "cca", "storage"} {
		found := false
		for id := range copyPins {
			found = found || strings.HasPrefix(id, owner+"/")
		}
		if !found {
			return nil, fmt.Errorf("evidence-pack-custody-pin-missing: %s", owner)
		}
	}
	return &Custody{root: actualRoot, pins: copyPins}, nil
}

func subject(caseRef, testerRef, correlationRef string) string {
	h := sha256.Sum256([]byte("dueprocess/evidence-pack-subject/v1\n" + caseRef + "\n" + testerRef + "\n" + correlationRef))
	return hex.EncodeToString(h[:])
}

func parseJSON(raw []byte, out any) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	return d.Decode(out) == nil && d.Decode(new(any)) == io.EOF && bytes.Equal(canonical(out), raw)
}

// Verify checks the complete wire stream, pack signature, each independently
// pinned source signature and every member's subject before storage or read.
func (s *Custody) Verify(pack []byte, caseRef, testerRef, correlationRef string) error {
	bad := func(detail string) error { return fmt.Errorf("pack-tamper: %s", detail) }
	if s == nil || !validRef(caseRef) || !validRef(testerRef) || !validRef(correlationRef) {
		return errors.New("pack-cross-tester")
	}
	if len(pack) < len(magic)+4+ed25519.SignatureSize || len(pack) > maxPack || !bytes.HasPrefix(pack, []byte(magic)) {
		return bad("wire-invalid")
	}
	pos := len(magic)
	manifestSize := int(binary.BigEndian.Uint32(pack[pos : pos+4]))
	pos += 4
	if manifestSize == 0 || manifestSize > 1<<20 || manifestSize > len(pack)-pos-ed25519.SignatureSize {
		return bad("manifest-size")
	}
	manifestBytes := pack[pos : pos+manifestSize]
	pos += manifestSize
	var header manifest
	if !parseJSON(manifestBytes, &header) || header.Version != "dueprocess-evidence-pack/1" ||
		len(header.Members) != len(roster) || !validRef(header.SignerKeyID) {
		return bad("manifest-invalid")
	}
	if header.CaseRef != caseRef || header.CorrelationRef != correlationRef {
		return errors.New("pack-cross-tester")
	}
	signer := s.pins["dueprocess/"+header.SignerKeyID]
	public, err := base64.RawURLEncoding.DecodeString(header.SignerPublicKey)
	if err != nil || len(signer) != ed25519.PublicKeySize || !bytes.Equal(public, signer) {
		return bad("signer-pin-mismatch")
	}
	for i, d := range header.Members {
		if d.Name != roster[i] || d.Size == 0 || d.Size > 64<<20 || !digest.MatchString(d.SHA256) || !validRef(d.IssuerKeyID) ||
			len(pack)-pos-ed25519.SignatureSize < 2 {
			return bad("descriptor-invalid")
		}
		nameLen := int(binary.BigEndian.Uint16(pack[pos : pos+2]))
		pos += 2
		if nameLen != len(d.Name) || len(pack)-pos-ed25519.SignatureSize < nameLen+8 || string(pack[pos:pos+nameLen]) != d.Name {
			return bad("frame-name")
		}
		pos += nameLen
		size := binary.BigEndian.Uint64(pack[pos : pos+8])
		pos += 8
		if size != d.Size || size > uint64(len(pack)-pos-ed25519.SignatureSize) {
			return bad("frame-size")
		}
		body := pack[pos : pos+int(size)]
		pos += int(size)
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != d.SHA256 {
			return bad("member-digest")
		}
		preimage := make([]byte, 0, len(memberDomain)+2+len(d.Name)+sha256.Size+2+len(correlationRef))
		preimage = append(preimage, memberDomain...)
		preimage = binary.BigEndian.AppendUint16(preimage, uint16(len(d.Name)))
		preimage = append(preimage, d.Name...)
		preimage = append(preimage, sum[:]...)
		preimage = binary.BigEndian.AppendUint16(preimage, uint16(len(correlationRef)))
		preimage = append(preimage, correlationRef...)
		sig, err := base64.RawURLEncoding.DecodeString(d.IssuerSignature)
		issuer := s.pins[sources[d.Name]+"/"+d.IssuerKeyID]
		if err != nil || len(issuer) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(issuer, preimage, sig) {
			return bad("source-attestation")
		}
		var member map[string]any
		if !parseJSON(body, &member) || member == nil {
			return bad("member-json")
		}
		if member["case_ref"] != caseRef || member["tester_ref"] != testerRef || member["correlation_ref"] != correlationRef ||
			member["subject_digest"] != subject(caseRef, testerRef, correlationRef) {
			return fmt.Errorf("pack-cross-tester: %s", d.Name)
		}
	}
	if pos != len(pack)-ed25519.SignatureSize {
		return bad("trailing-bytes")
	}
	preimage := make([]byte, 0, len(packDomain)+4+len(manifestBytes))
	preimage = append(preimage, packDomain...)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(manifestBytes)))
	preimage = append(preimage, manifestBytes...)
	if !ed25519.Verify(signer, preimage, pack[pos:]) {
		return bad("signature-invalid")
	}
	return nil
}

func key(caseRef string) string {
	h := sha256.Sum256([]byte("storage/evidence-pack-index/v1\n" + caseRef))
	return hex.EncodeToString(h[:])
}

func writeExclusive(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Put is append-only; a second write must be byte-identical, including its
// signed subject. A legal hold has no caller-controlled release operation.
func (s *Custody) Put(pack []byte, caseRef, testerRef, correlationRef string) (string, error) {
	if err := s.Verify(pack, caseRef, testerRef, correlationRef); err != nil {
		return "", err
	}
	manifestSize := int(binary.BigEndian.Uint32(pack[len(magic) : len(magic)+4]))
	var header manifest
	if !parseJSON(pack[len(magic)+4:len(magic)+4+manifestSize], &header) {
		return "", errors.New("pack-tamper: manifest-invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sum := sha256.Sum256(pack)
	value := hex.EncodeToString(sum[:])
	want := index{caseRef, testerRef, correlationRef, header.SignerKeyID, value, true}
	indexPath := filepath.Join(s.root, key(caseRef)+".json")
	objectPath := filepath.Join(s.root, value+".pack")
	if prior, err := os.ReadFile(indexPath); err == nil {
		object, readErr := os.ReadFile(objectPath)
		if readErr != nil || !bytes.Equal(prior, canonical(want)) || !bytes.Equal(object, pack) {
			return "", errors.New("evidence-pack-custody-conflict")
		}
		return value, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := writeExclusive(objectPath, pack); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
		prior, readErr := os.ReadFile(objectPath)
		if readErr != nil || !bytes.Equal(prior, pack) {
			return "", errors.New("evidence-pack-custody-conflict")
		}
	}
	if err := writeExclusive(indexPath, canonical(want)); err != nil {
		return "", err
	}
	d, err := os.Open(s.root)
	if err != nil {
		return "", err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return "", err
	}
	return value, nil
}

// SignReadClaim is called only after the Station WebSession role check. The
// custody daemon never receives the private key and verifies against its
// setup roster, so a request cannot introduce its own read authority.
func SignReadClaim(caseRef, testerRef, correlationRef, keyID string, private ed25519.PrivateKey, now time.Time) (ReadClaim, error) {
	if !validRef(caseRef) || !validRef(testerRef) || !validRef(correlationRef) || !validRef(keyID) || len(private) != ed25519.PrivateKeySize {
		return ReadClaim{}, errors.New("evidence-pack-read-claim-invalid")
	}
	claim := ReadClaim{CaseRef: caseRef, TesterRef: testerRef, CorrelationRef: correlationRef, IssuedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339), SignerKeyID: keyID}
	claim.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append([]byte(readDomain), canonical(claim)...)))
	return claim, nil
}

// Read verifies a short-lived signer claim and the retained pack anew.
func (s *Custody) Read(claim ReadClaim, now time.Time) ([]byte, string, error) {
	if s == nil || !validRef(claim.CaseRef) || !validRef(claim.TesterRef) || !validRef(claim.CorrelationRef) || !validRef(claim.SignerKeyID) {
		return nil, "", errors.New("pack-cross-tester")
	}
	issued, err := time.Parse(time.RFC3339, claim.IssuedAt)
	if err != nil || now.UTC().Before(issued) || now.UTC().Sub(issued) > time.Minute {
		return nil, "", errors.New("evidence-pack-read-claim-expired")
	}
	unsigned := claim
	unsigned.Signature = ""
	sig, err := base64.RawURLEncoding.DecodeString(claim.Signature)
	public := s.pins["dueprocess/"+claim.SignerKeyID]
	if err != nil || len(public) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(public, append([]byte(readDomain), canonical(unsigned)...), sig) {
		return nil, "", errors.New("evidence-pack-read-claim-signature-invalid")
	}
	indexPath := filepath.Join(s.root, key(claim.CaseRef)+".json")
	info, err := os.Lstat(indexPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return nil, "", errors.New("evidence-pack-custody-index-missing")
	}
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, "", err
	}
	var record index
	if !parseJSON(raw, &record) || record.CaseRef != claim.CaseRef || record.TesterRef != claim.TesterRef || record.CorrelationRef != claim.CorrelationRef || record.SignerKeyID != claim.SignerKeyID || !record.LegalHold || !digest.MatchString(record.Digest) {
		return nil, "", errors.New("pack-cross-tester")
	}
	path := filepath.Join(s.root, record.Digest+".pack")
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxPack {
		return nil, "", errors.New("evidence-pack-custody-object-missing")
	}
	pack, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(pack)
	if hex.EncodeToString(sum[:]) != record.Digest {
		return nil, "", errors.New("pack-tamper: retained-digest-drift")
	}
	if err := s.Verify(pack, claim.CaseRef, claim.TesterRef, claim.CorrelationRef); err != nil {
		return nil, "", err
	}
	return pack, record.Digest, nil
}
