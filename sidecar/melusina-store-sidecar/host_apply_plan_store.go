package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
)

const (
	hostApplyPlanDirName        = "host-apply-plans-v1"
	hostApplyProofDirName       = "host-apply-proofs-v1"
	hostApplyPlanIssuanceDir    = "host-apply-plan-issuances-v1"
	hostApplyPlanRecordSchema   = "bazaar-control-host-apply-plan-record-v1"
	hostApplyProofRecordSchema  = "bazaar-control-host-apply-proof-record-v1"
	hostApplyPlanIssuanceSchema = "bazaar-control-host-apply-plan-issuance-v1"

	maxHostApplyPlanRecordBytes   = 128 << 10
	maxHostApplyProofRecordBytes  = 128 << 10
	maxHostApplyPlanIssuanceBytes = 192 << 10
	maxHostApplyPlanRecords       = 4096
)

type hostApplyPlanRecord struct {
	Schema     string        `json:"schema"`
	Plan       hostApplyPlan `json:"plan"`
	PlanDigest string        `json:"planDigest"`
	CreatedAt  time.Time     `json:"createdAt"`
}

type hostApplyProofRecord struct {
	Schema      string               `json:"schema"`
	Proof       hostApplySquadsProof `json:"proof"`
	ProofDigest string               `json:"proofDigest"`
	CreatedAt   time.Time            `json:"createdAt"`
}

// hostApplyPlanIssuance retains the exact Store-signed receipt bytes as well
// as the immutable plan/proof identifiers that caused it. The public URL is
// derived only from AuthorizationID; it cannot select a plan or host action.
type hostApplyPlanIssuance struct {
	Schema          string    `json:"schema"`
	DossierID       string    `json:"dossierId"`
	PlanDigest      string    `json:"planDigest"`
	ProofDigest     string    `json:"proofDigest"`
	AuthorizationID string    `json:"authorizationId"`
	ReceiptSHA256   string    `json:"receiptSha256"`
	ReceiptB64      string    `json:"receiptB64"`
	CreatedAt       time.Time `json:"createdAt"`
}

func (r hostApplyPlanRecord) Validate() error {
	if r.Schema != hostApplyPlanRecordSchema || r.CreatedAt.IsZero() || r.PlanDigest != r.Plan.Digest() {
		return errors.New("host apply plan record has invalid immutable bindings")
	}
	return r.Plan.Validate(r.CreatedAt)
}

func (r hostApplyProofRecord) Validate(plan hostApplyPlan) error {
	if r.Schema != hostApplyProofRecordSchema || r.CreatedAt.IsZero() || r.ProofDigest != r.Proof.Digest() || r.Proof.PlanDigest != plan.Digest() {
		return errors.New("host apply proof record has invalid immutable bindings")
	}
	return r.Proof.Validate(plan, r.Proof.VerifiedAt)
}

func (r hostApplyPlanIssuance) receiptBytes() ([]byte, error) {
	if !isLowerHex(r.ReceiptSHA256, 64) || strings.TrimSpace(r.ReceiptB64) == "" {
		return nil, errors.New("host apply plan issuance has no canonical receipt bytes")
	}
	raw, err := base64.RawURLEncoding.DecodeString(r.ReceiptB64)
	if err != nil || len(raw) == 0 || len(raw) > maxHostApplyReceiptBytes {
		return nil, errors.New("host apply plan issuance receipt encoding is invalid")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != r.ReceiptSHA256 {
		return nil, errors.New("host apply plan issuance receipt hash does not match bytes")
	}
	return raw, nil
}

func (r hostApplyPlanIssuance) Validate(plan hostApplyPlan, proof hostApplySquadsProof) error {
	if r.Schema != hostApplyPlanIssuanceSchema || !isLowerHex(r.DossierID, 24) || r.DossierID != plan.DossierID ||
		r.PlanDigest != plan.Digest() || r.ProofDigest != proof.Digest() || !isLowerHex(r.AuthorizationID, 64) || r.CreatedAt.IsZero() {
		return errors.New("host apply plan issuance has invalid immutable bindings")
	}
	raw, err := r.receiptBytes()
	if err != nil {
		return err
	}
	receipt, err := decodeOneShotApplyReceipt(raw)
	if err != nil {
		return err
	}
	if receipt.Schema != componentrelease.OneShotApplyAuthorizationSchema || receipt.AuthorizationID != r.AuthorizationID ||
		receipt.GovernanceReceiptID != plan.DossierID || receipt.GovernanceReceiptSHA256 != plan.Digest() ||
		receipt.TargetControllerID != plan.TargetControllerID || receipt.TargetLicenseNftMint != plan.TargetLicenseNftMint ||
		receipt.ComponentID != plan.ComponentID || receipt.GenerationID != plan.GenerationID ||
		receipt.GenerationHash != plan.GenerationHash || receipt.RawGenerationSHA256 != plan.RawGenerationSHA256 ||
		receipt.ComponentDigest != plan.ComponentDigest || receipt.ComponentSHA256 != plan.ComponentSHA256 ||
		receipt.ComponentVersion != plan.ComponentVersion || receipt.PreviousSHA256 != plan.ExpectedPreviousSHA256 ||
		receipt.IssuedAtUnix <= 0 || receipt.ExpiresAtUnix <= receipt.IssuedAtUnix || strings.TrimSpace(receipt.StoreID) == "" ||
		strings.TrimSpace(receipt.OperatorPubkey) == "" || strings.TrimSpace(receipt.OperatorSignature) == "" {
		return errors.New("host apply plan issuance receipt does not bind its immutable plan")
	}
	return nil
}

type hostApplyPlanStore struct {
	plansRoot     string
	proofsRoot    string
	issuancesRoot string
	mu            sync.Mutex
}

func openOrInitializeHostApplyPlanStore(privateStageRoot string) (*hostApplyPlanStore, error) {
	if err := requireSecureDirectory(privateStageRoot, 0o700); err != nil {
		return nil, fmt.Errorf("host apply plan private-stage root: %w", err)
	}
	openDir := func(name string) (string, error) {
		root := filepath.Join(privateStageRoot, name)
		info, err := os.Lstat(root)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(root, 0o700); err != nil {
				return "", err
			}
			if err := syncDir(privateStageRoot); err != nil {
				return "", err
			}
		} else if err != nil {
			return "", err
		} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("not a real directory")
		}
		if err := requireSecureDirectory(root, 0o700); err != nil {
			return "", err
		}
		return root, nil
	}
	plans, err := openDir(hostApplyPlanDirName)
	if err != nil {
		return nil, fmt.Errorf("host apply plan directory: %w", err)
	}
	proofs, err := openDir(hostApplyProofDirName)
	if err != nil {
		return nil, fmt.Errorf("host apply proof directory: %w", err)
	}
	issuances, err := openDir(hostApplyPlanIssuanceDir)
	if err != nil {
		return nil, fmt.Errorf("host apply plan issuance directory: %w", err)
	}
	store := &hostApplyPlanStore{plansRoot: plans, proofsRoot: proofs, issuancesRoot: issuances}
	if err := store.validateLayout(); err != nil {
		return nil, err
	}
	return store, nil
}

func hostApplyPlanFile(root, key string, keyLen int) (string, error) {
	if !isLowerHex(key, keyLen) {
		return "", errors.New("invalid host apply immutable record key")
	}
	return filepath.Join(root, key+".json"), nil
}

func decodeStrictHostApplyJSON(raw []byte, out any) error {
	if len(raw) == 0 {
		return errors.New("empty immutable host apply record")
	}
	if err := assertNoDuplicateJSONKeys(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("immutable host apply record has trailing data")
	}
	return nil
}

func readHostApplyPlanRecord(path string) (hostApplyPlanRecord, bool, error) {
	var record hostApplyPlanRecord
	raw, err := readBoundedRegular(path, 0o600, maxHostApplyPlanRecordBytes)
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if err := decodeStrictHostApplyJSON(raw, &record); err != nil {
		return record, false, err
	}
	if err := record.Validate(); err != nil {
		return record, false, err
	}
	return record, true, nil
}

func readHostApplyProofRecord(path string) (hostApplyProofRecord, bool, error) {
	var record hostApplyProofRecord
	raw, err := readBoundedRegular(path, 0o600, maxHostApplyProofRecordBytes)
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if err := decodeStrictHostApplyJSON(raw, &record); err != nil {
		return record, false, err
	}
	if record.Schema != hostApplyProofRecordSchema || !isLowerHex(record.ProofDigest, 64) || record.CreatedAt.IsZero() {
		return record, false, errors.New("host apply proof record has invalid structural fields")
	}
	return record, true, nil
}

func readHostApplyPlanIssuance(path string) (hostApplyPlanIssuance, bool, error) {
	var record hostApplyPlanIssuance
	raw, err := readBoundedRegular(path, 0o600, maxHostApplyPlanIssuanceBytes)
	if errors.Is(err, os.ErrNotExist) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if err := decodeStrictHostApplyJSON(raw, &record); err != nil {
		return record, false, err
	}
	if record.Schema != hostApplyPlanIssuanceSchema || !isLowerHex(record.DossierID, 24) || !isLowerHex(record.PlanDigest, 64) ||
		!isLowerHex(record.ProofDigest, 64) || !isLowerHex(record.AuthorizationID, 64) || record.CreatedAt.IsZero() {
		return record, false, errors.New("host apply issuance record has invalid structural fields")
	}
	if _, err := record.receiptBytes(); err != nil {
		return record, false, err
	}
	return record, true, nil
}

func (s *hostApplyPlanStore) validateLayout() error {
	if s == nil {
		return errors.New("host apply plan store is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, root := range []string{s.plansRoot, s.proofsRoot, s.issuancesRoot} {
		if err := requireSecureDirectory(root, 0o700); err != nil {
			return err
		}
	}
	checks := []struct {
		root   string
		keyLen int
		read   func(string) (bool, error)
	}{
		{s.plansRoot, 24, func(path string) (bool, error) { _, found, err := readHostApplyPlanRecord(path); return found, err }},
		{s.proofsRoot, 64, func(path string) (bool, error) { _, found, err := readHostApplyProofRecord(path); return found, err }},
		{s.issuancesRoot, 24, func(path string) (bool, error) { _, found, err := readHostApplyPlanIssuance(path); return found, err }},
	}
	for _, check := range checks {
		names, err := readBoundedDirectoryNames(check.root, maxHostApplyPlanRecords)
		if err != nil {
			return err
		}
		for _, name := range names {
			key := strings.TrimSuffix(name, ".json")
			if !strings.HasSuffix(name, ".json") || !isLowerHex(key, check.keyLen) {
				return fmt.Errorf("unsafe host apply immutable record %q", name)
			}
			found, err := check.read(filepath.Join(check.root, name))
			if err != nil || !found {
				if err != nil {
					return err
				}
				return fmt.Errorf("host apply immutable record %q disappeared", name)
			}
		}
	}
	return nil
}

func writeHostApplyImmutable(path string, candidate any, maxBytes int64) error {
	raw, err := marshalBoundedJSON(candidate, maxBytes)
	if err != nil {
		return err
	}
	f, err := openExclusiveRegular(path, 0o600)
	if err != nil {
		return err
	}
	if err := writeAllBounded(f, raw, maxBytes); err != nil {
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
	return syncDir(filepath.Dir(path))
}

func (s *hostApplyPlanStore) loadPlan(dossierID string) (hostApplyPlanRecord, bool, error) {
	var zero hostApplyPlanRecord
	path, err := hostApplyPlanFile(s.plansRoot, dossierID, 24)
	if err != nil {
		return zero, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return readHostApplyPlanRecord(path)
}

func (s *hostApplyPlanStore) createPlan(candidate hostApplyPlanRecord) (hostApplyPlanRecord, bool, error) {
	var zero hostApplyPlanRecord
	if err := candidate.Validate(); err != nil {
		return zero, false, err
	}
	path, err := hostApplyPlanFile(s.plansRoot, candidate.Plan.DossierID, 24)
	if err != nil {
		return zero, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, found, err := readHostApplyPlanRecord(path); err != nil || found {
		if err != nil {
			return zero, false, err
		}
		if existing.PlanDigest != candidate.PlanDigest {
			return zero, false, errors.New("host apply dossier is already bound to different immutable plan facts")
		}
		return existing, false, nil
	}
	if names, err := readBoundedDirectoryNames(s.plansRoot, maxHostApplyPlanRecords); err != nil || len(names) >= maxHostApplyPlanRecords {
		if err != nil {
			return zero, false, err
		}
		return zero, false, errors.New("host apply plan capacity is exhausted")
	}
	if err := writeHostApplyImmutable(path, candidate, maxHostApplyPlanRecordBytes); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, found, readErr := readHostApplyPlanRecord(path)
			if readErr != nil || !found || existing.PlanDigest != candidate.PlanDigest {
				return zero, false, fmt.Errorf("read raced host apply plan: %w", readErr)
			}
			return existing, false, nil
		}
		return zero, false, err
	}
	return candidate, true, nil
}

func (s *hostApplyPlanStore) loadProof(planDigest string, plan hostApplyPlan) (hostApplyProofRecord, bool, error) {
	var zero hostApplyProofRecord
	path, err := hostApplyPlanFile(s.proofsRoot, planDigest, 64)
	if err != nil {
		return zero, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found, err := readHostApplyProofRecord(path)
	if err != nil || !found {
		return record, found, err
	}
	if err := record.Validate(plan); err != nil {
		return zero, false, err
	}
	return record, true, nil
}

func (s *hostApplyPlanStore) createProof(candidate hostApplyProofRecord, plan hostApplyPlan) (hostApplyProofRecord, bool, error) {
	var zero hostApplyProofRecord
	if err := candidate.Validate(plan); err != nil {
		return zero, false, err
	}
	path, err := hostApplyPlanFile(s.proofsRoot, candidate.Proof.PlanDigest, 64)
	if err != nil {
		return zero, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, found, err := readHostApplyProofRecord(path); err != nil || found {
		if err != nil {
			return zero, false, err
		}
		if err := existing.Validate(plan); err != nil {
			return zero, false, err
		}
		if existing.ProofDigest != candidate.ProofDigest {
			return zero, false, errors.New("host apply plan already has a different immutable Squads proof")
		}
		return existing, false, nil
	}
	if names, err := readBoundedDirectoryNames(s.proofsRoot, maxHostApplyPlanRecords); err != nil || len(names) >= maxHostApplyPlanRecords {
		if err != nil {
			return zero, false, err
		}
		return zero, false, errors.New("host apply proof capacity is exhausted")
	}
	if err := writeHostApplyImmutable(path, candidate, maxHostApplyProofRecordBytes); err != nil {
		return zero, false, err
	}
	return candidate, true, nil
}

func (s *hostApplyPlanStore) loadIssuance(dossierID string, plan hostApplyPlan, proof hostApplySquadsProof) (hostApplyPlanIssuance, bool, error) {
	var zero hostApplyPlanIssuance
	path, err := hostApplyPlanFile(s.issuancesRoot, dossierID, 24)
	if err != nil {
		return zero, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, found, err := readHostApplyPlanIssuance(path)
	if err != nil || !found {
		return record, found, err
	}
	if err := record.Validate(plan, proof); err != nil {
		return zero, false, err
	}
	return record, true, nil
}

func (s *hostApplyPlanStore) createIssuance(candidate hostApplyPlanIssuance, plan hostApplyPlan, proof hostApplySquadsProof) (hostApplyPlanIssuance, bool, error) {
	var zero hostApplyPlanIssuance
	if err := candidate.Validate(plan, proof); err != nil {
		return zero, false, err
	}
	path, err := hostApplyPlanFile(s.issuancesRoot, candidate.DossierID, 24)
	if err != nil {
		return zero, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, found, err := readHostApplyPlanIssuance(path); err != nil || found {
		if err != nil {
			return zero, false, err
		}
		if err := existing.Validate(plan, proof); err != nil {
			return zero, false, err
		}
		return existing, false, nil
	}
	if names, err := readBoundedDirectoryNames(s.issuancesRoot, maxHostApplyPlanRecords); err != nil || len(names) >= maxHostApplyPlanRecords {
		if err != nil {
			return zero, false, err
		}
		return zero, false, errors.New("host apply plan issuance capacity is exhausted")
	}
	if err := writeHostApplyImmutable(path, candidate, maxHostApplyPlanIssuanceBytes); err != nil {
		return zero, false, err
	}
	return candidate, true, nil
}

func (s *hostApplyPlanStore) findIssuanceByAuthorizationID(id string) (hostApplyPlanIssuance, bool, error) {
	var zero hostApplyPlanIssuance
	if !isLowerHex(id, 64) {
		return zero, false, errors.New("invalid host apply authorization id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	names, err := readBoundedDirectoryNames(s.issuancesRoot, maxHostApplyPlanRecords)
	if err != nil {
		return zero, false, err
	}
	for _, name := range names {
		record, found, err := readHostApplyPlanIssuance(filepath.Join(s.issuancesRoot, name))
		if err != nil || !found {
			if err != nil {
				return zero, false, err
			}
			return zero, false, errors.New("host apply issuance disappeared during lookup")
		}
		if record.AuthorizationID == id {
			return record, true, nil
		}
	}
	return zero, false, nil
}
