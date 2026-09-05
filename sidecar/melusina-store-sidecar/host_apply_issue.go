package main

// Governed issuance for a one-shot Fineract controller receipt.
//
// This is intentionally neither an app-control command nor a generic host
// command API. The private mTLS route accepts one purpose-bound policy-human
// decision, independently re-proves the exact currently served Fineract
// generation, and publishes one short-lived Store-signed receipt. The root
// controller still owns all host paths/actions and consumes the receipt once.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/componentrelease"
	primitives "github.com/melusina-os/melusina-solana-primitives"
)

const (
	hostApplyIssuePathPrefix   = "/control/v1/host-applies/"
	hostApplyIssuePathSuffix   = "/issue"
	hostApplyReceiptPathPrefix = "/update/one-shot/"

	hostApplyIssuanceDirName   = "host-apply-issuances-v1"
	hostApplyIssuanceSchema    = "bazaar-control-host-apply-issuance-v1"
	hostApplyIssueResultSchema = "bazaar-control-host-apply-issue-result-v1"

	maxHostApplyIssueBody     int64 = 96 << 10
	maxHostApplyIssuanceBytes       = 128 << 10
	maxHostApplyIssuances           = 4096
	maxHostApplyReceiptBytes        = 64 << 10

	// The legacy chain identity is deliberately never eligible for this rail.
	// `fineract-v2` is the new host-tier approval cascade; the component id stays
	// stable because it selects the root-owned controller registry entry.
	hostApplyFineractSidecarID = "fineract-v2"
)

// hostApplyIssueBody deliberately contains no artifact, component, URL, path,
// controller command, or Store selector. Every mutable fact is re-derived by
// the Store from its configured origin, operator, chain reader, and current
// signed DesiredGeneration.
type hostApplyIssueBody struct {
	HostApplyAuthorization hostApplyAuthorization `json:"hostApplyAuthorization"`
}

type hostApplyIssueResult struct {
	Schema          string    `json:"schema"`
	DossierID       string    `json:"dossierId"`
	AuthorizationID string    `json:"authorizationId"`
	ReceiptURL      string    `json:"receiptUrl"`
	ReceiptSHA256   string    `json:"receiptSha256"`
	ExpiresAt       time.Time `json:"expiresAt"`
}

// hostApplyIssuance is append-only. It persists exact signed receipt bytes
// BEFORE the public link is made, so a crash can be reconciled by retrying the
// same dossier without minting a second authority. We intentionally do not
// overwrite this record with a mutable “completed” state: an O_EXCL immutable
// record is stronger and an existing public file is reconciled byte-for-byte.
type hostApplyIssuance struct {
	Schema                 string                 `json:"schema"`
	HostApplyAuthorization hostApplyAuthorization `json:"hostApplyAuthorization"`
	AuthorizationDigest    string                 `json:"authorizationDigest"`
	AuthorizationID        string                 `json:"authorizationId"`
	ReceiptSHA256          string                 `json:"receiptSha256"`
	ReceiptB64             string                 `json:"receiptB64"`
	CreatedAt              time.Time              `json:"createdAt"`
}

type hostApplyIssuanceLedger struct {
	root string
	mu   sync.Mutex
}

func openOrInitializeHostApplyIssuanceLedger(privateStageRoot string) (*hostApplyIssuanceLedger, error) {
	if err := requireSecureDirectory(privateStageRoot, 0o700); err != nil {
		return nil, fmt.Errorf("host apply issuance private-stage root: %w", err)
	}
	root := filepath.Join(privateStageRoot, hostApplyIssuanceDirName)
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0o700); err != nil {
			return nil, fmt.Errorf("create host apply issuance directory: %w", err)
		}
		if err := syncDir(privateStageRoot); err != nil {
			return nil, fmt.Errorf("sync host apply issuance parent: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("inspect host apply issuance directory: %w", err)
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("host apply issuance directory is not a real directory")
	}
	if err := requireSecureDirectory(root, 0o700); err != nil {
		return nil, fmt.Errorf("host apply issuance directory: %w", err)
	}
	ledger := &hostApplyIssuanceLedger{root: root}
	if err := ledger.validateLayout(); err != nil {
		return nil, err
	}
	return ledger, nil
}

func (l *hostApplyIssuanceLedger) path(dossierID string) (string, error) {
	if l == nil || !isLowerHex(dossierID, 24) {
		return "", errors.New("invalid host apply dossier id")
	}
	return filepath.Join(l.root, dossierID+".json"), nil
}

func (i hostApplyIssuance) receiptBytes() ([]byte, error) {
	if !isLowerHex(i.ReceiptSHA256, 64) || strings.TrimSpace(i.ReceiptB64) == "" {
		return nil, errors.New("host apply issuance has no canonical receipt bytes")
	}
	raw, err := base64.RawURLEncoding.DecodeString(i.ReceiptB64)
	if err != nil || len(raw) == 0 || len(raw) > maxHostApplyReceiptBytes {
		return nil, errors.New("host apply issuance receipt encoding is invalid")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != i.ReceiptSHA256 {
		return nil, errors.New("host apply issuance receipt hash does not match bytes")
	}
	return raw, nil
}

func decodeOneShotApplyReceipt(raw []byte) (componentrelease.OneShotApplyAuthorization, error) {
	var receipt componentrelease.OneShotApplyAuthorization
	if len(raw) == 0 || len(raw) > maxHostApplyReceiptBytes {
		return receipt, errors.New("one-shot receipt has an invalid size")
	}
	if err := assertNoDuplicateJSONKeys(raw); err != nil {
		return receipt, fmt.Errorf("one-shot receipt duplicate key: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&receipt); err != nil {
		return receipt, fmt.Errorf("decode one-shot receipt: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return receipt, errors.New("one-shot receipt has trailing data")
	}
	return receipt, nil
}

func (i hostApplyIssuance) matchesAuthorization(a hostApplyAuthorization) error {
	if i.Schema != hostApplyIssuanceSchema || i.AuthorizationDigest != a.Digest() ||
		i.HostApplyAuthorization.Digest() != a.Digest() || i.HostApplyAuthorization.DossierID != a.DossierID {
		return errors.New("host apply dossier is already bound to different immutable facts")
	}
	if !isLowerHex(i.AuthorizationID, 64) || i.CreatedAt.IsZero() {
		return errors.New("host apply issuance has invalid immutable identity")
	}
	raw, err := i.receiptBytes()
	if err != nil {
		return err
	}
	receipt, err := decodeOneShotApplyReceipt(raw)
	if err != nil {
		return err
	}
	if receipt.Schema != componentrelease.OneShotApplyAuthorizationSchema ||
		receipt.AuthorizationID != i.AuthorizationID ||
		receipt.GovernanceReceiptID != a.DossierID ||
		receipt.GovernanceReceiptSHA256 != a.Digest() ||
		receipt.TargetControllerID != a.TargetControllerID ||
		receipt.TargetLicenseNftMint != a.TargetLicenseNftMint ||
		receipt.ComponentID != a.ComponentID ||
		receipt.GenerationID != a.GenerationID ||
		receipt.GenerationHash != a.GenerationHash ||
		receipt.RawGenerationSHA256 != a.RawGenerationSHA256 ||
		receipt.ComponentDigest != a.ComponentDigest ||
		receipt.ComponentSHA256 != a.ComponentSHA256 ||
		receipt.ComponentVersion != a.ComponentVersion ||
		receipt.PreviousSHA256 != a.ExpectedPreviousSHA256 ||
		receipt.IssuedAtUnix <= 0 || receipt.ExpiresAtUnix <= receipt.IssuedAtUnix ||
		strings.TrimSpace(receipt.StoreID) == "" || strings.TrimSpace(receipt.OperatorPubkey) == "" || strings.TrimSpace(receipt.OperatorSignature) == "" {
		return errors.New("host apply issuance receipt does not bind its immutable authorization")
	}
	return nil
}

func (i hostApplyIssuance) Validate() error {
	// Validate structural semantics at the issuance time, not the current wall
	// clock: retained expired records remain legitimate evidence and must not
	// stop a later Store boot or retention pass.
	if err := i.HostApplyAuthorization.Validate(i.HostApplyAuthorization.IssuedAt); err != nil {
		return fmt.Errorf("host apply issuance authorization is invalid: %w", err)
	}
	return i.matchesAuthorization(i.HostApplyAuthorization)
}

func (l *hostApplyIssuanceLedger) readLocked(path string) (hostApplyIssuance, bool, error) {
	var zero hostApplyIssuance
	raw, err := readBoundedRegular(path, 0o600, maxHostApplyIssuanceBytes)
	if errors.Is(err, os.ErrNotExist) {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, fmt.Errorf("read host apply issuance: %w", err)
	}
	if err := assertNoDuplicateJSONKeys(raw); err != nil {
		return zero, false, fmt.Errorf("host apply issuance duplicate key: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&zero); err != nil {
		return zero, false, fmt.Errorf("decode host apply issuance: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return zero, false, errors.New("host apply issuance has trailing data")
	}
	if err := zero.Validate(); err != nil {
		return hostApplyIssuance{}, false, err
	}
	return zero, true, nil
}

func (l *hostApplyIssuanceLedger) validateLayout() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.validateLayoutLocked()
}

func (l *hostApplyIssuanceLedger) validateLayoutLocked() error {
	if err := requireSecureDirectory(l.root, 0o700); err != nil {
		return fmt.Errorf("host apply issuance directory: %w", err)
	}
	names, err := readBoundedDirectoryNames(l.root, maxHostApplyIssuances)
	if err != nil {
		return fmt.Errorf("host apply issuance directory entries: %w", err)
	}
	for _, name := range names {
		if !strings.HasSuffix(name, ".json") || !isLowerHex(strings.TrimSuffix(name, ".json"), 24) {
			return fmt.Errorf("unsafe host apply issuance member %q", name)
		}
		if _, found, err := l.readLocked(filepath.Join(l.root, name)); err != nil || !found {
			if err != nil {
				return err
			}
			return fmt.Errorf("host apply issuance member %q disappeared", name)
		}
	}
	return nil
}

func (l *hostApplyIssuanceLedger) load(a hostApplyAuthorization) (hostApplyIssuance, bool, error) {
	var zero hostApplyIssuance
	path, err := l.path(a.DossierID)
	if err != nil {
		return zero, false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.validateLayoutLocked(); err != nil {
		return zero, false, err
	}
	record, found, err := l.readLocked(path)
	if err != nil || !found {
		return record, found, err
	}
	if err := record.matchesAuthorization(a); err != nil {
		return zero, false, err
	}
	return record, true, nil
}

// createOrLoad persists a completed immutable issuance with O_EXCL. If a
// second Store process or a concurrent request wins the race, exact facts load
// and return that same receipt; different facts refuse rather than overwriting.
func (l *hostApplyIssuanceLedger) createOrLoad(candidate hostApplyIssuance) (hostApplyIssuance, bool, error) {
	var zero hostApplyIssuance
	if err := candidate.Validate(); err != nil {
		return zero, false, fmt.Errorf("invalid host apply issuance: %w", err)
	}
	path, err := l.path(candidate.HostApplyAuthorization.DossierID)
	if err != nil {
		return zero, false, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.validateLayoutLocked(); err != nil {
		return zero, false, err
	}
	if existing, found, err := l.readLocked(path); err != nil || found {
		if err != nil {
			return zero, false, err
		}
		if err := existing.matchesAuthorization(candidate.HostApplyAuthorization); err != nil {
			return zero, false, err
		}
		return existing, false, nil
	}
	names, err := readBoundedDirectoryNames(l.root, maxHostApplyIssuances)
	if err != nil {
		return zero, false, fmt.Errorf("host apply issuance capacity: %w", err)
	}
	if len(names) >= maxHostApplyIssuances {
		return zero, false, errors.New("host apply issuance capacity is exhausted")
	}
	raw, err := marshalBoundedJSON(candidate, maxHostApplyIssuanceBytes)
	if err != nil {
		return zero, false, err
	}
	f, err := openExclusiveRegular(path, 0o600)
	if errors.Is(err, os.ErrExist) {
		existing, found, readErr := l.readLocked(path)
		if readErr != nil || !found {
			return zero, false, fmt.Errorf("read raced host apply issuance: %w", readErr)
		}
		if err := existing.matchesAuthorization(candidate.HostApplyAuthorization); err != nil {
			return zero, false, err
		}
		return existing, false, nil
	}
	if err != nil {
		return zero, false, fmt.Errorf("create host apply issuance: %w", err)
	}
	// Once O_EXCL succeeds, leave any partial or uncertain file in place. A
	// future attempt will fail closed during layout validation instead of
	// guessing whether an authority was emitted.
	if err := writeAllBounded(f, raw, maxHostApplyIssuanceBytes); err != nil {
		_ = f.Close()
		return zero, false, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return zero, false, err
	}
	if err := f.Close(); err != nil {
		return zero, false, err
	}
	if err := syncDir(l.root); err != nil {
		return zero, false, err
	}
	return candidate, true, nil
}

func (l *hostApplyIssuanceLedger) findAuthorizationID(id string) (hostApplyIssuance, bool, error) {
	var zero hostApplyIssuance
	if l == nil || !isLowerHex(id, 64) {
		return zero, false, errors.New("invalid one-shot authorization id")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.validateLayoutLocked(); err != nil {
		return zero, false, err
	}
	names, err := readBoundedDirectoryNames(l.root, maxHostApplyIssuances)
	if err != nil {
		return zero, false, err
	}
	for _, name := range names {
		record, found, err := l.readLocked(filepath.Join(l.root, name))
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

func parseHostApplyIssue(r *http.Request) (hostApplyAuthorization, error) {
	var zero hostApplyAuthorization
	if err := limitPublishBody(r, maxHostApplyIssueBody); err != nil {
		return zero, err
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return zero, fmt.Errorf("read request: %w", err)
	}
	if err := assertNoDuplicateJSONKeys(raw); err != nil {
		return zero, err
	}
	var body hostApplyIssueBody
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		return zero, err
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return zero, errors.New("request has trailing data")
	}
	return body.HostApplyAuthorization, nil
}

func hostApplyIssueDossier(path, rawQuery string) (string, error) {
	if rawQuery != "" || !strings.HasPrefix(path, hostApplyIssuePathPrefix) || !strings.HasSuffix(path, hostApplyIssuePathSuffix) {
		return "", errors.New("not a host apply issue route")
	}
	dossier := strings.TrimSuffix(strings.TrimPrefix(path, hostApplyIssuePathPrefix), hostApplyIssuePathSuffix)
	if strings.Contains(dossier, "/") || !isLowerHex(dossier, 24) {
		return "", errors.New("host apply issue route must name one canonical dossier")
	}
	return dossier, nil
}

func hostApplyReceiptID(path, rawQuery string) (string, error) {
	if rawQuery != "" || !strings.HasPrefix(path, hostApplyReceiptPathPrefix) {
		return "", errors.New("not a one-shot receipt route")
	}
	name := strings.TrimPrefix(path, hostApplyReceiptPathPrefix)
	if strings.Contains(name, "/") || !strings.HasSuffix(name, ".json") {
		return "", errors.New("one-shot receipt route must name one file")
	}
	id := strings.TrimSuffix(name, ".json")
	if !isLowerHex(id, 64) {
		return "", errors.New("one-shot receipt name is not canonical")
	}
	return id, nil
}

func newHostApplyAuthorizationID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func minHostApplyReceiptExpiry(now time.Time, approvalExpires time.Time) (int64, error) {
	now = now.UTC().Truncate(time.Second)
	expires := now.Add(time.Duration(componentrelease.MaxOneShotApplyAuthorizationTTLSeconds) * time.Second)
	if approvalExpires.UTC().Before(expires) {
		expires = approvalExpires.UTC().Truncate(time.Second)
	}
	if expires.Unix() <= now.Unix() {
		return 0, errors.New("host apply authorization expires before a controller receipt can be issued")
	}
	return expires.Unix(), nil
}

func verifyHostApplyCurrentBinding(a hostApplyAuthorization, doc componentrelease.DesiredGeneration, raw []byte) (componentrelease.ComponentRelease, error) {
	component, targetLicense, err := verifyHostApplyCurrentComponent(doc, raw)
	if err != nil {
		return componentrelease.ComponentRelease{}, err
	}
	rawHash := sha256.Sum256(raw)
	for label, gotWant := range map[string][2]string{
		"target license":           {a.TargetLicenseNftMint, targetLicense.Base58()},
		"generation hash":          {a.GenerationHash, doc.GenerationHash},
		"raw generation sha256":    {a.RawGenerationSHA256, hex.EncodeToString(rawHash[:])},
		"component digest":         {a.ComponentDigest, componentrelease.ComponentReleaseDigestHex(component)},
		"component sha256":         {a.ComponentSHA256, component.SHA256},
		"component version":        {a.ComponentVersion, component.Version},
		"expected previous sha256": {a.ExpectedPreviousSHA256, component.PreviousSHA256},
	} {
		if gotWant[0] != gotWant[1] {
			return componentrelease.ComponentRelease{}, fmt.Errorf("host apply authorization %s does not bind the current generation", label)
		}
	}
	if a.GenerationID != doc.GenerationID {
		return componentrelease.ComponentRelease{}, errors.New("host apply authorization generation id does not bind the current generation")
	}
	return component, nil
}

func (s *publishService) hostApplyIssueReadinessError() error {
	if s == nil || s.operator == nil || s.cr == nil || s.hostApplyIssuances == nil || s.hostApplyIssuanceErr != nil {
		return errors.New("host apply issuance dependencies are unavailable")
	}
	return nil
}

// handleHostApplyIssue is owned solely by the Store Link mTLS listener. It
// makes no claim that the supplied policy-human approval is a separate Squads
// quorum: the current on-chain StoreControlPolicy exposes one human key. The
// purpose-specific policy signature, chain operator authorization, and exact
// current release re-verification are all independently required here.
func (s *publishService) handleHostApplyIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dossierID, err := hostApplyIssueDossier(r.URL.Path, r.URL.RawQuery)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		http.Error(w, "check=request: content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	if rejectReceiveBypass(w) {
		return
	}
	authorization, err := parseHostApplyIssue(r)
	if err != nil {
		http.Error(w, "check=request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if authorization.DossierID != dossierID {
		http.Error(w, "check=authorization: authorization does not name this dossier", http.StatusForbidden)
		return
	}
	if err := s.hostApplyIssueReadinessError(); err != nil {
		http.Error(w, "host apply issuance is unavailable", http.StatusServiceUnavailable)
		return
	}

	// The policy, Store operator, selected generation, chain cascade, served
	// artifact, and issuance ledger all share this lock. A concurrent promotion
	// cannot slip a different generation between this re-check and signing.
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.currentTime().UTC().Truncate(time.Second)
	policy, err := fetchActiveStoreControlPolicy(r.Context(), s.cfg, s.cr)
	if err != nil {
		http.Error(w, "check=policy: "+err.Error(), http.StatusConflict)
		return
	}
	if err := verifyHostApplyAuthorization(authorization, policy, now); err != nil {
		http.Error(w, "check=authorization: "+err.Error(), http.StatusForbidden)
		return
	}
	operatorPub, err := signPubkey32(s.operator.Public())
	if err != nil {
		http.Error(w, "check=store_operator: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, _, err := VerifyStoreOperator(r.Context(), s.cr, s.cfg, operatorPub, false); err != nil {
		http.Error(w, "check=store_operator: "+err.Error(), http.StatusForbidden)
		return
	}
	doc, rawGeneration, err := s.loadVerifiedDesiredGeneration()
	if err != nil {
		http.Error(w, "check=generation: "+err.Error(), http.StatusConflict)
		return
	}
	component, err := verifyHostApplyCurrentBinding(authorization, doc, rawGeneration)
	if err != nil {
		http.Error(w, "check=generation_binding: "+err.Error(), http.StatusConflict)
		return
	}
	targetLicense, err := primitives.PubkeyFromBase58(strings.TrimSpace(component.Chain.LicenseNftMint))
	if err != nil {
		http.Error(w, "check=generation_binding: current component has invalid target license", http.StatusConflict)
		return
	}
	if err := s.verifyComponentReleaseOnChain(r.Context(), component); err != nil {
		http.Error(w, "check=component_chain: "+err.Error(), componentChainStatus(err))
		return
	}

	// An exact retry gets the same immutable receipt. The policy and dynamic
	// facts above were still re-read first, so a revoked operator/policy cannot
	// use an old HTTP body to mint or re-advertise authority.
	record, found, err := s.hostApplyIssuances.load(authorization)
	if err != nil {
		http.Error(w, "check=issuance: "+err.Error(), http.StatusConflict)
		return
	}
	if !found {
		id, err := newHostApplyAuthorizationID()
		if err != nil {
			http.Error(w, "check=issuance: random authorization id: "+err.Error(), http.StatusInternalServerError)
			return
		}
		expiresAtUnix, err := minHostApplyReceiptExpiry(now, authorization.ExpiresAt)
		if err != nil {
			http.Error(w, "check=issuance: "+err.Error(), http.StatusConflict)
			return
		}
		receipt := oneShotFromHostApply(authorization, s.cfg.StoreID, id, now.Unix(), expiresAtUnix)
		receipt, err = componentrelease.SignOneShotApplyAuthorization(s.operator, receipt)
		if err != nil {
			http.Error(w, "check=issuance: sign receipt: "+err.Error(), http.StatusInternalServerError)
			return
		}
		receiptBytes, err := marshalBoundedJSON(receipt, maxHostApplyReceiptBytes)
		if err != nil {
			http.Error(w, "check=issuance: marshal receipt: "+err.Error(), http.StatusInternalServerError)
			return
		}
		receiptHash := sha256.Sum256(receiptBytes)
		candidate := hostApplyIssuance{
			Schema:                 hostApplyIssuanceSchema,
			HostApplyAuthorization: authorization,
			AuthorizationDigest:    authorization.Digest(),
			AuthorizationID:        id,
			ReceiptSHA256:          hex.EncodeToString(receiptHash[:]),
			ReceiptB64:             base64.RawURLEncoding.EncodeToString(receiptBytes),
			CreatedAt:              now,
		}
		record, _, err = s.hostApplyIssuances.createOrLoad(candidate)
		if err != nil {
			http.Error(w, "check=issuance: "+err.Error(), http.StatusConflict)
			return
		}
	}
	receiptBytes, err := record.receiptBytes()
	if err != nil {
		http.Error(w, "check=issuance: stored receipt: "+err.Error(), http.StatusConflict)
		return
	}
	receipt, err := decodeOneShotApplyReceipt(receiptBytes)
	if err != nil {
		http.Error(w, "check=issuance: stored receipt decode: "+err.Error(), http.StatusInternalServerError)
		return
	}
	operatorKey, err := operatorSignPublicKey(s.operator)
	if err != nil {
		http.Error(w, "check=issuance: operator key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := componentrelease.VerifyOneShotApplyAuthorization(operatorKey, componentrelease.OneShotApplyExpectation{
		ExpectedStoreID:      s.cfg.StoreID,
		TargetControllerID:   hostApplyFineractControllerID,
		TargetLicenseNftMint: targetLicense.Base58(),
		ComponentID:          hostApplyFineractComponentID,
		GenerationID:         doc.GenerationID,
		GenerationHash:       doc.GenerationHash,
		RawGenerationSHA256:  authorization.RawGenerationSHA256,
		Component:            component,
		NowUnix:              now.Unix(),
	}, receipt); err != nil {
		// This check is deliberately after load/create but before publication:
		// it proves an existing immutable ledger record remains signed by THIS
		// Store operator and bound to THIS freshly re-verified generation before
		// its public URL can be created or returned again.
		http.Error(w, "check=issuance: stored receipt verification: "+err.Error(), http.StatusConflict)
		return
	}
	if err := publishHostApplyReceipt(s.cfg.DistDir, record.AuthorizationID, receiptBytes); err != nil {
		http.Error(w, "check=receipt_publish: "+err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(hostApplyIssueResult{
		Schema:          hostApplyIssueResultSchema,
		DossierID:       authorization.DossierID,
		AuthorizationID: record.AuthorizationID,
		ReceiptURL:      strings.TrimRight(s.cfg.PublicBaseURL, "/") + hostApplyReceiptPathPrefix + record.AuthorizationID + ".json",
		ReceiptSHA256:   record.ReceiptSHA256,
		ExpiresAt:       time.Unix(receipt.ExpiresAtUnix, 0).UTC(),
	})
}

// openHostApplyPublicDir opens the public receipt directory without following
// any directory symlink. The deployment's Store service group is a trusted
// writer (the existing DistDir is group-writable under the normal umask), but
// world-writable parents are refused so unrelated local principals cannot race
// a path-based hard-link call between descriptor checks.
func openHostApplyPublicDir(distDir string) (*os.File, error) {
	fd, err := syscall.Open(distDir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open dist dir: %w", err)
	}
	root := os.NewFile(uintptr(fd), distDir)
	if err := validateHostApplyPublicDir(root); err != nil {
		_ = root.Close()
		return nil, err
	}
	update, err := openOrCreateHostApplyPublicDir(root, "update")
	_ = root.Close()
	if err != nil {
		return nil, err
	}
	oneShot, err := openOrCreateHostApplyPublicDir(update, "one-shot")
	_ = update.Close()
	if err != nil {
		return nil, err
	}
	return oneShot, nil
}

func validateHostApplyPublicDir(dir *os.File) error {
	info, err := dir.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o002 != 0 {
		return fmt.Errorf("unsafe public receipt directory mode %s", info.Mode())
	}
	return nil
}

func openOrCreateHostApplyPublicDir(parent *os.File, name string) (*os.File, error) {
	fd, err := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		if err := syscall.Mkdirat(int(parent.Fd()), name, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if err := parent.Sync(); err != nil {
			return nil, err
		}
		fd, err = syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	}
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))
	if err := validateHostApplyPublicDir(dir); err != nil {
		_ = dir.Close()
		return nil, err
	}
	return dir, nil
}

func hostApplyReceiptFileName(id string) (string, error) {
	if !isLowerHex(id, 64) {
		return "", errors.New("invalid one-shot authorization id")
	}
	return id + ".json", nil
}

func readHostApplyPublicReceipt(dir *os.File, id string) ([]byte, error) {
	name, err := hostApplyReceiptFileName(id)
	if err != nil {
		return nil, err
	}
	return readBoundedRegular(filepath.Join(dir.Name(), name), 0o644, maxHostApplyReceiptBytes)
}

// publishHostApplyReceipt makes exact bytes visible with a hard-link commit.
// Readers are routed through handleOneShotApplyReceipt, so the temporary name
// is never served. os.Link is safe after the no-follow, non-world-writable
// directory validation above; the Store's single writer serializes its own
// calls and the deployment's trusted service group is the only extra writer.
func publishHostApplyReceipt(distDir, id string, raw []byte) error {
	if len(raw) == 0 || len(raw) > maxHostApplyReceiptBytes {
		return errors.New("one-shot receipt has an invalid size")
	}
	dir, err := openHostApplyPublicDir(distDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	name, err := hostApplyReceiptFileName(id)
	if err != nil {
		return err
	}
	if existing, err := readHostApplyPublicReceipt(dir, id); err == nil {
		if !bytes.Equal(existing, raw) {
			return errors.New("existing public one-shot receipt differs; reconciliation required")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing public one-shot receipt: %w", err)
	}
	tmpID, err := newHostApplyAuthorizationID()
	if err != nil {
		return err
	}
	tmpName := "." + name + "." + tmpID + ".tmp"
	tmpPath := filepath.Join(dir.Name(), tmpName)
	finalPath := filepath.Join(dir.Name(), name)
	f, err := openExclusiveRegular(tmpPath, 0o644)
	if err != nil {
		return fmt.Errorf("create public one-shot receipt temp: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = f.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if err := writeAllBounded(f, raw, maxHostApplyReceiptBytes); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, finalPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := readHostApplyPublicReceipt(dir, id)
			if readErr != nil {
				return fmt.Errorf("read raced public one-shot receipt: %w", readErr)
			}
			if !bytes.Equal(existing, raw) {
				return errors.New("raced public one-shot receipt differs; reconciliation required")
			}
		} else {
			return fmt.Errorf("link public one-shot receipt: %w", err)
		}
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	if err := os.Remove(tmpPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// handleOneShotApplyReceipt exposes a narrow public retrieval surface for the
// controller's pinned receipt URL. It never lists the directory, never serves a
// temporary file, and refuses an expired/mismatched record rather than falling
// back to DistDir's general static file server.
func (s *publishService) handleOneShotApplyReceipt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := hostApplyReceiptID(r.URL.Path, r.URL.RawQuery)
	if err != nil || s == nil || s.hostApplyIssuances == nil || s.hostApplyIssuanceErr != nil {
		http.NotFound(w, r)
		return
	}
	record, found, err := s.hostApplyIssuances.findAuthorizationID(id)
	if err != nil {
		http.Error(w, "one-shot receipt unavailable", http.StatusServiceUnavailable)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	raw, err := record.receiptBytes()
	if err != nil {
		http.Error(w, "one-shot receipt unavailable", http.StatusServiceUnavailable)
		return
	}
	receipt, err := decodeOneShotApplyReceipt(raw)
	if err != nil || receipt.StoreID != s.cfg.StoreID || receipt.ExpiresAtUnix <= s.currentTime().UTC().Unix() {
		http.NotFound(w, r)
		return
	}
	dir, err := openHostApplyPublicDir(s.cfg.DistDir)
	if err != nil {
		http.Error(w, "one-shot receipt unavailable", http.StatusServiceUnavailable)
		return
	}
	defer dir.Close()
	served, err := readHostApplyPublicReceipt(dir, id)
	if err != nil || !bytes.Equal(served, raw) {
		http.Error(w, "one-shot receipt unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
