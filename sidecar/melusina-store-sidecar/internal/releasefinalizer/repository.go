package releasefinalizer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/artifactvault"
)

const (
	recordSchema        = "bazaar-control-release-finalization-record-v1"
	requestIndexSchema  = "bazaar-control-release-finalization-request-index-v1"
	finalizerDirectory  = 0o700
	finalizerRecordMode = 0o600
	maxRecordBytes      = 1 << 20
)

// State deliberately describes only the worker's durable, human-relevant
// state. Provider internals, RPC retries, and signer implementation details do
// not become product state.
type State string

const (
	WaitingForGovernance State = "waiting_for_governance"
	Finalized            State = "finalized"
)

// Record is the owner-only durable state for one immutable finalization job.
// FinalBody is an artifact-vault descriptor, never a caller-supplied path or
// inlined package/envelope body. A caller that lost a response can therefore
// recover the same bounded result until its envelope expires.
type Record struct {
	Schema    string                    `json:"schema"`
	Job       Job                       `json:"job"`
	Request   Request                   `json:"request"`
	State     State                     `json:"state"`
	Result    *Result                   `json:"result,omitempty"`
	FinalBody *artifactvault.Descriptor `json:"finalBody,omitempty"`
	UpdatedAt time.Time                 `json:"updatedAt"`
}

type requestIndex struct {
	Schema        string `json:"schema"`
	RequestDigest string `json:"requestDigest"`
	JobID         string `json:"jobId"`
}

// Repository owns a fixed mode-0700 root. It is intentionally not a general
// database or document store: callers can create/load only finalization jobs,
// each bound to a canonical request digest.
type Repository struct {
	root         string
	jobs         string
	requests     string
	workerID     string
	resultPublic ed25519.PublicKey
	now          func() time.Time
	mu           sync.Mutex
}

// OpenRepository creates or verifies the fixed owner-only store. The worker's
// public result key is part of the store configuration so tampered result files
// fail closed before a retry can reuse them.
func OpenRepository(root, workerID string, resultPublic ed25519.PublicKey) (*Repository, error) {
	if !filepath.IsAbs(root) || !safeText(workerID, 256) || len(resultPublic) != ed25519.PublicKeySize {
		return nil, errors.New("finalization repository requires an absolute root, worker id, and result public key")
	}
	if err := createOrVerifyFinalizerDirectory(root); err != nil {
		return nil, fmt.Errorf("finalization repository root: %w", err)
	}
	jobs := filepath.Join(root, "jobs")
	if err := createOrVerifyFinalizerDirectory(jobs); err != nil {
		return nil, fmt.Errorf("finalization repository jobs: %w", err)
	}
	requests := filepath.Join(root, "requests")
	if err := createOrVerifyFinalizerDirectory(requests); err != nil {
		return nil, fmt.Errorf("finalization repository requests: %w", err)
	}
	return &Repository{
		root: root, jobs: jobs, requests: requests, workerID: workerID,
		resultPublic: append(ed25519.PublicKey(nil), resultPublic...), now: time.Now,
	}, nil
}

// Create stores the exact request before an observer or signer can run. An
// exact retry returns the same job. The digest index makes a conflicting body
// unable to replace an existing job even after a process restart.
func (r *Repository) Create(ctx context.Context, request Request) (Record, bool, error) {
	if r == nil || r.now == nil {
		return Record{}, false, errors.New("finalization repository is unavailable")
	}
	if err := request.validate(); err != nil {
		return Record{}, false, err
	}
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.verifyDirectories(); err != nil {
		return Record{}, false, err
	}
	if existing, found, err := r.loadByRequestLocked(request); err != nil {
		return Record{}, false, err
	} else if found {
		return existing, false, nil
	}
	for attempt := 0; attempt < 8; attempt++ {
		job, err := newStoredJob(request, r.now().UTC())
		if err != nil {
			return Record{}, false, err
		}
		record := Record{Schema: recordSchema, Job: job, Request: request, State: WaitingForGovernance, UpdatedAt: r.now().UTC()}
		if err := r.writeNewRecordLocked(record); errors.Is(err, fs.ErrExist) {
			continue
		} else if err != nil {
			return Record{}, false, err
		}
		index := requestIndex{Schema: requestIndexSchema, RequestDigest: request.RequestDigest, JobID: job.ID}
		created, err := r.writeNewIndexLocked(index)
		if err != nil {
			return Record{}, false, err
		}
		if created {
			return record, true, nil
		}
		// Another process won the request index after this process created an
		// otherwise unreachable job. Removing that private new file is safe:
		// no side effect can reference it before the index exists.
		if err := os.Remove(r.jobPath(job.ID)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return Record{}, false, err
		}
		if err := syncFinalizerDirectory(r.jobs); err != nil {
			return Record{}, false, err
		}
		existing, found, err := r.loadByRequestLocked(request)
		if err != nil {
			return Record{}, false, err
		}
		if found {
			return existing, false, nil
		}
		return Record{}, false, errors.New("finalization request index disappeared during create")
	}
	return Record{}, false, errors.New("could not allocate a unique finalization job")
}

// Load returns only a record named by a worker-generated job id. It does not
// accept request digests, filenames, source paths, or a broad query language.
func (r *Repository) Load(ctx context.Context, jobID string) (Record, bool, error) {
	if r == nil || r.now == nil || !lowerHex(jobID, 24) {
		return Record{}, false, errors.New("finalization job id is invalid")
	}
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.verifyDirectories(); err != nil {
		return Record{}, false, err
	}
	return r.loadRecordLocked(jobID)
}

// Complete persists the worker-signed result and its derived sidecar-body
// descriptor. Repeating an unexpired job returns the original record. Once the
// envelope has expired, a caller may safely replace it only with a newly signed
// result for the same job, immutable request, proposal and final body.
func (r *Repository) Complete(ctx context.Context, job Job, request Request, result Result, finalBody artifactvault.Descriptor) (Record, bool, error) {
	if r == nil || r.now == nil {
		return Record{}, false, errors.New("finalization repository is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	now := r.now().UTC()
	if err := job.Validate(request, now); err != nil {
		return Record{}, false, err
	}
	if err := finalBody.Validate(maxBytes); err != nil {
		return Record{}, false, err
	}
	if err := validateResult(result, r.workerID, r.resultPublic, job, request, finalBody, now, true); err != nil {
		return Record{}, false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.verifyDirectories(); err != nil {
		return Record{}, false, err
	}
	record, found, err := r.loadRecordLocked(job.ID)
	if err != nil || !found {
		if err == nil {
			err = errors.New("finalization job was not persisted")
		}
		return Record{}, false, err
	}
	if record.Request != request || record.Job != job {
		return Record{}, false, errors.New("finalization result does not bind the persisted job")
	}
	if record.State == Finalized {
		if record.Result == nil || record.FinalBody == nil {
			return Record{}, false, errors.New("persisted finalization record is incomplete")
		}
		if err := validateResult(*record.Result, r.workerID, r.resultPublic, job, request, *record.FinalBody, now, false); err != nil {
			return Record{}, false, fmt.Errorf("persisted finalization result: %w", err)
		}
		if record.Result.ExpiresAt.After(now) {
			return record, false, nil
		}
	}
	if record.State != WaitingForGovernance && record.State != Finalized {
		return Record{}, false, errors.New("finalization record is not resumable")
	}
	record.State = Finalized
	record.Result = &result
	record.FinalBody = &finalBody
	record.UpdatedAt = now
	if err := r.writeRecordLocked(record); err != nil {
		return Record{}, false, err
	}
	return record, true, nil
}

func (r *Repository) loadByRequestLocked(request Request) (Record, bool, error) {
	index, found, err := r.loadIndexLocked(request.RequestDigest)
	if err != nil || !found {
		return Record{}, found, err
	}
	if index.RequestDigest != request.RequestDigest {
		return Record{}, false, errors.New("finalization request index is not bound to its filename")
	}
	record, found, err := r.loadRecordLocked(index.JobID)
	if err != nil || !found {
		if err == nil {
			err = errors.New("finalization request index points to a missing job")
		}
		return Record{}, false, err
	}
	if record.Request != request || record.Job.RequestDigest != request.RequestDigest {
		return Record{}, false, errors.New("finalization request conflicts with its persisted job")
	}
	return record, true, nil
}

func (r *Repository) loadRecordLocked(jobID string) (Record, bool, error) {
	raw, found, err := readFinalizerFile(r.jobPath(jobID))
	if err != nil || !found {
		return Record{}, found, err
	}
	var record Record
	if err := decodeFinalizerJSON(raw, &record); err != nil {
		return Record{}, false, err
	}
	if err := r.validateRecord(record, r.now().UTC()); err != nil {
		return Record{}, false, err
	}
	return record, true, nil
}

func (r *Repository) loadIndexLocked(requestDigest string) (requestIndex, bool, error) {
	raw, found, err := readFinalizerFile(r.indexPath(requestDigest))
	if err != nil || !found {
		return requestIndex{}, found, err
	}
	var index requestIndex
	if err := decodeFinalizerJSON(raw, &index); err != nil {
		return requestIndex{}, false, err
	}
	if index.Schema != requestIndexSchema || !lowerHex(index.RequestDigest, 64) || !lowerHex(index.JobID, 24) {
		return requestIndex{}, false, errors.New("finalization request index is malformed")
	}
	return index, true, nil
}

func (r *Repository) validateRecord(record Record, now time.Time) error {
	if record.Schema != recordSchema || record.UpdatedAt.IsZero() || record.UpdatedAt.After(now.Add(2*time.Minute)) {
		return errors.New("finalization record is malformed")
	}
	if err := record.Request.validate(); err != nil {
		return err
	}
	if err := record.Job.Validate(record.Request, now); err != nil {
		return err
	}
	switch record.State {
	case WaitingForGovernance:
		if record.Result != nil || record.FinalBody != nil {
			return errors.New("waiting finalization record contains a result")
		}
	case Finalized:
		if record.Result == nil || record.FinalBody == nil {
			return errors.New("finalized record lacks result or final body")
		}
		if err := validateResult(*record.Result, r.workerID, r.resultPublic, record.Job, record.Request, *record.FinalBody, now, false); err != nil {
			return err
		}
	default:
		return errors.New("finalization record has an unknown state")
	}
	return nil
}

func validateResult(result Result, workerID string, public ed25519.PublicKey, job Job, request Request, finalBody artifactvault.Descriptor, now time.Time, requireCurrentEnvelope bool) error {
	if err := finalBody.Validate(maxBytes); err != nil {
		return err
	}
	if result.Schema != ResultSchema || result.WorkerID != workerID || result.Job != job || result.RequestDigest != request.RequestDigest || result.ReleaseAuthorizationDigest != request.ReleaseAuthorizationDigest || result.ProposalReference != request.ProposalReference || result.ProposalDigest != request.ProposalDigest {
		return errors.New("finalization result does not bind its worker, job, request, authorization, or proposal")
	}
	// A valid proposal may have executed long before the worker restarts or a
	// short-lived transport envelope needs refresh. History is maintained; only
	// an execution timestamp from the future is impossible. The active grant,
	// release, and approval are rechecked at their own authority boundaries.
	if result.ProposalExecutedAt.IsZero() || result.ProposalExecutedAt.After(now.Add(2*time.Minute)) {
		return errors.New("finalization result has invalid observed proposal timing")
	}
	if result.FinalCandidateSHA256 != finalBody.SHA256 || result.FinalCandidateBytes != finalBody.Bytes {
		return errors.New("finalization result does not bind its final body descriptor")
	}
	if !lowerHex(result.PublisherIntentHash, 64) {
		return errors.New("finalization result has no canonical publisher intent")
	}
	if result.FinalizedAt.IsZero() || result.FinalizedAt.After(now.Add(2*time.Minute)) || !result.ExpiresAt.After(result.FinalizedAt) || result.ExpiresAt.Sub(result.FinalizedAt) > 15*time.Minute || (requireCurrentEnvelope && !result.ExpiresAt.After(now)) {
		return errors.New("finalization result timing is invalid or expired")
	}
	signature, err := base64.RawURLEncoding.DecodeString(result.Signature)
	if err != nil || !ed25519.Verify(public, []byte(resultPrefix+result.Digest()), signature) {
		return errors.New("finalization result signature is invalid")
	}
	return nil
}

func (r *Repository) writeNewRecordLocked(record Record) error {
	if err := r.validateRecord(record, r.now().UTC()); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	created, err := writeNewFinalizerFile(r.jobs, r.jobPath(record.Job.ID), append(raw, '\n'))
	if err != nil {
		return err
	}
	if !created {
		return fs.ErrExist
	}
	return nil
}

func (r *Repository) writeNewIndexLocked(index requestIndex) (bool, error) {
	raw, err := json.Marshal(index)
	if err != nil {
		return false, err
	}
	return writeNewFinalizerFile(r.requests, r.indexPath(index.RequestDigest), append(raw, '\n'))
}

func (r *Repository) writeRecordLocked(record Record) error {
	if err := r.validateRecord(record, r.now().UTC()); err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return replaceFinalizerFile(r.jobs, r.jobPath(record.Job.ID), append(raw, '\n'))
}

func (r *Repository) verifyDirectories() error {
	for label, path := range map[string]string{"root": r.root, "jobs": r.jobs, "requests": r.requests} {
		if err := requireFinalizerDirectory(path); err != nil {
			return fmt.Errorf("finalization repository %s: %w", label, err)
		}
	}
	return nil
}

func (r *Repository) jobPath(jobID string) string { return filepath.Join(r.jobs, "job-"+jobID+".json") }

func (r *Repository) indexPath(requestDigest string) string {
	return filepath.Join(r.requests, "request-"+requestDigest+".json")
}

func newStoredJob(request Request, now time.Time) (Job, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Job{}, err
	}
	return Job{Schema: JobSchema, ID: hex.EncodeToString(random[:]), RequestDigest: request.RequestDigest, RequestedAt: now}, nil
}

func createOrVerifyFinalizerDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(path, finalizerDirectory); err != nil {
			return err
		}
		return requireFinalizerDirectory(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("must be a real directory")
	}
	return requireFinalizerDirectory(path)
}

func requireFinalizerDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != finalizerDirectory || int(stat.Uid) != os.Geteuid() {
		return errors.New("must be an owner-only mode-0700 directory owned by this user")
	}
	return nil
}

func readFinalizerFile(path string) ([]byte, bool, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != finalizerRecordMode || int(stat.Uid) != os.Geteuid() {
		return nil, false, errors.New("must be an owner-only mode-0600 regular file owned by this user")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(raw) == 0 || len(raw) > maxRecordBytes {
		return nil, false, errors.New("finalization record is empty or exceeds its limit")
	}
	return raw, true, nil
}

func decodeFinalizerJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("finalization record is not exact JSON")
	}
	return nil
}

func writeNewFinalizerFile(parent, target string, body []byte) (bool, error) {
	temporary, err := writeFinalizerTemporary(parent, body)
	if err != nil {
		return false, err
	}
	defer os.Remove(temporary)
	if err := os.Link(temporary, target); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, err
	}
	return true, syncFinalizerDirectory(parent)
}

func replaceFinalizerFile(parent, target string, body []byte) error {
	if _, found, err := readFinalizerFile(target); err != nil {
		return err
	} else if !found {
		return errors.New("cannot replace a missing finalization record")
	}
	temporary, err := writeFinalizerTemporary(parent, body)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	return syncFinalizerDirectory(parent)
}

func writeFinalizerTemporary(parent string, body []byte) (string, error) {
	if len(body) == 0 || len(body) > maxRecordBytes {
		return "", errors.New("finalization record exceeds its limit")
	}
	temporary, err := os.CreateTemp(parent, ".finalization-*")
	if err != nil {
		return "", err
	}
	path := temporary.Name()
	if err := temporary.Chmod(finalizerRecordMode); err != nil {
		temporary.Close()
		os.Remove(path)
		return "", err
	}
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		os.Remove(path)
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		os.Remove(path)
		return "", err
	}
	if err := temporary.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func syncFinalizerDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
