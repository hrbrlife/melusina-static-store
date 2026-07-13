package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	publishNonceLedgerSchema = "melusina-publish-nonce-ledger-v1"
	publishNonceMarkerSchema = "melusina-publish-nonce-claim-v1"

	publishNonceLedgerDirName = "nonce-receipts-v1"
	publishNonceClaimsDirName = "claims"
	publishNonceLockFileName  = "ledger.lock"
	publishNonceStateFileName = "state.json"
	publishNonceNextFileName  = "state.json.next"

	maxAppNonceMarkers         = 4096
	maxPublishNonceRecordBytes = 4096
	maxPublishNonceStateBytes  = 2 << 20
	maxPublishNonceInputBytes  = 1024
)

var (
	errPublishNonceReplay        = errors.New("publish nonce already consumed")
	errPublishNonceCapacity      = errors.New("check=nonce_capacity")
	errPublishNonceClockRollback = errors.New("publish nonce clock below durable high-water")
	errPublishNonceExpired       = errors.New("publish nonce expired before durable claim")
)

type publishNonceMarker struct {
	Schema       string `json:"schema"`
	LedgerID     string `json:"ledgerId"`
	KeyDigest    string `json:"keyDigest"`
	NonceDigest  string `json:"nonceDigest"`
	PayloadHash  string `json:"payloadHash"`
	ExpiresAtMs  int64  `json:"expiresAtMs"`
	AcceptedAtMs int64  `json:"acceptedAtMs"`
}

// publishNonceState is the exact durable manifest of live claim files. The map
// value is the SHA-256 digest of the complete marker bytes, so replacing a
// listed marker is a boot/runtime refusal rather than a way to alter expiry.
type publishNonceState struct {
	Schema          string            `json:"schema"`
	LedgerID        string            `json:"ledgerId"`
	Capacity        int               `json:"capacity"`
	HighWaterUnixMs int64             `json:"highWaterUnixMs"`
	Markers         map[string]string `json:"markers"`
}

type publishNonceLedgerOptions struct {
	Capacity int
	Now      func() time.Time
	SyncFile func(*os.File) error
	SyncDir  func(string) error
}

type publishNonceLedger struct {
	root     string
	claims   string
	ledgerID string
	capacity int
	now      func() time.Time
	syncFile func(*os.File) error
	syncDir  func(string) error
	mu       sync.Mutex
}

// CheckClock refuses a wall-clock rollback before envelope verification. It
// does not advance state or collect markers; Claim repeats this check and
// persists the high-water at the final acceptance instant.
func (l *publishNonceLedger) CheckClock(now time.Time) error {
	if l == nil {
		return errors.New("durable app nonce ledger is not initialized")
	}
	nowMs := now.UTC().UnixMilli()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.withLock(func() error {
		if err := l.validateLayoutLocked(); err != nil {
			return err
		}
		state, err := l.loadStateLocked()
		if err != nil {
			return err
		}
		if nowMs < state.HighWaterUnixMs {
			return errPublishNonceClockRollback
		}
		return nil
	})
}

func defaultPublishNonceLedgerOptions() publishNonceLedgerOptions {
	return publishNonceLedgerOptions{
		Capacity: maxAppNonceMarkers,
		Now:      time.Now,
		SyncFile: func(f *os.File) error { return f.Sync() },
		SyncDir:  publishNonceSyncDir,
	}
}

func normalizePublishNonceLedgerOptions(opts publishNonceLedgerOptions) (publishNonceLedgerOptions, error) {
	defaults := defaultPublishNonceLedgerOptions()
	if opts.Capacity == 0 {
		opts.Capacity = defaults.Capacity
	}
	if opts.Capacity < 1 || opts.Capacity > maxAppNonceMarkers {
		return opts, fmt.Errorf("nonce ledger capacity must be in [1,%d]", maxAppNonceMarkers)
	}
	if opts.Now == nil {
		opts.Now = defaults.Now
	}
	if opts.SyncFile == nil {
		opts.SyncFile = defaults.SyncFile
	}
	if opts.SyncDir == nil {
		opts.SyncDir = defaults.SyncDir
	}
	return opts, nil
}

// initializePublishNonceLedger is bootstrap-only. Runtime startup must call
// openPublishNonceLedger, which never creates a missing component. The caller
// owns the external migration-state and initialized-sentinel state machine.
func initializePublishNonceLedger(root, ledgerID string, opts publishNonceLedgerOptions) error {
	var err error
	opts, err = normalizePublishNonceLedgerOptions(opts)
	if err != nil {
		return err
	}
	if err := validatePublishNonceLedgerID(ledgerID); err != nil {
		return err
	}
	root = filepath.Clean(root)
	if root == "." || root == string(filepath.Separator) {
		return errors.New("unsafe nonce ledger root")
	}
	parent := filepath.Dir(root)
	if err := requireSecureDirectory(parent, 0); err != nil {
		return fmt.Errorf("nonce ledger parent: %w", err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		return fmt.Errorf("create nonce ledger: %w", err)
	}
	if err := opts.SyncDir(parent); err != nil {
		return fmt.Errorf("fsync private-stage parent: %w", err)
	}
	claims := filepath.Join(root, publishNonceClaimsDirName)
	if err := os.Mkdir(claims, 0o700); err != nil {
		return fmt.Errorf("create nonce claims: %w", err)
	}
	if err := opts.SyncDir(claims); err != nil {
		return fmt.Errorf("fsync empty nonce claims: %w", err)
	}
	lockPath := filepath.Join(root, publishNonceLockFileName)
	lock, err := openExclusiveRegular(lockPath, 0o600)
	if err != nil {
		return fmt.Errorf("create nonce ledger lock: %w", err)
	}
	if err := opts.SyncFile(lock); err != nil {
		_ = lock.Close()
		return fmt.Errorf("fsync nonce ledger lock: %w", err)
	}
	if err := lock.Close(); err != nil {
		return fmt.Errorf("close nonce ledger lock: %w", err)
	}
	if err := opts.SyncDir(root); err != nil {
		return fmt.Errorf("fsync nonce ledger components: %w", err)
	}
	state := publishNonceState{
		Schema:   publishNonceLedgerSchema,
		LedgerID: ledgerID,
		Capacity: opts.Capacity,
		Markers:  make(map[string]string),
	}
	ledger := &publishNonceLedger{
		root: root, claims: claims, ledgerID: ledgerID, capacity: opts.Capacity,
		now: opts.Now, syncFile: opts.SyncFile, syncDir: opts.SyncDir,
	}
	if err := ledger.writeState(state); err != nil {
		return fmt.Errorf("initialize nonce ledger state: %w", err)
	}
	return nil
}

// openPublishNonceLedger validates and reconciles an initialized ledger. It
// creates nothing: a missing ledger, claims directory, lock, or state is fatal.
func openPublishNonceLedger(root, ledgerID string, opts publishNonceLedgerOptions) (*publishNonceLedger, error) {
	var err error
	opts, err = normalizePublishNonceLedgerOptions(opts)
	if err != nil {
		return nil, err
	}
	if err := validatePublishNonceLedgerID(ledgerID); err != nil {
		return nil, err
	}
	ledger := &publishNonceLedger{
		root: filepath.Clean(root), claims: filepath.Join(filepath.Clean(root), publishNonceClaimsDirName),
		ledgerID: ledgerID, capacity: opts.Capacity, now: opts.Now,
		syncFile: opts.SyncFile, syncDir: opts.SyncDir,
	}
	if err := ledger.withLock(func() error {
		if err := ledger.validateLayoutLocked(); err != nil {
			return err
		}
		state, err := ledger.loadStateLocked()
		if err != nil {
			return err
		}
		nowMs := ledger.now().UTC().UnixMilli()
		if nowMs < state.HighWaterUnixMs {
			return errPublishNonceClockRollback
		}
		state.HighWaterUnixMs = nowMs
		changed, err := ledger.reconcileClaimsLocked(&state)
		if err != nil {
			return err
		}
		removed, err := ledger.collectExpiredLocked(&state)
		if err != nil {
			return err
		}
		if changed || len(removed) != 0 || state.HighWaterUnixMs != 0 {
			if err := ledger.writeState(state); err != nil {
				return err
			}
		}
		return ledger.unlinkCollectedLocked(removed)
	}); err != nil {
		return nil, err
	}
	return ledger, nil
}

// Claim durably consumes one nonce. The caller must pass the same claimNow used
// for its final tight raw-expiry check, immediately before this bounded ledger
// transaction and while holding the app single-writer lock.
func (l *publishNonceLedger) Claim(scope, nonce, payloadHash string, expiresAtMs int64, claimNow time.Time) error {
	if err := validatePublishNonceClaimInputs(scope, nonce, payloadHash); err != nil {
		return err
	}
	claimNowMs := claimNow.UTC().UnixMilli()
	if expiresAtMs < claimNowMs {
		return errPublishNonceExpired
	}
	key := publishNonceKey(scope, nonce)
	markerName := hex.EncodeToString(key[:])
	nonceHash := sha256.Sum256([]byte(nonce))
	marker := publishNonceMarker{
		Schema: publishNonceMarkerSchema, LedgerID: l.ledgerID,
		KeyDigest: markerName, NonceDigest: hex.EncodeToString(nonceHash[:]),
		PayloadHash: strings.ToLower(payloadHash), ExpiresAtMs: expiresAtMs,
		AcceptedAtMs: claimNowMs,
	}
	markerBytes, err := marshalBoundedJSON(marker, maxPublishNonceRecordBytes)
	if err != nil {
		return err
	}
	markerDigest := sha256.Sum256(markerBytes)

	l.mu.Lock()
	defer l.mu.Unlock()
	return l.withLock(func() error {
		if err := l.validateLayoutLocked(); err != nil {
			return err
		}
		state, err := l.loadStateLocked()
		if err != nil {
			return err
		}
		if claimNowMs < state.HighWaterUnixMs {
			return errPublishNonceClockRollback
		}
		state.HighWaterUnixMs = claimNowMs
		_, err = l.reconcileClaimsLocked(&state)
		if err != nil {
			return err
		}
		removed, err := l.collectExpiredLocked(&state)
		if err != nil {
			return err
		}
		// Persist the clock floor, reconciled extras, and strict-past GC
		// before creating a new marker. A crash can therefore only retain
		// (and later re-incorporate) an expired marker; it cannot roll the
		// durable clock backwards or reopen a consumed nonce.
		if err := l.writeState(state); err != nil {
			return err
		}
		if err := l.unlinkCollectedLocked(removed); err != nil {
			return err
		}
		if _, spent := state.Markers[markerName]; spent {
			return errPublishNonceReplay
		}
		if len(state.Markers) >= l.capacity {
			return errPublishNonceCapacity
		}
		if err := l.writeMarkerLocked(markerName, markerBytes); err != nil {
			return err
		}
		state.Markers[markerName] = hex.EncodeToString(markerDigest[:])
		if err := l.writeState(state); err != nil {
			return err
		}
		return nil
	})
}

func (l *publishNonceLedger) withLock(fn func() error) error {
	lockPath := filepath.Join(l.root, publishNonceLockFileName)
	f, err := openExistingRegular(lockPath, 0o600, syscall.O_RDWR)
	if err != nil {
		return fmt.Errorf("open nonce ledger lock: %w", err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock nonce ledger: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

func (l *publishNonceLedger) validateLayoutLocked() error {
	if err := requireSecureDirectory(l.root, 0o700); err != nil {
		return fmt.Errorf("nonce ledger root: %w", err)
	}
	if err := requireSecureDirectory(l.claims, 0o700); err != nil {
		return fmt.Errorf("nonce claims: %w", err)
	}
	for _, name := range []string{publishNonceLockFileName, publishNonceStateFileName} {
		f, err := openExistingRegular(filepath.Join(l.root, name), 0o600, syscall.O_RDONLY)
		if err != nil {
			return fmt.Errorf("nonce ledger %s: %w", name, err)
		}
		_ = f.Close()
	}
	if err := l.discardInterruptedStateWriteLocked(); err != nil {
		return err
	}
	entries, err := readBoundedDirectoryNames(l.root, 4)
	if err != nil {
		return fmt.Errorf("enumerate nonce ledger: %w", err)
	}
	for _, entry := range entries {
		switch entry {
		case publishNonceClaimsDirName, publishNonceLockFileName, publishNonceStateFileName:
		default:
			return fmt.Errorf("unexpected nonce ledger entry %q", entry)
		}
	}
	return nil
}

func (l *publishNonceLedger) discardInterruptedStateWriteLocked() error {
	path := filepath.Join(l.root, publishNonceNextFileName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect interrupted nonce state: %w", err)
	}
	if info.Mode().IsRegular() && info.Mode().Perm() == 0o600 {
		if info.Size() > maxPublishNonceStateBytes {
			return errors.New("oversize interrupted nonce state")
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("discard interrupted nonce state: %w", err)
		}
		return l.syncDir(l.root)
	}
	return errors.New("unsafe interrupted nonce state")
}

func (l *publishNonceLedger) loadStateLocked() (publishNonceState, error) {
	var state publishNonceState
	raw, err := readBoundedRegular(filepath.Join(l.root, publishNonceStateFileName), 0o600, maxPublishNonceStateBytes)
	if err != nil {
		return state, fmt.Errorf("read nonce ledger state: %w", err)
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return state, fmt.Errorf("decode nonce ledger state: %w", err)
	}
	if state.Schema != publishNonceLedgerSchema || state.LedgerID != l.ledgerID || state.Capacity != l.capacity || state.HighWaterUnixMs < 0 || state.Markers == nil {
		return state, errors.New("nonce ledger state identity mismatch")
	}
	if len(state.Markers) > l.capacity {
		return state, errPublishNonceCapacity
	}
	for name, digest := range state.Markers {
		if !validPublishNonceMarkerName(name) || !validLowerHexDigest(digest) {
			return state, errors.New("invalid nonce ledger state manifest")
		}
	}
	return state, nil
}

func (l *publishNonceLedger) reconcileClaimsLocked(state *publishNonceState) (bool, error) {
	entries, err := readBoundedDirectoryNames(l.claims, l.capacity)
	if err != nil {
		return false, fmt.Errorf("enumerate nonce claims: %w", err)
	}
	seen := make(map[string]struct{}, len(entries))
	changed := false
	for _, name := range entries {
		if !validPublishNonceMarkerName(name) {
			return false, fmt.Errorf("invalid nonce marker filename %q", name)
		}
		raw, err := readBoundedRegular(filepath.Join(l.claims, name), 0o600, maxPublishNonceRecordBytes)
		if err != nil {
			return false, fmt.Errorf("read nonce marker %s: %w", name, err)
		}
		digest := sha256.Sum256(raw)
		digestHex := hex.EncodeToString(digest[:])
		seen[name] = struct{}{}
		if want, listed := state.Markers[name]; listed {
			if want != digestHex {
				return false, fmt.Errorf("nonce marker %s replaced", name)
			}
			continue
		}
		state.Markers[name] = digestHex
		changed = true
	}
	for name := range state.Markers {
		if _, ok := seen[name]; !ok {
			return false, fmt.Errorf("nonce marker %s missing", name)
		}
	}
	if len(state.Markers) > l.capacity {
		return false, errPublishNonceCapacity
	}
	return changed, nil
}

func (l *publishNonceLedger) collectExpiredLocked(state *publishNonceState) ([]string, error) {
	removed := make([]string, 0)
	for name := range state.Markers {
		raw, err := readBoundedRegular(filepath.Join(l.claims, name), 0o600, maxPublishNonceRecordBytes)
		if err != nil {
			return nil, err
		}
		var marker publishNonceMarker
		if json.Unmarshal(raw, &marker) != nil || !l.validMarker(name, marker) {
			continue
		}
		if marker.ExpiresAtMs < state.HighWaterUnixMs {
			delete(state.Markers, name)
			removed = append(removed, name)
		}
	}
	sort.Strings(removed)
	return removed, nil
}

func (l *publishNonceLedger) validMarker(name string, marker publishNonceMarker) bool {
	return marker.Schema == publishNonceMarkerSchema && marker.LedgerID == l.ledgerID &&
		marker.KeyDigest == name && validLowerHexDigest(marker.NonceDigest) &&
		validLowerHexDigest(marker.PayloadHash) && marker.ExpiresAtMs >= 0 &&
		marker.AcceptedAtMs >= 0
}

func (l *publishNonceLedger) unlinkCollectedLocked(names []string) error {
	if len(names) == 0 {
		return nil
	}
	for _, name := range names {
		if err := os.Remove(filepath.Join(l.claims, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove expired nonce marker: %w", err)
		}
	}
	if err := l.syncDir(l.claims); err != nil {
		return fmt.Errorf("fsync nonce claims after GC: %w", err)
	}
	return nil
}

func (l *publishNonceLedger) writeMarkerLocked(name string, raw []byte) error {
	path := filepath.Join(l.claims, name)
	f, err := openExclusiveRegular(path, 0o600)
	if errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EEXIST) {
		return errPublishNonceReplay
	}
	if err != nil {
		return fmt.Errorf("create nonce marker: %w", err)
	}
	// Never remove a marker after O_EXCL succeeds. A partial or uncertain
	// marker is intentionally burned and reconciled on restart.
	defer f.Close()
	if err := writeAllBounded(f, raw, maxPublishNonceRecordBytes); err != nil {
		return fmt.Errorf("write nonce marker: %w", err)
	}
	if err := l.syncFile(f); err != nil {
		return fmt.Errorf("fsync nonce marker: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close nonce marker: %w", err)
	}
	if err := l.syncDir(l.claims); err != nil {
		return fmt.Errorf("fsync nonce claims: %w", err)
	}
	return nil
}

func (l *publishNonceLedger) writeState(state publishNonceState) error {
	raw, err := marshalBoundedJSON(state, maxPublishNonceStateBytes)
	if err != nil {
		return err
	}
	next := filepath.Join(l.root, publishNonceNextFileName)
	if _, err := os.Lstat(next); err == nil {
		return errors.New("interrupted nonce state write exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect nonce state temp: %w", err)
	}
	f, err := openExclusiveRegular(next, 0o600)
	if err != nil {
		return fmt.Errorf("create nonce state temp: %w", err)
	}
	cleanup := true
	defer func() {
		_ = f.Close()
		if cleanup {
			_ = os.Remove(next)
		}
	}()
	if err := writeAllBounded(f, raw, maxPublishNonceStateBytes); err != nil {
		return fmt.Errorf("write nonce state temp: %w", err)
	}
	if err := l.syncFile(f); err != nil {
		return fmt.Errorf("fsync nonce state temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close nonce state temp: %w", err)
	}
	if err := os.Rename(next, filepath.Join(l.root, publishNonceStateFileName)); err != nil {
		return fmt.Errorf("commit nonce state: %w", err)
	}
	cleanup = false
	if err := l.syncDir(l.root); err != nil {
		return fmt.Errorf("fsync nonce ledger state: %w", err)
	}
	return nil
}

func publishNonceKey(scope, nonce string) [32]byte {
	h := sha256.New()
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(scope)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(scope))
	binary.BigEndian.PutUint64(size[:], uint64(len(nonce)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(nonce))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func validatePublishNonceClaimInputs(scope, nonce, payloadHash string) error {
	if len(scope) == 0 || len(scope) > maxPublishNonceInputBytes || len(nonce) == 0 || len(nonce) > maxPublishNonceInputBytes {
		return errors.New("invalid bounded nonce scope or value")
	}
	if !validLowerHexDigest(strings.ToLower(payloadHash)) || payloadHash != strings.ToLower(payloadHash) {
		return errors.New("payload hash must be 32-byte lowercase hex")
	}
	return nil
}

func validatePublishNonceLedgerID(id string) error {
	if len(id) == 0 || len(id) > 128 || strings.TrimSpace(id) != id {
		return errors.New("invalid nonce ledger ID")
	}
	for _, r := range id {
		if r < 0x21 || r > 0x7e {
			return errors.New("invalid nonce ledger ID")
		}
	}
	return nil
}

func validPublishNonceMarkerName(name string) bool { return validLowerHexDigest(name) }

func validLowerHexDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func marshalBoundedJSON(value any, limit int64) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if int64(len(raw)) > limit {
		return nil, errors.New("bounded JSON exceeds limit")
	}
	return raw, nil
}

func writeAllBounded(w io.Writer, raw []byte, limit int64) error {
	if int64(len(raw)) > limit {
		return errors.New("bounded write exceeds limit")
	}
	for len(raw) != 0 {
		n, err := w.Write(raw)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}

func readBoundedRegular(path string, mode os.FileMode, limit int64) ([]byte, error) {
	f, err := openExistingRegular(path, mode, syscall.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reader := io.LimitReader(f, limit+1)
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("file exceeds bounded read limit")
	}
	return raw, nil
}

// readBoundedDirectoryNames stops as soon as max+1 entries are observed. It
// deliberately avoids os.ReadDir, which would allocate for an attacker-sized
// directory before enforcing the durable ledger's fixed capacity.
func readBoundedDirectoryNames(path string, max int) ([]string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	names := make([]string, 0, min(max, 128))
	for {
		chunk, err := dir.Readdirnames(128)
		for _, name := range chunk {
			if len(names) == max {
				return nil, errPublishNonceCapacity
			}
			names = append(names, name)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(names)
	return names, nil
}

func openExclusiveRegular(path string, mode os.FileMode) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openExistingRegular(path string, mode os.FileMode, flags int) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != mode.Perm() {
		_ = f.Close()
		return nil, fmt.Errorf("unsafe type or mode %s", info.Mode())
	}
	return f, nil
}

func requireSecureDirectory(path string, exactMode os.FileMode) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("not a directory")
	}
	if exactMode != 0 && info.Mode().Perm() != exactMode.Perm() {
		return fmt.Errorf("unsafe directory mode %s", info.Mode().Perm())
	}
	return nil
}

func publishNonceSyncDir(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	return f.Sync()
}

// newPublishNonceLedgerID is intended for the externally authorized bootstrap
// helper. The ID must be persisted in external migration state before init.
func newPublishNonceLedgerID() (string, error) {
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}
