package releasefinalizer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/artifactvault"
)

// BodyVault is the finalizer's fixed output boundary. The runner can store and
// reload only a sidecar body it derived from a validated immutable input; no
// caller can upload, name, or retrieve an arbitrary vault object through it.
type BodyVault interface {
	Store(context.Context, []byte) (artifactvault.Descriptor, error)
	Load(context.Context, artifactvault.Descriptor) ([]byte, error)
}

// Runner turns the pure finalizer engine into a restart-safe local workflow.
// It has no HTTP listener, sidecar client, Squads signer, or browser access.
// A later fixed-route worker service may call Run, but cannot expand its
// authority because requests, jobs, vault records, observer facts, signer
// envelope, and final body all remain independently bound here.
type Runner struct {
	engine  *Engine
	records *Repository
	body    BodyVault
	now     func() time.Time
	mu      sync.Mutex
}

func NewRunner(engine *Engine, records *Repository, body BodyVault) (*Runner, error) {
	if engine == nil || records == nil || body == nil {
		return nil, errors.New("finalizer engine, repository, and body vault are required")
	}
	return &Runner{engine: engine, records: records, body: body, now: time.Now}, nil
}

// Run creates or resumes exactly one persisted job. A pending proposal returns
// ErrPending without calling the signer. A retry after a lost response returns
// the stored result and body while its envelope is current. After expiry it
// refreshes only the same persisted job and immutable approval facts.
func (r *Runner) Run(ctx context.Context, request Request) (Record, []byte, error) {
	if r == nil || r.now == nil {
		return Record{}, nil, errors.New("finalizer runner is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return Record{}, nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	record, _, err := r.records.Create(ctx, request)
	if err != nil {
		return Record{}, nil, err
	}
	if record.State == Finalized && record.Result != nil && record.FinalBody != nil && record.Result.ExpiresAt.After(r.now().UTC()) {
		body, err := r.body.Load(ctx, *record.FinalBody)
		if err != nil {
			return Record{}, nil, fmt.Errorf("load persisted final sidecar body: %w", err)
		}
		return record, body, nil
	}
	result, body, err := r.engine.Finalize(ctx, record.Job, request)
	if errors.Is(err, ErrPending) {
		return record, nil, ErrPending
	}
	if err != nil {
		return Record{}, nil, err
	}
	descriptor, err := r.body.Store(ctx, body)
	if err != nil {
		return Record{}, nil, fmt.Errorf("persist final sidecar body: %w", err)
	}
	stored, changed, err := r.records.Complete(ctx, record.Job, request, result, descriptor)
	if err != nil {
		return Record{}, nil, err
	}
	if changed {
		return stored, body, nil
	}
	if stored.Result == nil || stored.FinalBody == nil {
		return Record{}, nil, errors.New("persisted finalization retry has no result")
	}
	persisted, err := r.body.Load(ctx, *stored.FinalBody)
	if err != nil {
		return Record{}, nil, fmt.Errorf("load exact finalization retry body: %w", err)
	}
	return stored, persisted, nil
}
