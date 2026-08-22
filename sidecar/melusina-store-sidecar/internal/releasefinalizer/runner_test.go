package releasefinalizer

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/artifactvault"
)

func TestRunnerPersistsTheDerivedBodyAndRecoversLostResponses(t *testing.T) {
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	engine, request, _, observer, signer, public := finalizerFixture(t, now)
	records, err := OpenRepository(filepath.Join(t.TempDir(), "records"), "finalizer-a", public)
	if err != nil {
		t.Fatal(err)
	}
	records.now = func() time.Time { return now }
	body, err := artifactvault.Open(filepath.Join(t.TempDir(), "bodies"), maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(engine, records, body)
	if err != nil {
		t.Fatal(err)
	}
	runner.now = func() time.Time { return now }
	first, firstBody, err := runner.Run(context.Background(), request)
	if err != nil || first.State != Finalized || first.Result == nil || first.FinalBody == nil || len(firstBody) == 0 {
		t.Fatalf("first run = %#v body=%d err=%v", first, len(firstBody), err)
	}
	retry, retryBody, err := runner.Run(context.Background(), request)
	if err != nil || retry.Job != first.Job || string(retryBody) != string(firstBody) || observer.calls != 1 || signer.calls != 1 {
		t.Fatalf("lost-response retry = %#v body=%q calls=%d/%d err=%v", retry, retryBody, observer.calls, signer.calls, err)
	}
}

func TestRunnerDoesNotSignUntilTheExactProposalExecutes(t *testing.T) {
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	engine, request, _, observer, signer, public := finalizerFixture(t, now)
	observer.observation.State = ProposalPending
	records, err := OpenRepository(filepath.Join(t.TempDir(), "records"), "finalizer-a", public)
	if err != nil {
		t.Fatal(err)
	}
	records.now = func() time.Time { return now }
	body, err := artifactvault.Open(filepath.Join(t.TempDir(), "bodies"), maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(engine, records, body)
	if err != nil {
		t.Fatal(err)
	}
	runner.now = func() time.Time { return now }
	record, output, err := runner.Run(context.Background(), request)
	if !errors.Is(err, ErrPending) || record.State != WaitingForGovernance || output != nil || observer.calls != 1 || signer.calls != 0 {
		t.Fatalf("pending run = %#v body=%q observer/signer=%d/%d err=%v", record, output, observer.calls, signer.calls, err)
	}
}
