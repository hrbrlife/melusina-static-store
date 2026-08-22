package releasefinalizer

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hrbrlife/melusina-store-sidecar/internal/artifactvault"
)

func TestRepositoryPersistsOneExactJobAndSignedFinalResult(t *testing.T) {
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	engine, request, _, _, _, public := finalizerFixture(t, now)
	repository, err := OpenRepository(filepath.Join(t.TempDir(), "finalizer"), "finalizer-a", public)
	if err != nil {
		t.Fatal(err)
	}
	repository.now = func() time.Time { return now }
	record, created, err := repository.Create(context.Background(), request)
	if err != nil || !created || record.State != WaitingForGovernance {
		t.Fatalf("create = %#v created=%v err=%v", record, created, err)
	}
	retry, created, err := repository.Create(context.Background(), request)
	if err != nil || created || retry.Job != record.Job {
		t.Fatalf("exact retry = %#v created=%v err=%v", retry, created, err)
	}
	result, body, err := engine.Finalize(context.Background(), record.Job, request)
	if err != nil {
		t.Fatal(err)
	}
	bodyDescriptor := artifactvault.Descriptor{SHA256: hash(body), Bytes: int64(len(body))}
	completed, changed, err := repository.Complete(context.Background(), record.Job, request, result, bodyDescriptor)
	if err != nil || !changed || completed.State != Finalized || completed.Result == nil || completed.FinalBody == nil || *completed.FinalBody != bodyDescriptor {
		t.Fatalf("complete = %#v changed=%v err=%v", completed, changed, err)
	}
	loaded, found, err := repository.Load(context.Background(), record.Job.ID)
	if err != nil || !found || loaded.Result == nil || loaded.Result.Digest() != result.Digest() || loaded.FinalBody == nil || *loaded.FinalBody != bodyDescriptor {
		t.Fatalf("load = %#v found=%v err=%v", loaded, found, err)
	}
	duplicate, changed, err := repository.Complete(context.Background(), record.Job, request, result, bodyDescriptor)
	if err != nil || changed || duplicate.Result == nil || duplicate.Result.Digest() != result.Digest() {
		t.Fatalf("unexpired duplicate = %#v changed=%v err=%v", duplicate, changed, err)
	}
}

func TestRepositoryRefusesCrossJobAndTamperedResults(t *testing.T) {
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	engine, request, _, _, _, public := finalizerFixture(t, now)
	repository, err := OpenRepository(filepath.Join(t.TempDir(), "finalizer"), "finalizer-a", public)
	if err != nil {
		t.Fatal(err)
	}
	repository.now = func() time.Time { return now }
	record, _, err := repository.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	result, body, err := engine.Finalize(context.Background(), record.Job, request)
	if err != nil {
		t.Fatal(err)
	}
	bodyDescriptor := artifactvault.Descriptor{SHA256: hash(body), Bytes: int64(len(body))}
	other := request
	other.StageID = strings.Repeat("e", 64)
	other.RequestDigest = other.Digest()
	if _, _, err := repository.Complete(context.Background(), record.Job, other, result, bodyDescriptor); err == nil {
		t.Fatal("cross-request result was accepted")
	}
	wrongBody := bodyDescriptor
	wrongBody.Bytes++
	if _, _, err := repository.Complete(context.Background(), record.Job, request, result, wrongBody); err == nil {
		t.Fatal("result was accepted with a different final-body descriptor")
	}
	if _, _, err := repository.Complete(context.Background(), record.Job, request, result, bodyDescriptor); err != nil {
		t.Fatal(err)
	}
	path := repository.jobPath(record.Job.ID)
	if err := os.WriteFile(path, []byte(`{"schema":"tampered"}\n`), finalizerRecordMode); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.Load(context.Background(), record.Job.ID); err == nil {
		t.Fatal("tampered finalization record was accepted")
	}
}

func TestRepositoryRefreshesOnlyExpiredResultForTheSameJob(t *testing.T) {
	now := time.Date(2026, 8, 24, 10, 0, 0, 0, time.UTC)
	engine, request, _, _, _, public := finalizerFixture(t, now)
	repository, err := OpenRepository(filepath.Join(t.TempDir(), "finalizer"), "finalizer-a", public)
	if err != nil {
		t.Fatal(err)
	}
	repository.now = func() time.Time { return now }
	record, _, err := repository.Create(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	first, body, err := engine.Finalize(context.Background(), record.Job, request)
	if err != nil {
		t.Fatal(err)
	}
	bodyDescriptor := artifactvault.Descriptor{SHA256: hash(body), Bytes: int64(len(body))}
	if _, _, err := repository.Complete(context.Background(), record.Job, request, first, bodyDescriptor); err != nil {
		t.Fatal(err)
	}
	now = now.Add(16 * time.Minute)
	refreshed := first
	refreshed.FinalizedAt = now
	refreshed.ExpiresAt = now.Add(15 * time.Minute)
	refreshed.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(engine.resultKey, []byte(resultPrefix+refreshed.Digest())))
	refreshedDescriptor := bodyDescriptor
	updated, changed, err := repository.Complete(context.Background(), record.Job, request, refreshed, refreshedDescriptor)
	if err != nil || !changed || updated.Result == nil || updated.Result.Digest() != refreshed.Digest() || updated.Result.Digest() == first.Digest() {
		t.Fatalf("expired refresh = %#v changed=%v err=%v", updated, changed, err)
	}
}
