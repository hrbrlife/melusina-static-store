package storelink

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type preflightWorkerForwarder struct {
	requests []WorkerRequest
	status   map[string]int
}

func (f *preflightWorkerForwarder) response(name string, request WorkerRequest) (WorkerResponse, error) {
	f.requests = append(f.requests, request)
	status := http.StatusNotFound
	if f.status != nil && f.status[name] != 0 {
		status = f.status[name]
	}
	return WorkerResponse{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader("{}"))}, nil
}

func (f *preflightWorkerForwarder) ForwardBuild(_ context.Context, request WorkerRequest) (WorkerResponse, error) {
	return f.response(buildJobCollection, request)
}

func (f *preflightWorkerForwarder) ForwardReleasePreparation(_ context.Context, request WorkerRequest) (WorkerResponse, error) {
	return f.response(releasePreparationJobCollection, request)
}

func (f *preflightWorkerForwarder) ForwardReleaseFinalization(_ context.Context, request WorkerRequest) (WorkerResponse, error) {
	return f.response(releaseFinalizationJobCollection, request)
}

func (f *preflightWorkerForwarder) ForwardTenantProof(_ context.Context, request WorkerRequest) (WorkerResponse, error) {
	return f.response(tenantProofJobCollection, request)
}

func TestVerifyFixedWorkersUsesOnlyReservedReadOnlyJobProbes(t *testing.T) {
	workers := &preflightWorkerForwarder{}
	if err := VerifyFixedWorkers(context.Background(), workers); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/v1/" + buildJobCollection + "/" + workerPreflightJobID,
		"/v1/" + releasePreparationJobCollection + "/" + workerPreflightJobID,
		"/v1/" + releaseFinalizationJobCollection + "/" + workerPreflightJobID,
		"/v1/" + tenantProofJobCollection + "/" + workerPreflightJobID,
	}
	if len(workers.requests) != len(want) {
		t.Fatalf("preflight requests = %d, want %d", len(workers.requests), len(want))
	}
	for i, request := range workers.requests {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		_ = request.Body.Close()
		if request.Method != http.MethodGet || request.Path != want[i] || len(body) != 0 {
			t.Fatalf("preflight request %d = %s %q %q", i, request.Method, request.Path, body)
		}
	}
}

func TestVerifyFixedWorkersFailsWhenAnyRouteDoesNotProveNoJob(t *testing.T) {
	workers := &preflightWorkerForwarder{status: map[string]int{releaseFinalizationJobCollection: http.StatusOK}}
	err := VerifyFixedWorkers(context.Background(), workers)
	if err == nil || !strings.Contains(err.Error(), "release finalization") || !strings.Contains(err.Error(), "want 404") {
		t.Fatalf("unexpected preflight result: %v", err)
	}
	if len(workers.requests) != 3 {
		t.Fatalf("preflight continued after unhealthy fixed route: %d requests", len(workers.requests))
	}
}
