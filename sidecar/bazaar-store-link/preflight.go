package storelink

// Fixed deployment preflight for the four release workers. This is not a
// health proxy or a job API: it sends only an authenticated GET for a reserved
// nonexistent job ID. A verified 404 proves the exact mTLS route reached the
// named worker without creating a release, invoking a build, or touching a
// tenant.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const workerPreflightJobID = "000000000000000000000000"

// VerifyControlPlane is the complete installer preflight. It verifies one
// private ready-status observation through the pinned sidecar mTLS path, then
// proves every pinned worker path using only the reserved no-job reads below.
// It deliberately cannot exercise a release mutation or public catalog route.
func VerifyControlPlane(ctx context.Context, config Config, sidecar Forwarder, workers WorkerForwarder) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if sidecar == nil {
		return errors.New("Store Link control-plane preflight requires a sidecar forwarder")
	}
	response, err := sidecar.Forward(ctx, ForwardRequest{Method: http.MethodGet, Path: "/control/v1/status", Headers: make(http.Header), Body: io.NopCloser(strings.NewReader(""))})
	if err != nil {
		return fmt.Errorf("Store Link sidecar control-plane preflight: %w", err)
	}
	if err := verifyReadyStoreStatus(config.StoreID, response); err != nil {
		return fmt.Errorf("Store Link sidecar control-plane preflight: %w", err)
	}
	if err := VerifyFixedWorkers(ctx, workers); err != nil {
		return err
	}
	return nil
}

// VerifyFixedWorkers proves that every configured worker accepts Store Link's
// pinned mTLS identity and exposes only its expected collection route. Each
// worker must return 404 for the reserved job ID; any other response, TLS
// failure, redirect, or body error is a failed deployment preflight.
func VerifyFixedWorkers(ctx context.Context, workers WorkerForwarder) error {
	if workers == nil {
		return errors.New("Store Link worker preflight requires configured workers")
	}
	targets := []struct {
		name       string
		collection string
		forward    func(context.Context, WorkerRequest) (WorkerResponse, error)
	}{
		{name: "build", collection: buildJobCollection, forward: workers.ForwardBuild},
		{name: "release preparation", collection: releasePreparationJobCollection, forward: workers.ForwardReleasePreparation},
		{name: "release finalization", collection: releaseFinalizationJobCollection, forward: workers.ForwardReleaseFinalization},
		{name: "tenant proof", collection: tenantProofJobCollection, forward: workers.ForwardTenantProof},
	}
	for _, target := range targets {
		response, err := target.forward(ctx, WorkerRequest{
			Method: http.MethodGet,
			Path:   "/v1/" + target.collection + "/" + workerPreflightJobID,
			Body:   io.NopCloser(strings.NewReader("")),
		})
		if err != nil {
			return fmt.Errorf("Store Link %s worker preflight: %w", target.name, err)
		}
		if response.Body == nil {
			return fmt.Errorf("Store Link %s worker preflight returned no response body", target.name)
		}
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			return fmt.Errorf("Store Link %s worker preflight returned %d, want 404", target.name, response.StatusCode)
		}
		if closeErr != nil {
			return fmt.Errorf("Store Link %s worker preflight close response: %w", target.name, closeErr)
		}
	}
	return nil
}
