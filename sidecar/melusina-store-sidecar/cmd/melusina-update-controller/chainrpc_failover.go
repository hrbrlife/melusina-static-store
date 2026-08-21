package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hrbrlife/melusina-identity-gate/verify"
)

// The update rail had exactly ONE trusted RPC endpoint and no failover, which is
// the shape that took the default Bazaar catalog to HTTP 503 when a single key
// hit its quota (agentchat F-235/F-238). It is worse here than in the store: the
// boot-identity ceremony turns ANY chain error into log.Fatalf, and the unit is
// Restart=on-failure with no start limit, so one exhausted endpoint crash-loops
// the controller rather than merely degrading it.
//
// chainRPC is the set of reads the chain gate and the boot ceremony perform.
// *verify.RPCClient satisfies it, so a single-endpoint deployment behaves exactly
// as before.
type chainRPC interface {
	FetchGlobalSidecarBinaryHash(ctx context.Context, addr string) ([32]byte, error)
	FetchGlobalSidecarStatus(ctx context.Context, addr string) (verify.ApprovalStatus, error)
	FetchInstallerReleaseEntry(ctx context.Context, addr string) ([32]byte, verify.AttestationStatus, error)
	FetchLicenseEntrySummary(ctx context.Context, addr string) (verify.LicenseEntrySummary, error)
	FetchLocalSidecarBinaryHash(ctx context.Context, addr string) ([32]byte, bool, error)
	FetchLocalSidecarStatus(ctx context.Context, addr string) (verify.ApprovalStatus, error)
	FetchReleaseEntry(ctx context.Context, addr string) ([32]byte, verify.AttestationStatus, error)
	FetchResellerEntryStatus(ctx context.Context, addr string) (verify.ResellerStatus, error)
	FetchResellerSidecarStatus(ctx context.Context, addr string) (verify.ApprovalStatus, error)
	FetchSidecarIdentity(ctx context.Context, addr string) (verify.SidecarIdentity, error)
}

var _ chainRPC = (*verify.RPCClient)(nil)
var _ chainRPC = (*failoverRPC)(nil)

const (
	controllerDefaultRPCAttempts = 2
	controllerMaxRPCAttempts     = 3
	controllerRPCRetryDelay      = 100 * time.Millisecond
)

// failoverRPC advances to the next configured endpoint on, and ONLY on,
// verify.ErrRPCUnreachable — the same classification the store sidecar uses. A
// valid answer that says an account is absent, revoked or malformed is a chain
// verdict, is returned immediately, and stays fail-closed. Trying another
// endpoint after a definitive denial would be equivocation-shopping.
type failoverRPC struct {
	clients  []chainRPC
	attempts int
	delay    time.Duration
}

func newFailoverRPC(primary string, fallbacks []string, attempts int) *failoverRPC {
	clients := make([]chainRPC, 0, 1+len(fallbacks))
	clients = append(clients, verify.NewRPCClient(primary))
	for _, endpoint := range fallbacks {
		clients = append(clients, verify.NewRPCClient(endpoint))
	}
	if attempts <= 0 {
		attempts = controllerDefaultRPCAttempts
	}
	return &failoverRPC{clients: clients, attempts: attempts, delay: controllerRPCRetryDelay}
}

func (f *failoverRPC) call(ctx context.Context, invoke func(context.Context, chainRPC) error) error {
	var transient int
	for i, client := range f.clients {
		for attempt := 0; attempt < f.attempts; attempt++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			err := invoke(ctx, client)
			if err == nil {
				return nil
			}
			if !errors.Is(err, verify.ErrRPCUnreachable) {
				return err
			}
			transient++
			if attempt+1 < f.attempts || i+1 < len(f.clients) {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(f.delay):
				}
			}
		}
	}
	return fmt.Errorf("%w: all configured RPC attempts failed (%d transport failure(s))", verify.ErrRPCUnreachable, transient)
}

func (f *failoverRPC) FetchGlobalSidecarBinaryHash(ctx context.Context, addr string) (out [32]byte, err error) {
	err = f.call(ctx, func(c context.Context, r chainRPC) error {
		out, err = r.FetchGlobalSidecarBinaryHash(c, addr)
		return err
	})
	return out, err
}

func (f *failoverRPC) FetchGlobalSidecarStatus(ctx context.Context, addr string) (out verify.ApprovalStatus, err error) {
	err = f.call(ctx, func(c context.Context, r chainRPC) error { out, err = r.FetchGlobalSidecarStatus(c, addr); return err })
	return out, err
}

func (f *failoverRPC) FetchInstallerReleaseEntry(ctx context.Context, addr string) (h [32]byte, s verify.AttestationStatus, err error) {
	err = f.call(ctx, func(c context.Context, r chainRPC) error {
		h, s, err = r.FetchInstallerReleaseEntry(c, addr)
		return err
	})
	return h, s, err
}

func (f *failoverRPC) FetchLicenseEntrySummary(ctx context.Context, addr string) (out verify.LicenseEntrySummary, err error) {
	err = f.call(ctx, func(c context.Context, r chainRPC) error { out, err = r.FetchLicenseEntrySummary(c, addr); return err })
	return out, err
}

func (f *failoverRPC) FetchLocalSidecarBinaryHash(ctx context.Context, addr string) (h [32]byte, present bool, err error) {
	err = f.call(ctx, func(c context.Context, r chainRPC) error {
		h, present, err = r.FetchLocalSidecarBinaryHash(c, addr)
		return err
	})
	return h, present, err
}

func (f *failoverRPC) FetchLocalSidecarStatus(ctx context.Context, addr string) (out verify.ApprovalStatus, err error) {
	err = f.call(ctx, func(c context.Context, r chainRPC) error { out, err = r.FetchLocalSidecarStatus(c, addr); return err })
	return out, err
}

func (f *failoverRPC) FetchReleaseEntry(ctx context.Context, addr string) (h [32]byte, s verify.AttestationStatus, err error) {
	err = f.call(ctx, func(c context.Context, r chainRPC) error { h, s, err = r.FetchReleaseEntry(c, addr); return err })
	return h, s, err
}

func (f *failoverRPC) FetchResellerEntryStatus(ctx context.Context, addr string) (out verify.ResellerStatus, err error) {
	err = f.call(ctx, func(c context.Context, r chainRPC) error { out, err = r.FetchResellerEntryStatus(c, addr); return err })
	return out, err
}

func (f *failoverRPC) FetchResellerSidecarStatus(ctx context.Context, addr string) (out verify.ApprovalStatus, err error) {
	err = f.call(ctx, func(c context.Context, r chainRPC) error {
		out, err = r.FetchResellerSidecarStatus(c, addr)
		return err
	})
	return out, err
}

func (f *failoverRPC) FetchSidecarIdentity(ctx context.Context, addr string) (out verify.SidecarIdentity, err error) {
	err = f.call(ctx, func(c context.Context, r chainRPC) error { out, err = r.FetchSidecarIdentity(c, addr); return err })
	return out, err
}

// normalizeControllerRPCEndpoints mirrors the store sidecar's validation. Errors
// never echo an endpoint value: these URLs carry API keys.
func normalizeControllerRPCEndpoints(primary string, fallbacks []string, attempts int) (string, []string, int, error) {
	primary = strings.TrimSpace(primary)
	if attempts == 0 {
		attempts = controllerDefaultRPCAttempts
	}
	if attempts < 1 || attempts > controllerMaxRPCAttempts {
		return "", nil, 0, fmt.Errorf("config: solanaRpcAttempts must be between 1 and %d", controllerMaxRPCAttempts)
	}
	if primary == "" {
		if len(fallbacks) != 0 {
			return "", nil, 0, errors.New("config: solanaRpcFallbackUrls requires solanaRpcUrl")
		}
		return "", nil, attempts, nil
	}
	seen := map[string]struct{}{primary: {}}
	out := make([]string, 0, len(fallbacks))
	for _, raw := range fallbacks {
		endpoint := strings.TrimSpace(raw)
		if endpoint == "" {
			return "", nil, 0, errors.New("config: solanaRpcFallbackUrls contains an empty endpoint")
		}
		if _, dup := seen[endpoint]; dup {
			// A duplicate is not a harmless no-op: it burns an attempt budget on
			// an endpoint already known to be failing.
			return "", nil, 0, errors.New("config: solanaRpcFallbackUrls contains a duplicate endpoint")
		}
		seen[endpoint] = struct{}{}
		out = append(out, endpoint)
	}
	return primary, out, attempts, nil
}
