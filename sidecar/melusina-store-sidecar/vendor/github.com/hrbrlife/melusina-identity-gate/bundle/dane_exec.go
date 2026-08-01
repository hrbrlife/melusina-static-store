package bundle

import (
	"context"
	"fmt"
	"os/exec"
)

// execDig is the default `dig +short TLSA <fqdn>` invocation. Kept in
// its own file so tests (dane_test.go) can swap the package-level
// `execDig` var to a fake without monkey-patching exec.Command.
//
// The dig binary must be on PATH. Callers that run inside a sandbox
// (Sandstorm grain, scratch container) MUST inject a custom Resolver
// via DANECrossCheckWithResolver instead — see the doc-comment on
// DefaultResolver for the trade-off.
var execDig = func(ctx context.Context, fqdn string) (string, error) {
	cmd := exec.CommandContext(ctx, "dig", "+short", "+time=3", "+tries=1", "TLSA", fqdn)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("dig: %w", err)
	}
	return string(out), nil
}
