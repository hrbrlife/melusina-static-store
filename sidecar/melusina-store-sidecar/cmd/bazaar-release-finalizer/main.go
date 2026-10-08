// Command bazaar-release-finalizer serves only the Store-Link-authenticated
// fixed finalization routes. Its private configuration composes the existing
// Core observer, custody clients and durable engine; no backend is selected
// by a browser, job, command argument or environment variable.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hrbrlife/melusina-store-sidecar/internal/releasefinalizer"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "bazaar-release-finalizer:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("bazaar-release-finalizer", flag.ContinueOnError)
	path := flags.String("config", "", "owner-only fixed finalizer service config")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 {
		return errors.New("exactly one -config path is required")
	}
	service, err := releasefinalizer.LoadService(*path)
	if err != nil {
		return err
	}
	return service.Serve(ctx)
}
