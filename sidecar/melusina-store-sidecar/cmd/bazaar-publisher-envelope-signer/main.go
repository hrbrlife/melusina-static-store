// Command bazaar-publisher-envelope-signer owns the finalizer-side publisher
// identity. It exposes only a same-user Unix socket; it cannot connect to the
// Store, Solana, Squads, a browser, or a caller-selected endpoint.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/hrbrlife/melusina-store-sidecar/internal/publisherenvelope"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "bazaar-publisher-envelope-signer:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("bazaar-publisher-envelope-signer", flag.ContinueOnError)
	socket := fs.String("socket", "", "absolute mode-0700-directory Unix socket path (required)")
	publisher := fs.String("publisher-identity", "", "absolute owner-only publisher identity JSON path (required)")
	store := fs.String("store-identity", "", "absolute Store public identity JSON path (required)")
	storeID := fs.String("store-id", "", "fixed Bazaar Store id (required)")
	uidText := fs.String("finalizer-uid", "", "numeric Unix uid allowed to request envelopes (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *uidText == "" {
		return fmt.Errorf("-finalizer-uid is required; do not default a custody peer")
	}
	uid, err := strconv.ParseUint(*uidText, 10, 32)
	if err != nil {
		return fmt.Errorf("-finalizer-uid: %w", err)
	}
	service, err := publisherenvelope.Load(publisherenvelope.Config{
		SocketPath: *socket, PublisherIdentityPath: *publisher, StoreIdentityPath: *store,
		StoreID: *storeID, AllowedUID: uint32(uid),
	})
	if err != nil {
		return err
	}
	return publisherenvelope.Serve(context.Background(), *socket, service)
}
