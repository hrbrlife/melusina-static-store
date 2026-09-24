package main

import (
	"errors"
	"net/http"
	"time"
)

// The public listener serves artifacts of up to maxServedArtifactBytes and
// accepts publications of the same size. Its limits are derived from that one
// size and a floor transfer rate, so a client that stops reading, or reads
// slower than the floor, cannot hold a connection, and the private snapshot
// behind a gated download, indefinitely.
//
// - WriteTimeout. Go starts it when a request's headers have been read and it
//   covers everything after: reading the body, handling it, and writing the
//   response. It is the time to move the largest artifact at the floor rate,
//   plus slack, so the largest publication or download a client moves at the
//   floor rate completes, and nothing takes longer.
// - Each gated download then tightens its own write deadline to its
//   artifact's size at the floor rate, plus the same slack
//   (serveGate.limitTransfer). A client that stops reading a small artifact
//   releases its snapshot within about a minute, not after the listener-wide
//   limit.
// - IdleTimeout closes a keep-alive connection that sends no next request.
// - ReadHeaderTimeout bounds a client that never finishes its headers.

const (
	// publicTransferFloorBytesPerSecond is the slowest transfer the public
	// listener completes: 4 Mbit/s. The largest artifact then takes 17
	// minutes 4 seconds.
	publicTransferFloorBytesPerSecond int64 = 512 << 10
	// publicTransferSlack is added to every transfer deadline: time to
	// establish TLS, and for a request's handling.
	publicTransferSlack     = 60 * time.Second
	publicIdleTimeout       = 120 * time.Second
	publicReadHeaderTimeout = 10 * time.Second
)

// transferPolicy turns a byte count into the time a transfer of that many
// bytes may take.
type transferPolicy struct {
	floorBytesPerSecond int64
	slack               time.Duration
}

var publicTransfer = transferPolicy{floorBytesPerSecond: publicTransferFloorBytesPerSecond, slack: publicTransferSlack}

// deadlineFor is size at the floor rate, rounded up to a whole second, plus
// the slack.
func (p transferPolicy) deadlineFor(size int64) time.Duration {
	if size < 0 {
		size = 0
	}
	seconds := (size + p.floorBytesPerSecond - 1) / p.floorBytesPerSecond
	return time.Duration(seconds)*time.Second + p.slack
}

// newPublicServer is the one constructor of the public listener.
func newPublicServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: publicReadHeaderTimeout,
		WriteTimeout:      publicTransfer.deadlineFor(maxServedArtifactBytes),
		IdleTimeout:       publicIdleTimeout,
	}
}

// limitTransfer sets the write deadline of one gated download to its
// artifact's size at the floor rate, plus slack. When it passes, the
// response's next write fails, the handler returns and its snapshot is
// closed and released. A ResponseWriter that has no deadline (an in-process
// test recorder) is left alone: the real listener's writers all have one.
func (g *serveGate) limitTransfer(w http.ResponseWriter, size int64) error {
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(g.transfer.deadlineFor(size)))
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}
