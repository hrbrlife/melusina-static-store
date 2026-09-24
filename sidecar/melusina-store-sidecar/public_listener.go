package main

import (
	"errors"
	"net/http"
	"time"
)

// The public listener serves artifacts of up to maxServedArtifactBytes and
// accepts request bodies of up to maxPublicRequestBody. Its limits are derived
// from those sizes and a floor transfer rate, so a client that stops sending,
// stops reading, or moves bytes slower than the floor cannot hold a
// connection, its handler, the body read so far, or the private snapshot
// behind a gated download, indefinitely.
//
// - ReadHeaderTimeout bounds a client that never finishes its headers.
// - ReadTimeout. Go counts it from when it starts reading a request, and it
//   bounds reading the headers and the body. It is the time to move the
//   largest body any route accepts at the floor rate, plus half the slack
//   (transferPolicy.readLimitFor). When it passes, the handler's next read of
//   the body fails, so a client that trickles an upload is cut off and its
//   route refuses it. Once a body has been read to its end, Go clears the
//   read deadline (HTTP/1.1, startBackgroundRead), so the limit never cuts
//   short a request's handling or a download.
// - WriteTimeout. Go starts it when a request's headers have been read and it
//   bounds writing the response, not reading the body. It is the time to move
//   the largest artifact at the floor rate, plus the whole slack. It
//   therefore passes at least half the slack after the read limit, so an
//   upload cut off at the read limit is still answered with its refusal, and
//   one whose body arrived in time still has that long to be handled.
// - Each gated download then tightens its own write deadline to its
//   artifact's size at the floor rate, plus the slack
//   (serveGate.limitTransfer). A client that stops reading a small artifact
//   releases its snapshot within about a minute, not after the listener-wide
//   limit.
// - IdleTimeout closes a keep-alive connection that sends no next request.
//
// The read limit is listener-wide, not per route: a client may trickle a body
// to a route with a small body limit for as long as the largest upload may
// take. It holds one connection and at most that route's limit in memory.

const (
	// publicTransferFloorBytesPerSecond is the slowest transfer the public
	// listener completes: 4 Mbit/s. The largest artifact then takes 17
	// minutes 4 seconds.
	publicTransferFloorBytesPerSecond int64 = 512 << 10
	// publicTransferSlack is added to every transfer deadline: time to
	// establish TLS and read the headers, and for a request's handling. A
	// request body's read limit gets only half of it (readLimitFor).
	publicTransferSlack     = 60 * time.Second
	publicIdleTimeout       = 120 * time.Second
	publicReadHeaderTimeout = 10 * time.Second

	// maxPublicRequestBody is the largest request body any Store route
	// accepts: the /publish/installer limit. limitPublishBody refuses a route
	// limit above it, so ReadTimeout, derived from it, always lets the
	// largest accepted upload arrive at the floor rate.
	maxPublicRequestBody = maxInstallerPublishBody
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

// readLimitFor is the time a request whose body has size bytes may take to
// arrive: size at the floor rate plus half the slack, which covers reading
// the headers (at most publicReadHeaderTimeout). The other half is kept for
// handling and answering the request before its write limit passes.
func (p transferPolicy) readLimitFor(size int64) time.Duration {
	return p.deadlineFor(size) - p.slack/2
}

// newPublicServer is the one constructor of the public listener.
func newPublicServer(addr string, handler http.Handler) *http.Server {
	return publicServerWithTransfer(addr, handler, publicTransfer)
}

// publicServerWithTransfer builds the public listener with its limits derived
// from policy. Only newPublicServer and tests call it; a test passes a policy
// whose limits are seconds long.
func publicServerWithTransfer(addr string, handler http.Handler, policy transferPolicy) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: publicReadHeaderTimeout,
		ReadTimeout:       policy.readLimitFor(maxPublicRequestBody),
		WriteTimeout:      policy.deadlineFor(maxServedArtifactBytes),
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
