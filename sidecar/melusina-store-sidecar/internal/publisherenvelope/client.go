package publisherenvelope

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const maxResponseBytes = 128 << 10

// Client is the finalizer-side half of the constrained local signer protocol.
// Its socket comes from supervised worker configuration, never from a release
// request. It does not know any Store URL, sidecar route, transaction, or key.
type Client struct {
	socketPath string
	dial       func(context.Context, string, string) (net.Conn, error)
}

func NewClient(socketPath string) (*Client, error) {
	if !filepath.IsAbs(socketPath) {
		return nil, errors.New("publisher-envelope client requires an absolute socket path")
	}
	return &Client{socketPath: socketPath, dial: (&net.Dialer{}).DialContext}, nil
}

// Sign sends only the fixed publisher-envelope request to the configured,
// owner-only Unix socket. It does not submit the envelope anywhere; the
// finalizer still validates all returned facts before it produces a result.
func (c *Client) Sign(ctx context.Context, request Request) (Response, error) {
	if c == nil || c.dial == nil || !filepath.IsAbs(c.socketPath) {
		return Response{}, errors.New("publisher-envelope client is unavailable")
	}
	if err := requireSignerSocket(c.socketPath); err != nil {
		return Response{}, fmt.Errorf("publisher-envelope socket: %w", err)
	}
	conn, err := c.dial(ctx, "unix", c.socketPath)
	if err != nil {
		return Response{}, fmt.Errorf("connect publisher-envelope signer: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return Response{}, fmt.Errorf("write publisher-envelope request: %w", err)
	}
	// The signer validates that this is the only JSON document by reading to
	// EOF. Half-close our request stream before waiting for its response; without
	// this, two strict decoders wait on each other forever for trailing input.
	halfClose, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		return Response{}, errors.New("publisher-envelope connection cannot close its request stream")
	}
	if err := halfClose.CloseWrite(); err != nil {
		return Response{}, fmt.Errorf("finish publisher-envelope request: %w", err)
	}
	var response Response
	decoder := json.NewDecoder(io.LimitReader(conn, maxResponseBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Response{}, errors.New("publisher-envelope signer response is malformed")
	}
	if response.Schema != ResponseSchema || response.Error != "" {
		return Response{}, errors.New("publisher-envelope signer refused the request")
	}
	return response, nil
}

func requireSignerSocket(path string) error {
	if err := ownerOnlyDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("socket directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != socketMode || int(stat.Uid) != os.Geteuid() {
		return errors.New("must be an owner-only mode-0600 Unix socket owned by this user")
	}
	return nil
}
